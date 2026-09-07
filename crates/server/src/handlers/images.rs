//! /images/* — pull (streaming progress), list, inspect, tag, history, rmi.

use crate::handlers::{bad_request, docker_error, not_found, server_error};
use crate::state::SharedState;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use ingot_api::{
    AuthConfig, HistoryResponseItem, ImageDeleteResponseItem, ImageInspect, ImageSummary,
    ImagesPruneReport, ProgressMessage, RootFs,
};
use ingot_registry::ImageRef;
use std::collections::HashMap;

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct CreateParams {
    #[serde(rename = "fromImage")]
    from_image: Option<String>,
    #[serde(rename = "fromSrc")]
    from_src: Option<String>,
    tag: Option<String>,
    platform: Option<String>,
    // Accepted for API compatibility; commit messages on tag/import land in
    // Plan Phase 4.
    #[allow(dead_code)]
    #[serde(default)]
    message: Option<String>,
}

/// POST /images/create — the pull endpoint. Streams newline JSON progress.
pub async fn create(
    State(state): State<SharedState>,
    Query(q): Query<CreateParams>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let _ = body; // (docker CLI sends an empty body for pulls)
    if q.from_src.is_some() {
        return crate::handlers::not_implemented("image import (fromSrc) is not implemented yet");
    }
    let Some(spec) = q.from_image.clone() else {
        return bad_request("fromImage or fromSrc required");
    };

    // "busybox" or "busybox:1.36" (CLI passes the tag via query too). The
    // CLI splits digest references across the two params (`pull
    // repo@digest` arrives as fromImage=repo + tag=sha256:…), so a
    // digest-looking tag joins with '@', never ':'.
    let mut spec = spec;
    if let Some(t) = &q.tag {
        spec = assemble_pull_spec(&spec, t);
    }
    let image_ref = match ImageRef::parse(&spec) {
        Ok(r) => r,
        Err(e) => return bad_request(e),
    };

    let auth = decode_auth_header(&headers);
    let platform = match q.platform.as_deref() {
        None | Some("") => None,
        Some(p) => match ingot_registry::parse_platform(p) {
            Ok(plat) => Some(plat),
            Err(e) => return bad_request(e),
        },
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<ProgressMessage>(64);
    let client = state.registry.clone();
    let store = state.images.clone();
    tokio::spawn(async move {
        if let Err(e) =
            ingot_image::pull::pull(client, store, image_ref, auth, platform, tx.clone()).await
        {
            let _ = tx.send(ProgressMessage::error(format!("{e:#}"))).await;
        }
    });

    let stream = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|msg| {
            let mut line = serde_json::to_string(&msg).unwrap_or_default();
            line.push('\n');
            (Ok::<_, std::io::Error>(axum::body::Bytes::from(line)), rx)
        })
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// Reassemble the CLI's split pull reference: fromImage carries the repo
/// (sometimes with tag and/or digest) while the tag query carries the rest.
/// Digest-looking pieces join with '@'; plain tags join with ':' only when
/// the spec has no tag yet. A spec that already pins a digest is complete.
fn assemble_pull_spec(spec: &str, tag: &str) -> String {
    if spec.contains('@') || tag.is_empty() {
        return spec.to_string();
    }
    if tag.starts_with("sha256:") {
        return format!("{spec}@{tag}");
    }
    if tag.contains('@') || !spec.contains(':') {
        return format!("{spec}:{tag}");
    }
    spec.to_string()
}

fn decode_auth_header(headers: &HeaderMap) -> Option<AuthConfig> {
    let raw = headers.get("X-Registry-Auth")?.to_str().ok()?;
    // The CLI sends either base64(json) or base64(base64(user:pass)).
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .ok()?;
    if let Ok(cfg) = serde_json::from_slice::<AuthConfig>(&decoded) {
        if !cfg.username.is_empty() || !cfg.identity_token.is_empty() {
            return Some(cfg);
        }
        // auth = base64(user:pass)
        if !cfg.auth.is_empty() {
            if let Ok(up) = base64::engine::general_purpose::STANDARD.decode(&cfg.auth) {
                if let Ok(s) = String::from_utf8(up) {
                    if let Some((u, p)) = s.split_once(':') {
                        return Some(AuthConfig {
                            username: u.into(),
                            password: p.into(),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
    None
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct ImageListQuery {
    filters: Option<String>,
}

/// Shared filter-object parsing for image list/prune: a JSON object of
/// key → string array. Empty/missing input matches everything.
// `Response` is large by nature; this is a cold error path, not a hot loop.
#[allow(clippy::result_large_err)]
fn parse_filter_map(
    raw: Option<&String>,
) -> Result<serde_json::Map<String, serde_json::Value>, Response> {
    match raw {
        None => Ok(Default::default()),
        Some(s) if s.trim().is_empty() => Ok(Default::default()),
        Some(s) => match serde_json::from_str::<serde_json::Value>(s) {
            Ok(serde_json::Value::Object(m)) => Ok(m),
            _ => Err(crate::handlers::bad_request(
                "invalid filters: expected a JSON object",
            )),
        },
    }
}

/// Image filters (units 1.3/4.4): dangling, label, reference, until.
/// Unknown keys are an explicit 400.
// `Response` is large by nature; this is a cold error path, not a hot loop.
#[allow(clippy::result_large_err)]
fn image_matches(
    r: &ingot_image::ImageRecord,
    filters: &serde_json::Map<String, serde_json::Value>,
    now_unix: i64,
) -> Result<bool, Response> {
    for (k, vals) in filters {
        // Docker sends `{"key":{"value":true}}`; accept that and the
        // lenient `{"key":["value"]}` shape. Map keys set to true win;
        // anything else yields no values (matching nothing).
        let vals: Vec<String> = match vals {
            serde_json::Value::Array(a) => a
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
            serde_json::Value::Object(m) => m
                .iter()
                .filter(|(_, v)| *v == &serde_json::Value::Bool(true))
                .map(|(k, _)| k.clone())
                .collect(),
            _ => Vec::new(),
        };
        let hit = match k.as_str() {
            "dangling" => {
                let want = vals.iter().any(|v| v == "true" || v == "1");
                r.repo_tags.is_empty() == want
            }
            "label" => vals.iter().any(|w| match w.split_once('=') {
                Some((k, v)) => r.config.Labels.get(k).is_some_and(|got| got == v),
                None => r.config.Labels.contains_key(w),
            }),
            "reference" => vals.iter().any(|pat| {
                r.repo_tags.iter().any(|t| {
                    t == pat
                        || t.split_once(':').is_some_and(|(repo, _)| repo == pat)
                        || (pat.strip_suffix('*').is_some_and(|p| t.starts_with(p)))
                })
            }),
            // Prune-only: created before the cutoff. Images with unknown
            // age (created_unix 0) never match: they cannot be aged.
            "until" => {
                let mut hit = false;
                for v in &vals {
                    let cutoff = parse_until(v, now_unix).map_err(|e| {
                        crate::handlers::bad_request(format!("invalid until filter {v:?}: {e}"))
                    })?;
                    if r.created_unix > 0 && r.created_unix < cutoff {
                        hit = true;
                        break;
                    }
                }
                hit
            }
            other => {
                return Err(crate::handlers::bad_request(format!(
                    "invalid filter '{other}' (supported: dangling, label, reference, until)"
                )));
            }
        };
        if !hit {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Parse an `until` filter value to a unix cutoff: unix timestamp,
/// RFC 3339 timestamp, or Go-style duration (`24h`, `30m`, `90s`, `1h30m`)
/// meaning that long ago.
fn parse_until(v: &str, now_unix: i64) -> Result<i64, String> {
    let v = v.trim();
    if v.is_empty() {
        return Err("empty value".to_string());
    }
    if let Ok(ts) = v.parse::<i64>() {
        if ts >= 0 {
            return Ok(ts);
        }
        return Err("negative timestamp".to_string());
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(v) {
        return Ok(dt.timestamp());
    }
    parse_go_duration(v)
        .map(|d| now_unix.saturating_sub(d))
        .ok_or_else(|| "want a unix timestamp, RFC 3339 time, or Go duration like 24h".to_string())
}

/// Go-style duration (`1h30m`, `90s`): digits + h/m/s segments.
fn parse_go_duration(v: &str) -> Option<i64> {
    let mut total = 0i64;
    let mut num = String::new();
    let mut any = false;
    for c in v.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else {
            let n: i64 = num.parse().ok()?;
            let secs = match c {
                'h' => n.checked_mul(3600)?,
                'm' => n.checked_mul(60)?,
                's' => n,
                _ => return None,
            };
            total = total.checked_add(secs)?;
            num.clear();
            any = true;
        }
    }
    if !num.is_empty() || !any {
        return None;
    }
    Some(total)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// GET /images/json
pub async fn list(State(state): State<SharedState>, Query(q): Query<ImageListQuery>) -> Response {
    let _tags = state.images.all_tags().await;
    let filters = match parse_filter_map(q.filters.as_ref()) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let now = now_unix();
    let mut out: Vec<ImageSummary> = Vec::new();
    match state.images.list_effective().await {
        Ok(records) => {
            // Container counts for the Containers column.
            let mut usage: std::collections::HashMap<String, i64> =
                std::collections::HashMap::new();
            if let Some(mgr) = state.containers.as_ref() {
                for rec in mgr.list_records().await {
                    let key = rec.image_id.trim_start_matches("sha256:").to_string();
                    *usage.entry(key).or_default() += 1;
                }
            }
            for r in records {
                match image_matches(&r, &filters, now) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(resp) => return resp,
                }
                out.push(ImageSummary {
                    Id: format!("sha256:{}", r.id),
                    ParentId: String::new(),
                    RepoTags: r.repo_tags.clone(),
                    RepoDigests: r.repo_digests.clone(),
                    Created: r.created_unix,
                    Size: r.size,
                    SharedSize: -1,
                    VirtualSize: r.size,
                    Labels: r.config.Labels.clone(),
                    Containers: usage.get(&r.id).copied().unwrap_or(0),
                });
            }
            out.sort_by_key(|b| std::cmp::Reverse(b.Created));
            axum::Json(out).into_response()
        }
        Err(e) => server_error(e),
    }
}

/// GET /images/{name}/json
pub async fn inspect(State(state): State<SharedState>, Path(name): Path<String>) -> Response {
    let id = match state.images.resolve(&name).await {
        Ok(id) => id,
        Err(e) => return not_found(e),
    };
    let record = match state.images.load(&id).await {
        Ok(Some(r)) => r,
        _ => return not_found(format!("No such image: {name}")),
    };
    // Effective tags: inspect shows the tags that resolve here, not stale
    // embedded copies from before the tag moved on.
    let repo_tags = state.images.effective_tags(&record).await;
    let inspect = ImageInspect {
        Id: format!("sha256:{}", record.id),
        RepoTags: repo_tags,
        RepoDigests: record.repo_digests.clone(),
        Parent: String::new(),
        Comment: record.comment.clone(),
        Created: record.created.clone(),
        Container: String::new(),
        ContainerConfig: Default::default(),
        DockerVersion: record.docker_version.clone(),
        Author: record.author.clone(),
        Config: record.config.clone(),
        Architecture: record.architecture.clone(),
        Variant: String::new(),
        Os: record.os.clone(),
        Size: record.size,
        VirtualSize: record.size,
        GraphDriver: ingot_api::GraphDriverData {
            Name: "overlay2".into(),
            Data: HashMap::new(),
        },
        RootFS: RootFs {
            typ: "layers".into(),
            Layers: Some(record.diff_ids.clone()),
            FsLayers: None,
        },
        Metadata: ingot_api::ImageMetadata { LastTagTime: None },
    };
    axum::Json(inspect).into_response()
}

/// GET /images/{name}/history
pub async fn history(State(state): State<SharedState>, Path(name): Path<String>) -> Response {
    let id = match state.images.resolve(&name).await {
        Ok(id) => id,
        Err(e) => return not_found(e),
    };
    let record = match state.images.load(&id).await {
        Ok(Some(r)) => r,
        _ => return not_found(format!("No such image: {name}")),
    };
    // Stored history is oldest-first (OCI config order); docker prints
    // newest-first, so walk it reversed. Non-empty entries in stored order
    // line up 1:1 with diff_ids/layer_blobs/chain_ids (bottom-up).
    let layer_order: Vec<usize> = record
        .history
        .iter()
        .enumerate()
        .filter(|(_, h)| h.empty_layer != Some(true))
        .map(|(i, _)| i)
        .collect();
    // Effective tags for the top row (index truth, not stale embeds).
    let top_tags = state.images.effective_tags(&record).await;
    let mut items: Vec<HistoryResponseItem> = Vec::with_capacity(record.history.len());
    for (rev_i, (i, h)) in record.history.iter().enumerate().rev().enumerate() {
        let (id, size) = if h.empty_layer == Some(true) {
            ("<missing>".to_string(), 0)
        } else {
            // Position of this layer among non-empty layers, bottom-up.
            let pos = layer_order.iter().position(|&k| k == i).unwrap_or(0);
            let id = record
                .chain_ids
                .get(pos)
                .cloned()
                .unwrap_or_else(|| format!("sha256:{}", record.id));
            let size = record
                .layer_blobs
                .get(pos)
                .and_then(|d| state.images.blob_size(d))
                .unwrap_or(0) as i64;
            (id, size)
        };
        items.push(HistoryResponseItem {
            Comment: h.comment.clone().unwrap_or_default(),
            Created: chrono::DateTime::parse_from_rfc3339(&h.created)
                .map(|d| d.timestamp())
                .unwrap_or(0),
            CreatedBy: h.created_by.clone(),
            Id: id,
            Size: size,
            // Repo tags sit on the top layer: the first row printed.
            Tags: if rev_i == 0 {
                Some(top_tags.clone())
            } else {
                None
            },
        });
    }
    axum::Json(items).into_response()
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct TagParams {
    repo: String,
    tag: Option<String>,
}

/// POST /images/{name}/tag?repo=x&tag=y
pub async fn tag(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    Query(q): Query<TagParams>,
) -> Response {
    let id = match state.images.resolve(&name).await {
        Ok(id) => id,
        Err(e) => return not_found(e),
    };
    let tag_key = match (!q.repo.is_empty(), q.tag.as_deref()) {
        (true, t) => format!("{}:{}", q.repo, t.unwrap_or("latest")),
        _ => return bad_request("repo parameter required"),
    };
    match state.images.tag(&id, &tag_key).await {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => server_error(e),
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct DeleteParams {
    force: Option<bool>,
    noprune: Option<bool>,
}

/// DELETE /images/{name}
pub async fn remove(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    Query(q): Query<DeleteParams>,
) -> Response {
    let _ = q.noprune;
    let id = state
        .images
        .resolve(&name)
        .await
        .unwrap_or_else(|_| name.clone());
    let record = match state.images.load(&id).await {
        Ok(Some(r)) => r,
        _ => return not_found(format!("No such image: {name}")),
    };
    let mut events: Vec<ImageDeleteResponseItem> = Vec::new();
    // If the reference is a tag (not an id) and more tags exist, just untag.
    let tag_key = record
        .repo_tags
        .iter()
        .find(|t| *t == &name || t.starts_with(&format!("{name}:")));
    let untag_only = match tag_key {
        Some(t) if record.repo_tags.len() > 1 && q.force != Some(true) => Some(t.clone()),
        _ => None,
    };
    if let Some(t) = untag_only {
        match state.images.remove_image(&id, Some(&t)).await {
            Ok(_) => events.push(ImageDeleteResponseItem {
                Untagged: t,
                Deleted: String::new(),
            }),
            Err(e) => return server_error(e),
        }
        return axum::Json(events).into_response();
    }
    match state.images.remove_image(&id, None).await {
        Ok(r) => {
            for t in &r.repo_tags {
                events.push(ImageDeleteResponseItem {
                    Untagged: t.clone(),
                    Deleted: String::new(),
                });
            }
            events.push(ImageDeleteResponseItem {
                Untagged: String::new(),
                Deleted: format!("sha256:{}", r.id),
            });
            let ev = ingot_api::EventMessage::new(
                "image",
                "delete",
                &r.id,
                [("name".to_string(), name.clone())].into_iter().collect(),
            );
            state.events.publish(ev);
            axum::Json(events).into_response()
        }
        Err(e) => docker_error(StatusCode::CONFLICT, e),
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct ImagePruneQuery {
    filters: Option<String>,
}

/// POST /images/prune — filters: dangling (default true), until, label.
/// Unknown keys are an explicit 400 (unit 4.4).
pub async fn prune(State(state): State<SharedState>, Query(q): Query<ImagePruneQuery>) -> Response {
    let filters = match parse_filter_map(q.filters.as_ref()) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    // Docker default: without filters, only dangling images are pruned.
    let filters = if filters.is_empty() {
        let mut m = serde_json::Map::new();
        m.insert("dangling".to_string(), serde_json::json!(["true"]));
        m
    } else {
        filters
    };
    let now = now_unix();

    // Effective tags: pruning matches index truth, so records whose tag
    // has moved on (or away) prune as dangling.
    let all_images = match state.images.list_effective().await {
        Ok(imgs) => imgs,
        Err(e) => return server_error(format!("failed to list images: {e}")),
    };

    let containers = if let Some(ref mgr) = state.containers {
        mgr.list_records().await
    } else {
        Vec::new()
    };
    let used_image_ids: std::collections::HashSet<String> =
        containers.iter().map(|c| c.image_id.clone()).collect();

    let mut deleted_items = Vec::new();
    let mut space_reclaimed: u64 = 0;

    for img in all_images {
        let is_used = used_image_ids.contains(&img.id)
            || used_image_ids.contains(&format!("sha256:{}", img.id))
            || img.repo_tags.iter().any(|t| used_image_ids.contains(t));
        if is_used {
            continue;
        }
        match image_matches(&img, &filters, now) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(resp) => return resp,
        }

        if let Ok(rec) = state.images.remove_image(&img.id, None).await {
            space_reclaimed += img.size.max(0) as u64;
            for t in &rec.repo_tags {
                deleted_items.push(ImageDeleteResponseItem {
                    Untagged: t.clone(),
                    Deleted: String::new(),
                });
            }
            deleted_items.push(ImageDeleteResponseItem {
                Untagged: String::new(),
                Deleted: format!("sha256:{}", rec.id),
            });
        }
    }

    let report = ImagesPruneReport {
        ImagesDeleted: if deleted_items.is_empty() {
            None
        } else {
            Some(deleted_items)
        },
        SpaceReclaimed: space_reclaimed,
    };
    axum::Json(report).into_response()
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct ImageGetQuery {
    #[serde(deserialize_with = "ingot_api::de::string_vec")]
    names: Vec<String>,
}

fn tar_dir_recursive<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    real_path: &std::path::Path,
    archive_prefix: &std::path::Path,
    seen_inodes: &mut std::collections::HashMap<(u64, u64), std::path::PathBuf>,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    builder.follow_symlinks(false);
    for entry in std::fs::read_dir(real_path)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let sub_archive = if archive_prefix.as_os_str().is_empty() {
            std::path::PathBuf::from(&file_name)
        } else {
            archive_prefix.join(&file_name)
        };
        let sym_meta = std::fs::symlink_metadata(entry.path())?;
        if sym_meta.file_type().is_symlink() {
            builder.append_path_with_name(entry.path(), &sub_archive)?;
        } else if sym_meta.is_dir() {
            builder.append_dir(&sub_archive, entry.path())?;
            tar_dir_recursive(builder, &entry.path(), &sub_archive, seen_inodes)?;
        } else {
            if sym_meta.nlink() > 1 {
                let key = (sym_meta.dev(), sym_meta.ino());
                if let Some(target_path) = seen_inodes.get(&key) {
                    let mut header = tar::Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Link);
                    header.set_size(0);
                    header.set_mode(sym_meta.permissions().mode());
                    let _ = header.set_link_name(target_path);
                    header.set_cksum();
                    builder.append_data(&mut header, &sub_archive, std::io::empty())?;
                    continue;
                }
                seen_inodes.insert(key, sub_archive.clone());
            }
            builder.append_path_with_name(entry.path(), &sub_archive)?;
        }
    }
    Ok(())
}

/// GET /images/get
pub async fn get_tar(State(state): State<SharedState>, Query(q): Query<ImageGetQuery>) -> Response {
    let images_to_save: Vec<String> = if q.names.is_empty() {
        let all = state.images.list_effective().await.unwrap_or_default();
        all.into_iter().map(|img| img.id).collect()
    } else {
        q.names
    };

    let mut outer_tar = tar::Builder::new(Vec::new());
    let mut manifests = Vec::new();

    for img_name in images_to_save {
        let id = state
            .images
            .resolve(&img_name)
            .await
            .unwrap_or_else(|_| img_name.clone());
        let record = match state.images.load(&id).await {
            Ok(Some(r)) => r,
            _ => continue,
        };

        let config_hex = record.id.trim_start_matches("sha256:");
        let config_tar_path = format!("{config_hex}.json");

        let config_path = state.paths.blob(&record.id);
        let config_bytes = match std::fs::read(&config_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mut header = tar::Header::new_gnu();
        header.set_size(config_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        if let Err(e) = outer_tar.append_data(&mut header, &config_tar_path, &config_bytes[..]) {
            return server_error(format!("failed to append config to tar: {e}"));
        }

        let mut layer_tar_paths = Vec::new();
        for diff_id in &record.diff_ids {
            let diff_hex = diff_id.trim_start_matches("sha256:");
            let layer_tar_name = format!("{diff_hex}/layer.tar");

            let layer_dir = state.paths.layer(diff_id);
            let mut layer_tar = tar::Builder::new(Vec::new());
            if layer_dir.exists() {
                let mut seen_inodes = std::collections::HashMap::new();
                let _ = tar_dir_recursive(
                    &mut layer_tar,
                    &layer_dir,
                    std::path::Path::new(""),
                    &mut seen_inodes,
                );
            }
            let layer_tar_bytes = match layer_tar.into_inner() {
                Ok(b) => b,
                Err(e) => return server_error(format!("failed to archive layer: {e}")),
            };

            let mut l_hdr = tar::Header::new_gnu();
            l_hdr.set_size(layer_tar_bytes.len() as u64);
            l_hdr.set_mode(0o644);
            l_hdr.set_cksum();
            if let Err(e) = outer_tar.append_data(&mut l_hdr, &layer_tar_name, &layer_tar_bytes[..])
            {
                return server_error(format!("failed to append layer to tar: {e}"));
            }

            layer_tar_paths.push(layer_tar_name);
        }

        // Effective tags only: a stale embedded tag must not leak into the
        // tar and steal the tag back on load.
        let manifest_entry = serde_json::json!({
            "Config": config_tar_path,
            "RepoTags": state.images.effective_tags(&record).await,
            "Layers": layer_tar_paths,
        });
        manifests.push(manifest_entry);
    }

    let manifest_bytes = serde_json::to_vec(&manifests).unwrap_or_default();
    let mut m_hdr = tar::Header::new_gnu();
    m_hdr.set_size(manifest_bytes.len() as u64);
    m_hdr.set_mode(0o644);
    m_hdr.set_cksum();
    if let Err(e) = outer_tar.append_data(&mut m_hdr, "manifest.json", &manifest_bytes[..]) {
        return server_error(format!("failed to append manifest.json to tar: {e}"));
    }

    let tar_bytes = match outer_tar.into_inner() {
        Ok(b) => b,
        Err(e) => return server_error(format!("failed to finalize save tar: {e}")),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-tar")
        .body(Body::from(tar_bytes))
        .unwrap()
}

/// GET /images/{name}/get
pub async fn get_tar_single(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> Response {
    get_tar(State(state), Query(ImageGetQuery { names: vec![name] })).await
}

/// POST /images/load
pub async fn load_tar(State(state): State<SharedState>, body: axum::body::Body) -> Response {
    let tmp_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => return server_error(format!("failed to create temp dir: {e}")),
    };

    let temp_tar =
        match crate::handlers::stream_body_to_temp_file(body, 10 * 1024 * 1024 * 1024).await {
            Ok(f) => f,
            Err(resp) => return resp,
        };
    let file = match temp_tar.reopen() {
        Ok(f) => f,
        Err(e) => return server_error(format!("failed to reopen temp tar: {e}")),
    };

    let mut archive = tar::Archive::new(std::io::BufReader::new(file));
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(e) => return bad_request(format!("failed to read tar entries: {e}")),
    };
    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => return bad_request(format!("malformed tar entry in image archive: {e}")),
        };
        if let Err(e) = entry.unpack_in(tmp_dir.path()) {
            return bad_request(format!("failed to unpack image archive entry: {e}"));
        }
    }

    let manifest_path = tmp_dir.path().join("manifest.json");
    if !manifest_path.exists() {
        return bad_request("invalid image archive: missing manifest.json");
    }

    let manifest_bytes = match std::fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) => return server_error(format!("failed to read manifest.json: {e}")),
    };

    #[derive(serde::Deserialize)]
    // Field names mirror docker's manifest.json verbatim.
    #[allow(non_snake_case)]
    struct ManifestEntry {
        Config: String,
        RepoTags: Option<Vec<String>>,
        Layers: Vec<String>,
    }

    let manifests: Vec<ManifestEntry> = match serde_json::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => return bad_request(format!("invalid manifest.json: {e}")),
    };

    let mut output_lines = Vec::new();

    for item in manifests {
        let config_res =
            match ingot_util::resolve_in_root(tmp_dir.path(), std::path::Path::new(&item.Config)) {
                Ok(r) => r,
                Err(e) => {
                    return bad_request(format!("invalid image config path {:?}: {e}", item.Config))
                }
            };
        let config_bytes = match std::fs::read(config_res.proc_path()) {
            Ok(b) => b,
            Err(e) => {
                return bad_request(format!("failed to read image config {}: {e}", item.Config))
            }
        };
        let config_val: serde_json::Value = match serde_json::from_slice(&config_bytes) {
            Ok(v) => v,
            Err(e) => return bad_request(format!("invalid image config JSON: {e}")),
        };

        let config_id = ingot_util::sha256_hex(&config_bytes);

        let blob_dest = state.paths.blob(&config_id);
        let _ = std::fs::create_dir_all(blob_dest.parent().unwrap());
        let _ = std::fs::write(&blob_dest, &config_bytes);

        let mut diff_ids = Vec::new();
        let mut layer_blobs = Vec::new();
        let mut total_size: i64 = config_bytes.len() as i64;

        for layer_rel in item.Layers {
            let layer_res =
                match ingot_util::resolve_in_root(tmp_dir.path(), std::path::Path::new(&layer_rel))
                {
                    Ok(r) => r,
                    Err(e) => {
                        return bad_request(format!(
                            "missing or invalid layer {:?}: {e}",
                            layer_rel
                        ))
                    }
                };
            let layer_tar_path = layer_res.proc_path();
            let layer_bytes = match std::fs::read(layer_tar_path) {
                Ok(b) => b,
                Err(e) => return bad_request(format!("failed to read layer {layer_rel}: {e}")),
            };
            let diff_hex = ingot_util::sha256_hex(&layer_bytes);
            let diff_id = format!("sha256:{diff_hex}");
            diff_ids.push(diff_id.clone());

            let layer_dir = state.paths.layer(&diff_id);
            if !layer_dir.exists() || !layer_dir.join(".ingot-unpacked").exists() {
                if let Err(e) = ingot_image::unpack_layer_dir(
                    layer_tar_path,
                    &layer_dir,
                    "application/vnd.oci.image.layer.v1.tar",
                ) {
                    return bad_request(format!("failed to unpack layer {layer_rel}: {e}"));
                }
            }

            use flate2::write::GzEncoder;
            use flate2::Compression;
            use std::io::Write;
            let mut gz = GzEncoder::new(Vec::new(), Compression::default());
            let _ = gz.write_all(&layer_bytes);
            let gz_bytes = gz.finish().unwrap_or_default();
            let blob_hex = ingot_util::sha256_hex(&gz_bytes);
            let blob_digest = format!("sha256:{blob_hex}");
            layer_blobs.push(blob_digest.clone());
            total_size += gz_bytes.len() as i64;

            let compressed_blob_path = state.paths.blob(&blob_digest);
            let _ = std::fs::create_dir_all(compressed_blob_path.parent().unwrap());
            let _ = std::fs::write(&compressed_blob_path, &gz_bytes);
        }

        let repo_tags = item.RepoTags.unwrap_or_default();
        let created = config_val
            .get("created")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let arch = config_val
            .get("architecture")
            .and_then(|v| v.as_str())
            .unwrap_or("amd64")
            .to_string();
        let os = config_val
            .get("os")
            .and_then(|v| v.as_str())
            .unwrap_or("linux")
            .to_string();

        let chain_ids = ingot_image::ImageRecord::compute_chain_ids(&diff_ids);

        // A load restores the image's own creation time; stamping now would
        // make every loaded image look brand-new to until-filters.
        let created_unix = chrono::DateTime::parse_from_rfc3339(&created)
            .map(|d| d.timestamp())
            .unwrap_or(0);
        let rec = ingot_image::ImageRecord {
            id: config_id.clone(),
            manifest_digest: String::new(),
            repo_tags: repo_tags.clone(),
            repo_digests: Vec::new(),
            created,
            created_unix,
            architecture: arch,
            os,
            author: String::new(),
            comment: String::new(),
            docker_version: String::new(),
            diff_ids,
            layer_blobs,
            size: total_size,
            config: serde_json::from_value(
                config_val
                    .get("config")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .unwrap_or_default(),
            history: Vec::new(),
            chain_ids,
        };

        // Merged, not blind overwrite: a load of a pulled image must keep
        // the pull's manifest digest and RepoDigests (same rule as pull).
        let prev = state.images.load(&config_id).await.ok().flatten();
        if let Err(e) = state.images.put_image_merged(&rec).await {
            return server_error(format!("failed to save image record: {e}"));
        }
        // Same-id layer swap orphans the previous revision's blobs/dirs
        // with no record deletion to GC them: collect those nothing else
        // references. Skipped while a container uses the image — a live
        // overlay still reads the old lowerdirs.
        if let Some(old) = prev {
            if old.diff_ids != rec.diff_ids || old.layer_blobs != rec.layer_blobs {
                let in_use = match state.containers.as_ref() {
                    Some(mgr) => mgr.list_records().await.iter().any(|c| {
                        c.image_id == config_id || c.image_id == format!("sha256:{config_id}")
                    }),
                    None => false,
                };
                if !in_use {
                    let _ = state.images.gc_replaced_layers(&old).await;
                }
            }
        }

        for tag in &repo_tags {
            output_lines.push(format!("Loaded image: {tag}\n"));
        }
        if repo_tags.is_empty() {
            output_lines.push(format!("Loaded image ID: sha256:{config_id}\n"));
        }
    }

    let mut body_str = String::new();
    for line in output_lines {
        let msg = serde_json::json!({ "stream": line });
        body_str.push_str(&msg.to_string());
        body_str.push('\n');
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body_str))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters(json: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        match json {
            serde_json::Value::Object(m) => m,
            _ => panic!("object"),
        }
    }

    fn record(tags: &[&str], created_unix: i64) -> ingot_image::ImageRecord {
        ingot_image::ImageRecord {
            repo_tags: tags.iter().map(|s| s.to_string()).collect(),
            created_unix,
            ..Default::default()
        }
    }

    #[test]
    fn pull_spec_assembly() {
        assert_eq!(assemble_pull_spec("busybox", "latest"), "busybox:latest");
        assert_eq!(assemble_pull_spec("busybox", ""), "busybox");
        assert_eq!(assemble_pull_spec("busybox:1.36", "1.36"), "busybox:1.36");
        // Digest split across params joins with '@', never ':'.
        assert_eq!(
            assemble_pull_spec("busybox", "sha256:abc"),
            "busybox@sha256:abc"
        );
        assert_eq!(
            assemble_pull_spec("busybox:1.36", "sha256:abc"),
            "busybox:1.36@sha256:abc"
        );
        assert_eq!(
            assemble_pull_spec("busybox", "1.36@sha256:abc"),
            "busybox:1.36@sha256:abc"
        );
        // Already-pinned spec is complete; a stray tag is ignored.
        assert_eq!(
            assemble_pull_spec("busybox@sha256:abc", "latest"),
            "busybox@sha256:abc"
        );
    }

    #[test]
    fn until_value_shapes() {
        let now = 1_000_000i64;
        assert_eq!(parse_until("999999", now).unwrap(), 999999);
        assert_eq!(parse_until("1970-01-01T00:00:10Z", now).unwrap(), 10);
        assert_eq!(parse_until("60s", now).unwrap(), now - 60);
        assert_eq!(parse_until("1h30m", now).unwrap(), now - 5400);
        assert_eq!(parse_until("24h", now).unwrap(), now - 86400);
        for bad in ["", "yesterday", "1d", "h", "1h30", "-5", "1.5h"] {
            assert!(parse_until(bad, now).is_err(), "{bad:?} must fail");
        }
    }

    #[test]
    fn until_matching_uses_created_age() {
        let now = 1_000_000i64;
        let old = record(&["img:old"], 100);
        let fresh = record(&["img:new"], 999_999);
        let ageless = record(&["img:?"], 0);
        let f = filters(serde_json::json!({"until": ["1h"]}));
        assert!(image_matches(&old, &f, now).unwrap());
        assert!(!image_matches(&fresh, &f, now).unwrap());
        // Unknown age never matches: it cannot be aged.
        assert!(!image_matches(&ageless, &f, now).unwrap());
    }

    #[test]
    fn prune_default_is_dangling_only_via_matches() {
        let tagged = record(&["img:t"], 1);
        let dangling = record(&[], 1);
        let f = filters(serde_json::json!({"dangling": ["true"]}));
        assert!(!image_matches(&tagged, &f, 9).unwrap());
        assert!(image_matches(&dangling, &f, 9).unwrap());
        let f = filters(serde_json::json!({"dangling": ["false"]}));
        assert!(image_matches(&tagged, &f, 9).unwrap());
    }

    #[test]
    fn docker_map_shaped_filters_match() {
        // The real CLI sends {"dangling":{"true":true}}, not arrays.
        let tagged = record(&["img:t"], 1);
        let dangling = record(&[], 1);
        let f = filters(serde_json::json!({"dangling": {"true": true}}));
        assert!(!image_matches(&tagged, &f, 9).unwrap());
        assert!(image_matches(&dangling, &f, 9).unwrap());
        let f = filters(serde_json::json!({"dangling": {"false": true}}));
        assert!(image_matches(&tagged, &f, 9).unwrap());
        assert!(!image_matches(&dangling, &f, 9).unwrap());
    }

    #[test]
    fn unknown_filter_key_is_400() {
        let r = record(&["img:t"], 1);
        let f = filters(serde_json::json!({"bogus": ["x"]}));
        assert!(image_matches(&r, &f, 9).is_err());
    }

    #[test]
    fn invalid_until_value_is_400() {
        let r = record(&["img:t"], 1);
        let f = filters(serde_json::json!({"until": ["yesterday"]}));
        assert!(image_matches(&r, &f, 9).is_err());
    }
}
