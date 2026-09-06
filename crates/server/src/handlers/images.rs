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

    // "busybox" or "busybox:1.36" (CLI passes the tag via query too).
    let mut spec = spec;
    if let (Some(t), false) = (&q.tag, spec.contains(':')) {
        spec = format!("{spec}:{t}");
    }
    let image_ref = match ImageRef::parse(&spec) {
        Ok(r) => r,
        Err(e) => return bad_request(e),
    };

    let auth = decode_auth_header(&headers);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProgressMessage>(64);
    let client = state.registry.clone();
    let store = state.images.clone();
    tokio::spawn(async move {
        if let Err(e) = ingot_image::pull::pull(client, store, image_ref, auth, tx.clone()).await {
            let _ = tx
                .send(ProgressMessage::error(format!("{e:#}")))
                .await;
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

fn decode_auth_header(headers: &HeaderMap) -> Option<AuthConfig> {
    let raw = headers.get("X-Registry-Auth")?.to_str().ok()?;
    // The CLI sends either base64(json) or base64(base64(user:pass)).
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(raw.trim()).ok()?;
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

/// GET /images/json
pub async fn list(State(state): State<SharedState>) -> Response {
    let tags = state.images.all_tags().await;
    let mut out: Vec<ImageSummary> = Vec::new();
    match state.images.list().await {
        Ok(records) => {
            for r in records {
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
                    Containers: 0,
                });
            }
            out.sort_by(|a, b| b.Created.cmp(&a.Created));
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
    let inspect = ImageInspect {
        Id: format!("sha256:{}", record.id),
        RepoTags: record.repo_tags.clone(),
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
    let mut layer_sizes: Vec<i64> = vec![0; record.diff_ids.len().max(1)];
    let items: Vec<HistoryResponseItem> = record
        .history
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let size = if h.empty_layer == Some(true) {
                0
            } else {
                // consume sizes for non-empty layers, bottom-up
                let idx = record
                    .history
                    .iter()
                    .take(i + 1)
                    .filter(|x| x.empty_layer != Some(true))
                    .count();
                let s = layer_sizes.get(idx.saturating_sub(1)).copied().unwrap_or(0);
                s
            };
            HistoryResponseItem {
                Comment: h.comment.clone().unwrap_or_default(),
                Created: chrono::DateTime::parse_from_rfc3339(&h.created)
                    .map(|d| d.timestamp())
                    .unwrap_or(0),
                CreatedBy: h.created_by.clone(),
                Id: if h.empty_layer == Some(true) {
                    "<missing>".into()
                } else {
                    format!("sha256:{}", record.id)
                },
                Size: size,
                Tags: if i == record.history.len().saturating_sub(1) {
                    Some(record.repo_tags.clone())
                } else {
                    None
                },
            }
        })
        .collect();
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
    let id = state.images.resolve(&name).await.unwrap_or_else(|_| name.clone());
    let record = match state.images.load(&id).await {
        Ok(Some(r)) => r,
        _ => return not_found(format!("No such image: {name}")),
    };
    let mut events: Vec<ImageDeleteResponseItem> = Vec::new();
    // If the reference is a tag (not an id) and more tags exist, just untag.
    let tag_key = record.repo_tags.iter().find(|t| *t == &name || t.starts_with(&format!("{name}:")));
    if tag_key.is_some() && record.repo_tags.len() > 1 {
        if q.force != Some(true) {
            let t = tag_key.unwrap().clone();
            match state.images.remove_image(&id, Some(&t)).await {
                Ok(_) => events.push(ImageDeleteResponseItem {
                    Untagged: t,
                    Deleted: String::new(),
                }),
                Err(e) => return server_error(e),
            }
            return axum::Json(events).into_response();
        }
    }
    match state.images.remove_image(&id, None).await {
        Ok(r) => {
            for t in &r.repo_tags {
                events.push(ImageDeleteResponseItem { Untagged: t.clone(), Deleted: String::new() });
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

/// POST /images/prune
pub async fn prune(
    State(state): State<SharedState>,
    Query(q): Query<ImagePruneQuery>,
) -> Response {
    let dangling_only = match q.filters {
        Some(ref f) => {
            !f.contains("\"dangling\":[\"false\"]") && !f.contains("\"dangling\":[\"0\"]")
        }
        None => true,
    };

    let all_images = match state.images.list().await {
        Ok(imgs) => imgs,
        Err(e) => return server_error(format!("failed to list images: {e}")),
    };

    let containers = if let Some(ref mgr) = state.containers {
        mgr.list_records().await
    } else {
        Vec::new()
    };
    let used_image_ids: std::collections::HashSet<String> = containers
        .iter()
        .map(|c| c.image_id.clone())
        .collect();

    let mut deleted_items = Vec::new();
    let mut space_reclaimed: u64 = 0;

    for img in all_images {
        let is_used = used_image_ids.contains(&img.id)
            || used_image_ids.contains(&format!("sha256:{}", img.id))
            || img.repo_tags.iter().any(|t| used_image_ids.contains(t));
        if is_used {
            continue;
        }
        let is_dangling = img.repo_tags.is_empty()
            || img.repo_tags.iter().all(|t| t == "<none>:<none>");
        if dangling_only && !is_dangling {
            continue;
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
        ImagesDeleted: if deleted_items.is_empty() { None } else { Some(deleted_items) },
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
pub async fn get_tar(
    State(state): State<SharedState>,
    Query(q): Query<ImageGetQuery>,
) -> Response {
    let images_to_save: Vec<String> = if q.names.is_empty() {
        let all = state.images.list().await.unwrap_or_default();
        all.into_iter().map(|img| img.id).collect()
    } else {
        q.names
    };

    let mut outer_tar = tar::Builder::new(Vec::new());
    let mut manifests = Vec::new();

    for img_name in images_to_save {
        let id = state.images.resolve(&img_name).await.unwrap_or_else(|_| img_name.clone());
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
                let _ = tar_dir_recursive(&mut layer_tar, &layer_dir, std::path::Path::new(""), &mut seen_inodes);
            }
            let layer_tar_bytes = match layer_tar.into_inner() {
                Ok(b) => b,
                Err(e) => return server_error(format!("failed to archive layer: {e}")),
            };

            let mut l_hdr = tar::Header::new_gnu();
            l_hdr.set_size(layer_tar_bytes.len() as u64);
            l_hdr.set_mode(0o644);
            l_hdr.set_cksum();
            if let Err(e) = outer_tar.append_data(&mut l_hdr, &layer_tar_name, &layer_tar_bytes[..]) {
                return server_error(format!("failed to append layer to tar: {e}"));
            }

            layer_tar_paths.push(layer_tar_name);
        }

        let manifest_entry = serde_json::json!({
            "Config": config_tar_path,
            "RepoTags": record.repo_tags,
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
pub async fn load_tar(
    State(state): State<SharedState>,
    body: axum::body::Bytes,
) -> Response {
    let cursor = std::io::Cursor::new(body);
    let mut archive = tar::Archive::new(cursor);

    let tmp_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => return server_error(format!("failed to create temp dir: {e}")),
    };

    if let Err(e) = archive.unpack(tmp_dir.path()) {
        return bad_request(format!("failed to unpack tar archive: {e}"));
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
        let config_file = tmp_dir.path().join(&item.Config);
        let config_bytes = match std::fs::read(&config_file) {
            Ok(b) => b,
            Err(e) => return server_error(format!("failed to read image config {}: {e}", item.Config)),
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
            let layer_tar_path = tmp_dir.path().join(&layer_rel);
            if !layer_tar_path.exists() {
                continue;
            }
            let layer_bytes = std::fs::read(&layer_tar_path).unwrap_or_default();
            let diff_hex = ingot_util::sha256_hex(&layer_bytes);
            let diff_id = format!("sha256:{diff_hex}");
            diff_ids.push(diff_id.clone());

            let layer_dir = state.paths.layer(&diff_id);
            if !layer_dir.exists() {
                let _ = std::fs::create_dir_all(&layer_dir);
                let mut layer_arc = tar::Archive::new(std::io::Cursor::new(&layer_bytes));
                layer_arc.set_preserve_permissions(true);
                layer_arc.set_preserve_mtime(true);
                let _ = layer_arc.unpack(&layer_dir);
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
        let created = config_val.get("created").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let arch = config_val.get("architecture").and_then(|v| v.as_str()).unwrap_or("amd64").to_string();
        let os = config_val.get("os").and_then(|v| v.as_str()).unwrap_or("linux").to_string();

        let chain_ids = ingot_image::ImageRecord::compute_chain_ids(&diff_ids);

        let rec = ingot_image::ImageRecord {
            id: config_id.clone(),
            manifest_digest: String::new(),
            repo_tags: repo_tags.clone(),
            repo_digests: Vec::new(),
            created,
            created_unix: ingot_util::now_unix(),
            architecture: arch,
            os,
            author: String::new(),
            comment: String::new(),
            docker_version: String::new(),
            diff_ids,
            layer_blobs,
            size: total_size,
            config: serde_json::from_value(config_val.get("config").cloned().unwrap_or(serde_json::Value::Null)).unwrap_or_default(),
            history: Vec::new(),
            chain_ids,
        };

        if let Err(e) = state.images.put_image(&rec).await {
            return server_error(format!("failed to save image record: {e}"));
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

