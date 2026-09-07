//! POST /build — classic builder: tar context upload + JSON progress stream.

use crate::state::SharedState;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use ingot_api::ProgressMessage;
use std::collections::HashMap;

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct BuildQuery {
    /// tag (repeatable via t=x&t=y)
    #[serde(rename = "t", deserialize_with = "ingot_api::de::string_vec", default)]
    t: Vec<String>,
    dockerfile: Option<String>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    q: Option<bool>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    nocache: Option<bool>,
    // Accepted for API compatibility; intermediate-container cleanup and
    // forced layer removal land in Plan Phase 5.
    #[allow(dead_code)]
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    rm: Option<bool>,
    #[allow(dead_code)]
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    forcerm: Option<bool>,
    target: Option<String>,
    /// Repeatable stage selector (index or AS name) bypassing cache for
    /// that stage and every later one; results are still stored.
    #[serde(
        rename = "nocachefilter",
        deserialize_with = "ingot_api::de::string_vec",
        default
    )]
    nocachefilter: Vec<String>,
    buildargs: Option<String>,
    // Accepted for API compatibility; builder-version selection lands in
    // Plan Phase 5.
    #[allow(dead_code)]
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    version: Option<bool>,
}

/// Upload/extraction caps: a build context is untrusted client input.
/// The body already sits in memory when we see it, so the upload cap is
/// enforced first; header-declared sizes are accounted per entry and the
/// extracted tree is measured afterwards (headers can lie, and gzip
/// bombs expand far past their upload size).
const MAX_CONTEXT_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CONTEXT_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CONTEXT_FILES: u64 = 100_000;

/// Unpack a context tarball (optionally gzipped) into `dest`, enforcing
/// traversal, link, size, and file-count limits. Fails closed: any
/// violation aborts the whole extraction with the destination removed.
#[allow(dead_code)]
fn unpack_context(bytes: &[u8], dest: &std::path::Path) -> Result<(u64, u64), anyhow::Error> {
    if bytes.len() as u64 > MAX_CONTEXT_UPLOAD_BYTES {
        anyhow::bail!(
            "build context upload is {} bytes, over the {}-byte limit",
            bytes.len(),
            MAX_CONTEXT_UPLOAD_BYTES
        );
    }
    std::fs::create_dir_all(dest)?;

    if bytes.starts_with(&[0x1f, 0x8b]) {
        let gz = flate2::read::GzDecoder::new(bytes);
        extract_entries(tar::Archive::new(gz), dest)
    } else {
        extract_entries(tar::Archive::new(bytes), dest)
    }
}

fn unpack_context_file(
    file: std::fs::File,
    dest: &std::path::Path,
) -> Result<(u64, u64), anyhow::Error> {
    use std::io::{Read, Seek, SeekFrom};
    let mut reader = std::io::BufReader::new(file);
    let mut magic = [0u8; 2];
    let n = reader.read(&mut magic)?;
    reader.seek(SeekFrom::Start(0))?;
    std::fs::create_dir_all(dest)?;
    if n >= 2 && magic == [0x1f, 0x8b] {
        let gz = flate2::read::GzDecoder::new(reader);
        extract_entries(tar::Archive::new(gz), dest)
    } else {
        extract_entries(tar::Archive::new(reader), dest)
    }
}

/// Validate-then-extract one archive: each entry is checked before it is
/// written, and `unpack_in` re-verifies containment as defense in depth.
/// All client-caused rejections are phrased starting with "build context"
/// so the caller can map them to 400 instead of 500.
fn extract_entries<R: std::io::Read>(
    mut archive: tar::Archive<R>,
    dest: &std::path::Path,
) -> Result<(u64, u64), anyhow::Error> {
    use std::path::Component;

    // Single streaming pass: each entry is validated immediately before
    // it is written. (Entries borrow the archive's sequential reader, so
    // they cannot be collected first — unpacking later would read file
    // data from the wrong offsets.)
    let mut total: u64 = 0;
    let mut files: u64 = 0;
    let mut entries = archive
        .entries()
        .map_err(|e| anyhow::anyhow!("build context tar is malformed: {e:#}"))?;
    for entry in entries.by_ref() {
        let mut entry =
            entry.map_err(|e| anyhow::anyhow!("build context tar is malformed: {e:#}"))?;
        files += 1;
        if files > MAX_CONTEXT_FILES {
            anyhow::bail!("build context holds over {MAX_CONTEXT_FILES} entries, rejected");
        }
        let path = entry.path()?.into_owned();
        // Reject absolute paths, parent escapes, and Windows prefixes
        // lexically — before touching the filesystem.
        let mut normal = std::path::PathBuf::new();
        for c in path.components() {
            match c {
                Component::Normal(p) => normal.push(p),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    anyhow::bail!(
                        "build context entry escapes the context: {}",
                        path.display()
                    );
                }
            }
        }
        if normal.as_os_str().is_empty() {
            continue;
        }
        total = total.saturating_add(entry.size());
        if total > MAX_CONTEXT_EXTRACTED_BYTES || files > MAX_CONTEXT_FILES {
            anyhow::bail!("build context exceeds size/file limits during extraction");
        }
        match entry.header().entry_type() {
            tar::EntryType::Symlink | tar::EntryType::Link => {
                // Links must resolve inside the context. Lexical check
                // on the normalized join; unpack_in confines the write.
                let target = entry.link_name()?.ok_or_else(|| {
                    anyhow::anyhow!("build context link without target: {}", path.display())
                })?;
                let target = target.into_owned();
                if target.is_absolute() {
                    anyhow::bail!("build context link escapes the context: {}", path.display());
                }
                let mut joined = normal.clone();
                joined.pop();
                for c in target.components() {
                    match c {
                        Component::Normal(p) => joined.push(p),
                        Component::CurDir => {}
                        Component::ParentDir => {
                            if !joined.pop() {
                                anyhow::bail!(
                                    "build context link escapes the context: {}",
                                    path.display()
                                );
                            }
                        }
                        Component::RootDir | Component::Prefix(_) => {
                            anyhow::bail!(
                                "build context link escapes the context: {}",
                                path.display()
                            );
                        }
                    }
                }
            }
            _ => {}
        }
        entry.unpack_in(dest)?;
    }

    // Headers can lie about sizes: measure what actually landed.
    let mut actual: u64 = 0;
    let mut actual_files: u64 = 0;
    for e in walkdir::WalkDir::new(dest).follow_links(false) {
        let e = e?;
        actual_files += 1;
        if e.file_type().is_file() {
            actual = actual.saturating_add(e.metadata().map(|m| m.len()).unwrap_or(0));
        }
    }
    if actual > MAX_CONTEXT_EXTRACTED_BYTES || actual_files > MAX_CONTEXT_FILES {
        anyhow::bail!("build context exceeds size/file limits after extraction");
    }
    Ok((actual_files, actual))
}

/// Resolve the `dockerfile` query value under the context directory.
/// Absolute paths and `..` escapes are rejected: the Dockerfile must
/// come from the uploaded context, never the host filesystem.
fn context_subpath(
    context_dir: &std::path::Path,
    name: &str,
) -> Result<std::path::PathBuf, String> {
    use std::path::Component;
    let mut rel = std::path::PathBuf::new();
    for c in std::path::Path::new(name).components() {
        match c {
            Component::Normal(p) => rel.push(p),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("invalid Dockerfile path: {name}"));
            }
        }
    }
    if rel.as_os_str().is_empty() {
        return Err(format!("invalid Dockerfile path: {name}"));
    }
    Ok(context_dir.join(rel))
}

pub async fn build(
    State(state): State<SharedState>,
    Query(q): Query<BuildQuery>,
    headers: axum::http::HeaderMap,
    body: axum::body::Body,
) -> Response {
    let (tx, rx) = tokio::sync::mpsc::channel::<ProgressMessage>(64);
    let build_id = ingot_util::new_id()[..16].to_string();
    let context_dir = state.paths.build_contexts().join(&build_id);

    let dockerfile_name = q.dockerfile.clone().unwrap_or_else(|| "Dockerfile".into());
    let dockerfile_path = match context_subpath(&context_dir, &dockerfile_name) {
        Ok(p) => p,
        Err(e) => return crate::handlers::bad_request(e),
    };

    let temp_file =
        match crate::handlers::stream_body_to_temp_file(body, MAX_CONTEXT_UPLOAD_BYTES).await {
            Ok(f) => f,
            Err(resp) => return resp,
        };
    let file = match temp_file.reopen() {
        Ok(f) => f,
        Err(e) => return crate::handlers::server_error(format!("failed to reopen temp file: {e}")),
    };

    // Extract the uploaded tar context on a blocking thread.
    let ctx_dir = context_dir.clone();
    let extract = tokio::task::spawn_blocking(move || -> Result<(u64, u64), anyhow::Error> {
        unpack_context_file(file, &ctx_dir).inspect_err(|_| {
            let _ = std::fs::remove_dir_all(&ctx_dir);
        })
    })
    .await;

    match extract {
        Ok(Ok(_)) if dockerfile_path.exists() => {}
        Ok(Ok(_)) => {
            return crate::handlers::not_found(format!(
                "Cannot locate specified Dockerfile: {dockerfile_name}"
            ))
        }
        // Client-caused rejections (traversal, links escaping, over
        // limits) are phrased "build context ..." by unpack_context and
        // map to 400; anything else is a server-side failure.
        Ok(Err(e)) => {
            let msg = format!("{e:#}");
            if msg.starts_with("build context") {
                return crate::handlers::bad_request(format!("unpack context: {msg}"));
            }
            return crate::handlers::server_error(format!("unpack context: {msg}"));
        }
        Err(e) => return crate::handlers::server_error(format!("join: {e}")),
    }

    let dockerfile = match std::fs::read_to_string(&dockerfile_path) {
        Ok(d) => d,
        Err(e) => return crate::handlers::server_error(format!("read Dockerfile: {e}")),
    };

    // buildargs JSON: {"name":"value",...}
    let build_args: HashMap<String, String> = q
        .buildargs
        .as_deref()
        .and_then(|s| serde_json::from_str::<HashMap<String, String>>(s).ok())
        .unwrap_or_default();

    let opts = ingot_builder::BuildOptions {
        dockerfile,
        context_dir: context_dir.clone(),
        tags: q.t.clone(),
        target: q.target.clone(),
        build_args,
        nocache: q.nocache.unwrap_or(false),
        no_cache_filter: q.nocachefilter.clone(),
    };
    // Build secrets arrive as a one-time token in a header (never the
    // URL, so it stays out of access logs). Taking invalidates the
    // token: each build consumes its own staging.
    let secrets = match headers.get(ingot_api::BUILD_SECRET_TOKEN_HEADER) {
        None => HashMap::new(),
        Some(raw) => {
            let token = raw.to_str().unwrap_or_default().trim().to_string();
            match state.build_secrets.lock().await.take(&token) {
                Some(values) => values,
                None => {
                    return crate::handlers::bad_request(
                        "unknown or already-used build secret token",
                    )
                }
            }
        }
    };
    let registry = state.registry.clone();
    let images = state.images.clone();
    let paths = state.paths.clone();
    tokio::spawn(async move {
        if let Err(e) =
            ingot_builder::build_image(images, registry, paths, opts, secrets, tx.clone()).await
        {
            let _ = tx.send(ProgressMessage::error(format!("{e:#}"))).await;
        }
        let _ = tokio::fs::remove_dir_all(context_dir).await;
    });

    let quiet = q.q.unwrap_or(false);
    let stream = futures::stream::unfold(rx, move |mut rx| async move {
        rx.recv().await.map(|msg| {
            let rendered = if quiet {
                // -q: only the final image id (stream lines)
                msg.stream.clone().unwrap_or_default()
            } else {
                let mut line = serde_json::to_string(&msg).unwrap_or_default();
                line.push('\n');
                line
            };
            (
                Ok::<_, std::io::Error>(axum::body::Bytes::from(rendered)),
                rx,
            )
        })
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ingot-ctx-test-{}-{}",
            std::process::id(),
            ingot_util::random_token()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Minimal tar writer: the `tar` builder refuses `..` names itself,
    /// so traversal fixtures are encoded by hand (512-byte headers,
    /// nul-padded data, correct checksum).
    fn raw_entry(out: &mut Vec<u8>, name: &str, typeflag: u8, linkname: &str, data: &[u8]) {
        let mut h = [0u8; 512];
        h[..name.len().min(100)].copy_from_slice(&name.as_bytes()[..name.len().min(100)]);
        let mode = if typeflag == b'5' {
            "0000755\0"
        } else {
            "0000644\0"
        };
        h[100..108].copy_from_slice(mode.as_bytes());
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        let size = format!("{0:011o}\0", data.len());
        h[124..136].copy_from_slice(size.as_bytes());
        let mtime = format!("{:011o}\0", 1_700_000_000u64);
        h[136..148].copy_from_slice(mtime.as_bytes());
        h[148..156].copy_from_slice(b"        ");
        h[156] = typeflag;
        // Link target lives at 157..257 (name stays at 0..100).
        h[157..157 + linkname.len().min(100)]
            .copy_from_slice(&linkname.as_bytes()[..linkname.len().min(100)]);
        h[257..262].copy_from_slice(b"ustar");
        h[262..264].copy_from_slice(b"00");
        let cksum: u32 = h.iter().map(|b| *b as u32).sum();
        let cks = format!("{cksum:06o}\0 ");
        h[148..156].copy_from_slice(cks.as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len() + (512 - data.len() % 512) % 512, 0);
    }

    fn tar_bytes(build: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut out = Vec::new();
        build(&mut out);
        out.extend_from_slice(&[0u8; 1024]); // end-of-archive
        out
    }

    #[test]
    fn unpack_accepts_normal_tree() {
        let bytes = tar_bytes(|b| {
            raw_entry(b, "Dockerfile", b'0', "", b"FROM busybox");
            raw_entry(b, "sub", b'5', "", b"");
            raw_entry(b, "sub/app.txt", b'0', "", b"hi");
        });
        let dir = scratch();
        let (files, _) = unpack_context(&bytes, &dir).unwrap();
        assert!(files >= 3); // root + 2 entries (walkdir counts dirs)
                             // Content must survive the round trip byte-for-byte (guards
                             // against reader-offset corruption in the streaming pass).
        assert_eq!(
            std::fs::read_to_string(dir.join("Dockerfile")).unwrap(),
            "FROM busybox"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("sub/app.txt")).unwrap(),
            "hi"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unpack_rejects_traversal_and_absolute() {
        for evil in ["../../evil.txt", "/abs.txt", "a/../../../evil.txt"] {
            let bytes = tar_bytes(|b| {
                raw_entry(b, evil, b'0', "", b"x");
            });
            let dir = scratch();
            let err = unpack_context(&bytes, &dir).unwrap_err().to_string();
            assert!(
                err.starts_with("build context"),
                "evil path {evil:?} gave: {err}"
            );
            assert!(!dir.join("evil.txt").exists());
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn unpack_rejects_escaping_symlink_allows_inner() {
        // Absolute-target and parent-escaping links are rejected.
        for target in ["/etc/passwd", "../outside.txt"] {
            let bytes = tar_bytes(|b| {
                raw_entry(b, "link.txt", b'2', target, b"");
            });
            let dir = scratch();
            let err = unpack_context(&bytes, &dir).unwrap_err().to_string();
            assert!(err.starts_with("build context"), "target {target:?}: {err}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
        // A link staying inside the context is fine.
        let bytes = tar_bytes(|b| {
            raw_entry(b, "real.txt", b'0', "", b"v");
            raw_entry(b, "link.txt", b'2', "real.txt", b"");
        });
        let dir = scratch();
        unpack_context(&bytes, &dir).unwrap();
        assert_eq!(
            std::fs::read_link(dir.join("link.txt")).unwrap(),
            std::path::Path::new("real.txt")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unpack_rejects_lying_size_header() {
        // A header declaring gigabytes for a byte-long body trips the
        // extraction cap before anything is written.
        let mut bytes = tar_bytes(|b| {
            raw_entry(b, "big.bin", b'0', "", b"x");
        });
        // Size field lives at 124..135 (octal, NUL-terminated).
        let forged = format!("{:011o}\0", 2 * 1024 * 1024 * 1024u64);
        bytes[124..136].copy_from_slice(forged.as_bytes());
        let dir = scratch();
        let err = unpack_context(&bytes, &dir).unwrap_err().to_string();
        assert!(err.starts_with("build context"), "got: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dockerfile_param_is_confined() {
        let root = std::path::Path::new("/ctx");
        assert!(context_subpath(root, "Dockerfile").is_ok());
        assert!(context_subpath(root, "sub/Dockerfile").is_ok());
        assert!(context_subpath(root, "../../etc/passwd").is_err());
        assert!(context_subpath(root, "/etc/passwd").is_err());
        assert!(context_subpath(root, "").is_err());
    }
}
