//! Shared helpers: ids, digests, docker-style random names, small fs utils.

pub mod digest;
pub mod id;
pub mod ignore;
pub mod name;
pub mod path;

pub use digest::{digest_hex, sha256_hex};
pub use id::random_token;
pub use path::{
    clean_relative_path, ensure_dir_in_root, ensure_file_in_root, resolve_in_root,
    validate_container_name, validate_resource_name, ResolvedPath,
};

use anyhow::{Context, Result};
use std::path::Path;

/// Generate a docker-style 64-hex-char container/image id.
pub fn new_id() -> String {
    id::random_hex(64)
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("create dir {}", path.display()))
}

pub fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp = path.with_extension("tmp");
    let data = serde_json::to_vec_pretty(value)?;
    std::fs::write(&tmp, &data).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_slice(&data)?)
}

pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

/// Recursively delete, tolerating missing paths.
pub fn remove_path(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_dir() => {
            std::fs::remove_dir_all(path).with_context(|| format!("rm -rf {}", path.display()))
        }
        Ok(_) => std::fs::remove_file(path).with_context(|| format!("rm {}", path.display())),
        Err(_) => Ok(()),
    }
}
