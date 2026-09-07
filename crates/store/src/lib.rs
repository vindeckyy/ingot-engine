//! Event bus and persistence primitives shared by the daemon subsystems.

pub mod events;
pub mod lock;
pub mod paths;

pub use events::EventBus;
pub use lock::DaemonLock;
pub use paths::DataPaths;

use anyhow::{Context, Result};
use std::path::Path;

/// Durable, atomic JSON write: serialize to a unique tempfile in the target dir,
/// flush, sync_all, atomically rename over target, and sync parent directory.
/// Uses compact JSON (not pretty) to minimize serialize + fsync payload on
/// hot paths (container state, tags, IPAM leases).
pub fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    write_json_atomic_inner(path, value, true)
}

/// Fast batched variant for high-frequency steady-state writes (state.json
/// ticks, IPAM allocate/release, tag index churn): atomic rename without
/// file+dir fsync. Callers must fsync on create/delete/stop boundaries via
/// [`write_json_atomic`]. Crash may lose the last window, which boot
/// reconciliation heals (orphan sweep, stale overlay/cgroup cleanup).
pub fn write_json_batched<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    write_json_atomic_inner(path, value, false)
}

fn write_json_atomic_inner<T: serde::Serialize>(
    path: &Path,
    value: &T,
    durable: bool,
) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;

    let data = serde_json::to_vec(value)?;

    // Unique temporary file in the destination directory
    let mut tmp = tempfile::Builder::new()
        .prefix(".tmp-")
        .tempfile_in(parent)
        .with_context(|| format!("create tempfile in {}", parent.display()))?;

    tmp.write_all(&data)
        .with_context(|| format!("write to tempfile for {}", path.display()))?;
    if durable {
        tmp.as_file()
            .sync_all()
            .with_context(|| format!("sync tempfile for {}", path.display()))?;
    } else {
        let _ = tmp.as_file().sync_data();
    }

    // Atomically persist to target path, replacing any existing file
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("persist tempfile to {}: {e}", path.display()))?;

    // Sync parent directory only on durable path; batched writes skip it.
    if durable {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_slice(&data)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_write_and_read_json_atomic() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("sub").join("test.json");

        let data = serde_json::json!({
            "key": "value",
            "count": 42
        });

        write_json_atomic(&target, &data).unwrap();
        let read: serde_json::Value = read_json(&target).unwrap();
        assert_eq!(read, data);

        // Overwrite atomically
        let data2 = serde_json::json!({
            "key": "new_value",
            "count": 43
        });
        write_json_atomic(&target, &data2).unwrap();
        let read2: serde_json::Value = read_json(&target).unwrap();
        assert_eq!(read2, data2);
    }
}
