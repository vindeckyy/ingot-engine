//! Event bus and persistence primitives shared by the daemon subsystems.

pub mod events;
pub mod paths;

pub use events::EventBus;
pub use paths::DataPaths;

use anyhow::{Context, Result};
use std::path::Path;

/// Atomic JSON write: serialize to `<path>.tmp`, sync, rename over target.
pub fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let data = serde_json::to_vec_pretty(value)?;
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(&data)?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename {}", tmp.display()))?;
    Ok(())
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_slice(&data)?)
}
