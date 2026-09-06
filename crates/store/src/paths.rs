//! Canonical filesystem layout under the data root (`/var/lib/ingot`).

use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DataPaths {
    pub root: PathBuf,
    pub run_root: PathBuf, // /run/ingot
}

impl DataPaths {
    pub fn new(root: impl Into<PathBuf>, run_root: impl Into<PathBuf>) -> Self {
        Self { root: root.into(), run_root: run_root.into() }
    }

    // ---- images ----
    pub fn blobs(&self) -> PathBuf { self.root.join("blobs/sha256") }
    pub fn blob(&self, digest: &str) -> PathBuf {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        self.blobs().join(hex)
    }
    pub fn layers(&self) -> PathBuf { self.root.join("layers") }
    pub fn layer(&self, diff_id: &str) -> PathBuf {
        let hex = diff_id.strip_prefix("sha256:").unwrap_or(diff_id);
        self.layers().join(hex)
    }
    pub fn images(&self) -> PathBuf { self.root.join("images") }
    pub fn image_record(&self, image_id: &str) -> PathBuf {
        self.images().join(format!("{}.json", image_id))
    }
    pub fn tags(&self) -> PathBuf { self.root.join("tags.json") }

    // ---- containers ----
    pub fn containers(&self) -> PathBuf { self.root.join("containers") }
    pub fn container(&self, id: &str) -> PathBuf { self.containers().join(id) }
    pub fn container_config(&self, id: &str) -> PathBuf { self.container(id).join("config.json") }
    pub fn container_hostconfig(&self, id: &str) -> PathBuf { self.container(id).join("hostconfig.json") }
    pub fn container_state(&self, id: &str) -> PathBuf { self.container(id).join("state.json") }
    pub fn container_log(&self, id: &str) -> PathBuf { self.container(id).join(format!("{}-json.log", id)) }
    pub fn container_resolv(&self, id: &str) -> PathBuf { self.container(id).join("resolv.conf") }
    pub fn container_hosts(&self, id: &str) -> PathBuf { self.container(id).join("hosts") }
    pub fn container_hostname(&self, id: &str) -> PathBuf { self.container(id).join("hostname") }
    pub fn container_netns(&self, id: &str) -> PathBuf { self.container(id).join("netns") }
    pub fn container_mntns(&self, id: &str) -> PathBuf { self.container(id).join("mntns") }

    // ---- overlay snapshots ----
    pub fn overlay(&self) -> PathBuf { self.root.join("overlay") }
    pub fn overlay_container(&self, id: &str) -> PathBuf { self.overlay().join(id) }
    pub fn overlay_diff(&self, id: &str) -> PathBuf { self.overlay_container(id).join("diff") }
    pub fn overlay_work(&self, id: &str) -> PathBuf { self.overlay_container(id).join("work") }
    pub fn overlay_merged(&self, id: &str) -> PathBuf { self.overlay_container(id).join("merged") }

    // ---- networks ----
    pub fn networks(&self) -> PathBuf { self.root.join("networks") }
    pub fn network(&self, id: &str) -> PathBuf { self.networks().join(format!("{}.json", id)) }
    pub fn ipam_leases(&self) -> PathBuf { self.root.join("ipam-leases.json") }

    // ---- volumes ----
    pub fn volumes(&self) -> PathBuf { self.root.join("volumes") }
    pub fn volume(&self, name: &str) -> PathBuf { self.volumes().join(name) }

    // ---- builder ----
    pub fn builder(&self) -> PathBuf { self.root.join("builder") }
    pub fn build_cache(&self) -> PathBuf { self.builder().join("cache.json") }
    pub fn build_contexts(&self) -> PathBuf { self.builder().join("contexts") }

    // ---- runtime (/run/ingot) ----
    pub fn socket(&self) -> PathBuf { self.run_root.join("ingot.sock") }
    pub fn netns(&self) -> PathBuf { self.run_root.join("netns") }
    pub fn netns_bind(&self, id: &str) -> PathBuf { self.netns().join(id) }
    pub fn pid_file(&self) -> PathBuf { self.run_root.join("ingotd.pid") }

    /// Create the whole directory skeleton. Daemon boot does this.
    pub fn create_all(&self) -> Result<()> {
        for p in [
            self.blobs(), self.layers(), self.images(), self.containers(),
            self.overlay(), self.networks(), self.volumes(), self.builder(),
            self.build_contexts(), self.run_root.clone(), self.netns(),
        ] {
            std::fs::create_dir_all(&p)?;
        }
        Ok(())
    }

    pub fn exists(&self, p: &Path) -> bool {
        p.exists()
    }
}
