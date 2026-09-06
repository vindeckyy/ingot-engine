//! Local volume management for Ingot.

use anyhow::{anyhow, Context, Result};
use ingot_api::Volume;
use ingot_store::paths::DataPaths;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMeta {
    pub name: String,
    pub created_at: String,
    pub driver: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub options: HashMap<String, String>,
}

#[derive(Clone)]
pub struct VolumeManager {
    paths: DataPaths,
}

impl VolumeManager {
    pub fn new(paths: DataPaths) -> Result<Self> {
        std::fs::create_dir_all(paths.volumes())?;
        Ok(Self { paths })
    }

    pub fn volume_dir(&self, name: &str) -> PathBuf {
        self.paths.volumes().join(name)
    }

    pub fn create(
        &self,
        name: Option<&str>,
        driver: Option<&str>,
        labels: HashMap<String, String>,
        options: HashMap<String, String>,
    ) -> Result<Volume> {
        let name = match name {
            Some(n) if !n.trim().is_empty() => n.trim().to_string(),
            _ => ingot_util::new_id()[..32].to_string(),
        };

        let dir = self.volume_dir(&name);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create volume dir at {}", dir.display()))?;

        let meta = VolumeMeta {
            name: name.clone(),
            created_at: ingot_util::now_rfc3339(),
            driver: driver.unwrap_or("local").to_string(),
            labels,
            options,
        };

        let meta_path = dir.join("metadata.json");
        let _ = ingot_store::write_json_atomic(&meta_path, &meta);

        Ok(self.to_volume(&meta, &dir))
    }

    pub fn get(&self, name: &str) -> Result<Option<Volume>> {
        let dir = self.volume_dir(name);
        if !dir.is_dir() {
            return Ok(None);
        }
        let meta_path = dir.join("metadata.json");
        let meta = if let Ok(data) = std::fs::read(&meta_path) {
            serde_json::from_slice(&data).unwrap_or_else(|_| self.default_meta(name))
        } else {
            self.default_meta(name)
        };
        Ok(Some(self.to_volume(&meta, &dir)))
    }

    pub fn list(&self) -> Result<Vec<Volume>> {
        let mut list = Vec::new();
        let read_dir = match std::fs::read_dir(self.paths.volumes()) {
            Ok(rd) => rd,
            Err(_) => return Ok(list),
        };
        for entry in read_dir.flatten() {
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Ok(Some(vol)) = self.get(&name) {
                    list.push(vol);
                }
            }
        }
        list.sort_by(|a, b| a.Name.cmp(&b.Name));
        Ok(list)
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        let dir = self.volume_dir(name);
        if !dir.is_dir() {
            return Err(anyhow!("no such volume: {name}"));
        }
        std::fs::remove_dir_all(&dir)
            .with_context(|| format!("remove volume dir at {}", dir.display()))?;
        Ok(())
    }

    pub fn prune(&self) -> Result<Vec<String>> {
        let mut removed = Vec::new();
        for vol in self.list()? {
            if self.remove(&vol.Name).is_ok() {
                removed.push(vol.Name);
            }
        }
        Ok(removed)
    }

    fn default_meta(&self, name: &str) -> VolumeMeta {
        VolumeMeta {
            name: name.to_string(),
            created_at: ingot_util::now_rfc3339(),
            driver: "local".into(),
            labels: HashMap::new(),
            options: HashMap::new(),
        }
    }

    fn to_volume(&self, meta: &VolumeMeta, dir: &Path) -> Volume {
        Volume {
            CreatedAt: meta.created_at.clone(),
            Driver: meta.driver.clone(),
            Labels: meta.labels.clone(),
            Mountpoint: dir.to_string_lossy().to_string(),
            Name: meta.name.clone(),
            Options: meta.options.clone(),
            Scope: "local".into(),
        }
    }
}
