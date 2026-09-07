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

    pub fn volume_dir(&self, name: &str) -> Result<PathBuf> {
        ingot_util::validate_resource_name(name)?;
        Ok(self.paths.volumes().join(name))
    }

    pub fn create(
        &self,
        name: Option<&str>,
        driver: Option<&str>,
        labels: HashMap<String, String>,
        options: HashMap<String, String>,
    ) -> Result<Volume> {
        let name = match name {
            Some(n) if !n.trim().is_empty() => {
                let trimmed = n.trim();
                ingot_util::validate_resource_name(trimmed)?;
                trimmed.to_string()
            }
            _ => ingot_util::new_id()[..32].to_string(),
        };

        let dir = self.volume_dir(&name)?;
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
        ingot_store::write_json_atomic(&meta_path, &meta)?;

        Ok(self.to_volume(&meta, &dir))
    }

    pub fn get(&self, name: &str) -> Result<Option<Volume>> {
        ingot_util::validate_resource_name(name)?;
        let dir = self.volume_dir(name)?;
        if !dir.is_dir() {
            return Ok(None);
        }
        let meta_path = dir.join("metadata.json");
        if !meta_path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&meta_path)
            .with_context(|| format!("read volume metadata {}", meta_path.display()))?;
        let meta: VolumeMeta = serde_json::from_slice(&data)
            .with_context(|| format!("corrupt volume metadata in {}", meta_path.display()))?;
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
        ingot_util::validate_resource_name(name)?;
        let dir = self.volume_dir(name)?;
        if !dir.is_dir() {
            return Err(anyhow!("no such volume: {name}"));
        }
        std::fs::remove_dir_all(&dir)
            .with_context(|| format!("remove volume dir at {}", dir.display()))?;
        Ok(())
    }

    /// Remove volumes not in `protected`, honoring `until` (unix
    /// timestamp, older-than) and `label_filter` (all key/value pairs
    /// must match; empty value means the key must simply exist). Never
    /// removes a protected (in-use) volume. Returns the deleted names.
    pub fn prune(
        &self,
        protected: &[&str],
        until: Option<i64>,
        label_filter: &HashMap<String, String>,
    ) -> Result<Vec<String>> {
        let protected: std::collections::HashSet<&str> = protected.iter().copied().collect();
        let now = chrono::Utc::now().timestamp();
        let mut removed = Vec::new();
        for vol in self.list()? {
            if protected.contains(vol.Name.as_str()) {
                continue;
            }
            if until.is_some_and(|ts| {
                // CreatedAt may be missing/malformed for legacy volumes: treat
                // unknown age as not-matching, safer than deleting blindly.
                let created = parse_rfc3339(&vol.CreatedAt).unwrap_or(now);
                created > ts
            }) {
                continue;
            }
            if !label_filter.is_empty() && !labels_match(&vol.Labels, label_filter) {
                continue;
            }
            if self.remove(&vol.Name).is_ok() {
                removed.push(vol.Name);
            }
        }
        Ok(removed)
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

fn parse_rfc3339(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.timestamp())
}

fn labels_match(vol: &HashMap<String, String>, filter: &HashMap<String, String>) -> bool {
    for (k, v) in filter {
        match vol.get(k) {
            Some(got) if v.is_empty() || got == v => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_paths(tag: &str) -> DataPaths {
        let dir = std::env::temp_dir().join(format!("ingot-vol-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        DataPaths::new(&dir, dir.join("run"))
    }

    #[test]
    fn prune_respects_protected() {
        let paths = tmp_paths("prot");
        let vm = VolumeManager::new(paths.clone()).unwrap();
        let _ = vm.create(Some("keep"), None, HashMap::new(), HashMap::new());
        let _ = vm.create(Some("drop"), None, HashMap::new(), HashMap::new());
        let removed = vm.prune(&["keep"], None, &HashMap::new()).unwrap();
        assert_eq!(removed, vec!["drop".to_string()]);
        assert!(vm.get("keep").unwrap().is_some());
        assert!(vm.get("drop").unwrap().is_none());
    }

    #[test]
    fn prune_filters_labels_and_until() {
        let paths = tmp_paths("filters");
        let vm = VolumeManager::new(paths.clone()).unwrap();
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "test".to_string());
        let _ = vm.create(Some("match-me"), None, labels.clone(), HashMap::new());
        let _ = vm.create(Some("no-label"), None, HashMap::new(), HashMap::new());

        let mut filter = HashMap::new();
        filter.insert("env".to_string(), "test".to_string());
        let removed = vm.prune(&[], None, &filter).unwrap();
        assert_eq!(removed, vec!["match-me".to_string()]);

        // until filter: far past deletes nothing (all test volumes are new).
        let now = chrono::Utc::now().timestamp();
        let removed = vm.prune(&[], Some(now - 86400), &HashMap::new()).unwrap();
        assert!(removed.is_empty(), "past until should delete nothing");

        // Far future until deletes the remaining volume.
        let removed = vm.prune(&[], Some(now + 86400), &HashMap::new()).unwrap();
        assert_eq!(removed, vec!["no-label".to_string()]);
    }

    #[test]
    fn prune_empty_is_safe() {
        let paths = tmp_paths("empty");
        let vm = VolumeManager::new(paths).unwrap();
        let removed = vm.prune(&[], None, &HashMap::new()).unwrap();
        assert!(removed.is_empty());
    }

    #[test]
    fn volume_name_validation() {
        let paths = tmp_paths("name-val");
        let vm = VolumeManager::new(paths).unwrap();

        // Path separators and traversal are rejected
        assert!(vm
            .create(Some("foo/bar"), None, HashMap::new(), HashMap::new())
            .is_err());
        assert!(vm
            .create(Some("../foo"), None, HashMap::new(), HashMap::new())
            .is_err());
        assert!(vm
            .create(Some(".."), None, HashMap::new(), HashMap::new())
            .is_err());
        assert!(vm
            .create(Some("."), None, HashMap::new(), HashMap::new())
            .is_err());
        assert!(vm
            .create(Some("foo\\bar"), None, HashMap::new(), HashMap::new())
            .is_err());
        assert!(vm.get("foo/bar").is_err());
        assert!(vm.get("../foo").is_err());
        assert!(vm.remove("foo/bar").is_err());
        assert!(vm.remove("../foo").is_err());
    }

    #[test]
    fn corrupt_metadata_returns_error() {
        let paths = tmp_paths("corrupt");
        let vm = VolumeManager::new(paths).unwrap();
        let vol = vm
            .create(Some("valid-vol"), None, HashMap::new(), HashMap::new())
            .unwrap();
        let meta_path = PathBuf::from(vol.Mountpoint).join("metadata.json");
        std::fs::write(&meta_path, "not valid json").unwrap();

        // Getting a corrupt volume returns an error, does not invent new creation time
        assert!(vm.get("valid-vol").is_err());
    }
}
