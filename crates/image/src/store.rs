//! Content-addressed image store on disk.

use crate::unpack::unpack_layer;
use anyhow::{anyhow, Context, Result};
use ingot_api::ContainerConfig;
use ingot_store::paths::DataPaths;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// One image as stored in images/<id>.json.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ImageRecord {
    /// Config blob digest (docker image id).
    pub id: String,
    /// Top-level manifest/index digest for RepoDigests: repo@digest.
    pub manifest_digest: String,
    pub repo_tags: Vec<String>,
    pub repo_digests: Vec<String>,
    pub created: String,
    pub created_unix: i64,
    pub architecture: String,
    pub os: String,
    pub author: String,
    pub comment: String,
    pub docker_version: String,
    /// Ordered uncompressed layer digests (base-first).
    pub diff_ids: Vec<String>,
    /// Compressed layer blob digests (base-first), parallel to diff_ids.
    pub layer_blobs: Vec<String>,
    /// Compressed size sum (config + layers).
    pub size: i64,
    pub config: ContainerConfig,
    /// History entries (created_by etc.) for /images/{name}/history.
    pub history: Vec<HistoryEntry>,
    /// chainIDs matching diff_ids (chain i = fold of 0..=i).
    pub chain_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HistoryEntry {
    pub created: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_for: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empty_layer: Option<bool>,
}

pub struct ImageStore {
    paths: DataPaths,
    tags: tokio::sync::Mutex<HashMap<String, String>>, // repo:tag → image id
}

impl ImageStore {
    pub fn new(paths: DataPaths) -> Result<Self> {
        let tags = match std::fs::read_to_string(paths.tags()) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        Ok(ImageStore { paths, tags: tokio::sync::Mutex::new(tags) })
    }

    pub fn blob_path(&self, digest: &str) -> PathBuf {
        self.paths.blob(digest)
    }

    pub fn has_blob(&self, digest: &str) -> bool {
        self.paths.blob(digest).exists()
    }

    pub async fn all_tags(&self) -> HashMap<String, String> {
        self.tags.lock().await.clone()
    }

    pub async fn save_tags(&self) -> Result<()> {
        let tags = self.tags.lock().await;
        ingot_store::write_json_atomic(&self.paths.tags(), &*tags)
    }

    pub async fn put_image(&self, record: &ImageRecord) -> Result<()> {
        ingot_store::write_json_atomic(&self.paths.image_record(&record.id), record)?;
        let mut tags = self.tags.lock().await;
        for tag in &record.repo_tags {
            tags.insert(tag.clone(), record.id.clone());
        }
        drop(tags);
        self.save_tags().await
    }

    /// Add an extra tag to an existing image.
    pub async fn tag(&self, image_id: &str, tag_key: &str) -> Result<()> {
        let mut record = self
            .load(image_id)
            .await?
            .ok_or_else(|| anyhow!("no such image: {image_id}"))?;
        if !record.repo_tags.contains(&tag_key.to_string()) {
            record.repo_tags.push(tag_key.to_string());
            self.put_image(&record).await?;
        }
        Ok(())
    }

    pub async fn load(&self, image_id: &str) -> Result<Option<ImageRecord>> {
        let path = self.paths.image_record(image_id);
        if !path.exists() {
            return Ok(None);
        }
        let data = tokio::fs::read(&path).await?;
        Ok(Some(serde_json::from_slice(&data)?))
    }

    /// Resolve a user-supplied name: full id, id prefix, `repo:tag`, or `repo`
    /// (implies :latest). Returns the image id.
    pub async fn resolve(&self, name: &str) -> Result<String> {
        // Full or partial id?
        if name.starts_with("sha256:") || name.chars().all(|c| c.is_ascii_hexdigit()) {
            let hex = name.trim_start_matches("sha256:");
            if hex.len() >= 12 {
                if hex.len() == 64 {
                    if self.paths.image_record(hex).exists() {
                        return Ok(hex.to_string());
                    }
                } else if let Some(id) = self.find_by_prefix(hex).await? {
                    return Ok(id);
                }
            }
        }
        let (repo_part, tag_part) = match name.rsplit_once(':') {
            // Careful: "registry:5000/x/y" — ':' in host position, no tag.
            Some((r, t)) if !t.contains('/') => (r, Some(t)),
            _ => (name, None),
        };
        let tag_key = format!("{}:{}", repo_part, tag_part.unwrap_or("latest"));
        let tags = self.tags.lock().await;
        tags.get(&tag_key)
            .cloned()
            .ok_or_else(|| anyhow!("No such image: {name}"))
    }

    async fn find_by_prefix(&self, prefix: &str) -> Result<Option<String>> {
        let mut dir = tokio::fs::read_dir(self.paths.images()).await?;
        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id) = name.strip_suffix(".json") {
                if id.starts_with(prefix) {
                    return Ok(Some(id.to_string()));
                }
            }
        }
        Ok(None)
    }

    /// Unpack a layer blob into layers/<diffid>/ if not already there.
    /// Returns the diffID.
    pub async fn ensure_layer_unpacked(
        &self,
        blob_digest: &str,
        media_type: &str,
    ) -> Result<String> {
        // Downloading blobs is the slow part; unpack on a blocking thread.
        let blob_path = self.paths.blob(blob_digest);
        let layers_dir = self.paths.layers();
        let media = media_type.to_string();
        tokio::task::spawn_blocking(move || {
            // Two-pass: hash first (fast) to find the diffID dir; if it
            // exists we're done.
            let diff_id = hash_uncompressed(&blob_path, &media)?;
            let dest = {
                let hex = diff_id.trim_start_matches("sha256:");
                layers_dir.join(hex)
            };
            if dest.join(".ingot-unpacked").exists() {
                return Ok(diff_id);
            }
            let actual = unpack_layer(&blob_path, &dest, &media)?;
            if actual != diff_id {
                anyhow::bail!("diffID mismatch: expected {diff_id}, unpacked {actual}");
            }
            std::fs::write(dest.join(".ingot-unpacked"), "ok")?;
            Ok(diff_id)
        })
        .await?
    }

    /// Ordered lowerdirs for overlayfs, bottom-first, for these diff_ids.
    pub fn lowerdirs(&self, diff_ids: &[String]) -> Vec<String> {
        diff_ids
            .iter()
            .map(|d| {
                let hex = d.trim_start_matches("sha256:");
                self.paths.layers().join(hex).to_string_lossy().to_string()
            })
            .collect()
    }

    /// Delete a layer dir (refcounting is done by the caller).
    pub async fn remove_layer(&self, diff_id: &str) -> Result<()> {
        let hex = diff_id.trim_start_matches("sha256:");
        ingot_util::remove_path(&self.paths.layers().join(hex))
    }

    pub async fn remove_image(&self, image_id: &str, tag_key: Option<&str>) -> Result<ImageRecord> {
        let record = self
            .load(image_id)
            .await?
            .ok_or_else(|| anyhow!("No such image: {image_id}"))?;
        match tag_key {
            // Untag only.
            Some(t) => {
                let mut r = record.clone();
                r.repo_tags.retain(|x| x != t);
                let mut tags = self.tags.lock().await;
                tags.remove(t);
                drop(tags);
                if r.repo_tags.is_empty() {
                    self.delete_record(&r).await?;
                } else {
                    self.put_image(&r).await?;
                }
                Ok(r)
            }
            // Remove every tag + record + blobs that nothing else references.
            None => {
                {
                    let mut tags = self.tags.lock().await;
                    for t in &record.repo_tags {
                        tags.remove(t);
                    }
                }
                self.delete_record(&record).await?;
                Ok(record)
            }
        }
    }

    async fn delete_record(&self, record: &ImageRecord) -> Result<()> {
        self.save_tags().await?;
        let _ = tokio::fs::remove_file(self.paths.image_record(&record.id)).await;
        // Remove layer dirs not used by any remaining image.
        let remaining = self.list().await?;
        let used: std::collections::HashSet<String> =
            remaining.iter().flat_map(|r| r.diff_ids.iter().cloned()).collect();
        for d in &record.diff_ids {
            if !used.contains(d) {
                let _ = ingot_util::remove_path(
                    &self.paths.layers().join(d.trim_start_matches("sha256:")),
                );
            }
        }
        for b in &record.layer_blobs {
            if !remaining.iter().any(|r| r.layer_blobs.contains(b)) {
                let _ = tokio::fs::remove_file(self.paths.blob(b)).await;
            }
        }
        let _ = tokio::fs::remove_file(self.paths.blob(&record.id)).await; // config blob
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<ImageRecord>> {
        let mut out = Vec::new();
        let mut dir = match tokio::fs::read_dir(self.paths.images()).await {
            Ok(d) => d,
            Err(_) => return Ok(out),
        };
        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") || name == "tags.json" {
                continue;
            }
            if let Ok(data) = tokio::fs::read(entry.path()).await {
                if let Ok(r) = serde_json::from_slice::<ImageRecord>(&data) {
                    out.push(r);
                }
            }
        }
        Ok(out)
    }
}

/// Hash the uncompressed tar without unpacking (fast diffID probe).
fn hash_uncompressed(blob_path: &Path, media_type: &str) -> Result<String> {
    use sha2::Digest;
    let file = std::fs::File::open(blob_path)?;
    let mut hasher = sha2::Sha256::new();
    let mut reader: Box<dyn std::io::Read> =
        if media_type.ends_with("+gzip") || media_type.contains("gzip") {
            Box::new(flate2::read::GzDecoder::new(file))
        } else if media_type.ends_with("+zstd") || media_type.contains("zstd") {
            Box::new(zstd::Decoder::new(file)?)
        } else {
            Box::new(file)
        };
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

impl ImageRecord {
    /// Compute chainIDs from diff_ids (chain_i = sha256(chain_{i-1} + " " + diff_i)).
    pub fn compute_chain_ids(diff_ids: &[String]) -> Vec<String> {
        let mut out = Vec::with_capacity(diff_ids.len());
        for d in diff_ids {
            let parent = out.last().cloned();
            out.push(ingot_util::digest::chain_id(parent.as_deref(), d));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_ids_align_with_diffs() {
        let ids = vec!["sha256:a".into(), "sha256:b".into()];
        let chains = ImageRecord::compute_chain_ids(&ids);
        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0], "sha256:a");
        assert_eq!(
            chains[1],
            format!("sha256:{}", ingot_util::digest::sha256_hex(b"sha256:a sha256:b"))
        );
    }
}
