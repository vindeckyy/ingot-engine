//! Content-addressed image store on disk.

use crate::unpack::unpack_layer;
use anyhow::{anyhow, Result};
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
        Ok(ImageStore {
            paths,
            tags: tokio::sync::Mutex::new(tags),
        })
    }

    pub fn blob_path(&self, digest: &str) -> PathBuf {
        self.paths.blob(digest)
    }

    pub fn has_blob(&self, digest: &str) -> bool {
        self.paths.blob(digest).exists()
    }

    /// Compressed blob size for history/size accounting (Plan Phase 1).
    pub fn blob_size(&self, digest: &str) -> Option<u64> {
        std::fs::metadata(self.paths.blob(digest))
            .ok()
            .map(|m| m.len())
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
        // A tag names exactly one record. When this put moves a tag, evict
        // the stale embedded copy from the previous holder so embeds never
        // disagree with the index (list/prune/df read the embeds).
        for tag in &record.repo_tags {
            let prev = { self.tags.lock().await.get(tag).cloned() };
            if let Some(prev_id) = prev {
                if prev_id != record.id {
                    if let Some(mut old) = self.load(&prev_id).await? {
                        if old.repo_tags.iter().any(|t| t == tag) {
                            old.repo_tags.retain(|t| t != tag);
                            ingot_store::write_json_atomic(
                                &self.paths.image_record(&old.id),
                                &old,
                            )?;
                        }
                    }
                }
            }
        }
        let mut tags = self.tags.lock().await;
        for tag in &record.repo_tags {
            tags.insert(tag.clone(), record.id.clone());
        }
        drop(tags);
        self.save_tags().await
    }

    /// Merge a freshly-built record with the stored one under the same id:
    /// union of tags and digests, keeping a stored manifest digest when the
    /// new record has none. Single rule shared by pull and load so a
    /// save/load round-trip can never clobber the pull's digest fields.
    pub async fn put_image_merged(&self, record: &ImageRecord) -> Result<()> {
        let mut merged = record.clone();
        if let Some(existing) = self.load(&record.id).await? {
            for t in existing.repo_tags {
                if !merged.repo_tags.contains(&t) {
                    merged.repo_tags.push(t);
                }
            }
            for d in existing.repo_digests {
                if !merged.repo_digests.contains(&d) {
                    merged.repo_digests.push(d);
                }
            }
            if merged.manifest_digest.is_empty() {
                merged.manifest_digest = existing.manifest_digest;
            }
        }
        self.put_image(&merged).await
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

    /// Records with tag lists reduced to index truth: a tag shows on (and
    /// filters/prunes with) a record only while the index points it there.
    /// Embeds are a cache that can lag the index (pre-reconciliation
    /// stores, crash windows); the index decides. Display and GC paths
    /// (list/prune/df/save-all) use this; mutating paths use [`Self::load`]
    /// and decide explicitly. fsck reads raw files so the audit trail
    /// stays intact.
    pub async fn list_effective(&self) -> Result<Vec<ImageRecord>> {
        let tags = self.tags.lock().await;
        let mut out = self.list().await?;
        for r in &mut out {
            r.repo_tags
                .retain(|t| tags.get(t).is_some_and(|id| id == &r.id));
        }
        Ok(out)
    }

    /// Index-truth tags for one record (see [`Self::list_effective`]).
    pub async fn effective_tags(&self, record: &ImageRecord) -> Vec<String> {
        let tags = self.tags.lock().await;
        record
            .repo_tags
            .iter()
            .filter(|t| tags.get(*t).is_some_and(|id| id == &record.id))
            .cloned()
            .collect()
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
        // Digest reference (`repo@sha256:...`, optionally registry-qualified):
        // match the RepoDigests entry pull recorded. Parsing normalizes
        // `docker.io/library/` spellings so all forms find the same record.
        if name.contains('@') {
            let probe = ingot_registry::ImageRef::parse(name).map_err(|e| anyhow!("{e:#}"))?;
            if let Some(pinned) = probe.digest.as_deref() {
                let want = format!("{}@{pinned}", probe.display_ref_no_tag());
                for record in self.list().await? {
                    if record.repo_digests.iter().any(|d| d == &want) {
                        return Ok(record.id.clone());
                    }
                }
                return Err(anyhow!("No such image: {name}"));
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
                // Guarded: only drop the index entry when it still names
                // this record, never a tag another record has since taken.
                if tags.get(t).is_some_and(|id| id == &record.id) {
                    tags.remove(t);
                }
                drop(tags);
                if r.repo_tags.is_empty() {
                    self.delete_record(&r).await?;
                } else {
                    // Direct write, not put_image: untagging expresses no
                    // intent about the remaining tags, so it must not
                    // steal them back if they have since moved elsewhere.
                    ingot_store::write_json_atomic(&self.paths.image_record(&r.id), &r)?;
                    self.save_tags().await?;
                }
                Ok(r)
            }
            // Remove every tag + record + blobs that nothing else references.
            None => {
                {
                    let mut tags = self.tags.lock().await;
                    for t in &record.repo_tags {
                        if tags.get(t).is_some_and(|id| id == &record.id) {
                            tags.remove(t);
                        }
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
        let used: std::collections::HashSet<String> = remaining
            .iter()
            .flat_map(|r| r.diff_ids.iter().cloned())
            .collect();
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

    /// Drop layer blobs/dirs a previous revision of a record referenced
    /// that no current record references anymore. Used when a same-id
    /// rewrite (load, and in principle pull) swaps an image's layers
    /// without deleting the record — otherwise every save/load cycle
    /// strands a full layer copy no GC pass can attribute. The record's
    /// own config blob is untouched (same id, still live). Callers must
    /// skip this while containers use the image: a mounted overlay still
    /// reads the old lowerdirs.
    pub async fn gc_replaced_layers(&self, old: &ImageRecord) -> Result<()> {
        let remaining = self.list().await?;
        let used_layers: std::collections::HashSet<&str> = remaining
            .iter()
            .flat_map(|r| r.diff_ids.iter().map(String::as_str))
            .collect();
        for d in &old.diff_ids {
            if !used_layers.contains(d.as_str()) {
                let _ = ingot_util::remove_path(
                    &self.paths.layers().join(d.trim_start_matches("sha256:")),
                );
            }
        }
        for b in &old.layer_blobs {
            if !remaining.iter().any(|r| r.layer_blobs.contains(b)) {
                let _ = tokio::fs::remove_file(self.paths.blob(b)).await;
            }
        }
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

    fn scratch_store() -> (ImageStore, DataPaths) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "ingot-store-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let paths = DataPaths::new(base.join("data"), base.join("run"));
        std::fs::create_dir_all(paths.images()).unwrap();
        std::fs::create_dir_all(paths.blobs()).unwrap();
        std::fs::create_dir_all(paths.layers()).unwrap();
        let store = ImageStore::new(paths.clone()).unwrap();
        (store, paths)
    }

    fn record(id: &str, tags: &[&str]) -> ImageRecord {
        ImageRecord {
            id: id.to_string(),
            repo_tags: tags.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn put_steals_tag_and_evicts_stale_embed() {
        let (store, _) = scratch_store();
        store
            .put_image(&record("aaa", &["x:latest"]))
            .await
            .unwrap();
        // Same tag on a new record: index moves, old embed evicted.
        store
            .put_image(&record("bbb", &["x:latest"]))
            .await
            .unwrap();
        assert_eq!(store.resolve("x:latest").await.unwrap(), "bbb");
        let old = store.load("aaa").await.unwrap().unwrap();
        assert!(old.repo_tags.is_empty(), "{:?}", old.repo_tags);
        let new = store.load("bbb").await.unwrap().unwrap();
        assert_eq!(new.repo_tags, vec!["x:latest".to_string()]);
    }

    #[tokio::test]
    async fn remove_by_id_keeps_stolen_tag() {
        let (store, _) = scratch_store();
        store
            .put_image(&record("aaa", &["x:latest"]))
            .await
            .unwrap();
        store
            .put_image(&record("bbb", &["x:latest"]))
            .await
            .unwrap();
        // Old holder still embeds nothing now; removing it by id must not
        // amputate the tag that names bbb. Re-embed to simulate a
        // pre-reconciliation store, then remove.
        let mut stale = store.load("aaa").await.unwrap().unwrap();
        stale.repo_tags = vec!["x:latest".to_string()];
        ingot_store::write_json_atomic(&store.paths.image_record("aaa"), &stale).unwrap();
        store.remove_image("aaa", None).await.unwrap();
        assert_eq!(store.resolve("x:latest").await.unwrap(), "bbb");
    }

    #[tokio::test]
    async fn merged_put_preserves_digests() {
        let (store, _) = scratch_store();
        let mut pulled = record("aaa", &["x:latest"]);
        pulled.manifest_digest = "sha256:m".to_string();
        pulled.repo_digests = vec!["x@sha256:m".to_string()];
        store.put_image_merged(&pulled).await.unwrap();
        // A load round-trip carries tags but no digests: merge keeps them.
        let mut loaded = record("aaa", &["x:latest", "y:1"]);
        loaded.repo_digests = Vec::new();
        store.put_image_merged(&loaded).await.unwrap();
        let back = store.load("aaa").await.unwrap().unwrap();
        assert_eq!(back.manifest_digest, "sha256:m");
        assert_eq!(back.repo_digests, vec!["x@sha256:m".to_string()]);
        assert!(back.repo_tags.contains(&"y:1".to_string()));
    }

    #[tokio::test]
    async fn list_effective_hides_stale_embeds() {
        let (store, _) = scratch_store();
        store
            .put_image(&record("aaa", &["x:latest"]))
            .await
            .unwrap();
        store
            .put_image(&record("bbb", &["x:latest"]))
            .await
            .unwrap();
        // Simulate a pre-reconciliation stale copy on the old holder.
        let mut stale = store.load("aaa").await.unwrap().unwrap();
        stale.repo_tags = vec!["x:latest".to_string()];
        ingot_store::write_json_atomic(&store.paths.image_record("aaa"), &stale).unwrap();
        let listed = store.list_effective().await.unwrap();
        let a = listed.iter().find(|r| r.id == "aaa").unwrap();
        let b = listed.iter().find(|r| r.id == "bbb").unwrap();
        assert!(a.repo_tags.is_empty(), "{:?}", a.repo_tags);
        assert_eq!(b.repo_tags, vec!["x:latest".to_string()]);
        assert!(store.effective_tags(&stale).await.is_empty());
    }

    #[tokio::test]
    async fn gc_replaced_layers_keeps_shared() {
        let (store, paths) = scratch_store();
        for f in ["b-old", "b-new", "b-shared", "b-solo"] {
            std::fs::write(paths.blob(f), b"x").unwrap();
        }
        for d in ["d-old", "d-new", "d-shared", "d-solo"] {
            std::fs::create_dir_all(paths.layer(d)).unwrap();
        }
        let mut old = record("aaa", &[]);
        old.layer_blobs = vec!["b-old".into(), "b-shared".into(), "b-solo".into()];
        old.diff_ids = vec!["d-old".into(), "d-shared".into(), "d-solo".into()];
        let mut new = record("aaa", &[]);
        new.layer_blobs = vec!["b-new".into(), "b-shared".into()];
        new.diff_ids = vec!["d-new".into(), "d-shared".into()];
        // A third record still roots the old blob and dir.
        let mut third = record("ccc", &[]);
        third.layer_blobs = vec!["b-old".into()];
        third.diff_ids = vec!["d-old".into()];
        store.put_image(&old).await.unwrap();
        store.put_image(&third).await.unwrap();
        store.put_image(&new).await.unwrap();
        store.gc_replaced_layers(&old).await.unwrap();
        // Referenced nowhere else: collected.
        assert!(!paths.blob("b-solo").exists());
        assert!(!paths.layer("d-solo").exists());
        // Shared with the new revision or the third record: kept.
        for f in ["b-new", "b-shared", "b-old"] {
            assert!(paths.blob(f).exists(), "{f} wrongly collected");
        }
        for d in ["d-new", "d-shared", "d-old"] {
            assert!(paths.layer(d).exists(), "{d} wrongly collected");
        }
        // Dropping the third record releases its pair through the
        // deletion path, composing with the replace path above.
        store.remove_image("ccc", None).await.unwrap();
        assert!(!paths.blob("b-old").exists());
        assert!(!paths.layer("d-old").exists());
        assert!(paths.blob("b-new").exists());
        assert!(paths.layer("d-new").exists());
    }

    #[tokio::test]
    async fn remove_image_keeps_shared_layers() {
        // Exact live scenario: two records share one layer; deleting one
        // record must not collect the shared blob or dir.
        let (store, paths) = scratch_store();
        std::fs::write(paths.blob("b-shared"), b"x").unwrap();
        std::fs::create_dir_all(paths.layer("d-shared")).unwrap();
        let mut a = record("aaa", &[]);
        a.layer_blobs = vec!["b-shared".into()];
        a.diff_ids = vec!["d-shared".into()];
        let mut b = record("bbb", &["t:1"]);
        b.layer_blobs = vec!["b-shared".into()];
        b.diff_ids = vec!["d-shared".into()];
        store.put_image(&a).await.unwrap();
        store.put_image(&b).await.unwrap();
        store.remove_image("bbb", None).await.unwrap();
        assert!(paths.blob("b-shared").exists(), "shared blob collected");
        assert!(paths.layer("d-shared").exists(), "shared dir collected");
        assert!(store.load("aaa").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn resolve_digest_ref() {
        let (store, _) = scratch_store();
        let mut r = record("aaa", &[]);
        r.repo_digests = vec!["busybox@sha256:m".to_string()];
        store.put_image(&r).await.unwrap();
        assert_eq!(store.resolve("busybox@sha256:m").await.unwrap(), "aaa");
        assert!(store.resolve("busybox@sha256:other").await.is_err());
    }

    #[test]
    fn chain_ids_align_with_diffs() {
        let ids = vec!["sha256:a".into(), "sha256:b".into()];
        let chains = ImageRecord::compute_chain_ids(&ids);
        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0], "sha256:a");
        assert_eq!(
            chains[1],
            format!(
                "sha256:{}",
                ingot_util::digest::sha256_hex(b"sha256:a sha256:b")
            )
        );
    }
}
