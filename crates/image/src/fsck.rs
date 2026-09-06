//! Offline image-store consistency check (`ingotd --fsck [--repair]`).
//!
//! Read-only `--fsck` reports every inconsistency it finds and exits
//! nonzero when the store is not clean. `--repair` additionally removes
//! what is provably safe: stale `.part` downloads and blobs no image
//! references (blobs are content-addressed, so unreferenced ones can
//! never be needed). Records with missing blobs, dangling tags and
//! orphan layer directories are reported, never silently fixed, except
//! that repair drops tag entries pointing at absent records.
//!
//! Repair refuses to run while the daemon is live: a running daemon may
//! be mid-pull (`.part` files) or hold the store lock.

use ingot_store::paths::DataPaths;
use std::collections::{HashMap, HashSet};

/// Outcome of [`check`] / [`repair`].
#[derive(Debug, Default, serde::Serialize)]
pub struct FsckReport {
    pub images_checked: usize,
    pub blobs_referenced: usize,
    pub errors: Vec<String>,
    pub fixed: Vec<String>,
}

impl FsckReport {
    pub fn clean(&self) -> bool {
        self.errors.is_empty()
    }
}

fn short(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

/// Blob digests (short hex, no `sha256:` prefix) rooted by one image
/// record: its config blob plus its layer blobs. The record id IS the
/// config digest — pull and builder both store the image config under
/// its own digest and use that digest as the record id — so the config
/// must be rooted here, or repair will mistake live configs for orphans
/// and delete them. Single rule shared by [`check`] and [`repair`] so
/// the two can never disagree about what is safe to delete.
fn record_blob_refs(rec: &super::store::ImageRecord) -> Vec<String> {
    let mut out = Vec::with_capacity(rec.layer_blobs.len() + 1);
    if !rec.id.is_empty() {
        out.push(short(&rec.id).to_string());
    }
    out.extend(rec.layer_blobs.iter().map(|b| short(b).to_string()));
    out
}

/// Read-only verification. Never modifies the store.
pub fn check(paths: &DataPaths) -> anyhow::Result<FsckReport> {
    let mut rep = FsckReport::default();
    let mut referenced: HashSet<String> = HashSet::new();
    let mut layer_refs: HashSet<String> = HashSet::new();

    // Tag index first: record embeds are checked against it below.
    let tags: HashMap<String, String> = std::fs::read_to_string(paths.tags())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    // Builder cache roots blobs the same way it roots layer dirs (§4):
    // multi-stage intermediates live here by design until builder prune
    // (Phase 5) accounts and collects them. New entries name the blob;
    // legacy ones predate blob naming, so the diff id stands in.
    let cache_blobs: HashSet<String> = std::fs::read_to_string(paths.build_cache())
        .ok()
        .and_then(|s| serde_json::from_str::<HashMap<String, serde_json::Value>>(&s).ok())
        .map(|cache| {
            cache
                .values()
                .map(|e| {
                    e.get("blob_digest")
                        .and_then(|v| v.as_str())
                        .map(short)
                        .unwrap_or_else(|| {
                            e.get("diff_id")
                                .and_then(|v| v.as_str())
                                .map(short)
                                .unwrap_or("")
                        })
                        .to_string()
                })
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // 1. Image records parse and their blobs/layers exist.
    let images_dir = paths.images();
    let entries = std::fs::read_dir(&images_dir)
        .map(|rd| rd.filter_map(|e| e.ok()).collect::<Vec<_>>())
        .unwrap_or_default();
    for entry in &entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Mirror ImageStore::list: skip non-records, including a legacy
        // tags.json that older layouts kept beside the records.
        if !name.ends_with(".json") || name == "tags.json" {
            continue;
        }
        let raw = match std::fs::read(entry.path()) {
            Ok(b) => b,
            Err(e) => {
                rep.errors.push(format!("images/{name}: unreadable: {e}"));
                continue;
            }
        };
        let rec: super::store::ImageRecord = match serde_json::from_slice(&raw) {
            Ok(r) => r,
            Err(e) => {
                rep.errors
                    .push(format!("images/{name}: invalid record: {e}"));
                continue;
            }
        };
        rep.images_checked += 1;
        if rec.id.is_empty() {
            rep.errors.push(format!("images/{name}: empty id"));
        } else if name.trim_end_matches(".json") != short(&rec.id) {
            rep.errors.push(format!(
                "images/{name}: filename does not match id {}",
                rec.id
            ));
        }
        if rec.diff_ids.len() != rec.layer_blobs.len() {
            rep.errors.push(format!(
                "images/{name}: {} diff_ids but {} layer_blobs",
                rec.diff_ids.len(),
                rec.layer_blobs.len()
            ));
        }
        // Embedded tags must agree with the index (put_image enforces this
        // on write; older stores predate it). A tag the index points
        // elsewhere is provably stale. A tag the index lacks is ambiguous
        // (tag-crash vs untag-crash remnant): reported, never trimmed.
        for t in &rec.repo_tags {
            match tags.get(t) {
                Some(owner) if short(owner) != short(&rec.id) => {
                    rep.errors.push(format!(
                        "images/{name}: stale embedded tag {t} (index points at {owner})"
                    ));
                }
                None => {
                    rep.errors.push(format!(
                        "images/{name}: embedded tag {t} missing from index"
                    ));
                }
                _ => {}
            }
        }
        if !rec.id.is_empty() && !paths.blob(&rec.id).exists() {
            rep.errors
                .push(format!("images/{name}: missing config blob {}", rec.id));
        }
        for b in record_blob_refs(&rec) {
            referenced.insert(b);
            rep.blobs_referenced += 1;
        }
        // Content presence, not blob-file presence: base layers inherited
        // from a built image live unpacked-only (layers/<diff_id>), so a
        // layer whose blob file is absent is fine while its unpacked dir
        // exists — run and save only need the dir. Truly lost content
        // (neither form) errors.
        for (i, b) in rec.layer_blobs.iter().enumerate() {
            let dir_ok = rec.diff_ids.get(i).is_some_and(|d| paths.layer(d).exists());
            if !paths.blob(b).exists() && !dir_ok {
                rep.errors.push(format!("images/{name}: missing blob {b}"));
            }
        }
        for d in &rec.diff_ids {
            layer_refs.insert(short(d).to_string());
            if !paths.layer(d).exists() {
                rep.errors.push(format!("images/{name}: missing layer {d}"));
            }
        }
    }

    // 2. Tags resolve to existing records.
    for (tag, id) in &tags {
        if !paths.image_record(short(id)).exists() {
            rep.errors
                .push(format!("tags.json: {tag} points at missing image {id}"));
        }
    }

    // 3. Blobs on disk that no record references (`.part` files are
    // in-flight downloads, handled separately).
    if let Ok(files) = std::fs::read_dir(paths.blobs()) {
        for f in files.filter_map(|e| e.ok()) {
            if !f.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let n = f.file_name().to_string_lossy().into_owned();
            if n.ends_with(".part") || n.ends_with(".tmp") {
                rep.errors
                    .push(format!("stale partial download {}", f.path().display()));
            } else if !referenced.contains(n.as_str()) && !cache_blobs.contains(n.as_str()) {
                rep.errors
                    .push(format!("unreferenced blob {}", f.path().display()));
            }
        }
    }

    // 4. Layer directories no image record references. The builder cache
    // also roots layers, so those are skipped (reported only when neither
    // images nor the build cache need them; never auto-removed).
    let builder_cache =
        std::fs::read_to_string(paths.root.join("builder/cache.json")).unwrap_or_default();
    if let Ok(rd) = std::fs::read_dir(paths.layers()) {
        for l in rd.filter_map(|e| e.ok()) {
            let n = l.file_name().to_string_lossy().into_owned();
            if !layer_refs.contains(n.as_str()) && !builder_cache.contains(n.as_str()) {
                rep.errors
                    .push(format!("unreferenced layer {}", l.path().display()));
            }
        }
    }

    Ok(rep)
}

/// Verify, then remove what is provably safe. Refuses while live.
pub fn repair(paths: &DataPaths, run_root: &std::path::Path) -> anyhow::Result<FsckReport> {
    if daemon_live(run_root) {
        anyhow::bail!("refusing --repair while ingotd is running (stop the daemon first)");
    }
    let mut rep = check(paths)?;
    if rep.clean() {
        return Ok(rep);
    }
    // Deletion decisions come from check()'s error strings, which already
    // apply the shared record_blob_refs rule (configs rooted alongside
    // layers). No second recompute: a duplicated rule here is how the
    // config-orphan bug survived.
    let mut kept_errors = Vec::new();
    for e in rep.errors.drain(..) {
        if let Some(path) = e
            .strip_prefix("stale partial download ")
            .or_else(|| e.strip_prefix("unreferenced blob "))
        {
            match std::fs::remove_file(path) {
                Ok(()) => rep.fixed.push(format!("removed {path}")),
                Err(err) => kept_errors.push(format!("{e} (remove failed: {err})")),
            }
        } else if let Some(rest) = e.strip_prefix("tags.json: ") {
            // "tag points at missing image id": drop the dangling entry.
            if let Some((tag, _)) = rest.split_once(" points at missing image ") {
                let tags_path = paths.tags();
                let mut tags: HashMap<String, String> = std::fs::read_to_string(&tags_path)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();
                if tags.remove(tag).is_some() {
                    match ingot_store::write_json_atomic(&tags_path, &serde_json::json!(tags)) {
                        Ok(()) => rep.fixed.push(format!("dropped dangling tag {tag}")),
                        Err(err) => kept_errors.push(format!("{e} (tag drop failed: {err})")),
                    }
                    continue;
                }
            }
            kept_errors.push(e);
        } else if let Some(evicted) = try_evict_stale_embed(paths, &e) {
            match evicted {
                Ok(msg) => rep.fixed.push(msg),
                Err(kept) => kept_errors.push(kept),
            }
        } else {
            kept_errors.push(e);
        }
    }
    rep.errors = kept_errors;
    Ok(rep)
}

/// Repair one `images/<file>: stale embedded tag <t> (index points at …)`
/// finding by evicting `<t>` from that record's tag list. Returns None when
/// `e` is a different finding. Safe: the index provably assigns the tag
/// elsewhere, so this copy is stale; records are never deleted here (an
/// emptied record simply becomes dangling and prunable).
fn try_evict_stale_embed(paths: &DataPaths, e: &str) -> Option<Result<String, String>> {
    let rest = e.strip_prefix("images/")?;
    let (file, msg) = rest.split_once(": stale embedded tag ")?;
    let (tag, _) = msg.split_once(" (index points at ")?;
    let path = paths.images().join(file);
    let raw = std::fs::read(&path).ok()?;
    let mut rec: super::store::ImageRecord = serde_json::from_slice(&raw).ok()?;
    if !rec.repo_tags.iter().any(|t| t == tag) {
        return Some(Err(e.to_string()));
    }
    rec.repo_tags.retain(|t| t != tag);
    match ingot_store::write_json_atomic(&path, &rec) {
        Ok(()) => Some(Ok(format!("evicted stale tag {tag} from images/{file}"))),
        Err(err) => Some(Err(format!("{e} (evict failed: {err})"))),
    }
}

/// True when a daemon answers on the run root's socket.
fn daemon_live(run_root: &std::path::Path) -> bool {
    let sock = run_root.join("ingot.sock");
    std::os::unix::net::UnixStream::connect(sock).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> (DataPaths, std::path::PathBuf) {
        // Counter, not wall-clock: parallel tests in one process can share
        // a pid and land in the same clock tick, colliding on one dir.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "ingot-fsck-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let run = base.join("run");
        let paths = DataPaths::new(base.join("data"), run.clone());
        std::fs::create_dir_all(paths.images()).unwrap();
        std::fs::create_dir_all(paths.blobs()).unwrap();
        std::fs::create_dir_all(paths.layers()).unwrap();
        std::fs::create_dir_all(paths.build_cache().parent().unwrap()).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        (paths, base)
    }

    fn record(id: &str, blobs: &[&str], layers: &[&str]) -> super::super::store::ImageRecord {
        super::super::store::ImageRecord {
            id: id.to_string(),
            layer_blobs: blobs.iter().map(|s| s.to_string()).collect(),
            diff_ids: layers.iter().map(|s| s.to_string()).collect(),
            repo_tags: vec!["test:latest".to_string()],
            ..Default::default()
        }
    }

    fn write_record(paths: &DataPaths, rec: &super::super::store::ImageRecord) {
        // Like pull and builder: the config lives under the record id.
        if !rec.id.is_empty() {
            std::fs::write(paths.blob(&rec.id), b"config").unwrap();
        }
        for b in &rec.layer_blobs {
            std::fs::write(paths.blob(b), b"blob").unwrap();
        }
        for d in &rec.diff_ids {
            std::fs::create_dir_all(paths.layer(d)).unwrap();
        }
        std::fs::write(
            paths.image_record(&rec.id),
            serde_json::to_vec(rec).unwrap(),
        )
        .unwrap();
        let mut tags = HashMap::new();
        for t in &rec.repo_tags {
            tags.insert(t.clone(), rec.id.clone());
        }
        std::fs::write(paths.tags(), serde_json::to_vec(&tags).unwrap()).unwrap();
    }

    #[test]
    fn clean_store_passes() {
        let (paths, _base) = scratch();
        write_record(&paths, &record("abc", &["sha256:b1"], &["sha256:d1"]));
        let rep = check(&paths).unwrap();
        assert!(rep.clean(), "{:?}", rep.errors);
        assert_eq!(rep.images_checked, 1);
        // Config (rooted by record id) + one layer blob.
        assert_eq!(rep.blobs_referenced, 2);
    }

    #[test]
    fn config_blob_is_rooted_not_orphan() {
        // Regression: repair once deleted live config blobs because only
        // layer_blobs were rooted. The config must survive check+repair
        // while a true orphan is still collected.
        let (paths, base) = scratch();
        write_record(&paths, &record("abc", &["sha256:b1"], &["sha256:d1"]));
        std::fs::write(paths.blob("sha256:orphan"), b"x").unwrap();
        let rep = check(&paths).unwrap();
        assert_eq!(rep.errors.len(), 1, "{:?}", rep.errors);
        assert!(rep.errors[0].contains("unreferenced blob"));
        assert!(rep.errors[0].contains("orphan"));
        let run = base.join("run");
        let rep = repair(&paths, &run).unwrap();
        assert!(rep.clean(), "{:?}", rep.errors);
        assert!(paths.blob("abc").exists(), "live config blob was deleted");
        assert!(paths.blob("sha256:b1").exists());
        assert!(!paths.blob("sha256:orphan").exists());
    }

    #[test]
    fn missing_config_blob_reported_not_removed() {
        // A record whose config blob is gone is reported (never silently
        // fixed): repair must leave the record alone.
        let (paths, base) = scratch();
        let rec = record("abc", &["sha256:b1"], &["sha256:d1"]);
        for b in &rec.layer_blobs {
            std::fs::write(paths.blob(b), b"blob").unwrap();
        }
        for d in &rec.diff_ids {
            std::fs::create_dir_all(paths.layer(d)).unwrap();
        }
        std::fs::write(
            paths.image_record(&rec.id),
            serde_json::to_vec(&rec).unwrap(),
        )
        .unwrap();
        let rep = check(&paths).unwrap();
        assert!(rep.errors.iter().any(|e| e.contains("missing config blob")));
        let run = base.join("run");
        let rep = repair(&paths, &run).unwrap();
        assert!(rep.errors.iter().any(|e| e.contains("missing config blob")));
        assert!(paths.image_record("abc").exists());
    }

    #[test]
    fn missing_blob_and_layer_reported() {
        let (paths, _base) = scratch();
        let rec = record("abc", &["sha256:gone"], &["sha256:nodir"]);
        std::fs::write(
            paths.image_record(&rec.id),
            serde_json::to_vec(&rec).unwrap(),
        )
        .unwrap();
        let rep = check(&paths).unwrap();
        assert!(!rep.clean());
        assert!(rep.errors.iter().any(|e| e.contains("missing blob")));
        assert!(rep.errors.iter().any(|e| e.contains("missing layer")));
    }

    #[test]
    fn unpacked_dir_satisfies_builder_layer_blob() {
        // Builder base layers have no blob file (content lives unpacked
        // under layers/<diff_id>); that must not flag "missing blob".
        let (paths, _base) = scratch();
        let mut rec = record("abc", &["sha256:d1"], &["sha256:d1"]);
        rec.repo_tags = Vec::new();
        std::fs::write(paths.blob("abc"), b"config").unwrap();
        std::fs::create_dir_all(paths.layer("sha256:d1")).unwrap();
        std::fs::write(
            paths.image_record(&rec.id),
            serde_json::to_vec(&rec).unwrap(),
        )
        .unwrap();
        let rep = check(&paths).unwrap();
        assert!(rep.clean(), "{:?}", rep.errors);
    }

    #[test]
    fn stale_embed_reported_and_repaired() {
        // Two records embed the same tag but the index names only the new
        // holder: the old copy is stale and repair evicts it (the record
        // itself stays, now dangling and prunable).
        let (paths, base) = scratch();
        let mut old = record("old", &["sha256:b1"], &["sha256:d1"]);
        old.repo_tags = vec!["t:1".to_string()];
        let mut new = record("new", &["sha256:b1"], &["sha256:d1"]);
        new.repo_tags = vec!["t:1".to_string()];
        write_record(&paths, &old);
        // Second write_record overwrote tags.json; write both records then
        // set the index explicitly.
        std::fs::write(
            paths.image_record(&new.id),
            serde_json::to_vec(&new).unwrap(),
        )
        .unwrap();
        std::fs::write(paths.blob("new"), b"config").unwrap();
        let mut tags = HashMap::new();
        tags.insert("t:1".to_string(), "new".to_string());
        std::fs::write(paths.tags(), serde_json::to_vec(&tags).unwrap()).unwrap();
        let rep = check(&paths).unwrap();
        assert!(rep
            .errors
            .iter()
            .any(|e| e.contains("stale embedded tag t:1")));
        let run = base.join("run");
        let rep = repair(&paths, &run).unwrap();
        assert!(rep.clean(), "{:?}", rep.errors);
        assert!(rep
            .fixed
            .iter()
            .any(|f| f.contains("evicted stale tag t:1")));
        let back: super::super::store::ImageRecord =
            serde_json::from_slice(&std::fs::read(paths.image_record("old")).unwrap()).unwrap();
        assert!(back.repo_tags.is_empty());
        // Second repair is a no-op: nothing left to evict.
        let rep = repair(&paths, &run).unwrap();
        assert!(rep.clean(), "{:?}", rep.errors);
        assert!(rep.fixed.is_empty());
    }

    #[test]
    fn index_missing_tag_reported_not_trimmed() {
        // An embedded tag the index lacks is ambiguous (tag-crash vs
        // untag-crash remnant): report it, never trim it.
        let (paths, base) = scratch();
        let mut rec = record("abc", &["sha256:b1"], &["sha256:d1"]);
        rec.repo_tags = vec!["ghost:1".to_string()];
        write_record(&paths, &rec);
        std::fs::write(paths.tags(), b"{}").unwrap();
        let rep = check(&paths).unwrap();
        assert!(rep.errors.iter().any(|e| e.contains("missing from index")));
        let run = base.join("run");
        let rep = repair(&paths, &run).unwrap();
        assert!(rep.errors.iter().any(|e| e.contains("missing from index")));
        let back: super::super::store::ImageRecord =
            serde_json::from_slice(&std::fs::read(paths.image_record("abc")).unwrap()).unwrap();
        assert_eq!(back.repo_tags, vec!["ghost:1".to_string()]);
    }

    #[test]
    fn cache_entries_root_blobs() {
        // Multi-stage intermediates live in the build cache by design:
        // new entries root by blob digest, legacy ones by diff id. Only
        // a blob neither records nor the cache need is an orphan.
        let (paths, _base) = scratch();
        std::fs::write(
            paths.build_cache(),
            serde_json::json!({
                "run-new": {"diff_id": "sha256:d1", "blob_digest": "sha256:b1"},
                "run-legacy": {"diff_id": "sha256:d2"},
            })
            .to_string(),
        )
        .unwrap();
        for f in ["b1", "d2", "orphan"] {
            std::fs::write(paths.blobs().join(f), b"x").unwrap();
        }
        let rep = check(&paths).unwrap();
        assert_eq!(rep.errors.len(), 1, "{:?}", rep.errors);
        assert!(rep.errors[0].contains("orphan"));
    }

    #[test]
    fn corrupt_record_reported() {
        let (paths, _base) = scratch();
        std::fs::write(paths.image_record("bad"), b"{oops").unwrap();
        let rep = check(&paths).unwrap();
        assert!(rep.errors.iter().any(|e| e.contains("invalid record")));
    }

    #[test]
    fn orphans_and_parts_repaired() {
        let (paths, base) = scratch();
        write_record(&paths, &record("abc", &["sha256:b1"], &["sha256:d1"]));
        std::fs::write(paths.blob("sha256:orphan"), b"x").unwrap();
        std::fs::write(paths.blobs().join("left.part"), b"half").unwrap();
        let rep = check(&paths).unwrap();
        assert!(rep.errors.iter().any(|e| e.contains("unreferenced blob")));
        assert!(rep.errors.iter().any(|e| e.contains("stale partial")));
        let run = base.join("run");
        let rep = repair(&paths, &run).unwrap();
        assert!(rep.clean(), "{:?}", rep.errors);
        assert_eq!(rep.fixed.len(), 2);
        assert!(!paths.blob("sha256:orphan").exists());
    }

    #[test]
    fn dangling_tag_dropped_on_repair() {
        let (paths, base) = scratch();
        write_record(&paths, &record("abc", &["sha256:b1"], &["sha256:d1"]));
        let mut tags: HashMap<String, String> = [("gone:t".to_string(), "nope".to_string())]
            .into_iter()
            .collect();
        tags.insert("test:latest".to_string(), "abc".to_string());
        std::fs::write(paths.tags(), serde_json::to_vec(&tags).unwrap()).unwrap();
        let run = base.join("run");
        let rep = repair(&paths, &run).unwrap();
        assert!(rep.clean(), "{:?}", rep.errors);
        assert!(rep.fixed.iter().any(|f| f.contains("gone:t")));
        let back: HashMap<String, String> =
            serde_json::from_slice(&std::fs::read(paths.tags()).unwrap()).unwrap();
        assert!(!back.contains_key("gone:t"));
    }

    #[test]
    fn repair_refuses_live_daemon() {
        use std::os::unix::net::UnixListener;
        let (paths, base) = scratch();
        let run = base.join("run");
        let _sock = UnixListener::bind(run.join("ingot.sock")).expect("bind fixture socket");
        assert!(repair(&paths, &run).is_err());
    }
}
