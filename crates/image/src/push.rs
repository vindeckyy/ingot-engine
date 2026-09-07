//! Push orchestration: local blobs → registry (config + layers, then a
//! single image manifest). Emits docker-format progress messages, mirroring
//! [`crate::pull`].

use crate::store::{ImageRecord, ImageStore};
use anyhow::{anyhow, Context, Result};
use ingot_api::ProgressMessage;
use ingot_registry::{ImageRef, RegistryClient};
use std::sync::Arc;
use tokio::sync::mpsc;

/// OCI single-manifest media type for pushes. The daemon pushes exactly the
/// platform it stored, never a manifest list (unit 4.6).
pub const PUSH_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const PUSH_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";

/// Run the push pipeline for the already-resolved `record`, addressed at
/// `target` (registry-qualified repo plus the tag to push). Returns the
/// registry-confirmed manifest digest.
pub async fn push(
    client: Arc<RegistryClient>,
    store: Arc<ImageStore>,
    target: ImageRef,
    record: ImageRecord,
    auth: Option<ingot_api::AuthConfig>,
    tx: mpsc::Sender<ProgressMessage>,
) -> Result<String> {
    // Docker defaults an untagged push to `latest`; a digest-only reference
    // resolves the image but cannot address the manifest PUT, so it lands
    // on `latest` too rather than failing.
    let tag = target.tag.clone().unwrap_or_else(|| "latest".to_string());
    send(
        &tx,
        ProgressMessage::status(format!(
            "The push refers to repository [{}]",
            target.display_ref_no_tag()
        )),
    )
    .await;

    let config_digest = format!("sha256:{}", record.id);
    let config_bytes = tokio::fs::read(store.blob_path(&config_digest))
        .await
        .with_context(|| format!("read local config blob {config_digest}"))?;
    let mut layers = Vec::with_capacity(record.layer_blobs.len());
    for digest in &record.layer_blobs {
        let path = store.blob_path(digest);
        let meta = tokio::fs::metadata(&path)
            .await
            .with_context(|| format!("read local layer blob {digest}"))?;
        layers.push((digest.clone(), meta.len()));
    }

    // Config first (docker pushes it with the layers, order unimportant).
    push_one(
        &client,
        &target,
        &config_digest,
        &store.blob_path(&config_digest),
        auth.as_ref(),
        &tx,
    )
    .await?;
    for (digest, _) in &layers {
        push_one(
            &client,
            &target,
            digest,
            &store.blob_path(digest),
            auth.as_ref(),
            &tx,
        )
        .await?;
    }

    let manifest =
        build_push_manifest(&config_digest, config_bytes.len() as u64, &layers, &store).await?;
    let total = manifest.len() as u64
        + config_bytes.len() as u64
        + layers.iter().map(|(_, n)| n).sum::<u64>();
    let digest = client
        .push_manifest(
            &target,
            &tag,
            PUSH_MANIFEST_MEDIA_TYPE,
            &manifest,
            auth.as_ref(),
        )
        .await
        .map_err(|e| {
            let _ = tx.try_send(ProgressMessage::error(format!("{e:#}")));
            e
        })?;

    let mut done = ProgressMessage::status(format!("{tag}: digest: {digest} size: {total}"));
    done.aux = Some(serde_json::json!({
        "Tag": tag,
        "Digest": digest,
        "Size": total as i64,
    }));
    send(&tx, done).await;
    Ok(digest)
}

/// Upload one blob with Preparing/Pushing/Pushed progress, skipping the
/// bytes when the registry already holds the digest.
async fn push_one(
    client: &Arc<RegistryClient>,
    target: &ImageRef,
    digest: &str,
    path: &std::path::Path,
    auth: Option<&ingot_api::AuthConfig>,
    tx: &mpsc::Sender<ProgressMessage>,
) -> Result<()> {
    // `push_blob_file` HEADs first and reports whether bytes went out,
    // so one call drives both progress outcomes with no extra round trip.
    let id = short(digest);
    send(
        tx,
        ProgressMessage {
            id: Some(id.clone()),
            status: Some("Preparing".into()),
            ..Default::default()
        },
    )
    .await;
    let sent = client
        .push_blob_file(target, digest, path, auth)
        .await
        .map_err(|e| {
            let _ = tx.try_send(ProgressMessage::error(format!("{e:#}")));
            e
        })?;
    send(
        tx,
        ProgressMessage {
            id: Some(id),
            status: Some(
                if sent {
                    "Pushed"
                } else {
                    "Layer already exists"
                }
                .into(),
            ),
            ..Default::default()
        },
    )
    .await;
    Ok(())
}

/// Assemble the single-manifest body for `config_digest` plus `layers`
/// (`(digest, compressed_len)`). Layer media types come from sniffing the
/// stored blobs: the record keeps digests, not media types.
async fn build_push_manifest(
    config_digest: &str,
    config_len: u64,
    layers: &[(String, u64)],
    store: &ImageStore,
) -> Result<Vec<u8>> {
    let mut descs = Vec::with_capacity(layers.len());
    for (digest, len) in layers {
        let magic = read_magic(&store.blob_path(digest)).await?;
        descs.push(serde_json::json!({
            "mediaType": sniff_layer_media(&magic),
            "digest": digest,
            "size": len,
        }));
    }
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": PUSH_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": PUSH_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": config_len,
        },
        "layers": descs,
    });
    serde_json::to_vec(&manifest).map_err(|e| anyhow!("encode push manifest: {e}"))
}

/// First bytes of a blob for compression sniffing (4 bytes covers gzip
/// and zstd magic; short files just yield fewer).
async fn read_magic(path: &std::path::Path) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    let mut buf = vec![0u8; 4];
    let n = f.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

/// Layer media type from compression magic. Pulled blobs are gzip in the
/// common case; `load` re-compresses to gzip too, so anything else is the
/// exception, never the assumption.
fn sniff_layer_media(magic: &[u8]) -> &'static str {
    if magic.starts_with(&[0x1f, 0x8b]) {
        "application/vnd.oci.image.layer.v1.tar+gzip"
    } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        "application/vnd.oci.image.layer.v1.tar+zstd"
    } else {
        "application/vnd.oci.image.layer.v1.tar"
    }
}

fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
}

async fn send(tx: &mpsc::Sender<ProgressMessage>, msg: ProgressMessage) {
    let _ = tx.send(msg).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_media_sniffing() {
        assert_eq!(
            sniff_layer_media(&[0x1f, 0x8b, 0x08, 0x00]),
            "application/vnd.oci.image.layer.v1.tar+gzip"
        );
        assert_eq!(
            sniff_layer_media(&[0x28, 0xb5, 0x2f, 0xfd]),
            "application/vnd.oci.image.layer.v1.tar+zstd"
        );
        assert_eq!(
            sniff_layer_media(b"ustar"),
            "application/vnd.oci.image.layer.v1.tar"
        );
        assert_eq!(
            sniff_layer_media(&[]),
            "application/vnd.oci.image.layer.v1.tar"
        );
        assert_eq!(
            sniff_layer_media(&[0x1f]),
            "application/vnd.oci.image.layer.v1.tar"
        );
    }

    #[tokio::test]
    async fn manifest_body_shapes() {
        let dir = std::env::temp_dir().join(format!("ingot-push-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let gz = [0x1f, 0x8b, 0x08, 0x00, 0x01];
        std::fs::write(dir.join("l1"), gz).unwrap();
        std::fs::write(dir.join("l2"), b"plain-tar-bytes").unwrap();
        let paths = ingot_store::paths::DataPaths::new(dir.clone(), dir.join("run"));
        let store = ImageStore::new(paths).unwrap();
        // Point the store paths at our files via blob_path naming is
        // indirect; instead build the manifest against temp blob paths by
        // seeding through the real layout.
        for (name, digest) in [("l1", "sha256:aa"), ("l2", "sha256:bb")] {
            let dest = store.blob_path(digest);
            std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
            std::fs::copy(dir.join(name), &dest).unwrap();
        }
        let body = build_push_manifest(
            "sha256:cc",
            42,
            &[("sha256:aa".to_string(), 5), ("sha256:bb".to_string(), 15)],
            &store,
        )
        .await
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["schemaVersion"], 2);
        assert_eq!(v["mediaType"], PUSH_MANIFEST_MEDIA_TYPE);
        assert_eq!(v["config"]["digest"], "sha256:cc");
        assert_eq!(v["config"]["size"], 42);
        assert_eq!(
            v["layers"][0]["mediaType"],
            "application/vnd.oci.image.layer.v1.tar+gzip"
        );
        assert_eq!(v["layers"][0]["digest"], "sha256:aa");
        assert_eq!(
            v["layers"][1]["mediaType"],
            "application/vnd.oci.image.layer.v1.tar"
        );
        assert_eq!(v["layers"][1]["size"], 15);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
