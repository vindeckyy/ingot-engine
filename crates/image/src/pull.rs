//! Pull orchestration: manifest → config + layers (parallel) → unpack →
//! image record + tags. Emits docker-format progress messages.

use crate::store::{HistoryEntry, ImageRecord, ImageStore};
use anyhow::{anyhow, Result};
use ingot_api::{ContainerConfig, ProgressMessage};
use ingot_registry::{ImageRef, RegistryClient};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct PullHandle {
    pub image_ref: ImageRef,
    pub auth: Option<ingot_api::AuthConfig>,
}

/// Run the pull pipeline. Progress JSON lines are sent on `tx`; the receiver
/// (HTTP handler) forwards them to the client. Returns the image id.
/// `platform` (`os/arch`) overrides the daemon default (unit 4.1).
pub async fn pull(
    client: Arc<RegistryClient>,
    store: Arc<ImageStore>,
    image: ImageRef,
    auth: Option<ingot_api::AuthConfig>,
    platform: Option<(String, String)>,
    tx: mpsc::Sender<ProgressMessage>,
) -> Result<String> {
    send(
        &tx,
        ProgressMessage::status(format!("Pulling from {}", image.display_ref())),
    )
    .await;

    let (manifest, top_digest) = client
        .fetch_manifest(&image, auth.as_ref(), platform)
        .await
        .map_err(|e| {
            let _ = tx.try_send(ProgressMessage::error(format!("{e:#}")));
            e
        })?;

    // ---- config blob (concurrent with layers) ----
    let config_digest = manifest.config_digest.clone();
    let cfg_client = Arc::clone(&client);
    let cfg_image = image.clone();
    let cfg_auth = auth.clone();
    let cfg_store = Arc::clone(&store);
    let cfg_endpoint = manifest.endpoint.clone();
    let cfg_digest = config_digest.clone();
    let cfg_task = tokio::spawn(async move {
        cfg_client
            .fetch_blob_to_file(
                &cfg_image,
                &cfg_digest,
                &cfg_store.blob_path(&cfg_digest),
                cfg_auth.as_ref(),
                &cfg_endpoint,
            )
            .await
    });

    // ---- layers (bounded parallel download, then parallel unpack) ----
    let mut blobs = Vec::with_capacity(manifest.layers.len());
    let total: i64 = manifest.layers.iter().map(|l| l.size).sum();
    let mut downloaded: i64 = 0;

    let sem = Arc::new(tokio::sync::Semaphore::new(6));
    let blob_endpoint = manifest.endpoint.clone();
    let mut tasks = Vec::with_capacity(manifest.layers.len());
    for (idx, layer) in manifest.layers.iter().enumerate() {
        let permit = Arc::clone(&sem);
        let client = Arc::clone(&client);
        let image = image.clone();
        let auth = auth.clone();
        let store = Arc::clone(&store);
        let tx = tx.clone();
        let endpoint = blob_endpoint.clone();
        let size = layer.size;
        let digest = layer.digest.clone();
        let media = layer.media_type.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = permit.acquire_owned().await;
            send(
                &tx,
                ProgressMessage {
                    id: Some(format!(
                        "layer-{}",
                        digest.chars().take(12).collect::<String>()
                    )),
                    status: Some("Pulling fs layer".into()),
                    ..Default::default()
                },
            )
            .await;
            send(
                &tx,
                ProgressMessage {
                    id: Some(short(&digest)),
                    status: Some("Downloading".into()),
                    progressDetail: Some(ingot_api::ProgressDetail {
                        current: 0,
                        total: size,
                    }),
                    ..Default::default()
                },
            )
            .await;
            let n = client
                .fetch_blob_to_file(
                    &image,
                    &digest,
                    &store.blob_path(&digest),
                    auth.as_ref(),
                    &endpoint,
                )
                .await?;
            send(
                &tx,
                ProgressMessage {
                    id: Some(short(&digest)),
                    status: Some("Download complete".into()),
                    progressDetail: Some(ingot_api::ProgressDetail {
                        current: n as i64,
                        total: n as i64,
                    }),
                    ..Default::default()
                },
            )
            .await;
            Ok::<(usize, String, String, i64), anyhow::Error>((idx, digest, media, n as i64))
        }));
    }

    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await??);
    }
    // Config downloaded concurrently with layers.
    cfg_task.await??;
    let config_bytes = tokio::fs::read(store.blob_path(&config_digest)).await?;
    let oci_config: OciImageConfig =
        serde_json::from_slice(&config_bytes).map_err(|e| anyhow!("parse image config: {e}"))?;
    results.sort_by_key(|(idx, _, _, _)| *idx);
    for (_, digest, media, n) in results {
        downloaded += n;
        blobs.push((digest, media));
    }

    // ---- unpack in parallel (bounded), results re-ordered ----
    let mut diff_ids = vec![String::new(); blobs.len()];
    {
        let unpack_sem = Arc::new(tokio::sync::Semaphore::new(4));
        let mut unpack_tasks = Vec::with_capacity(blobs.len());
        for (i, (digest, media)) in blobs.iter().enumerate() {
            let permit = Arc::clone(&unpack_sem);
            let store = Arc::clone(&store);
            let digest = digest.clone();
            let media = media.clone();
            unpack_tasks.push(tokio::spawn(async move {
                let _p = permit.acquire_owned().await;
                let d = store.ensure_layer_unpacked(&digest, &media).await?;
                Ok::<(usize, String), anyhow::Error>((i, d))
            }));
        }
        for t in unpack_tasks {
            let (i, d) = t.await??;
            diff_ids[i] = d;
        }
    }
    for (i, digest) in blobs.iter().map(|(d, _)| d).enumerate() {
        send(
            &tx,
            ProgressMessage {
                id: Some(short(digest)),
                status: Some("Extracting".into()),
                progressDetail: Some(ingot_api::ProgressDetail {
                    current: i as i64,
                    total: blobs.len() as i64,
                }),
                ..Default::default()
            },
        )
        .await;
    }
    // Cross-check unpacked content against the image config's rootfs
    // descriptor: every unpacked diffID must appear in the config list in
    // order. (The config may list extra empty-layer entries, so this is a
    // subsequence check, not an equality check.) A mismatch means a corrupt
    // layer or a tampered store.
    if !oci_config.rootfs.typ.is_empty() && oci_config.rootfs.typ != "layers" {
        anyhow::bail!(
            "unsupported rootfs type {:?} for {}",
            oci_config.rootfs.typ,
            image.display_ref()
        );
    }
    if !oci_config.rootfs.diff_ids.is_empty() {
        let mut want = oci_config.rootfs.diff_ids.iter();
        for got in &diff_ids {
            if !want.any(|w| w == got) {
                anyhow::bail!(
                    "layer diffID mismatch for {}: unpacked layer {got} not listed in image config",
                    image.display_ref()
                );
            }
        }
    }
    send(
        &tx,
        ProgressMessage {
            status: Some("Pull complete".into()),
            progressDetail: Some(ingot_api::ProgressDetail {
                current: downloaded,
                total,
            }),
            ..Default::default()
        },
    )
    .await;

    // ---- image record ----
    let size: i64 = manifest.layers.iter().map(|l| l.size).sum::<i64>()
        + config_bytes.len() as i64
        + manifest.media_type.len() as i64;
    let repo_digest = format!("{}@{}", image.display_ref_no_tag(), top_digest);
    let record = ImageRecord {
        id: config_digest.trim_start_matches("sha256:").to_string(),
        manifest_digest: top_digest.clone(),
        repo_tags: image.tag_key_opt().into_iter().collect(),
        repo_digests: vec![repo_digest],
        created: oci_config.created.clone().unwrap_or_default(),
        created_unix: parse_rfc3339_or_zero(&oci_config.created),
        architecture: oci_config.architecture.clone(),
        os: oci_config.os.clone(),
        author: oci_config.author.clone().unwrap_or_default(),
        comment: oci_config.comment.clone().unwrap_or_default(),
        docker_version: oci_config.docker_version.clone(),
        diff_ids: diff_ids.clone(),
        layer_blobs: blobs.iter().map(|(d, _)| d.clone()).collect(),
        size,
        config: to_container_config(&oci_config),
        history: to_history(&oci_config),
        chain_ids: ImageRecord::compute_chain_ids(&diff_ids),
    };

    // Merge tags/digests if the image already exists under another tag.
    let id = record.id.clone();
    store.put_image_merged(&record).await?;

    send(
        &tx,
        ProgressMessage::status(format!(
            "Downloaded newer image for {}",
            image.display_ref()
        )),
    )
    .await;
    Ok(id)
}

fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
}

async fn send(tx: &mpsc::Sender<ProgressMessage>, msg: ProgressMessage) {
    let _ = tx.send(msg).await;
}

/// The image config blob (OCI image config / docker schema2 config).
#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(default)]
pub struct OciImageConfig {
    #[serde(rename = "created")]
    created: Option<String>,
    #[serde(rename = "author")]
    author: Option<String>,
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    config: OciRuntimeConfig,
    #[serde(default)]
    rootfs: OciRootFs,
    #[serde(default)]
    history: Vec<OciHistory>,
    #[serde(rename = "docker_version")]
    docker_version: String,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(default)]
// Field names mirror the OCI image config JSON verbatim.
#[allow(non_snake_case)]
pub struct OciRuntimeConfig {
    #[serde(default)]
    Env: Vec<String>,
    #[serde(default)]
    Cmd: Option<Vec<String>>,
    #[serde(default)]
    Entrypoint: Option<Vec<String>>,
    #[serde(default)]
    WorkingDir: String,
    #[serde(default)]
    User: String,
    #[serde(default)]
    Labels: HashMap<String, String>,
    #[serde(default)]
    ExposedPorts: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    Volumes: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    StopSignal: Option<String>,
    #[serde(default)]
    ArgsEscaped: Option<bool>,
    #[serde(default)]
    Healthcheck: Option<ingot_api::HealthConfig>,
    #[serde(default)]
    Shell: Option<Vec<String>>,
    #[serde(default)]
    OnBuild: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(default)]
pub struct OciRootFs {
    #[serde(default, rename = "type")]
    typ: String,
    #[serde(default)]
    diff_ids: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[serde(default)]
pub struct OciHistory {
    #[serde(default)]
    created: String,
    #[serde(default)]
    created_by: String,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    empty_layer: Option<bool>,
    #[serde(default)]
    created_for: Option<String>,
}

fn to_container_config(c: &OciImageConfig) -> ContainerConfig {
    ContainerConfig {
        Hostname: String::new(),
        Domainname: String::new(),
        User: c.config.User.clone(),
        AttachStdin: false,
        AttachStdout: false,
        AttachStderr: false,
        ExposedPorts: c.config.ExposedPorts.clone(),
        Tty: false,
        OpenStdin: false,
        StdinOnce: false,
        Env: c.config.Env.clone(),
        Cmd: c.config.Cmd.clone().unwrap_or_default(),
        Healthcheck: c.config.Healthcheck.clone(),
        ArgsEscaped: c.config.ArgsEscaped.unwrap_or(false),
        Image: String::new(),
        Volumes: c.config.Volumes.clone(),
        WorkingDir: c.config.WorkingDir.clone(),
        Entrypoint: c.config.Entrypoint.clone(),
        OnBuild: c.config.OnBuild.clone(),
        Labels: c.config.Labels.clone(),
        StopSignal: c.config.StopSignal.clone().unwrap_or_default(),
        StopTimeout: None,
        Shell: c.config.Shell.clone(),
    }
}

fn to_history(c: &OciImageConfig) -> Vec<HistoryEntry> {
    c.history
        .iter()
        .map(|h| HistoryEntry {
            created: h.created.clone(),
            created_by: h.created_by.clone(),
            created_for: h.created_for.clone(),
            author: h.author.clone(),
            comment: h.comment.clone(),
            empty_layer: h.empty_layer,
        })
        .collect()
}

fn parse_rfc3339_or_zero(s: &Option<String>) -> i64 {
    s.as_deref()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|d| d.timestamp())
        .unwrap_or(0)
}
