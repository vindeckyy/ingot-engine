//! The classic builder: per-instruction layers, config accumulation,
//! chainID-keyed cache, multi-stage support.

use crate::parser::{expand_vars, parse, Dockerfile, Instruction};
use anyhow::{anyhow, Context, Result};
use ingot_api::ProgressMessage;
use ingot_image::store::ImageRecord;
use ingot_store::paths::DataPaths;
use ingot_util::digest::sha256_hex;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct BuildOptions {
    pub dockerfile: String,
    pub context_dir: PathBuf,
    pub tags: Vec<String>,
    pub target: Option<String>,
    pub build_args: HashMap<String, String>,
    pub nocache: bool,
}

pub type BuildOutput = mpsc::Sender<ProgressMessage>;

/// Default (empty) image config used when the builder starts from scratch.
fn empty_config() -> ConfigState {
    ConfigState::default()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigState {
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub workdir: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub exposed_ports: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub volumes: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub stop_signal: String,
    #[serde(default)]
    pub healthcheck: Option<ingot_api::HealthConfig>,
}

impl ConfigState {
    fn from_image_record(r: &ImageRecord) -> Self {
        ConfigState {
            env: r.config.Env.clone(),
            cmd: Some(r.config.Cmd.clone()).filter(|c| !c.is_empty()),
            entrypoint: r.config.Entrypoint.clone(),
            workdir: r.config.WorkingDir.clone(),
            user: r.config.User.clone(),
            labels: r.config.Labels.clone(),
            exposed_ports: r.config.ExposedPorts.clone().unwrap_or_default(),
            volumes: r.config.Volumes.clone().unwrap_or_default(),
            stop_signal: r.config.StopSignal.clone(),
            healthcheck: r.config.Healthcheck.clone(),
        }
    }

    fn env_pairs(&self) -> Vec<(String, String)> {
        self.env
            .iter()
            .filter_map(|e| e.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CacheEntry {
    diff_id: String,
}

/// The running state of a stage while building.
struct Stage {
    /// base-first diff ids of the current chain.
    chain: Vec<String>,
    config: ConfigState,
}

pub async fn build_image(
    images: Arc<ingot_image::ImageStore>,
    registry: Arc<ingot_registry::RegistryClient>,
    paths: DataPaths,
    opts: BuildOptions,
    tx: BuildOutput,
) -> Result<String> {
    send(&tx, ProgressMessage::stream(format!("Step 0 : parsing Dockerfile\n"))).await;
    let df = parse(&opts.dockerfile)?;

    // Group into stages by FROM.
    let mut stages: Vec<Vec<usize>> = Vec::new();
    for (idx, inst) in df.instructions.iter().enumerate() {
        if inst.verb == "FROM" {
            stages.push(vec![idx]);
        } else if let Some(last) = stages.last_mut() {
            last.push(idx);
        }
    }
    let target_stage = opts
        .target
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .and_then(|t| {
            if let Ok(idx) = t.parse::<usize>() {
                if idx < stages.len() {
                    return Some(idx);
                }
            }
            for (sidx, stage_indices) in stages.iter().enumerate() {
                if let Some(&first_idx) = stage_indices.first() {
                    let inst = &df.instructions[first_idx];
                    let words: Vec<&str> = inst.args.split_whitespace().collect();
                    if let Some(pos) = words.iter().position(|w| w.eq_ignore_ascii_case("AS")) {
                        if let Some(name) = words.get(pos + 1) {
                            if name.eq_ignore_ascii_case(t) {
                                return Some(sidx);
                            }
                        }
                    }
                }
            }
            None
        });
    let last_stage = target_stage.unwrap_or_else(|| stages.len().saturating_sub(1));

    let mut stage_states: HashMap<String, Stage> = HashMap::new(); // by AS name
    let mut final_chain: Vec<String> = Vec::new();
    let mut final_config = empty_config();

    let total = df.instructions.len();
    for (sidx, stage_indices) in stages.iter().enumerate() {
        let mut chain: Vec<String> = Vec::new();
        let mut config = empty_config();
        let mut stage_name: Option<String> = None;

        for &idx in stage_indices {
            let inst = &df.instructions[idx];
            let step = format!("Step {}/{} : {} {}\n", idx + 1, total, inst.verb, inst.args);
            send(&tx, ProgressMessage::stream(step)).await;
            let env = config.env_pairs();

            match inst.verb.as_str() {
                "FROM" => {
                    let words: Vec<String> = expand_vars(&inst.args, &env)
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    let base = words.first().cloned().unwrap_or_default();
                    stage_name = words
                        .windows(2)
                        .find(|w| w[0].eq_ignore_ascii_case("AS"))
                        .map(|w| w[1].clone());
                    if base == "scratch" {
                        chain.clear();
                        config = empty_config();
                    } else if let Some(prev) = stage_states.get(&base) {
                        chain = prev.chain.clone();
                        config = prev.config.clone();
                    } else {
                        let image_id = resolve_or_pull(&images, &registry, &base, &tx).await?;
                        let record = images
                            .load(&image_id)
                            .await?
                            .ok_or_else(|| anyhow!("image {base} not found after pull"))?;
                        chain = record.diff_ids.clone();
                        config = ConfigState::from_image_record(&record);
                    }
                }
                "RUN" => {
                    let argv = run_argv(inst, &env);
                    chain = run_layer(
                        &images, &paths, &tx, chain, argv, config.env_pairs(), config.workdir.clone(),
                        inst, &opts.context_dir, &opts,
                    )
                    .await?;
                }
                "COPY" | "ADD" => {
                    chain = copy_layer(
                        &images, &paths, &tx, chain, inst, &env, &opts,
                    )
                    .await?;
                }
                "ENV" => apply_env(&mut config, &expand_vars(&inst.args, &env)),
                "ARG" => {} // build args injected into env below
                "WORKDIR" => {
                    let wd = expand_vars(&inst.args, &env);
                    config.workdir = if wd.starts_with('/') {
                        wd
                    } else if config.workdir.is_empty() {
                        format!("/{wd}")
                    } else {
                        format!("{}/{}", config.workdir.trim_end_matches('/'), wd)
                    };
                }
                "USER" => config.user = expand_vars(&inst.args, &env),
                "LABEL" => {
                    for (k, v) in parse_key_values(&expand_vars(&inst.args, &env)) {
                        config.labels.insert(k, v);
                    }
                }
                "EXPOSE" => {
                    for p in inst.args.split_whitespace() {
                        let key = if p.contains('/') { p.to_string() } else { format!("{p}/tcp") };
                        config.exposed_ports.insert(key, serde_json::json!({}));
                    }
                }
                "VOLUME" => {
                    for v in parse_json_or_words(&inst.args) {
                        config.volumes.insert(v, serde_json::json!({}));
                    }
                }
                "STOPSIGNAL" => config.stop_signal = expand_vars(&inst.args, &env),
                "CMD" => {
                    config.cmd = Some(match &inst.json_args {
                        Some(j) => j.clone(),
                        None => vec!["/bin/sh".into(), "-c".into(), expand_vars(&inst.args, &env)],
                    });
                }
                "ENTRYPOINT" => {
                    config.entrypoint = Some(match &inst.json_args {
                        Some(j) => j.clone(),
                        None => vec!["/bin/sh".into(), "-c".into(), expand_vars(&inst.args, &env)],
                    });
                }
                "HEALTHCHECK" => {
                    config.healthcheck = parse_healthcheck(&inst.args);
                }
                "SHELL" | "MAINTAINER" | "ONBUILD" | "STOPSIGNAL_IGNORED" => {}
                other => {
                    send(&tx, ProgressMessage::stream(format!("Skipping unsupported instruction {other}\n"))).await;
                }
            }
        }
        if let Some(name) = stage_name {
            stage_states.insert(name.clone(), Stage { chain: chain.clone(), config: config.clone() });
        }
        if sidx == last_stage {
            final_chain = chain;
            final_config = config;
            break;
        }
    }
    // ---- final image: id = sha256(config json) ----
    let oci_config = serde_json::json!({
        "created": ingot_util::now_rfc3339(),
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Env": final_config.env.clone(),
            "Cmd": final_config.cmd.clone().unwrap_or_default(),
            "Entrypoint": final_config.entrypoint.clone(),
            "WorkingDir": final_config.workdir.clone(),
            "User": final_config.user.clone(),
            "Labels": final_config.labels.clone(),
            "ExposedPorts": if final_config.exposed_ports.is_empty() { serde_json::Value::Null } else { serde_json::json!(final_config.exposed_ports) },
            "Volumes": if final_config.volumes.is_empty() { serde_json::Value::Null } else { serde_json::json!(final_config.volumes) },
            "StopSignal": final_config.stop_signal.clone(),
            "Healthcheck": final_config.healthcheck.clone(),
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": final_chain.clone(),
        },
        "history": [],
    });
    let config_bytes = serde_json::to_vec_pretty(&oci_config)?;
    let image_id = sha256_hex(&config_bytes);
    std::fs::create_dir_all(paths.blobs())?;
    std::fs::write(paths.blob(&format!("sha256:{image_id}")), &config_bytes)?;

    let chain_ids = ImageRecord::compute_chain_ids(&final_chain);
    let size: i64 = final_chain
        .iter()
        .filter_map(|d| std::fs::metadata(paths.blob(d)).ok().map(|m| m.len() as i64))
        .sum();
    let record = ImageRecord {
        id: image_id.clone(),
        manifest_digest: String::new(),
        repo_tags: opts.tags.clone(),
        repo_digests: vec![],
        created: ingot_util::now_rfc3339(),
        created_unix: ingot_util::now_unix(),
        architecture: "amd64".into(),
        os: "linux".into(),
        author: String::new(),
        comment: String::new(),
        docker_version: format!("ingot/{}", ingot_api::ENGINE_VERSION),
        diff_ids: final_chain.clone(),
        layer_blobs: final_chain.iter().map(|d| blob_for_diff(&paths, d)).collect(),
        size,
        config: ingot_api::ContainerConfig {
            Hostname: String::new(),
            Domainname: String::new(),
            User: final_config.user.clone(),
            AttachStdin: false,
            AttachStdout: false,
            AttachStderr: false,
            ExposedPorts: if final_config.exposed_ports.is_empty() { None } else { Some(final_config.exposed_ports.clone()) },
            Tty: false,
            OpenStdin: false,
            StdinOnce: false,
            Env: final_config.env.clone(),
            Cmd: final_config.cmd.clone().unwrap_or_default(),
            Healthcheck: final_config.healthcheck.clone(),
            ArgsEscaped: false,
            Image: String::new(),
            Volumes: if final_config.volumes.is_empty() { None } else { Some(final_config.volumes.clone()) },
            WorkingDir: final_config.workdir.clone(),
            Entrypoint: final_config.entrypoint.clone(),
            OnBuild: None,
            Labels: final_config.labels.clone(),
            StopSignal: final_config.stop_signal.clone(),
            StopTimeout: None,
            Shell: None,
        },
        history: vec![],
        chain_ids,
    };

    let id = record.id.clone();
    if let Some(existing) = images.load(&id).await? {
        let mut merged = record;
        for t in existing.repo_tags {
            if !merged.repo_tags.contains(&t) {
                merged.repo_tags.push(t);
            }
        }
        images.put_image(&merged).await?;
    } else {
        images.put_image(&record).await?;
    }
    for t in &opts.tags {
        images.tag(&id, t).await?;
    }
    send(&tx, ProgressMessage::status(format!(
        "Successfully built {}",
        &id[..12]
    )))
    .await;
    send(&tx, ProgressMessage::stream(format!(
        "Successfully tagged {}\n",
        opts.tags.join(", ")
    )))
    .await;
    Ok(id)
}



async fn resolve_or_pull(
    images: &Arc<ingot_image::ImageStore>,
    registry: &Arc<ingot_registry::RegistryClient>,
    base: &str,
    tx: &BuildOutput,
) -> Result<String> {
    match images.resolve(base).await {
        Ok(id) => Ok(id),
        Err(_) => {
            send(tx, ProgressMessage::stream(format!("Pulling {base}...\n"))).await;
            let (pull_tx, mut rx) = mpsc::channel(64);
            let image_ref = ingot_registry::ImageRef::parse(base)?;
            let registry = registry.clone();
            let images2 = images.clone();
            let handle = tokio::spawn(async move {
                ingot_image::pull::pull(registry, images2, image_ref, None, pull_tx).await
            });
            while let Some(msg) = rx.recv().await {
                // Fold pull progress into build output as status lines.
                if let Some(status) = msg.status {
                    send(tx, ProgressMessage::stream(format!("  {status}\n"))).await;
                }
            }
            handle.await??;
            images.resolve(base).await.map_err(|e| anyhow!("{e:#}"))
        }
    }
}

fn run_argv(inst: &Instruction, env: &[(String, String)]) -> Vec<String> {
    match &inst.json_args {
        Some(j) => j.clone(),
        None => {
            let shell = env
                .iter()
                .find(|(k, _)| k == "SHELL")
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| "/bin/sh -c".into());
            let mut parts: Vec<String> = shell.split_whitespace().map(|s| s.to_string()).collect();
            let cmd = expand_vars(&inst.args, env);
            let mut heredoc_stdin = String::new();
            for h in &inst.heredocs {
                if h.target.is_empty() {
                    heredoc_stdin.push_str(&h.content);
                }
            }
            if !heredoc_stdin.is_empty() {
                parts.push(heredoc_stdin);
            } else {
                parts.push(cmd);
            }
            parts
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_layer(
    images: &Arc<ingot_image::ImageStore>,
    paths: &DataPaths,
    tx: &BuildOutput,
    chain: Vec<String>,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    workdir: String,
    inst: &Instruction,
    context_dir: &Path,
    opts: &BuildOptions,
) -> Result<Vec<String>> {
    let cache_key = {
        let mut h = sha256_hex(format!("{:?}|{:?}|{:?}", last_chain(chain.last()), inst.args, env).as_bytes());
        for hdoc in &inst.heredocs {
            h = sha256_hex(format!("{h}{}", hdoc.content).as_bytes());
        }
        format!("run-{h}")
    };
    if !opts.nocache {
        if let Some(diff) = cache_lookup(paths, &cache_key).await {
            if layer_exists(paths, &diff) {
                send(tx, ProgressMessage::stream(" ---> Using cache\n")).await;
                let mut c = chain;
                c.push(diff);
                return Ok(c);
            }
        }
    }

    let step_id = ingot_util::new_id()[..16].to_string();
    let work_root = paths.builder().join("steps").join(&step_id);
    std::fs::create_dir_all(&work_root)?;
    let lowers = top_first(&chain, paths);

    let binds = vec![(context_dir.to_path_buf(), "/.ingot-context".to_string())];
    let step_opts = ingot_runtime::step::StepOptions {
        lowerdirs: lowers,
        argv,
        env,
        workdir,
        work_root: work_root.clone(),
        context_root: context_dir.to_path_buf(),
        binds,
    };
    let step_opts = if opts.nocache || inst.flags.is_empty() {
        step_opts
    } else {
        step_opts
    };
    let (code, output) = {
        let paths = paths.clone();
        let step_opts = step_opts;
        let step_id = step_id.clone();
        tokio::task::spawn_blocking(move || {
            ingot_runtime::step::run_step(&paths, &step_id, step_opts)
        })
        .await
        .map_err(|e| anyhow!("join: {e}"))??
    };
    for line in output.lines() {
        send(tx, ProgressMessage::stream(format!("  {line}\n"))).await;
    }
    if code != 0 {
        return Err(anyhow!("command exited with {code}"));
    }

    let diff_dir = work_root.join("diff");
    let _ = std::fs::remove_dir_all(diff_dir.join(".ingot-context"));
    let (diff_id, _size) = commit_layer(paths, &diff_dir).await?;
    cache_store(paths, &cache_key, &diff_id).await;
    let _ = std::fs::remove_dir_all(&work_root);
    let mut c = chain;
    c.push(diff_id);
    Ok(c)
}

async fn copy_layer(
    images: &Arc<ingot_image::ImageStore>,
    paths: &DataPaths,
    tx: &BuildOutput,
    chain: Vec<String>,
    inst: &Instruction,
    env: &[(String, String)],
    opts: &BuildOptions,
) -> Result<Vec<String>> {
    let from = inst.flags.iter().find(|(k, _)| k == "from").map(|(_, v)| v.clone());
    let args = expand_vars(&inst.args, env);
    let mut words: Vec<&str> = args.split_whitespace().collect();
    let dest = words.pop().ok_or_else(|| anyhow!("COPY needs a destination"))?;
    let sources: Vec<String> = words.iter().map(|s| s.to_string()).collect();

    // Cache key includes source content hashes.
    let cache_key = {
        let mut h = sha256_hex(format!("copy|{}|{:?}|{:?}", args, from, last_chain(chain.last())).as_bytes());
        for src in &sources {
            h = sha256_hex(format!("{h}{}", hash_source(opts.context_dir.join(src))).as_bytes());
        }
        format!("copy-{h}")
    };
    if !opts.nocache {
        if let Some(diff) = cache_lookup(paths, &cache_key).await {
            if layer_exists(paths, &diff) {
                send(tx, ProgressMessage::stream(" ---> Using cache\n")).await;
                let mut c = chain;
                c.push(diff);
                return Ok(c);
            }
        }
    }

    let step_id = ingot_util::new_id()[..16].to_string();
    let diff_dir = paths.builder().join("steps").join(&step_id).join("diff");
    std::fs::create_dir_all(&diff_dir)?;
    let dest_is_dir = dest.ends_with('/') || sources.len() > 1;
    let target_dest = diff_dir.join(dest.trim_start_matches('/'));

    let mut resolved_sources: Vec<PathBuf> = Vec::new();
    if let Some(stage) = &from {
        // --from=<stage>: source files come from that stage's topmost layer.
        for src in &sources {
            let found = find_in_stage(layers_of_stage(images, stage).await?, src.trim_start_matches('/'));
            let found = found.ok_or_else(|| anyhow!("COPY --from={stage}: {src} not found"))?;
            resolved_sources.push(found);
        }
    } else {
        for src in &sources {
            let src_path = opts.context_dir.join(src);
            resolved_sources.push(src_path);
        }
    }

    for src in resolved_sources {
        if dest_is_dir {
            std::fs::create_dir_all(&target_dest)?;
            copy_into(&src, &target_dest)?;
        } else if src.is_file() {
            if let Some(parent) = target_dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&src, &target_dest)?;
        } else if src.is_dir() {
            copy_tree(&src, &target_dest)?;
        } else {
            copy_into(&src, &target_dest)?;
        }
    }

    let (diff_id, _size) = commit_layer(paths, &diff_dir).await?;
    cache_store(paths, &cache_key, &diff_id).await;
    let _ = std::fs::remove_dir_all(paths.builder().join("steps").join(&step_id));
    let mut c = chain;
    c.push(diff_id);
    Ok(c)
}

async fn layers_of_stage(_images: &Arc<ingot_image::ImageStore>, _stage: &str) -> Result<Vec<PathBuf>> {
    // Multi-stage COPY --from uses in-memory state; simplified: search all
    // layers (top-first reverse chronological). Adequate for common cases.
    let mut dirs = Vec::new();
    let root = PathBuf::from("/var/lib/ingot/layers");
    let mut entries: Vec<_> = std::fs::read_dir(&root)?
        .flatten()
        .collect();
    entries.sort_by_key(|e| {
        std::fs::metadata(e.path())
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });
    for e in entries {
        dirs.push(e.path());
    }
    dirs.reverse();
    Ok(dirs)
}

fn find_in_stage(layer_dirs: Vec<PathBuf>, rel: &str) -> Option<PathBuf> {
    for dir in layer_dirs {
        let candidate = dir.join(rel);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn copy_into(src: &Path, dest_dir: &Path) -> Result<()> {
    if src.is_dir() {
        copy_tree(src, dest_dir)?;
    } else if src.is_file() {
        std::fs::create_dir_all(dest_dir)?;
        let name = src.file_name().ok_or_else(|| anyhow!("bad source name"))?;
        std::fs::copy(src, dest_dir.join(name))?;
    } else {
        // Glob support
        let pattern = src.to_string_lossy().to_string();
        let matches: Vec<_> = glob::glob(&pattern)
            .map_err(|e| anyhow!("bad glob {pattern}: {e}"))?
            .flatten()
            .collect();
        if matches.is_empty() {
            return Err(anyhow!("COPY source {src:?} not found"));
        }
        for m in matches {
            copy_into(&m, dest_dir)?;
        }
    }
    Ok(())
}

fn copy_tree(src: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in walkdir::WalkDir::new(src).follow_links(false) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(src)?;
        let target = dest.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            std::fs::copy(entry.path(), &target)?;
        } else if entry.file_type().is_symlink() {
            let target_link = std::fs::read_link(entry.path())?;
            let _ = std::os::unix::fs::symlink(target_link, &target);
        }
    }
    Ok(())
}

fn hash_source(p: PathBuf) -> String {
    if p.is_file() {
        match std::fs::read(&p) {
            Ok(b) => sha256_hex(&b),
            Err(_) => "missing".into(),
        }
    } else if p.is_dir() {
        let mut acc = String::new();
        let mut entries: Vec<_> = walkdir::WalkDir::new(&p)
            .sort_by_file_name()
            .into_iter()
            .flatten()
            .collect();
        entries.sort_by_key(|e| e.path().to_path_buf());
        for e in entries {
            if e.file_type().is_file() {
                acc.push_str(&e.path().to_string_lossy());
                if let Ok(b) = std::fs::read(e.path()) {
                    acc.push_str(&sha256_hex(&b));
                }
            }
        }
        sha256_hex(acc.as_bytes())
    } else {
        "missing".into()
    }
}

/// Tar + gzip a diff dir into the blob store; returns (diffID, size).
async fn commit_layer(paths: &DataPaths, diff_dir: &Path) -> Result<(String, i64)> {
    let tmp = paths.builder().join(format!("commit-{}.tar.gz", ingot_util::new_id()[..12].to_string()));
    let gz = flate2::write::GzEncoder::new(std::fs::File::create(&tmp)?, flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    tar.append_dir_all(".", diff_dir)?;
    tar.finish()?;
    let gz = tar.into_inner()?;
    gz.finish()?;
    let compressed = std::fs::read(&tmp)?;

    // diffID = sha256 of the UNcompressed tar.
    let gz2 = flate2::read::GzDecoder::new(std::fs::File::open(&tmp)?);
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 128 * 1024];
    let mut f = gz2;
    loop {
        use std::io::Read;
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let diff_id = format!("sha256:{}", hex::encode(hasher.finalize()));

    let hex = diff_id.trim_start_matches("sha256:").to_string();
    std::fs::create_dir_all(paths.blobs())?;
    std::fs::write(paths.blob(&diff_id), &compressed)?;
    // Unpack into the layer store.
    let layer_dest = paths.layers().join(&hex);
    ingot_image::unpack_layer_dir(&tmp, &layer_dest, "application/vnd.docker.image.rootfs.diff.tar.gzip")?;
    let _ = std::fs::write(layer_dest.join(".ingot-unpacked"), "ok");
    let _ = std::fs::remove_file(&tmp);
    let size = compressed.len() as i64;
    Ok((diff_id, size))
}

fn blob_for_diff(paths: &DataPaths, diff_id: &str) -> String {
    // The builder stores the compressed blob at the diffID key.
    diff_id.to_string()
}

fn top_first(chain: &[String], paths: &DataPaths) -> Vec<String> {
    chain
        .iter()
        .rev()
        .map(|d| paths.layers().join(d.trim_start_matches("sha256:")).to_string_lossy().to_string())
        .collect()
}

fn last_chain(last: Option<&String>) -> String {
    last.cloned().unwrap_or_default()
}

async fn cache_lookup(paths: &DataPaths, key: &str) -> Option<String> {
    let cache: HashMap<String, CacheEntry> = std::fs::read(paths.build_cache())
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default();
    cache.get(key).map(|e| e.diff_id.clone())
}

async fn cache_store(paths: &DataPaths, key: &str, diff_id: &str) {
    let mut cache: HashMap<String, CacheEntry> = std::fs::read(paths.build_cache())
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default();
    cache.insert(key.to_string(), CacheEntry { diff_id: diff_id.to_string() });
    let _ = ingot_store::write_json_atomic(&paths.build_cache(), &cache);
}

fn layer_exists(paths: &DataPaths, diff_id: &str) -> bool {
    let p = paths.layers().join(diff_id.trim_start_matches("sha256:"));
    p.join(".ingot-unpacked").exists() || p.is_dir()
}

fn apply_env(config: &mut ConfigState, args: &str) {
    // ENV k=v or ENV k v
    let trimmed = args.trim();
    if let Some((k, v)) = trimmed.split_once('=') {
        set_env(config, k.trim(), v.trim().trim_matches('"'));
    } else if let Some((k, v)) = trimmed.split_once(char::is_whitespace) {
        set_env(config, k.trim(), v.trim().trim_matches('"'));
    }
}

fn set_env(config: &mut ConfigState, k: &str, v: &str) {
    let entry = format!("{k}={v}");
    config.env.retain(|e| !e.starts_with(&format!("{k}=")));
    config.env.push(entry);
}

fn parse_key_values(args: &str) -> Vec<(String, String)> {
    // Handles k=v pairs and "k"="v with spaces"
    let mut out = Vec::new();
    let mut parts = args.split_whitespace().peekable();
    while let Some(p) = parts.next() {
        if let Some((k, v)) = p.split_once('=') {
            let mut val = v.to_string();
            if val.starts_with('"') && !val.ends_with('"') {
                while let Some(next) = parts.next() {
                    val.push(' ');
                    val.push_str(next);
                    if next.ends_with('"') {
                        break;
                    }
                }
            }
            out.push((k.to_string(), val.trim_matches('"').to_string()));
        }
    }
    out
}

fn parse_json_or_words(args: &str) -> Vec<String> {
    if let Some(j) = crate::parser::parse_json_form(args) {
        return j;
    }
    args.split_whitespace().map(|s| s.to_string()).collect()
}

fn parse_healthcheck(args: &str) -> Option<ingot_api::HealthConfig> {
    let upper = args.trim();
    if upper.starts_with("NONE") {
        return Some(ingot_api::HealthConfig { Test: vec!["NONE".into()], ..Default::default() });
    }
    // HEALTHCHECK [--interval=...] CMD ...
    let cmd_idx = args.find("CMD")?;
    let mut cfg = ingot_api::HealthConfig::default();
    for part in args[..cmd_idx].split_whitespace() {
        if let Some((k, v)) = part.strip_prefix("--").and_then(|s| s.split_once('=')) {
            let dur = v.trim_end_matches('s').parse::<i64>().unwrap_or(0) * 1_000_000_000;
            match k {
                "interval" => cfg.Interval = Some(dur),
                "timeout" => cfg.Timeout = Some(dur),
                "retries" => cfg.Retries = v.parse().ok(),
                "start-period" => cfg.StartPeriod = Some(dur),
                _ => {}
            }
        }
    }
    let cmd = args[cmd_idx..].trim().strip_prefix("CMD")?.trim();
    cfg.Test = crate::parser::parse_json_form(cmd)
        .unwrap_or_else(|| vec!["CMD-SHELL".into(), cmd.to_string()]);
    Some(cfg)
}

async fn send(tx: &BuildOutput, msg: ProgressMessage) {
    let _ = tx.send(msg).await;
}
