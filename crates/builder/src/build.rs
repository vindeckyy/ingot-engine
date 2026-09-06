//! The classic builder: per-instruction layers, config accumulation,
//! chainID-keyed cache, multi-stage support.

use crate::parser::{expand_vars, parse, Instruction};
use anyhow::{anyhow, Result};
use ingot_api::ProgressMessage;
use ingot_image::store::ImageRecord;
use ingot_store::paths::DataPaths;
use ingot_util::digest::sha256_hex;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
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
    /// Stage selectors (index or AS name) whose cache is bypassed, plus
    /// every later stage: buildx-style selective invalidation.
    pub no_cache_filter: Vec<String>,
}

pub type BuildOutput = mpsc::Sender<ProgressMessage>;

/// Default (empty) image config used when the builder starts from scratch.
/// Parse an ARG declaration (`name` or `name=default`) into its name and
/// optional default. The default is literal: Docker expands it against
/// nothing at declaration time.
fn parse_arg_decl(s: &str) -> anyhow::Result<(String, Option<String>)> {
    let s = s.trim();
    let (name, default) = match s.split_once('=') {
        Some((n, v)) => (n.trim().to_string(), Some(v.trim().to_string())),
        None => (s.to_string(), None),
    };
    if name.is_empty() || name.contains(char::is_whitespace) {
        anyhow::bail!("invalid ARG declaration {s:?}");
    }
    Ok((name, default))
}

/// Resolve one in-stage ARG declaration to its effective value: an
/// explicit `--build-arg` wins; a bare re-declaration inherits the global
/// value; otherwise the declaration default applies; unset means empty.
fn resolve_stage_arg(
    name: &str,
    default: Option<String>,
    build_args: &HashMap<String, String>,
    globals: &HashMap<String, String>,
) -> Option<String> {
    build_args.get(name).cloned().or_else(|| match default {
        Some(d) => Some(d),
        None => globals.get(name).cloned(),
    })
}

/// Expansion scope for one stage instruction: stage ENV first, then
/// in-scope stage ARG values (first match wins in expand_vars, so ENV
/// shadows ARG per Docker precedence). Pre-FROM globals are NOT in this
/// scope: they are visible to FROM lines (expanded separately) and to a
/// stage only after an explicit `ARG name` re-declaration, which copies
/// the resolved value into the stage map.
/// Expansion scope for one stage instruction. `expand_vars` takes the
/// FIRST binding for a name, so layer order is precedence order: stage
/// ENV beats in-scope stage ARGs beats pre-FROM global ARGs. A declared
/// but value-less entry (`None`) stays out of the scope entirely so it
/// expands to empty instead of leaking a stale value.
fn merge_scope(
    env: &[(String, String)],
    stage: &HashMap<String, Option<String>>,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = env.to_vec();
    for (k, v) in stage {
        if !out.iter().any(|(ek, _)| ek == k) {
            if let Some(v) = v {
                out.push((k.clone(), v.clone()));
            }
        }
    }
    out
}

fn empty_config() -> ConfigState {
    ConfigState::default()
}

fn default_shell() -> Vec<String> {
    vec!["/bin/sh".to_string(), "-c".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigState {
    #[serde(default)]
    pub env: Vec<String>,
    /// Default shell for shell-form RUN (set by the SHELL instruction,
    /// reset every stage — never taken from an ENV variable).
    #[serde(default = "default_shell")]
    pub shell: Vec<String>,
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

impl Default for ConfigState {
    fn default() -> Self {
        ConfigState {
            env: Vec::new(),
            // A fresh stage starts on the default shell; only the SHELL
            // instruction changes it (mirrors Docker's per-stage reset).
            shell: default_shell(),
            cmd: None,
            entrypoint: None,
            workdir: String::new(),
            user: String::new(),
            labels: HashMap::new(),
            exposed_ports: HashMap::new(),
            volumes: HashMap::new(),
            stop_signal: String::new(),
            healthcheck: None,
        }
    }
}

impl ConfigState {
    fn from_image_record(r: &ImageRecord) -> Self {
        ConfigState {
            env: r.config.Env.clone(),
            // A new stage resets the shell even when inheriting the rest
            // of the base image's config.
            shell: default_shell(),
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
            .filter_map(|e| {
                e.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CacheEntry {
    diff_id: String,
    /// Compressed blob digest for the diff. None for entries written
    /// before blobs were named correctly; those fall back to the diff id.
    #[serde(default)]
    blob_digest: Option<String>,
    /// Fingerprint of the layer dir at commit time. None for entries
    /// written before fingerprints existed; those skip tamper checks.
    #[serde(default)]
    layer_fingerprint: Option<String>,
}

/// Cheap tamper tripwire for a cached layer dir: relative paths plus
/// sizes, mtimes, modes, and link targets. Any add, remove, resize,
/// retouch, chmod, or relink changes it. Deliberately not a content
/// hash — re-tarring the layer on every hit would cost the build the
/// cache is meant to save.
fn layer_fingerprint(paths: &DataPaths, diff_id: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    let dir = paths.layers().join(diff_id.trim_start_matches("sha256:"));
    let mut acc = String::new();
    let mut entries: Vec<_> = walkdir::WalkDir::new(&dir)
        .sort_by_file_name()
        .into_iter()
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.path().to_path_buf());
    for e in entries {
        let rel = e.path().strip_prefix(&dir).unwrap_or(e.path());
        acc.push_str(&rel.to_string_lossy());
        acc.push('\0');
        match e.metadata() {
            Ok(m) => {
                let mtime = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| format!("{}.{}", d.as_secs(), d.subsec_nanos()))
                    .unwrap_or_default();
                acc.push_str(&format!("{}|{mtime}|{:o};", m.len(), m.mode()));
            }
            Err(_) => acc.push_str("unreadable;"),
        }
        if e.file_type().is_symlink() {
            if let Ok(t) = std::fs::read_link(e.path()) {
                acc.push_str(&t.to_string_lossy());
                acc.push(';');
            }
        }
    }
    sha256_hex(acc.as_bytes())
}

/// Validate a cache hit: the blob file must still exist (a blob GC'd
/// while its dir survived would otherwise mint records pointing at a
/// missing blob) and the layer dir must be present and unchanged since
/// commit (tamper safety). Anything off falls through to recommit,
/// which heals both the layer and the cache record.
fn cache_hit_valid(paths: &DataPaths, hit: &CacheEntry) -> bool {
    let blob = hit
        .blob_digest
        .clone()
        .unwrap_or_else(|| hit.diff_id.clone());
    if !layer_exists(paths, &hit.diff_id) || !paths.blob(&blob).exists() {
        return false;
    }
    match &hit.layer_fingerprint {
        None => true, // legacy entries predate fingerprints
        Some(fp) => layer_fingerprint(paths, &hit.diff_id) == *fp,
    }
}

/// The running state of a stage while building.
struct Stage {
    /// base-first diff ids of the current chain.
    chain: Vec<String>,
    /// Parallel compressed-blob digests, same order and length as chain.
    /// Base entries are the base record's own layer_blobs; committed
    /// layers carry their real compressed digest.
    blobs: Vec<String>,
    config: ConfigState,
}

/// Resolve a stage selector (index or AS name, case-insensitive) to a
/// stage position. Shared by `--target` and `--no-cache-filter` so both
/// spellings agree on what a stage is called.
fn resolve_stage_index(
    stages: &[Vec<usize>],
    instructions: &[Instruction],
    sel: &str,
) -> Option<usize> {
    let t = sel.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(idx) = t.parse::<usize>() {
        if idx < stages.len() {
            return Some(idx);
        }
    }
    for (sidx, stage_indices) in stages.iter().enumerate() {
        if let Some(&first_idx) = stage_indices.first() {
            let inst = &instructions[first_idx];
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
}

/// Cache key for a RUN step. Every input that can change the step's
/// output must be here: parent chain, raw instruction, effective
/// environment (ENV + in-scope ARGs), shell, working directory, and
/// user. A missing input is a wrong cache hit, never just a miss.
fn run_cache_key(
    last: Option<&String>,
    inst: &Instruction,
    env: &[(String, String)],
    shell: &[String],
    workdir: &str,
    user: &str,
    mounts: &str,
) -> String {
    // The shell is part of the step's meaning: changing SHELL must
    // not hit a cache entry computed under another shell. Mount
    // DECLARATIONS join the key; secret VALUES never do.
    let mut h = sha256_hex(
        format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            last_chain(last),
            inst.args,
            env,
            shell,
            workdir,
            user,
            mounts
        )
        .as_bytes(),
    );
    for hdoc in &inst.heredocs {
        h = sha256_hex(format!("{h}{}", hdoc.content).as_bytes());
    }
    format!("run-{h}")
}

/// Cache key for a COPY/ADD step: expanded instruction, parent chain,
/// resolved ownership/mode, and one content hash per source (context
/// files or `--from` stage content — never the stage NAME alone, which
/// can point at new bytes).
fn copy_cache_key(
    args: &str,
    from: &Option<String>,
    last: Option<&String>,
    source_hashes: &[String],
    ownership: &str,
) -> String {
    let mut h =
        sha256_hex(format!("copy|{args}|{from:?}|{ownership}|{:?}", last_chain(last)).as_bytes());
    for s in source_hashes {
        h = sha256_hex(format!("{h}{s}").as_bytes());
    }
    format!("copy-{h}")
}

pub async fn build_image(
    images: Arc<ingot_image::ImageStore>,
    registry: Arc<ingot_registry::RegistryClient>,
    paths: DataPaths,
    opts: BuildOptions,
    secrets: HashMap<String, String>,
    tx: BuildOutput,
) -> Result<String> {
    send(
        &tx,
        ProgressMessage::stream("Step 0 : parsing Dockerfile\n".to_string()),
    )
    .await;
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
        .and_then(|t| resolve_stage_index(&stages, &df.instructions, t));
    let last_stage = target_stage.unwrap_or_else(|| stages.len().saturating_sub(1));
    // Selective invalidation: the earliest filtered stage and everything
    // after it bypass cache lookup (results are still stored).
    let bust_start: Option<usize> = opts
        .no_cache_filter
        .iter()
        .filter_map(|f| resolve_stage_index(&stages, &df.instructions, f))
        .min();

    // Global ARG declarations (before the first FROM): effective values
    // resolve build-arg overrides over literal defaults. Unset names stay
    // absent and expand to empty.
    let mut globals: HashMap<String, String> = HashMap::new();
    let mut declared_args: HashSet<String> = HashSet::new();
    {
        let mut seen_from = false;
        for inst in &df.instructions {
            if inst.verb == "FROM" {
                seen_from = true;
                continue;
            }
            if seen_from || inst.verb != "ARG" {
                continue;
            }
            let (name, default) = parse_arg_decl(&inst.args)?;
            declared_args.insert(name.clone());
            // Explicitly empty still counts as set; fully unset stays out
            // (expands to empty).
            match (opts.build_args.get(&name).cloned(), default) {
                (Some(v), _) | (None, Some(v)) => {
                    globals.insert(name, v);
                }
                (None, None) => {}
            }
        }
    }
    let global_pairs: Vec<(String, String)> = globals
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let mut stage_states: HashMap<String, Stage> = HashMap::new(); // by AS name
                                                                   // Completed stage chains in build order (for COPY --from=<index>).
    let mut completed_chains: Vec<Vec<String>> = Vec::new();
    let mut final_chain: Vec<String> = Vec::new();
    let mut final_blobs: Vec<String> = Vec::new();
    let mut final_config = empty_config();

    let total = df.instructions.len();
    for (sidx, stage_indices) in stages.iter().enumerate() {
        let mut chain: Vec<String> = Vec::new();
        let mut blobs: Vec<String> = Vec::new();
        let mut config = empty_config();
        // In-stage ARG scope: fresh every stage, seeded only by explicit
        // re-declaration (a bare `ARG name` inherits the global value).
        let mut stage_args: HashMap<String, Option<String>> = HashMap::new();
        let mut stage_name: Option<String> = None;

        for &idx in stage_indices {
            let inst = &df.instructions[idx];
            let step = format!("Step {}/{} : {} {}\n", idx + 1, total, inst.verb, inst.args);
            send(&tx, ProgressMessage::stream(step)).await;
            let env = config.env_pairs();
            // Expansion scope for this instruction: stage ENV shadowing
            // in-scope ARGs. FROM lines have no stage yet and expand
            // against the globals only.
            let scope = merge_scope(&env, &stage_args);
            match inst.verb.as_str() {
                "FROM" => {
                    let words: Vec<String> = expand_vars(&inst.args, &global_pairs)
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
                        blobs.clear();
                        config = empty_config();
                    } else if let Some(prev) = stage_states.get(&base) {
                        chain = prev.chain.clone();
                        blobs = prev.blobs.clone();
                        config = prev.config.clone();
                    } else {
                        let image_id = resolve_or_pull(&images, &registry, &base, &tx).await?;
                        let record = images
                            .load(&image_id)
                            .await?
                            .ok_or_else(|| anyhow!("image {base} not found after pull"))?;
                        chain = record.diff_ids.clone();
                        // Inherit the base record's own blob mapping (its
                        // pulled layers carry real compressed digests; its
                        // built layers are content-addressed as stored).
                        blobs = record.layer_blobs.clone();
                        config = ConfigState::from_image_record(&record);
                    }
                }
                "RUN" => {
                    let argv = run_argv(inst, &scope, &config.shell);
                    let bust = bust_start.is_some_and(|b| sidx >= b);
                    (chain, blobs) = run_layer(
                        &images,
                        &paths,
                        &tx,
                        chain,
                        blobs,
                        argv,
                        config.shell.clone(),
                        scope.clone(),
                        config.workdir.clone(),
                        config.user.clone(),
                        inst,
                        &opts.context_dir,
                        &secrets,
                        bust,
                        &opts,
                    )
                    .await?;
                }
                "COPY" | "ADD" => {
                    let bust = bust_start.is_some_and(|b| sidx >= b);
                    let stages = FromStages {
                        named: &stage_states,
                        ordered: &completed_chains,
                    };
                    (chain, blobs) = copy_layer(
                        &paths, &tx, chain, blobs, inst, &scope, &stages, bust, &opts,
                    )
                    .await?;
                }
                "ENV" => apply_env(&mut config, &expand_vars(&inst.args, &scope)),
                "ARG" => {
                    let (name, default) = parse_arg_decl(&inst.args)?;
                    declared_args.insert(name.clone());
                    let value = resolve_stage_arg(&name, default, &opts.build_args, &globals);
                    stage_args.insert(name, value);
                }
                "WORKDIR" => {
                    let wd = expand_vars(&inst.args, &scope);
                    config.workdir = if wd.starts_with('/') {
                        wd
                    } else if config.workdir.is_empty() {
                        format!("/{wd}")
                    } else {
                        format!("{}/{}", config.workdir.trim_end_matches('/'), wd)
                    };
                }
                "USER" => config.user = expand_vars(&inst.args, &scope),
                "LABEL" => {
                    for (k, v) in parse_key_values(&expand_vars(&inst.args, &scope)) {
                        config.labels.insert(k, v);
                    }
                }
                "EXPOSE" => {
                    for p in inst.args.split_whitespace() {
                        let key = if p.contains('/') {
                            p.to_string()
                        } else {
                            format!("{p}/tcp")
                        };
                        config.exposed_ports.insert(key, serde_json::json!({}));
                    }
                }
                "VOLUME" => {
                    for v in parse_json_or_words(&inst.args) {
                        config.volumes.insert(v, serde_json::json!({}));
                    }
                }
                "STOPSIGNAL" => config.stop_signal = expand_vars(&inst.args, &scope),
                "CMD" => {
                    config.cmd = Some(match &inst.json_args {
                        Some(j) => j.clone(),
                        None => vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            expand_vars(&inst.args, &scope),
                        ],
                    });
                }
                "ENTRYPOINT" => {
                    config.entrypoint = Some(match &inst.json_args {
                        Some(j) => j.clone(),
                        None => vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            expand_vars(&inst.args, &scope),
                        ],
                    });
                }
                "HEALTHCHECK" => {
                    config.healthcheck = parse_healthcheck(&inst.args);
                }
                "SHELL" => match &inst.json_args {
                    Some(argv) if !argv.is_empty() => config.shell = argv.clone(),
                    _ => anyhow::bail!(
                        "SHELL requires JSON-array form (e.g. SHELL [\"/bin/sh\", \"-c\"])"
                    ),
                },
                "MAINTAINER" => {
                    send(
                        &tx,
                        ProgressMessage::stream(
                            "Warning: MAINTAINER is deprecated and ignored; use LABEL instead\n",
                        ),
                    )
                    .await;
                }
                "ONBUILD" => {
                    send(
                        &tx,
                        ProgressMessage::stream(
                            "Warning: ONBUILD triggers are not stored or fired by this builder; the instruction is ignored\n",
                        ),
                    )
                    .await;
                }
                other => {
                    send(
                        &tx,
                        ProgressMessage::stream(format!(
                            "Skipping unsupported instruction {other}\n"
                        )),
                    )
                    .await;
                }
            }
        }
        if let Some(name) = stage_name {
            stage_states.insert(
                name.clone(),
                Stage {
                    chain: chain.clone(),
                    blobs: blobs.clone(),
                    config: config.clone(),
                },
            );
        }
        completed_chains.push(chain.clone());
        if sidx == last_stage {
            final_chain = chain;
            final_blobs = blobs;
            final_config = config;
            break;
        }
    }
    // Unconsumed build-args warn, like Docker's "[Warning] One or more
    // build-args were not consumed". Persisting stale values into the image
    // env would leak secrets into `inspect`, so set values must either be
    // declared by an ARG (in which case they were promoted into scope) or
    // be flagged here.
    for name in opts.build_args.keys() {
        if !declared_args.contains(name) {
            send(
                &tx,
                ProgressMessage::stream(format!(
                    "[Warning] One or more build-args were not consumed: [{name}]\n"
                )),
            )
            .await;
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
    // Size over the blob chain: pulled base layers (real compressed
    // digests) and committed layers (named by their bytes) all count now.
    // Unpacked-only entries (pre-existing builder bases) have no file and
    // are skipped, as before.
    let size: i64 = final_blobs
        .iter()
        .filter_map(|d| {
            std::fs::metadata(paths.blob(d))
                .ok()
                .map(|m| m.len() as i64)
        })
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
        layer_blobs: final_blobs.clone(),
        size,
        config: ingot_api::ContainerConfig {
            Hostname: String::new(),
            Domainname: String::new(),
            User: final_config.user.clone(),
            AttachStdin: false,
            AttachStdout: false,
            AttachStderr: false,
            ExposedPorts: if final_config.exposed_ports.is_empty() {
                None
            } else {
                Some(final_config.exposed_ports.clone())
            },
            Tty: false,
            OpenStdin: false,
            StdinOnce: false,
            Env: final_config.env.clone(),
            Cmd: final_config.cmd.clone().unwrap_or_default(),
            Healthcheck: final_config.healthcheck.clone(),
            ArgsEscaped: false,
            Image: String::new(),
            Volumes: if final_config.volumes.is_empty() {
                None
            } else {
                Some(final_config.volumes.clone())
            },
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

    // Shared merge rule (see ImageStore::put_image_merged): union tags and
    // digests, keep a stored manifest digest a rebuild lacks.
    let id = record.id.clone();
    images.put_image_merged(&record).await?;
    for t in &opts.tags {
        images.tag(&id, t).await?;
    }
    send(
        &tx,
        ProgressMessage::status(format!("Successfully built {}", &id[..12])),
    )
    .await;
    send(
        &tx,
        ProgressMessage::stream(format!("Successfully tagged {}\n", opts.tags.join(", "))),
    )
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
                ingot_image::pull::pull(registry, images2, image_ref, None, None, pull_tx).await
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

fn run_argv(inst: &Instruction, env: &[(String, String)], shell: &[String]) -> Vec<String> {
    match &inst.json_args {
        Some(j) => j.clone(),
        None => {
            let mut parts: Vec<String> = shell.to_vec();
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
/// Append one committed layer; returns (diff chain, blob chain) in lockstep.
async fn run_layer(
    _images: &Arc<ingot_image::ImageStore>,
    paths: &DataPaths,
    tx: &BuildOutput,
    chain: Vec<String>,
    blobs: Vec<String>,
    argv: Vec<String>,
    shell: Vec<String>,
    env: Vec<(String, String)>,
    workdir: String,
    user: String,
    inst: &Instruction,
    context_dir: &Path,
    secrets: &HashMap<String, String>,
    bust: bool,
    opts: &BuildOptions,
) -> Result<(Vec<String>, Vec<String>)> {
    // Secret mounts resolve here: declarations join the key, values
    // never do (and never reach progress output either).
    let (mount_key, secret_mounts) = resolve_secret_mounts(&parse_secret_mounts(inst)?, secrets)?;
    let cache_key = run_cache_key(
        chain.last(),
        inst,
        &env,
        &shell,
        &workdir,
        &user,
        &mount_key,
    );
    if !opts.nocache && !bust {
        if let Some(hit) = cache_lookup(paths, &cache_key).await {
            if cache_hit_valid(paths, &hit) {
                send(tx, ProgressMessage::stream(" ---> Using cache\n")).await;
                let mut c = chain;
                let mut b = blobs;
                b.push(
                    hit.blob_digest
                        .clone()
                        .unwrap_or_else(|| hit.diff_id.clone()),
                );
                c.push(hit.diff_id);
                return Ok((c, b));
            }
        }
    }

    let step_id = ingot_util::new_id()[..16].to_string();
    let work_root = paths.builder().join("steps").join(&step_id);
    std::fs::create_dir_all(&work_root)?;
    let _step_guard = StepGuard {
        root: work_root.clone(),
    };
    let lowers = top_first(&chain, paths);

    // Materialize secret values as root-only files OUTSIDE the diff dir
    // (they can never be committed into the layer) and bind them
    // read-only. work_root is removed after the step either way.
    let mut binds_ro: Vec<(PathBuf, String)> = Vec::with_capacity(secret_mounts.len());
    if !secret_mounts.is_empty() {
        use std::os::unix::fs::PermissionsExt;
        let secrets_dir = work_root.join("secrets");
        std::fs::create_dir_all(&secrets_dir)?;
        for (n, s) in secret_mounts.iter().enumerate() {
            let file = secrets_dir.join(format!("secret-{n}"));
            std::fs::write(&file, &s.value)?;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(s.mode))?;
            binds_ro.push((file, s.target.clone()));
        }
    }

    let binds = vec![(context_dir.to_path_buf(), "/.ingot-context".to_string())];
    let step_opts = ingot_runtime::step::StepOptions {
        lowerdirs: lowers,
        argv,
        env,
        workdir,
        work_root: work_root.clone(),
        context_root: context_dir.to_path_buf(),
        binds,
        binds_ro,
    };
    let (code, output) = {
        let paths = paths.clone();
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
    let (diff_id, blob_digest, _size) = commit_layer(paths, &diff_dir).await?;
    let fingerprint = layer_fingerprint(paths, &diff_id);
    cache_store(paths, &cache_key, &diff_id, &blob_digest, Some(fingerprint)).await;
    let _ = std::fs::remove_dir_all(&work_root);
    let mut c = chain;
    let mut b = blobs;
    c.push(diff_id);
    b.push(blob_digest);
    Ok((c, b))
}

/// Resolved ownership/mode flags for one COPY/ADD step (numeric
/// already: name lookups happen before the cache key so the key stays
/// stable across machines).
#[derive(Default)]
struct CopyOwnership {
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
}

impl CopyOwnership {
    fn is_none(&self) -> bool {
        self.uid.is_none() && self.gid.is_none() && self.mode.is_none()
    }

    fn key_part(&self) -> String {
        format!("{:?}:{:?}:{:?}", self.uid, self.gid, self.mode)
    }
}

/// Resolve one --chown id: a decimal uid/gid, or a name looked up in the
/// image under construction (its base layers, top-first).
fn resolve_copy_id(spec: &str, rootfs_dirs: &[PathBuf], is_user: bool) -> Result<u32> {
    let what = if is_user { "user" } else { "group" };
    if let Ok(n) = spec.parse::<u32>() {
        return Ok(n);
    }
    if spec.is_empty() || spec.contains('/') {
        anyhow::bail!("COPY --chown: invalid {what} {spec:?}");
    }
    let file = if is_user { "etc/passwd" } else { "etc/group" };
    for dir in rootfs_dirs {
        if let Ok(text) = std::fs::read_to_string(dir.join(file)) {
            for line in text.lines() {
                let mut f = line.split(':');
                match (f.next(), f.next(), f.next()) {
                    (Some(name), _, Some(id)) if name == spec => {
                        return id
                            .parse::<u32>()
                            .map_err(|_| anyhow!("COPY --chown: bad {what} id for {spec:?}"));
                    }
                    _ => {}
                }
            }
        }
    }
    anyhow::bail!("COPY --chown: unknown {what} {spec:?} (use a numeric id or a name from the image's /etc/{})", if is_user { "passwd" } else { "group" })
}

/// Parse --chown/--chmod flags. `--chown=user[:group]` (ids or names),
/// `--chmod=mode` (octal only, e.g. 755). Anything else is an explicit
/// error, never a silent ignore.
fn parse_copy_ownership(
    flags: &[(String, String)],
    rootfs_dirs: &[PathBuf],
) -> Result<CopyOwnership> {
    let raw = |name: &str| {
        flags
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let mut out = CopyOwnership::default();
    if let Some(spec) = raw("chown") {
        let (user, group) = match spec.split_once(':') {
            Some((u, g)) => (u, Some(g)),
            None => (spec.as_str(), None),
        };
        if user.is_empty() {
            anyhow::bail!("COPY --chown: missing user in {spec:?}");
        }
        out.uid = Some(resolve_copy_id(user, rootfs_dirs, true)?);
        if let Some(g) = group {
            if !g.is_empty() {
                out.gid = Some(resolve_copy_id(g, rootfs_dirs, false)?);
            }
        }
    }
    if let Some(spec) = raw("chmod") {
        let digits = spec.trim_start_matches('0');
        let digits = if digits.is_empty() { "0" } else { digits };
        if digits.len() > 4 || !digits.chars().all(|c| ('0'..='7').contains(&c)) {
            anyhow::bail!("COPY --chmod: expected an octal mode (e.g. 755), got {spec:?}");
        }
        out.mode = Some(
            u32::from_str_radix(digits, 8)
                .map_err(|_| anyhow!("COPY --chmod: bad mode {spec:?}"))?,
        );
    }
    Ok(out)
}

/// Apply resolved ownership/mode under `root` (fresh diff dir: everything
/// beneath it was copied by this step). Symlinks are relinked, never
/// followed: chmod skips them (no-op on Linux anyway), chown uses lchown.
fn apply_copy_ownership(root: &Path, own: &CopyOwnership) -> Result<()> {
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        let p = entry.path();
        let is_link = entry.file_type().is_symlink();
        if let Some(mode) = own.mode {
            if !is_link {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))?;
            }
        }
        if own.uid.is_some() || own.gid.is_some() {
            let path = std::ffi::CString::new(p.as_os_str().as_encoded_bytes())
                .map_err(|e| anyhow!("bad path for chown: {e}"))?;
            let uid = own.uid.unwrap_or(u32::MAX);
            let gid = own.gid.unwrap_or(u32::MAX);
            // u32::MAX == (uid_t)-1: "unchanged" for chown/lchown.
            let rc = if is_link {
                unsafe { libc::lchown(path.as_ptr(), uid, gid) }
            } else {
                unsafe { libc::chown(path.as_ptr(), uid, gid) }
            };
            if rc != 0 {
                return Err(anyhow!(
                    "chown {} failed: {}",
                    p.display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
    Ok(())
}

/// Removes a step work root when it drops: every exit path (success,
/// step failure, commit failure) cleans up, so secret files and mounts
/// never linger in builder scratch. Removal is best-effort — the boot
/// sweep is the backstop for SIGKILL.
struct StepGuard {
    root: PathBuf,
}

impl Drop for StepGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// True for remote ADD sources, which this builder rejects by policy
/// (fetching belongs outside the build sandbox).
fn is_remote_url(src: &str) -> bool {
    let lower = src.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// One parsed `RUN --mount=type=secret,...` declaration.
struct SecretMount {
    id: String,
    target: String,
    required: bool,
    mode: u32,
}

/// A secret mount with its value resolved (empty when optional and
/// absent). Values travel here only — never into cache keys, layers,
/// or progress output.
struct ResolvedSecret {
    target: String,
    mode: u32,
    value: String,
}

/// Parse RUN --mount flags. Only `type=secret` mounts exist; anything
/// else (bind/cache/tmpfs, `rw`, `uid`/`gid`, unknown keys) is an
/// explicit error, never a silent ignore.
fn parse_secret_mounts(inst: &Instruction) -> Result<Vec<SecretMount>> {
    let mut out = Vec::new();
    for (k, v) in &inst.flags {
        if !k.eq_ignore_ascii_case("mount") {
            continue;
        }
        let mut mtype: Option<String> = None;
        let mut id: Option<String> = None;
        let mut target: Option<String> = None;
        let mut required = true;
        let mut mode = 0o400u32;
        for part in v.split(',') {
            let (k, val) = match part.split_once('=') {
                Some((a, b)) => (a.trim(), b.trim()),
                None => anyhow::bail!("RUN --mount: malformed option {part:?}"),
            };
            match k {
                "type" => mtype = Some(val.to_string()),
                "id" => id = Some(val.to_string()),
                "target" | "dst" | "destination" => target = Some(val.to_string()),
                "required" => {
                    required = match val {
                        "true" | "1" => true,
                        "false" | "0" => false,
                        _ => anyhow::bail!("RUN --mount: required must be true/false, got {val:?}"),
                    }
                }
                "mode" => {
                    let digits = val.trim_start_matches('0');
                    let digits = if digits.is_empty() { "0" } else { digits };
                    if digits.len() > 4 || !digits.chars().all(|c| ('0'..='7').contains(&c)) {
                        anyhow::bail!("RUN --mount: mode must be octal (e.g. 400), got {val:?}");
                    }
                    mode = u32::from_str_radix(digits, 8)
                        .map_err(|_| anyhow!("RUN --mount: bad mode {val:?}"))?;
                }
                other => anyhow::bail!(
                    "RUN --mount: unsupported option {other:?} (only type=secret with id/target/required/mode)"
                ),
            }
        }
        match mtype.as_deref() {
            Some("secret") => {}
            Some(t) => anyhow::bail!("RUN --mount: only type=secret is supported, got {t:?}"),
            None => anyhow::bail!("RUN --mount: missing type=secret"),
        }
        let id = id.ok_or_else(|| anyhow!("RUN --mount=type=secret needs id="))?;
        if id.is_empty() {
            anyhow::bail!("RUN --mount=type=secret needs a non-empty id");
        }
        let target = target.unwrap_or_else(|| format!("/run/secrets/{id}"));
        if !target.starts_with('/') {
            anyhow::bail!("RUN --mount: target must be absolute, got {target:?}");
        }
        out.push(SecretMount {
            id,
            target,
            required,
            mode,
        });
    }
    Ok(out)
}

/// Resolve mount declarations against provided secrets. Declarations
/// (id=target) join the cache key; VALUES never do (a rotated secret
/// reuses the cache, like BuildKit). Missing required ids fail the
/// build (naming only the id, never any value); missing optional ones
/// mount an empty file.
fn resolve_secret_mounts(
    mounts: &[SecretMount],
    secrets: &HashMap<String, String>,
) -> Result<(String, Vec<ResolvedSecret>)> {
    let key = mounts
        .iter()
        .map(|m| format!("{}={}", m.id, m.target))
        .collect::<Vec<_>>()
        .join(",");
    let mut resolved = Vec::with_capacity(mounts.len());
    for m in mounts {
        match secrets.get(&m.id) {
            Some(v) => resolved.push(ResolvedSecret {
                target: m.target.clone(),
                mode: m.mode,
                value: v.clone(),
            }),
            None if m.required => {
                anyhow::bail!(
                    "RUN --mount: secret id {:?} was not provided (pass --secret)",
                    m.id
                )
            }
            None => resolved.push(ResolvedSecret {
                target: m.target.clone(),
                mode: m.mode,
                value: String::new(),
            }),
        }
    }
    Ok((key, resolved))
}

#[allow(clippy::too_many_arguments)]
async fn copy_layer(
    paths: &DataPaths,
    tx: &BuildOutput,
    chain: Vec<String>,
    blobs: Vec<String>,
    inst: &Instruction,
    env: &[(String, String)],
    stages: &FromStages<'_>,
    bust: bool,
    opts: &BuildOptions,
) -> Result<(Vec<String>, Vec<String>)> {
    let is_add = inst.verb == "ADD";
    let from = inst
        .flags
        .iter()
        .find(|(k, _)| k == "from")
        .map(|(_, v)| v.clone());
    let args = expand_vars(&inst.args, env);
    let mut words: Vec<&str> = args.split_whitespace().collect();
    let dest = words
        .pop()
        .ok_or_else(|| anyhow!("{} needs a destination", inst.verb))?;
    let sources: Vec<String> = words.iter().map(|s| s.to_string()).collect();

    // ADD fetches nothing: remote URLs are rejected by policy, with the
    // sanctioned alternative spelled out.
    if is_add {
        for src in &sources {
            if is_remote_url(src) {
                anyhow::bail!("ADD remote URL {src:?} is not supported: fetch the file into the build context and ADD it by path");
            }
        }
    }

    // Ownership/mode resolve BEFORE the key (names become numbers, so the
    // key stays stable across machines).
    let rootfs_dirs = chain_layer_dirs(paths, &chain);
    let own = parse_copy_ownership(&inst.flags, &rootfs_dirs)?;

    // Resolve sources BEFORE the cache key: the key hashes what the step
    // actually reads. `--from` hashes stage content (a name alone would
    // go stale); context sources hash content + modes.
    let mut resolved_sources: Vec<(PathBuf, bool)> = Vec::new();
    let mut source_hashes: Vec<String> = Vec::new();
    if let Some(sel) = &from {
        let stage_chain = resolve_from_chain(sel, stages)?;
        let dirs = chain_layer_dirs(paths, stage_chain);
        for src in &sources {
            let found = find_in_stage(dirs.clone(), src.trim_start_matches('/'))
                .ok_or_else(|| anyhow!("COPY --from={sel}: {src} not found"))?;
            let extract = is_add && sniff_tar(&found).is_some();
            source_hashes.push(hash_tree(&found));
            resolved_sources.push((found, extract));
        }
    } else {
        for src in &sources {
            let p = resolve_context_source(&opts.context_dir, src)?;
            let extract = is_add && sniff_tar(&p).is_some();
            source_hashes.push(hash_source(&opts.context_dir, src));
            resolved_sources.push((p, extract));
        }
    }
    let cache_key = copy_cache_key(&args, &from, chain.last(), &source_hashes, &own.key_part());
    if !opts.nocache && !bust {
        if let Some(hit) = cache_lookup(paths, &cache_key).await {
            if cache_hit_valid(paths, &hit) {
                send(tx, ProgressMessage::stream(" ---> Using cache\n")).await;
                let mut c = chain;
                let mut b = blobs;
                b.push(
                    hit.blob_digest
                        .clone()
                        .unwrap_or_else(|| hit.diff_id.clone()),
                );
                c.push(hit.diff_id);
                return Ok((c, b));
            }
        }
    }

    let step_id = ingot_util::new_id()[..16].to_string();
    let diff_dir = paths.builder().join("steps").join(&step_id).join("diff");
    std::fs::create_dir_all(&diff_dir)?;
    let _step_guard = StepGuard {
        root: paths.builder().join("steps").join(&step_id),
    };
    let dest_is_dir = dest.ends_with('/') || sources.len() > 1;
    let target_dest = diff_dir.join(normalize_container_dest(dest));

    for (src, extract) in &resolved_sources {
        if *extract {
            // ADD tar auto-extract: the archive's own paths land under
            // the destination (guarded against traversal).
            extract_tar_guarded(src, &target_dest)?;
        } else if dest_is_dir {
            std::fs::create_dir_all(&target_dest)?;
            copy_into(src, &target_dest)?;
        } else if src.is_file() {
            if let Some(parent) = target_dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(src, &target_dest)?;
        } else if src.is_dir() {
            copy_tree(src, &target_dest)?;
        } else {
            copy_into(src, &target_dest)?;
        }
    }
    if !own.is_none() {
        apply_copy_ownership(&target_dest, &own)?;
    }

    let (diff_id, blob_digest, _size) = commit_layer(paths, &diff_dir).await?;
    let fingerprint = layer_fingerprint(paths, &diff_id);
    cache_store(paths, &cache_key, &diff_id, &blob_digest, Some(fingerprint)).await;
    let _ = std::fs::remove_dir_all(paths.builder().join("steps").join(&step_id));
    let mut c = chain;
    let mut b = blobs;
    c.push(diff_id);
    b.push(blob_digest);
    Ok((c, b))
}

/// Completed stages available to COPY --from: named states plus build
/// order (numeric selectors count all stages, named or not).
struct FromStages<'a> {
    named: &'a HashMap<String, Stage>,
    ordered: &'a [Vec<String>],
}

/// Resolve a COPY --from selector (AS name or stage index) to its layer
/// chain. Only already-completed stages resolve: the current stage and
/// later ones are correctly reported as unknown.
fn resolve_from_chain<'a>(sel: &str, stages: &'a FromStages<'a>) -> Result<&'a Vec<String>> {
    if let Ok(idx) = sel.parse::<usize>() {
        return stages.ordered.get(idx).ok_or_else(|| {
            anyhow!("COPY --from={sel}: no completed stage {idx} (use a name or earlier index)")
        });
    }
    stages
        .named
        .get(sel)
        .map(|s| &s.chain)
        .ok_or_else(|| anyhow!("COPY --from={sel}: unknown stage (not built yet?)"))
}

/// Top-first layer dirs for one chain: the first directory holding a
/// path wins, so upper layers shadow lower ones.
fn chain_layer_dirs(paths: &DataPaths, chain: &[String]) -> Vec<PathBuf> {
    chain
        .iter()
        .rev()
        .map(|d| paths.layers().join(d.trim_start_matches("sha256:")))
        .collect()
}

/// Confine a COPY/ADD source string to the build context. Absolute
/// paths and `..` escapes are rejected; existing paths are canonicalized
/// (resolving symlinks) and verified to stay inside the context, while
/// missing paths (globs or typos) are confined lexically and reported
/// downstream (`not found`) or expanded by the caller. Returns the
/// UNRESOLVED join so symlinks keep their link identity on copy.
fn resolve_context_source(context_dir: &Path, src: &str) -> Result<PathBuf> {
    use std::path::Component;
    if std::path::Path::new(src).is_absolute() {
        anyhow::bail!("COPY source {src:?} must be within the build context");
    }
    let mut rel = PathBuf::new();
    for c in std::path::Path::new(src).components() {
        match c {
            Component::Normal(p) => rel.push(p),
            Component::CurDir => {}
            Component::ParentDir => {
                if !rel.pop() {
                    anyhow::bail!("COPY source {src:?} escapes the build context");
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("COPY source {src:?} escapes the build context");
            }
        }
    }
    let joined = context_dir.join(&rel);
    if let Ok(canon) = std::fs::canonicalize(&joined) {
        let ctx_canon = std::fs::canonicalize(context_dir)?;
        if canon.strip_prefix(&ctx_canon).is_err() {
            anyhow::bail!("COPY source {src:?} escapes the build context");
        }
    }
    Ok(joined)
}

/// Normalize a container destination path: collapse `.`/`..` lexically,
/// clamping pops at the filesystem root (Docker resolves `/a/../../x`
/// to `/x`, it never escapes the container).
fn normalize_container_dest(dest: &str) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in std::path::Path::new(dest).components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// Archive kind sniffed from magic bytes (or the ustar marker).
/// bzip2/xz are RECOGNIZED but unsupported: naming them in the error
/// beats a confusing "not a tar" for a real archive.
enum TarKind {
    Plain,
    Gzip,
    Zstd,
    Unsupported(&'static str),
}

fn sniff_tar(path: &Path) -> Option<TarKind> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut magic = [0u8; 512];
    let n = f.read(&mut magic).ok()?;
    if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        return Some(TarKind::Gzip);
    }
    if n >= 4 && magic[0..4] == [0x28, 0xB5, 0x2F, 0xFD] {
        return Some(TarKind::Zstd);
    }
    if n >= 3 && magic[0..3] == [0x42, 0x5A, 0x68] {
        return Some(TarKind::Unsupported("bzip2"));
    }
    if n >= 6 && magic[0..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
        return Some(TarKind::Unsupported("xz"));
    }
    if n >= 262 && magic[257..262] == *b"ustar" {
        return Some(TarKind::Plain);
    }
    None
}

/// Caps for one ADD-extracted archive: archives are untrusted input even
/// from the local context (a gzip bomb is kilobytes on the wire).
const ADD_EXTRACT_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const ADD_EXTRACT_MAX_FILES: u64 = 100_000;

/// ADD tar auto-extract with the same traversal discipline as context
/// unpacking: relative paths only, links confined to the destination,
/// size/file caps enforced on headers and re-measured afterwards.
fn extract_tar_guarded(src: &Path, dest: &Path) -> Result<()> {
    use std::path::Component;
    let kind = sniff_tar(src);
    if let Some(TarKind::Unsupported(what)) = &kind {
        anyhow::bail!(
            "ADD: {what}-compressed archives are not supported (use plain tar, gzip, or zstd)"
        );
    }
    std::fs::create_dir_all(dest)?;
    // Open the selected decoder, then stream entries with per-entry
    // validation (same rules as daemon context unpacking).
    enum Opened {
        Plain(std::fs::File),
        Gzip(flate2::read::GzDecoder<std::fs::File>),
        Zstd(Vec<u8>),
    }
    let opened = match kind {
        Some(TarKind::Plain) => Opened::Plain(std::fs::File::open(src)?),
        Some(TarKind::Gzip) => {
            Opened::Gzip(flate2::read::GzDecoder::new(std::fs::File::open(src)?))
        }
        Some(TarKind::Zstd) => {
            let bytes = zstd::decode_all(std::fs::File::open(src)?)
                .map_err(|e| anyhow!("ADD: zstd decode failed: {e}"))?;
            if bytes.len() as u64 > ADD_EXTRACT_MAX_BYTES {
                anyhow::bail!("ADD: archive exceeds size limits");
            }
            Opened::Zstd(bytes)
        }
        _ => anyhow::bail!("ADD: {src:?} is not an archive"),
    };
    let mut total: u64 = 0;
    let mut files: u64 = 0;
    macro_rules! entries {
        ($archive:expr) => {{
            for entry in $archive.entries()? {
                let mut entry = entry?;
                files += 1;
                if files > ADD_EXTRACT_MAX_FILES {
                    anyhow::bail!("ADD: archive exceeds file limits");
                }
                let path = entry.path()?.into_owned();
                let mut normal = std::path::PathBuf::new();
                for c in path.components() {
                    match c {
                        Component::Normal(p) => normal.push(p),
                        Component::CurDir => {}
                        Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                            anyhow::bail!(
                                "ADD: archive entry escapes its destination: {}",
                                path.display()
                            );
                        }
                    }
                }
                if normal.as_os_str().is_empty() {
                    continue;
                }
                total = total.saturating_add(entry.size());
                if total > ADD_EXTRACT_MAX_BYTES {
                    anyhow::bail!("ADD: archive exceeds size limits");
                }
                if matches!(
                    entry.header().entry_type(),
                    tar::EntryType::Symlink | tar::EntryType::Link
                ) {
                    let target = entry.link_name()?.ok_or_else(|| {
                        anyhow!("ADD: archive link without target: {}", path.display())
                    })?;
                    confined_link(&normal, &target.into_owned(), &path)?;
                }
                entry.unpack_in(dest)?;
            }
        }};
    }
    match opened {
        Opened::Plain(f) => entries!(tar::Archive::new(f)),
        Opened::Gzip(g) => entries!(tar::Archive::new(g)),
        Opened::Zstd(b) => entries!(tar::Archive::new(&b[..])),
    }
    // Headers can lie: measure what actually landed.
    let mut actual: u64 = 0;
    let mut actual_files: u64 = 0;
    for e in walkdir::WalkDir::new(dest).follow_links(false) {
        let e = e?;
        actual_files += 1;
        if e.file_type().is_file() {
            actual = actual.saturating_add(e.metadata().map(|m| m.len()).unwrap_or(0));
        }
    }
    if actual > ADD_EXTRACT_MAX_BYTES || actual_files > ADD_EXTRACT_MAX_FILES {
        anyhow::bail!("ADD: archive exceeds size/file limits after extraction");
    }
    Ok(())
}

/// Lexical containment for one archive link target: resolved against the
/// link's own directory, it must stay inside the destination tree.
fn confined_link(link_path: &Path, target: &Path, entry: &Path) -> Result<()> {
    use std::path::Component;
    if target.is_absolute() {
        anyhow::bail!(
            "ADD: archive link escapes its destination: {}",
            entry.display()
        );
    }
    let mut joined = link_path.to_path_buf();
    joined.pop();
    for c in target.components() {
        match c {
            Component::Normal(p) => joined.push(p),
            Component::CurDir => {}
            Component::ParentDir => {
                if !joined.pop() {
                    anyhow::bail!(
                        "ADD: archive link escapes its destination: {}",
                        entry.display()
                    );
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!(
                    "ADD: archive link escapes its destination: {}",
                    entry.display()
                );
            }
        }
    }
    Ok(())
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

/// Stable content hash of one file or tree for cache keys: relative
/// paths, bytes, and ownership/mode bits. A chmod/chown without content
/// change still alters the committed layer, so it must bust the cache.
/// Missing paths hash as "missing" (the copy step itself errors on those,
/// except `--from` globs resolved elsewhere).
fn hash_tree(root: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    if root.is_file() {
        let mut acc = String::from("file\0");
        if let Ok(b) = std::fs::read(root) {
            acc.push_str(&sha256_hex(&b));
        }
        if let Ok(m) = std::fs::symlink_metadata(root) {
            acc.push_str(&format!("|{}|{}|{:o}", m.uid(), m.gid(), m.mode()));
        }
        return sha256_hex(acc.as_bytes());
    }
    if !root.is_dir() {
        return "missing".into();
    }
    let mut acc = String::new();
    let mut entries: Vec<_> = walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.path().to_path_buf());
    for e in entries {
        // Relative to the tree root: absolute data-root locations must
        // not make identical trees hash differently (or poison keys
        // across machines).
        let rel = e.path().strip_prefix(root).unwrap_or(e.path());
        acc.push_str(&rel.to_string_lossy());
        acc.push('\0');
        if e.file_type().is_symlink() {
            acc.push_str("link\0");
            if let Ok(t) = std::fs::read_link(e.path()) {
                acc.push_str(&t.to_string_lossy());
            }
            acc.push(';');
            continue;
        }
        if e.file_type().is_file() {
            if let Ok(b) = std::fs::read(e.path()) {
                acc.push_str(&sha256_hex(&b));
            }
        }
        if let Ok(m) = std::fs::symlink_metadata(e.path()) {
            acc.push_str(&format!("|{}|{}|{:o};", m.uid(), m.gid(), m.mode()));
        }
    }
    sha256_hex(acc.as_bytes())
}

/// Stable content hash of a COPY source for cache keys: the context join
/// of `src`, hashed as a tree.
fn hash_source(context_dir: &Path, src: &str) -> String {
    hash_tree(&context_dir.join(src))
}

/// Tar + gzip a diff dir into the blob store; returns (diffID,
/// compressed-blob digest, compressed size). The blob is content-addressed
/// by its own bytes — never by the diff id.
async fn commit_layer(paths: &DataPaths, diff_dir: &Path) -> Result<(String, String, i64)> {
    let tmp = paths
        .builder()
        .join(format!("commit-{}.tar.gz", &ingot_util::new_id()[..12]));
    let gz =
        flate2::write::GzEncoder::new(std::fs::File::create(&tmp)?, flate2::Compression::fast());
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

    let blob_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&compressed)));
    let hex = diff_id.trim_start_matches("sha256:").to_string();
    std::fs::create_dir_all(paths.blobs())?;
    std::fs::write(paths.blob(&blob_digest), &compressed)?;
    // Unpack into the layer store.
    let layer_dest = paths.layers().join(&hex);
    ingot_image::unpack_layer_dir(
        &tmp,
        &layer_dest,
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
    )?;
    let _ = std::fs::write(layer_dest.join(".ingot-unpacked"), "ok");
    let _ = std::fs::remove_file(&tmp);
    let size = compressed.len() as i64;
    Ok((diff_id, blob_digest, size))
}

fn top_first(chain: &[String], paths: &DataPaths) -> Vec<String> {
    chain
        .iter()
        .rev()
        .map(|d| {
            paths
                .layers()
                .join(d.trim_start_matches("sha256:"))
                .to_string_lossy()
                .to_string()
        })
        .collect()
}

fn last_chain(last: Option<&String>) -> String {
    last.cloned().unwrap_or_default()
}

async fn cache_lookup(paths: &DataPaths, key: &str) -> Option<CacheEntry> {
    let cache: HashMap<String, CacheEntry> = std::fs::read(paths.build_cache())
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default();
    cache.get(key).cloned()
}

async fn cache_store(
    paths: &DataPaths,
    key: &str,
    diff_id: &str,
    blob_digest: &str,
    layer_fingerprint: Option<String>,
) {
    let mut cache: HashMap<String, CacheEntry> = std::fs::read(paths.build_cache())
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default();
    cache.insert(
        key.to_string(),
        CacheEntry {
            diff_id: diff_id.to_string(),
            blob_digest: Some(blob_digest.to_string()),
            layer_fingerprint,
        },
    );
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
                for next in parts.by_ref() {
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
        return Some(ingot_api::HealthConfig {
            Test: vec!["NONE".into()],
            ..Default::default()
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_paths() -> (DataPaths, std::path::PathBuf) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "ingot-build-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let paths = DataPaths::new(base.join("data"), base.join("run"));
        (paths, base)
    }

    fn instruction(args: &str, json: Option<Vec<String>>) -> Instruction {
        Instruction {
            verb: "RUN".to_string(),
            args: args.to_string(),
            json_args: json,
            flags: Vec::new(),
            heredocs: Vec::new(),
            line: 1,
        }
    }

    #[test]
    fn run_argv_shell_selection() {
        let env: Vec<(String, String)> = vec![("PATH".into(), "/bin".into())];
        // Shell form uses the stage shell (default /bin/sh -c).
        assert_eq!(
            run_argv(&instruction("echo hi", None), &env, &default_shell()),
            vec!["/bin/sh", "-c", "echo hi"]
        );
        // A SHELL instruction replaces it for later steps.
        let pwsh = vec!["pwsh".to_string(), "-c".to_string()];
        assert_eq!(
            run_argv(&instruction("echo hi", None), &env, &pwsh),
            vec!["pwsh", "-c", "echo hi"]
        );
        // Exec form bypasses the shell entirely.
        let exec = vec!["echo".to_string(), "hi".to_string()];
        assert_eq!(
            run_argv(&instruction("", Some(exec.clone())), &env, &pwsh),
            exec
        );
        // An ENV variable literally named SHELL is just data: it must not
        // hijack step execution (the old behavior this replaces).
        let sneaky: Vec<(String, String)> = vec![("SHELL".into(), "/bin/evil -c".into())];
        assert_eq!(
            run_argv(&instruction("echo hi", None), &sneaky, &default_shell()),
            vec!["/bin/sh", "-c", "echo hi"]
        );
    }

    #[test]
    fn arg_scope_precedence() {
        let env = vec![("X".to_string(), "env".to_string())];
        let stage: HashMap<String, Option<String>> =
            [("X".to_string(), Some("arg".to_string()))].into();
        // Stage ENV beats in-scope stage ARG (first match wins in
        // expand_vars). Pre-FROM globals are NOT in stage scope: a stage
        // sees a global only after re-declaring it (which copies the
        // resolved value into the stage map).
        assert_eq!(expand_vars("$X", &merge_scope(&env, &stage)), "env");
        assert_eq!(expand_vars("$X", &merge_scope(&[], &stage)), "arg");
        // No declaration at all: expands to empty.
        assert_eq!(
            expand_vars("[$X]", &merge_scope(&[], &HashMap::new())),
            "[]"
        );
        // Declared-but-unset stays out: expands to empty, never a leak.
        let unset: HashMap<String, Option<String>> = [("X".to_string(), None)].into();
        assert_eq!(expand_vars("[$X]", &merge_scope(&[], &unset)), "[]");
        // FROM lines expand against the globals directly.
        let globals = vec![("X".to_string(), "global".to_string())];
        assert_eq!(expand_vars("img:$X", &globals), "img:global");
    }

    #[test]
    fn stage_arg_resolution_order() {
        // --build-arg beats the in-file default beats the inherited global.
        let cli: HashMap<String, String> = [("X".to_string(), "cli".to_string())].into();
        let globals: HashMap<String, String> = [("X".to_string(), "global".to_string())].into();
        assert_eq!(
            resolve_stage_arg("X", Some("dflt".into()), &cli, &globals),
            Some("cli".into())
        );
        let cli: HashMap<String, String> = HashMap::new();
        assert_eq!(
            resolve_stage_arg("X", Some("dflt".into()), &cli, &globals),
            Some("dflt".into())
        );
        assert_eq!(
            resolve_stage_arg("X", None, &cli, &globals),
            Some("global".into())
        );
        // Bare re-declaration with no value anywhere: in scope but unset.
        let globals: HashMap<String, String> = HashMap::new();
        assert_eq!(resolve_stage_arg("X", None, &cli, &globals), None);
        // Explicitly empty --build-arg counts as set and masks everything.
        let cli: HashMap<String, String> = [("X".to_string(), String::new())].into();
        let globals: HashMap<String, String> = [("X".to_string(), "global".to_string())].into();
        assert_eq!(
            resolve_stage_arg("X", Some("dflt".into()), &cli, &globals),
            Some(String::new())
        );
    }

    #[test]
    fn arg_decl_parsing() {
        assert_eq!(
            parse_arg_decl("NAME=default=with=equals").unwrap(),
            ("NAME".to_string(), Some("default=with=equals".to_string()))
        );
        assert_eq!(
            parse_arg_decl("  NAME  ").unwrap(),
            ("NAME".to_string(), None)
        );
        assert!(parse_arg_decl("=novalue").is_err());
        assert!(parse_arg_decl("").is_err());
    }

    #[test]
    fn context_source_confinement() {
        let ctx = std::env::temp_dir().join(format!(
            "ingot-src-test-{}-{}",
            std::process::id(),
            ingot_util::random_token()
        ));
        std::fs::create_dir_all(ctx.join("sub")).unwrap();
        std::fs::write(ctx.join("sub/f.txt"), "x").unwrap();
        // Inside stays inside (unresolved join preserves link identity).
        assert_eq!(
            resolve_context_source(&ctx, "sub/f.txt").unwrap(),
            ctx.join("sub/f.txt")
        );
        assert_eq!(
            resolve_context_source(&ctx, "sub/../sub/f.txt").unwrap(),
            ctx.join("sub/f.txt")
        );
        // Absolute paths and escapes are rejected.
        assert!(resolve_context_source(&ctx, "/etc/passwd").is_err());
        assert!(resolve_context_source(&ctx, "../escape").is_err());
        assert!(resolve_context_source(&ctx, "sub/../../escape").is_err());
        // A symlink pointing outside is rejected; an inner link resolves.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc", ctx.join("evil")).unwrap();
            assert!(resolve_context_source(&ctx, "evil/passwd").is_err());
            std::os::unix::fs::symlink("sub/f.txt", ctx.join("ok-link")).unwrap();
            assert_eq!(
                resolve_context_source(&ctx, "ok-link").unwrap(),
                ctx.join("ok-link")
            );
        }
        // Missing-but-confined paths pass through for downstream reporting.
        assert_eq!(
            resolve_context_source(&ctx, "nope/*.txt").unwrap(),
            ctx.join("nope/*.txt")
        );
        std::fs::remove_dir_all(&ctx).unwrap();
    }

    #[test]
    fn container_dest_normalization() {
        assert_eq!(
            normalize_container_dest("/a/b/../c"),
            std::path::PathBuf::from("a/c")
        );
        // Excess `..` clamps at the root instead of escaping.
        assert_eq!(
            normalize_container_dest("/../../x"),
            std::path::PathBuf::from("x")
        );
        assert_eq!(
            normalize_container_dest("rel/./d"),
            std::path::PathBuf::from("rel/d")
        );
    }

    #[test]
    fn source_hash_is_location_independent() {
        let mk = || {
            let d = std::env::temp_dir().join(format!(
                "ingot-hash-test-{}-{}",
                std::process::id(),
                ingot_util::random_token()
            ));
            std::fs::create_dir_all(d.join("tree")).unwrap();
            std::fs::write(d.join("tree/a.txt"), "alpha").unwrap();
            std::fs::write(d.join("tree/b.txt"), "beta").unwrap();
            d
        };
        let (a, b) = (mk(), mk());
        assert_ne!(a, b);
        assert_eq!(hash_source(&a, "tree"), hash_source(&b, "tree"));
        std::fs::write(b.join("tree/b.txt"), "CHANGED").unwrap();
        assert_ne!(hash_source(&a, "tree"), hash_source(&b, "tree"));
        assert_eq!(hash_source(&a, "missing"), "missing");
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn run_key_covers_execution_inputs() {
        let inst = instruction("echo hi", None);
        let env = vec![("A".to_string(), "1".to_string())];
        let shell = default_shell();
        let base = run_cache_key(None, &inst, &env, &shell, "/", "", "");
        // Working directory and user change execution: same command
        // elsewhere (or as someone) must not reuse the layer.
        assert_ne!(
            base,
            run_cache_key(None, &inst, &env, &shell, "/app", "", "")
        );
        assert_ne!(
            base,
            run_cache_key(None, &inst, &env, &shell, "/", "nobody", "")
        );
        assert_ne!(
            base,
            run_cache_key(
                None,
                &inst,
                &[("A".into(), "2".into())],
                &shell,
                "/",
                "",
                ""
            )
        );
        assert_eq!(base, run_cache_key(None, &inst, &env, &shell, "/", "", ""));
        // Mount declarations join the key (values never do).
        assert_ne!(
            base,
            run_cache_key(None, &inst, &env, &shell, "/", "", "pw=/run/secrets/pw")
        );
    }

    #[test]
    fn copy_key_tracks_content_not_names() {
        let from = Some("stage0".to_string());
        let h1 = vec!["aaa".to_string()];
        let h2 = vec!["bbb".to_string()];
        let k1 = copy_cache_key("COPY a /x", &from, None, &h1, "None:None:None");
        // Same stage name, new bytes: different key.
        assert_ne!(
            k1,
            copy_cache_key("COPY a /x", &from, None, &h2, "None:None:None")
        );
        assert_eq!(
            k1,
            copy_cache_key("COPY a /x", &from, None, &h1, "None:None:None")
        );
        // Ownership/mode flags join the key too.
        assert_ne!(
            k1,
            copy_cache_key("COPY a /x", &from, None, &h1, "Some(0):Some(0):None")
        );
    }

    #[test]
    fn tree_hash_sees_mode_changes() {
        let d = std::env::temp_dir().join(format!(
            "ingot-mode-test-{}-{}",
            std::process::id(),
            ingot_util::random_token()
        ));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("f.txt"), "same bytes").unwrap();
        let before = hash_tree(&d.join("f.txt"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.join("f.txt"), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            assert_ne!(before, hash_tree(&d.join("f.txt")));
        }
        // Same tree elsewhere hashes the same (location-independent).
        let d2 = std::env::temp_dir().join(format!(
            "ingot-mode-test-{}-{}",
            std::process::id(),
            ingot_util::random_token()
        ));
        std::fs::create_dir_all(&d2).unwrap();
        std::fs::write(d2.join("f.txt"), "same bytes").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join("f.txt"))
                .unwrap()
                .permissions()
                .mode();
            std::fs::set_permissions(d2.join("f.txt"), std::fs::Permissions::from_mode(mode))
                .unwrap();
        }
        assert_eq!(hash_tree(&d), hash_tree(&d2));
        std::fs::remove_dir_all(&d).unwrap();
        std::fs::remove_dir_all(&d2).unwrap();
    }

    #[test]
    fn fingerprint_trips_on_tamper() {
        let (paths, base) = scratch_paths();
        let layer = paths.layers().join("abc123");
        std::fs::create_dir_all(&layer).unwrap();
        std::fs::write(layer.join("payload.txt"), "original").unwrap();
        let fp = layer_fingerprint(&paths, "sha256:abc123");
        assert!(!fp.is_empty());
        // Untouched: stable.
        assert_eq!(fp, layer_fingerprint(&paths, "sha256:abc123"));
        // Content tamper trips it.
        std::fs::write(layer.join("payload.txt"), "tampered-and-longer").unwrap();
        assert_ne!(fp, layer_fingerprint(&paths, "sha256:abc123"));
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn stage_selector_resolution() {
        let df = crate::parser::parse("FROM a AS base\nRUN x\nFROM b AS app\nRUN y").unwrap();
        let mut stages: Vec<Vec<usize>> = Vec::new();
        for (idx, inst) in df.instructions.iter().enumerate() {
            if inst.verb == "FROM" {
                stages.push(vec![idx]);
            } else if let Some(last) = stages.last_mut() {
                last.push(idx);
            }
        }
        assert_eq!(
            resolve_stage_index(&stages, &df.instructions, "base"),
            Some(0)
        );
        assert_eq!(
            resolve_stage_index(&stages, &df.instructions, "APP"),
            Some(1)
        );
        assert_eq!(resolve_stage_index(&stages, &df.instructions, "1"), Some(1));
        assert_eq!(resolve_stage_index(&stages, &df.instructions, "nope"), None);
        assert_eq!(resolve_stage_index(&stages, &df.instructions, ""), None);
    }

    #[test]
    fn copy_flag_parsing() {
        let dirs: Vec<PathBuf> = Vec::new();
        // Numeric ids pass through; missing group stays unchanged.
        let o = parse_copy_ownership(
            &[
                ("chown".into(), "1000:100".into()),
                ("chmod".into(), "0755".into()),
            ],
            &dirs,
        )
        .unwrap();
        assert_eq!((o.uid, o.gid, o.mode), (Some(1000), Some(100), Some(0o755)));
        let o = parse_copy_ownership(&[("chown".into(), "0".into())], &dirs).unwrap();
        assert_eq!((o.uid, o.gid, o.mode), (Some(0), None, None));
        // Symbolic chmod and unknown names are explicit errors.
        assert!(parse_copy_ownership(&[("chmod".into(), "u+x".into())], &dirs).is_err());
        assert!(parse_copy_ownership(&[("chmod".into(), "9999".into())], &dirs).is_err());
        assert!(parse_copy_ownership(&[("chown".into(), "nosuchuser".into())], &dirs).is_err());
        assert!(parse_copy_ownership(&[("chown".into(), ":0".into())], &dirs).is_err());
    }

    #[test]
    fn copy_flag_names_resolve_against_rootfs() {
        let base = std::env::temp_dir().join(format!(
            "ingot-passwd-test-{}-{}",
            std::process::id(),
            ingot_util::random_token()
        ));
        std::fs::create_dir_all(base.join("etc")).unwrap();
        std::fs::write(base.join("etc/passwd"), "app:x:1000:1000::/:/bin/sh\n").unwrap();
        std::fs::write(base.join("etc/group"), "app:x:1000:\n").unwrap();
        let o = parse_copy_ownership(
            &[("chown".into(), "app:app".into())],
            std::slice::from_ref(&base),
        )
        .unwrap();
        assert_eq!((o.uid, o.gid), (Some(1000), Some(1000)));
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn from_selector_resolution() {
        let mut named: HashMap<String, Stage> = HashMap::new();
        named.insert(
            "base".into(),
            Stage {
                chain: vec!["a".into()],
                blobs: vec![],
                config: empty_config(),
            },
        );
        let ordered = vec![vec!["a".into()], vec!["b".into()]];
        let stages = FromStages {
            named: &named,
            ordered: &ordered,
        };
        assert_eq!(
            resolve_from_chain("base", &stages).unwrap(),
            &vec!["a".to_string()]
        );
        // Numeric selectors count ALL stages, named or not.
        assert_eq!(
            resolve_from_chain("1", &stages).unwrap(),
            &vec!["b".to_string()]
        );
        assert!(resolve_from_chain("7", &stages).is_err());
        assert!(resolve_from_chain("nope", &stages).is_err());
    }

    #[test]
    fn secret_mount_parsing() {
        let mk = |flags: Vec<(&str, &str)>| Instruction {
            verb: "RUN".to_string(),
            args: "echo hi".to_string(),
            json_args: None,
            flags: flags
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            heredocs: Vec::new(),
            line: 1,
        };
        // Full form with defaults filled.
        let m = parse_secret_mounts(&mk(vec![(
            "mount",
            "type=secret,id=pw,target=/x,dst=/y,required=false,mode=440",
        )]))
        .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(
            (m[0].id.as_str(), m[0].required, m[0].mode),
            ("pw", false, 0o440)
        );
        assert_eq!(m[0].target, "/y"); // last target alias wins
        let m = parse_secret_mounts(&mk(vec![("mount", "type=secret,id=pw")])).unwrap();
        assert_eq!(m[0].target, "/run/secrets/pw");
        // Rejections: other types, missing type/id, bad mode, bad target,
        // unknown keys, non-mount flags ignored.
        for bad in [
            "type=cache,id=x",
            "type=bind,id=x",
            "id=x",
            "type=secret",
            "type=secret,id=",
            "type=secret,id=x,mode=u+r",
            "type=secret,id=x,target=relative",
            "type=secret,id=x,rw=true",
            "type=secret,id=x,uid=0",
            "type=secret,id=x,bogus=1",
            "type=secret,id=x,required=maybe",
        ] {
            assert!(
                parse_secret_mounts(&mk(vec![("mount", bad)])).is_err(),
                "accepted {bad:?}"
            );
        }
        assert!(parse_secret_mounts(&mk(vec![("from", "x")]))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn secret_mount_resolution() {
        let mounts = vec![SecretMount {
            id: "pw".into(),
            target: "/run/secrets/pw".into(),
            required: true,
            mode: 0o400,
        }];
        let opt = vec![SecretMount {
            id: "missing".into(),
            target: "/run/secrets/missing".into(),
            required: false,
            mode: 0o400,
        }];
        let secrets: HashMap<String, String> = [("pw".to_string(), "s3cr3t".to_string())].into();
        let (key, resolved) = resolve_secret_mounts(&mounts, &secrets).unwrap();
        assert_eq!(key, "pw=/run/secrets/pw");
        assert_eq!(resolved[0].value, "s3cr3t");
        // The key carries declarations, never values.
        assert!(!key.contains("s3cr3t"));
        // Missing required fails naming only the id. (Matched by hand:
        // ResolvedSecret deliberately has no Debug so values can never
        // leak through a debug format.)
        match resolve_secret_mounts(&mounts, &HashMap::new()) {
            Ok(_) => panic!("missing required secret was accepted"),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("pw") && !msg.contains("s3cr3t"), "got: {msg}");
            }
        }
        // Missing optional mounts an empty file.
        let (_, resolved) = resolve_secret_mounts(&opt, &secrets).unwrap();
        assert!(resolved[0].value.is_empty());
    }

    #[test]
    fn remote_url_policy() {
        assert!(is_remote_url("http://example.com/f.tar"));
        assert!(is_remote_url("HTTPS://example.com/f"));
        assert!(!is_remote_url("files/f.tar"));
        assert!(!is_remote_url("./http://tricky"));
    }

    #[test]
    fn cache_entry_reads_legacy_shape() {
        // Pre-naming entries carry no blob digest; the hit path falls back
        // to the diff id for those instead of failing to parse the cache.
        let legacy: CacheEntry = serde_json::from_str(r#"{"diff_id":"sha256:x"}"#).unwrap();
        assert_eq!(legacy.diff_id, "sha256:x");
        assert_eq!(legacy.blob_digest, None);
    }

    #[tokio::test]
    async fn commit_names_blob_by_its_own_bytes() {
        // Regression: blobs were stored under the *uncompressed* digest,
        // so every built layer's content address lied about its bytes.
        let (paths, base) = scratch_paths();
        std::fs::create_dir_all(paths.builder()).unwrap();
        let diff_dir = base.join("input");
        std::fs::create_dir_all(&diff_dir).unwrap();
        std::fs::write(diff_dir.join("payload.txt"), "x".repeat(4096)).unwrap();
        let (diff_id, blob_digest, size) = commit_layer(&paths, &diff_dir).await.unwrap();
        let stored = std::fs::read(paths.blob(&blob_digest)).unwrap();
        assert_eq!(size, stored.len() as i64);
        assert_eq!(format!("sha256:{}", sha256_hex(&stored)), blob_digest);
        assert_ne!(diff_id, blob_digest, "gzip output must differ in digest");
        // The diff id still addresses the unpacked content.
        assert!(paths.layer(&diff_id).join("payload.txt").exists());
    }
}
