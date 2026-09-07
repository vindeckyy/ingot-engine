//! Docker Compose implementation for Ingot CLI.
//! Supports `ingot compose up`, `down`, `ps`, `logs`.

use crate::client::ApiClient;
use anyhow::{anyhow, Context, Result};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
// Compose-spec surface: fields are consumed incrementally (Plan Phase 9).
#[allow(dead_code)]
pub struct ComposeFile {
    pub version: Option<String>,
    #[serde(default)]
    pub services: HashMap<String, ServiceConfig>,
    #[serde(default)]
    pub volumes: HashMap<String, Option<ComposeVolumeConfig>>,
    #[serde(default)]
    pub networks: HashMap<String, Option<ComposeNetworkConfig>>,
    #[serde(default)]
    pub secrets: HashMap<String, ComposeSecretConfig>,
    #[serde(default)]
    pub configs: HashMap<String, ComposeSecretConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ServiceConfig {
    // Skip-unset on serialize so `extends` merges inherit base keys
    // instead of being clobbered by explicit nulls/empties.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<StringOrList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<StringOrList>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<DependsOnSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Image pull policy: `always`, `missing` (default), `never`, `build`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_policy: Option<String>,
    /// Compose profiles: the service only starts when one of these is
    /// active via `--profile` or `COMPOSE_PROFILES`. Empty means always.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    /// Service inheritance from a local file (`file` + `service` keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<ExtendsSpec>,
    /// Deployment constraints (`deploy.resources.limits` maps onto the
    /// container create `NanoCpus`/`Memory` fields; reservations advisory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy: Option<DeployConfig>,
    /// Runtime secrets (short `- name` or long `- source:/target:` form),
    /// mounted from top-level `secrets` entries with a `file:` source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretRef>,
    /// Runtime configs, same short/long shape as `secrets`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configs: Vec<SecretRef>,
}

/// `extends` target: a service from a local compose file. `file` defaults
/// to the current file (same-file inheritance).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ExtendsSpec {
    #[serde(default)]
    pub file: Option<String>,
    pub service: String,
}

/// `deploy` block (only `resources` is read; siblings are ignored).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DeployConfig {
    #[serde(default)]
    pub resources: Option<DeployResources>,
}

/// `deploy.resources` block. `limits` constrain the container;
/// `reservations` are accepted and documented as advisory (ignored).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DeployResources {
    #[serde(default)]
    pub limits: Option<ResourceLimits>,
    #[serde(default)]
    pub reservations: Option<ResourceLimits>,
}

/// One side of `deploy.resources.{limits,reservations}`. Both keys accept
/// a YAML number or string (`cpus: 0.5` / `cpus: "0.50"`,
/// `memory: 536870912` / `memory: "512M"`).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ResourceLimits {
    #[serde(default)]
    pub cpus: Option<serde_json::Value>,
    #[serde(default)]
    pub memory: Option<serde_json::Value>,
}

/// Short (`- my_secret`) or long (`- source: …`) service secret/config ref.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SecretRef {
    Short(String),
    Long(SecretRefLong),
}

/// Long-syntax secret/config ref. `uid`/`gid`/`mode` are parsed and
/// accepted but advisory: the bind-mount flow carrying the file exposes
/// no ownership knobs, so they are documented, not applied.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SecretRefLong {
    pub source: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub uid: Option<serde_json::Value>,
    #[serde(default)]
    pub gid: Option<serde_json::Value>,
    #[serde(default)]
    pub mode: Option<serde_json::Value>,
}

/// Top-level `secrets:` / `configs:` entry. Only `file:` sources can be
/// mounted into containers; `environment:` and `external:` entries fail
/// per service with an explicit 501-style reason.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ComposeSecretConfig {
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub external: Option<bool>,
}

/// Image acquisition decision for one service (Plan Phase 9, unit 9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullAction {
    /// Build from the service's `build` section.
    Build,
    /// Pull even if the image is present locally.
    PullAlways,
    /// Pull only when the image is absent locally.
    PullIfMissing,
    /// Fail if the image is absent locally; never pull.
    RequireLocal,
}

/// Decide how to obtain a service image. `force_build` is the CLI
/// `--build` flag. Unknown policies are an error, never silent `missing`.
pub fn decide_pull(
    policy: Option<&str>,
    has_image: bool,
    has_build: bool,
    force_build: bool,
) -> Result<PullAction, String> {
    if force_build {
        return Ok(PullAction::Build);
    }
    match policy.unwrap_or("missing") {
        "" | "missing" => {
            if !has_image && has_build {
                Ok(PullAction::Build)
            } else {
                Ok(PullAction::PullIfMissing)
            }
        }
        "always" => {
            if !has_image && has_build {
                Ok(PullAction::Build)
            } else {
                Ok(PullAction::PullAlways)
            }
        }
        "never" => Ok(PullAction::RequireLocal),
        "build" => {
            if has_build {
                Ok(PullAction::Build)
            } else {
                Ok(PullAction::PullIfMissing)
            }
        }
        other => Err(format!(
            "unknown pull_policy {other:?} (expected: always, missing, never, build)"
        )),
    }
}

/// `depends_on` readiness condition (compose-spec long syntax).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepCondition {
    Started,
    Healthy,
    Completed,
}

/// Parse conditions for every dependency. Short-syntax entries default
/// to `service_started`. Unknown conditions are an error, never silent
/// `service_started`.
pub fn dependency_conditions(
    deps: Option<&DependsOnSpec>,
) -> Result<Vec<(String, DepCondition)>, String> {
    let Some(deps) = deps else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    match deps {
        DependsOnSpec::List(names) => {
            for n in names {
                out.push((n.clone(), DepCondition::Started));
            }
        }
        DependsOnSpec::Map(m) => {
            let mut names: Vec<&String> = m.keys().collect();
            names.sort();
            for n in names {
                let cond = match &m[n] {
                    serde_json::Value::String(s) => s.as_str(),
                    serde_json::Value::Object(o) => {
                        o.get("condition").and_then(|c| c.as_str()).unwrap_or("")
                    }
                    _ => "",
                };
                let cond = match cond {
                    "" | "service_started" => DepCondition::Started,
                    "service_healthy" => DepCondition::Healthy,
                    "service_completed_successfully" => DepCondition::Completed,
                    other => {
                        return Err(format!(
                            "unknown depends_on condition {other:?} for service {n:?} \
                             (expected: service_started, service_healthy, \
                             service_completed_successfully)"
                        ));
                    }
                };
                out.push(((*n).clone(), cond));
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BuildSpec {
    Simple(String),
    Detailed {
        context: Option<String>,
        dockerfile: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum StringOrList {
    String(String),
    List(Vec<String>),
}

impl StringOrList {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            StringOrList::List(l) => l.clone(),
            StringOrList::String(s) => s.split_whitespace().map(|x| x.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EnvSpec {
    List(Vec<String>),
    Map(HashMap<String, serde_json::Value>),
}

impl EnvSpec {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            EnvSpec::List(l) => l.clone(),
            EnvSpec::Map(m) => m
                .iter()
                .map(|(k, v)| {
                    let val = match v {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        _ => v.to_string(),
                    };
                    format!("{k}={val}")
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DependsOnSpec {
    List(Vec<String>),
    Map(HashMap<String, serde_json::Value>),
}

impl DependsOnSpec {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            DependsOnSpec::List(l) => l.clone(),
            DependsOnSpec::Map(m) => m.keys().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
// Compose-spec surface: honored by a future Phase 9 unit.
#[allow(dead_code)]
pub struct ComposeVolumeConfig {
    pub driver: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
// Compose-spec surface: honored by a future Phase 9 unit.
#[allow(dead_code)]
pub struct ComposeNetworkConfig {
    pub driver: Option<String>,
}

pub fn resolve_compose_file(file_opt: Option<&str>) -> Result<(PathBuf, ComposeFile)> {
    let path = match file_opt {
        Some(f) => {
            let p = PathBuf::from(f);
            if !p.is_file() {
                return Err(anyhow!("compose file not found: {f}"));
            }
            p
        }
        None => {
            let candidates = [
                "compose.yaml",
                "compose.yml",
                "docker-compose.yaml",
                "docker-compose.yml",
            ];
            candidates
                .iter()
                .map(PathBuf::from)
                .find(|p| p.is_file())
                .ok_or_else(|| anyhow!("no compose file found (looked for compose.yaml, compose.yml, docker-compose.yaml, docker-compose.yml)"))?
        }
    };

    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("read compose file {}", path.display()))?;
    let file: ComposeFile = serde_yaml::from_str(&content)
        .with_context(|| format!("parse compose yaml {}", path.display()))?;
    Ok((path, file))
}

pub fn resolve_project_name(proj_opt: Option<&str>, compose_path: &Path) -> String {
    if let Some(p) = proj_opt {
        return p
            .to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect();
    }
    if let Ok(dir) = compose_path.canonicalize().and_then(|p| {
        p.parent()
            .map(|p| {
                p.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            })
            .ok_or_else(|| std::io::Error::other("no parent"))
    }) {
        let clean: String = dir
            .to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        if !clean.is_empty() {
            return clean;
        }
    }
    "default".to_string()
}

pub fn topological_sort(services: &HashMap<String, ServiceConfig>) -> Result<Vec<String>> {
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();

    for name in services.keys() {
        in_degree.insert(name.clone(), 0);
        adj.insert(name.clone(), Vec::new());
    }

    for (name, cfg) in services {
        if let Some(deps) = &cfg.depends_on {
            for dep in deps.to_vec() {
                if services.contains_key(&dep) {
                    adj.entry(dep).or_default().push(name.clone());
                    *in_degree.entry(name.clone()).or_default() += 1;
                }
            }
        }
    }

    let mut queue: Vec<String> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(name, _)| name.clone())
        .collect();
    queue.sort();

    let mut result = Vec::new();
    while let Some(node) = queue.pop() {
        result.push(node.clone());
        if let Some(neighbors) = adj.get(&node) {
            for neighbor in neighbors {
                let deg = in_degree.get_mut(neighbor).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push(neighbor.clone());
                    queue.sort();
                }
            }
        }
    }

    if result.len() < services.len() {
        for name in services.keys() {
            if !result.contains(name) {
                result.push(name.clone());
            }
        }
    }

    Ok(result)
}

/// Active compose profiles: repeatable `--profile` flags merged with the
/// comma-separated `COMPOSE_PROFILES` environment variable, in order,
/// deduplicated. Either source enables a profile-gated service.
pub fn active_profiles(cli: &[String]) -> Vec<String> {
    let env = std::env::var("COMPOSE_PROFILES").ok();
    active_profiles_from(cli, env.as_deref())
}

fn active_profiles_from(cli: &[String], env: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |raw: &str| {
        for p in raw.split(',') {
            let p = p.trim().to_string();
            if !p.is_empty() && !out.contains(&p) {
                out.push(p);
            }
        }
    };
    for p in cli {
        push(p);
    }
    if let Some(e) = env {
        push(e);
    }
    out
}

/// A service runs when it declares no profiles or when one of its profiles
/// is active. Services that declare profiles but match none are skipped.
pub fn service_enabled(svc: &ServiceConfig, active: &[String]) -> bool {
    svc.profiles.is_empty() || svc.profiles.iter().any(|p| active.contains(p))
}

/// Resolve every service's `extends` against local files. The base service
/// is shallow-merged under the override: each top-level key present in the
/// override wins whole, keys absent fall back to the base. Remote URLs are
/// rejected — only local files (relative to the composing file) are read.
pub fn apply_extends(compose_path: &Path, compose: &ComposeFile) -> Result<ComposeFile> {
    let mut merged = compose.clone();
    for name in compose.services.keys().cloned().collect::<Vec<_>>() {
        let stack = vec![extends_id(compose_path, &name)];
        let svc = resolve_service(compose_path, compose, &name, &stack)?;
        merged.services.insert(name, svc);
    }
    Ok(merged)
}

fn extends_id(path: &Path, service: &str) -> String {
    format!("{}#{service}", path.to_string_lossy())
}

fn resolve_service(
    compose_path: &Path,
    compose: &ComposeFile,
    name: &str,
    stack: &[String],
) -> Result<ServiceConfig> {
    let svc = compose.services.get(name).cloned().ok_or_else(|| {
        anyhow!(
            "service {name}: extends unknown service {name:?} in file {}",
            compose_path.display()
        )
    })?;
    let Some(ext) = svc.extends.clone() else {
        return Ok(svc);
    };
    if ext.service.is_empty() {
        return Err(anyhow!(
            "service {name}: extends needs a `service:` key naming the base service"
        ));
    }
    // Resolve the base service, recursing through its own extends.
    let base = match ext.file.as_deref() {
        // Same-file inheritance.
        None => {
            let id = extends_id(compose_path, &ext.service);
            if stack.contains(&id) {
                return Err(anyhow!(
                    "service {name}: extends cycle detected ({})",
                    stack.join(" -> ")
                ));
            }
            if !compose.services.contains_key(&ext.service) {
                return Err(anyhow!(
                    "service {name}: extends unknown service {:?} in the same file",
                    ext.service
                ));
            }
            let mut stack = stack.to_vec();
            stack.push(id);
            resolve_service(compose_path, compose, &ext.service, &stack)?
        }
        // Another local file, resolved relative to the composing file.
        Some(file) => {
            if file.contains("://") || file.starts_with("git@") {
                return Err(anyhow!(
                    "service {name}: extends file {file:?} is a remote URL, which is not \
                     supported (local files only)"
                ));
            }
            let dir = compose_path.parent().unwrap_or_else(|| Path::new("."));
            let base_path = dir.join(file);
            if !base_path.is_file() {
                return Err(anyhow!(
                    "service {name}: extends file {:?} not found",
                    base_path.to_string_lossy()
                ));
            }
            let content = std::fs::read_to_string(&base_path).with_context(|| {
                format!("service {name}: read extends file {}", base_path.display())
            })?;
            let base_file: ComposeFile = serde_yaml::from_str(&content).with_context(|| {
                format!("service {name}: parse extends file {}", base_path.display())
            })?;
            if !base_file.services.contains_key(&ext.service) {
                return Err(anyhow!(
                    "service {name}: extends unknown service {:?} in file {}",
                    ext.service,
                    base_path.display()
                ));
            }
            let id = extends_id(&base_path, &ext.service);
            if stack.contains(&id) {
                return Err(anyhow!(
                    "service {name}: extends cycle detected ({})",
                    stack.join(" -> ")
                ));
            }
            let mut stack = stack.to_vec();
            stack.push(id);
            resolve_service(&base_path, &base_file, &ext.service, &stack)?
        }
    };
    // Shallow merge: every top-level key set in the override wins whole;
    // unset override keys serialize as null and fall back to the base.
    // The `extends` key itself never survives the merge.
    let base_v = serde_json::to_value(&base)
        .with_context(|| format!("service {name}: cannot merge extends base"))?;
    let over_v = serde_json::to_value(&svc)
        .with_context(|| format!("service {name}: cannot merge extends override"))?;
    let mut out_map = base_v.as_object().cloned().unwrap_or_default();
    for (k, v) in over_v.as_object().cloned().unwrap_or_default() {
        if k != "extends" && !v.is_null() {
            out_map.insert(k, v);
        }
    }
    let mut out: ServiceConfig = serde_json::from_value(serde_json::Value::Object(out_map))
        .with_context(|| format!("service {name}: cannot merge extends base"))?;
    out.extends = None;
    Ok(out)
}

/// Parse a `deploy.resources.{limits,reservations}.cpus` value (YAML number
/// or numeric string) into Docker `NanoCpus`. Errors name the field path.
pub fn parse_cpus_value(v: &serde_json::Value, field: &str) -> Result<i64, String> {
    let n: f64 = match v {
        serde_json::Value::Number(n) => n.as_f64().ok_or_else(|| bad_cpus(v, field))?,
        serde_json::Value::String(s) => s.trim().parse::<f64>().map_err(|_| bad_cpus(v, field))?,
        _ => return Err(bad_cpus(v, field)),
    };
    if !n.is_finite() || n < 0.0 {
        return Err(bad_cpus(v, field));
    }
    Ok((n * 1e9).round() as i64)
}

fn bad_cpus(v: &serde_json::Value, field: &str) -> String {
    format!("{field} {v} is invalid (want a CPU count like \"0.50\" or 2)")
}

/// Parse a `deploy.resources.{limits,reservations}.memory` value (byte
/// count or a suffixed string like `512M`, `1g`, `256k`, case-insensitive
/// with an optional trailing `b`) into bytes. Errors name the field path.
pub fn parse_memory_value(v: &serde_json::Value, field: &str) -> Result<i64, String> {
    let bad = || format!("{field} {v} is invalid (want bytes like 536870912 or \"512M\")");
    match v {
        serde_json::Value::Number(n) => {
            let i = n.as_i64().ok_or_else(bad)?;
            if i < 0 {
                return Err(bad());
            }
            Ok(i)
        }
        serde_json::Value::String(s) => parse_memory_str(s.trim()).ok_or_else(bad),
        _ => Err(bad()),
    }
}

fn parse_memory_str(s: &str) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let lower = lower.strip_suffix('b').unwrap_or(&lower);
    let lower = lower.strip_suffix('i').unwrap_or(lower);
    let (num, mult) = match lower.strip_suffix(['k', 'm', 'g']) {
        Some(rest) => {
            let m = match lower.chars().last()? {
                'k' => 1024i64,
                'm' => 1024i64 * 1024,
                'g' => 1024i64 * 1024 * 1024,
                _ => return None,
            };
            (rest, m)
        }
        None => (lower, 1),
    };
    let n: f64 = num.trim().parse().ok()?;
    if !n.is_finite() || n < 0.0 {
        return None;
    }
    Some((n * mult as f64).round() as i64)
}

/// Map `deploy.resources.limits` onto the container create fields
/// (`NanoCpus`, `Memory`). Returns `(nano_cpus, memory)`; unset keys yield
/// 0 (Docker "unset"). `reservations` are accepted but advisory: parsed
/// for validation only, never applied.
pub fn deploy_limits(deploy: Option<&DeployConfig>, service: &str) -> Result<(i64, i64), String> {
    let mut nano_cpus = 0i64;
    let mut memory = 0i64;
    let Some(deploy) = deploy else {
        return Ok((0, 0));
    };
    let Some(resources) = deploy.resources.as_ref() else {
        return Ok((0, 0));
    };
    // Validate reservations so typos fail fast, then ignore them.
    if let Some(res) = resources.reservations.as_ref() {
        if let Some(c) = res.cpus.as_ref() {
            parse_cpus_value(
                c,
                &format!("service {service}: deploy.resources.reservations.cpus"),
            )?;
        }
        if let Some(m) = res.memory.as_ref() {
            parse_memory_value(
                m,
                &format!("service {service}: deploy.resources.reservations.memory"),
            )?;
        }
    }
    if let Some(limits) = resources.limits.as_ref() {
        if let Some(c) = limits.cpus.as_ref() {
            nano_cpus = parse_cpus_value(
                c,
                &format!("service {service}: deploy.resources.limits.cpus"),
            )?;
        }
        if let Some(m) = limits.memory.as_ref() {
            memory = parse_memory_value(
                m,
                &format!("service {service}: deploy.resources.limits.memory"),
            )?;
        }
    }
    Ok((nano_cpus, memory))
}

/// Resolve a service's `secrets`/`configs` refs into read-only bind mounts
/// against the existing `Binds` flow. File-based top-level entries mount
/// at `/run/secrets/<target>` (secrets) or `/<target>` (configs);
/// long-syntax `uid`/`gid`/`mode` are accepted but advisory (bind mounts
/// expose no ownership knobs). Anything without a mountable `file:`
/// source fails per service with an explicit 501-style reason — the
/// daemon has no runtime secret store (POST /secrets stages build
/// secrets only), so there is nothing else to wire to.
pub fn credential_mounts(
    kind: &str,
    refs: &[SecretRef],
    top: &HashMap<String, ComposeSecretConfig>,
    service: &str,
    compose_dir: &Path,
) -> Result<Vec<String>, String> {
    let mut mounts = Vec::new();
    for r in refs {
        let (source, target) = match r {
            SecretRef::Short(s) => (s.clone(), None),
            SecretRef::Long(l) => (l.source.clone(), l.target.clone()),
        };
        let target = target.unwrap_or_else(|| source.clone());
        if target.is_empty() || target.contains('/') || target.contains('\0') {
            return Err(format!(
                "service {service}: {kind} target {target:?} is invalid (want a file name)"
            ));
        }
        let entry = top.get(&source).ok_or_else(|| {
            format!("service {service}: {kind} {source:?} is not defined in the top-level {kind} section")
        })?;
        let Some(file) = entry.file.as_deref() else {
            let why = if entry.external.unwrap_or(false) {
                "it is external".to_string()
            } else if let Some(var) = entry.environment.as_deref() {
                format!("it uses environment source {var:?}")
            } else {
                "it has no file: source".to_string()
            };
            return Err(format!(
                "service {service}: {kind} {source:?} is not supported (501: {why}; \
                 only file-based {kind} can be mounted)"
            ));
        };
        let abs = if file.starts_with('/') {
            PathBuf::from(file)
        } else {
            compose_dir.join(file)
        };
        if !abs.is_file() {
            return Err(format!(
                "service {service}: {kind} {source:?} file {} not found",
                abs.display()
            ));
        }
        let dest = if kind == "secrets" {
            format!("/run/secrets/{target}")
        } else {
            format!("/{target}")
        };
        mounts.push(format!("{}:{dest}:ro", abs.to_string_lossy()));
    }
    Ok(mounts)
}

pub async fn up(
    api: &ApiClient,
    file_opt: Option<&str>,
    proj_opt: Option<&str>,
    detach: bool,
    force_build: bool,
    profiles: &[String],
) -> Result<()> {
    let (compose_path, compose) = resolve_compose_file(file_opt)?;
    let project = resolve_project_name(proj_opt, &compose_path);
    let compose_dir = compose_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    let compose = apply_extends(&compose_path, &compose)?;

    let active = active_profiles(profiles);
    let mut services: HashMap<String, ServiceConfig> = HashMap::new();
    for (name, svc) in &compose.services {
        if service_enabled(svc, &active) {
            services.insert(name.clone(), svc.clone());
        } else {
            println!(
                "Service {name} skipped (profiles [{}] not active)",
                svc.profiles.join(", ")
            );
        }
    }

    println!("[+] Running services for project \"{project}\"");

    // 1. Create default network: <project>_default
    let net_name = format!("{project}_default");
    let net_body = serde_json::json!({
        "Name": net_name,
        "CheckDuplicate": true,
        "Driver": "bridge",
        "Labels": {
            "com.docker.compose.project": project,
            "com.docker.compose.network": "default"
        }
    });
    if let Err(e) = api
        .post::<serde_json::Value>("/networks/create", Some(net_body))
        .await
    {
        let msg = format!("{e:#}");
        if !msg.contains("Conflict") && !msg.contains("already exists") {
            return Err(anyhow!("failed to create network {net_name}: {e}"));
        }
    }

    // 2. Create named volumes declared in compose
    for vname in compose.volumes.keys() {
        let full_vname = format!("{project}_{vname}");
        let vol_body = serde_json::json!({
            "Name": full_vname,
            "Driver": "local",
            "Labels": {
                "com.docker.compose.project": project,
                "com.docker.compose.volume": vname
            }
        });
        if let Err(e) = api
            .post::<serde_json::Value>("/volumes/create", Some(vol_body))
            .await
        {
            let msg = format!("{e:#}");
            if !msg.contains("Conflict") && !msg.contains("already exists") {
                return Err(anyhow!("failed to create volume {full_vname}: {e}"));
            }
        }
    }

    // 3. Dependency order
    let sorted_services = topological_sort(&services)?;

    // Fail fast on unknown pull policies / conditions / resource limits /
    // secret refs before creating anything: a half-started project is the
    // worst outcome.
    for name in &sorted_services {
        let s = &services[name];
        decide_pull(
            s.pull_policy.as_deref(),
            s.image.is_some(),
            s.build.is_some(),
            force_build,
        )
        .map_err(|e| anyhow!("service {name}: {e}"))?;
        dependency_conditions(s.depends_on.as_ref()).map_err(|e| anyhow!("service {name}: {e}"))?;
        deploy_limits(s.deploy.as_ref(), name).map_err(|e| anyhow!("{e}"))?;
        credential_mounts("secrets", &s.secrets, &compose.secrets, name, &compose_dir)
            .map_err(|e| anyhow!("{e}"))?;
        credential_mounts("configs", &s.configs, &compose.configs, name, &compose_dir)
            .map_err(|e| anyhow!("{e}"))?;
    }

    let mut started_ids: HashMap<String, String> = HashMap::new();

    // 4. Create & start each service container
    for service_name in &sorted_services {
        let s = &services[service_name];

        // Health/completion gates: a dependent only starts after its
        // dependencies are ready, not merely created.
        for (dep, cond) in dependency_conditions(s.depends_on.as_ref())
            .map_err(|e| anyhow!("service {service_name}: {e}"))?
        {
            let Some(dep_id) = started_ids.get(&dep) else {
                if cond == DepCondition::Started {
                    continue;
                }
                return Err(anyhow!(
                    "service {service_name} waits for {dep}, which was not started by this project"
                ));
            };
            match cond {
                DepCondition::Started => {}
                DepCondition::Healthy => {
                    wait_healthy(api, dep_id, &dep).await.with_context(|| {
                        format!("service {service_name}: dependency {dep} never became healthy")
                    })?;
                }
                DepCondition::Completed => {
                    wait_completed(api, dep_id, &dep).await.with_context(|| {
                        format!("service {service_name}: dependency {dep} did not exit 0")
                    })?;
                }
            }
        }

        let action = decide_pull(
            s.pull_policy.as_deref(),
            s.image.is_some(),
            s.build.is_some(),
            force_build,
        )
        .map_err(|e| anyhow!("service {service_name}: {e}"))?;

        // Determine image
        let image = if action == PullAction::Build {
            let tag = format!("{project}-{service_name}:latest");
            let (ctx_dir, df) = match &s.build {
                Some(BuildSpec::Simple(c)) => (compose_dir.join(c), "Dockerfile".to_string()),
                Some(BuildSpec::Detailed {
                    context,
                    dockerfile,
                }) => {
                    let c = context.as_deref().unwrap_or(".");
                    let d = dockerfile.as_deref().unwrap_or("Dockerfile");
                    (compose_dir.join(c), d.to_string())
                }
                None => (compose_dir.to_path_buf(), "Dockerfile".to_string()),
            };
            println!("Building service {service_name}...");
            crate::commands::build(
                api,
                std::slice::from_ref(&tag),
                &df,
                false,
                &[],
                &[],
                false,
                &ctx_dir.to_string_lossy(),
            )
            .await?;
            tag
        } else if let Some(img) = &s.image {
            let inspect_path = format!("/images/{img}/json");
            let present = api
                .get_json::<serde_json::Value>(&inspect_path)
                .await
                .is_ok();
            match action {
                PullAction::PullAlways => {
                    println!("Pulling {img} (pull_policy: always)...");
                    crate::commands::pull(api, img, None).await?;
                }
                PullAction::PullIfMissing => {
                    if !present {
                        println!("Pulling {img}...");
                        crate::commands::pull(api, img, None).await?;
                    }
                }
                PullAction::RequireLocal => {
                    if !present {
                        return Err(anyhow!(
                            "service {service_name}: image {img} is not present locally \
                             and pull_policy is \"never\""
                        ));
                    }
                }
                // Build without an image tag cannot happen (decide_pull
                // only returns Build when a build section exists or the
                // CLI --build flag forces it, both handled above).
                PullAction::Build => {}
            }
            img.clone()
        } else {
            return Err(anyhow!(
                "service {service_name} has neither image nor build specified"
            ));
        };

        let cname = s
            .container_name
            .clone()
            .unwrap_or_else(|| format!("{project}-{service_name}-1"));

        let _ = api
            .request_raw("DELETE", &format!("/containers/{cname}?force=1"), None)
            .await;

        let mut port_bindings: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
        for p in &s.ports {
            for m in crate::ports::parse_port_spec(p).map_err(|e| anyhow::anyhow!("{e}"))? {
                port_bindings
                    .entry(m.container_key)
                    .or_default()
                    .push(serde_json::json!({
                        "HostIp": m.host_ip,
                        "HostPort": m.host_port
                    }));
            }
        }

        let mut binds = Vec::new();
        for v in &s.volumes {
            if let Some((src, dst)) = v.split_once(':') {
                if compose.volumes.contains_key(src) {
                    binds.push(format!("{project}_{src}:{dst}"));
                } else if src.starts_with('.') || src.starts_with('/') {
                    let abs_src = if src.starts_with('/') {
                        PathBuf::from(src)
                    } else {
                        compose_dir.join(src)
                    };
                    binds.push(format!("{}:{dst}", abs_src.to_string_lossy()));
                } else {
                    binds.push(v.clone());
                }
            } else {
                binds.push(v.clone());
            }
        }

        let env = s
            .environment
            .as_ref()
            .map(|e| e.to_vec())
            .unwrap_or_default();
        let cmd = s.command.as_ref().map(|c| c.to_vec()).unwrap_or_default();
        let ep = s.entrypoint.as_ref().map(|e| e.to_vec());

        // deploy.resources.limits -> container create fields (reservations
        // are advisory and were validated up front, never applied).
        let (nano_cpus, memory) =
            deploy_limits(s.deploy.as_ref(), service_name).map_err(|e| anyhow!("{e}"))?;
        // File-based secrets/configs ride the existing Binds flow as
        // read-only mounts (validated up front; re-resolved here).
        for m in credential_mounts(
            "secrets",
            &s.secrets,
            &compose.secrets,
            service_name,
            &compose_dir,
        )
        .map_err(|e| anyhow!("{e}"))?
        {
            binds.push(m);
        }
        for m in credential_mounts(
            "configs",
            &s.configs,
            &compose.configs,
            service_name,
            &compose_dir,
        )
        .map_err(|e| anyhow!("{e}"))?
        {
            binds.push(m);
        }

        let mut labels = HashMap::new();
        labels.insert("com.docker.compose.project".to_string(), project.clone());
        labels.insert(
            "com.docker.compose.service".to_string(),
            service_name.clone(),
        );
        labels.insert(
            "com.docker.compose.container-number".to_string(),
            "1".to_string(),
        );
        labels.insert("com.docker.compose.oneoff".to_string(), "False".to_string());
        labels.insert(
            "com.docker.compose.version".to_string(),
            "2.24.0".to_string(),
        );

        let create_body = serde_json::json!({
            "Image": image,
            "Cmd": cmd,
            "Entrypoint": ep,
            "Env": env,
            "WorkingDir": s.working_dir.clone().unwrap_or_default(),
            "User": s.user.clone().unwrap_or_default(),
            "Labels": labels,
            "HostConfig": {
                "NetworkMode": net_name,
                "PortBindings": port_bindings,
                "Binds": binds,
                "NanoCpus": nano_cpus,
                "Memory": memory,
                "RestartPolicy": {
                    "Name": s.restart.clone().unwrap_or_default(),
                    "MaximumRetryCount": 0
                }
            }
        });

        let created = api
            .request_json(
                "POST",
                &format!("/containers/create?name={cname}"),
                Some(serde_json::to_vec(&create_body)?),
            )
            .await
            .with_context(|| format!("create container for {service_name}"))?;

        let cid = created["Id"].as_str().unwrap_or(&cname).to_string();

        api.request_raw("POST", &format!("/containers/{cid}/start"), None)
            .await
            .with_context(|| format!("start container for {service_name}"))?;

        println!(" ✔ Container {cname}  Started");
        started_ids.insert(service_name.clone(), cid);
    }

    if detach {
        return Ok(());
    }

    println!("[+] All services started. Press Ctrl+C to stop.");
    let names: Vec<String> = services.keys().cloned().collect();
    logs(api, file_opt, proj_opt, true, &names).await
}

/// Seconds to wait for a `service_healthy` gate before failing `up`.
const HEALTH_WAIT_SECS: u64 = 60;

/// Wait until a dependency container reports healthy. A missing
/// healthcheck, an `unhealthy` verdict, a dead container, or the timeout
/// all fail the dependent's startup with an actionable error.
async fn wait_healthy(api: &ApiClient, id: &str, dep: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(HEALTH_WAIT_SECS);
    loop {
        let st: serde_json::Value = api
            .get_json(&format!("/containers/{id}/json"))
            .await
            .with_context(|| format!("inspect dependency {dep}"))?;
        let running = st["State"]["Running"].as_bool().unwrap_or(false);
        if !running {
            return Err(anyhow!(
                "dependency {dep} is not running while waiting for healthy"
            ));
        }
        match st["State"]["Health"]["Status"].as_str() {
            Some("healthy") => return Ok(()),
            Some("unhealthy") => {
                return Err(anyhow!("dependency {dep} reported unhealthy"));
            }
            Some("none") | None => {
                return Err(anyhow!(
                    "dependency {dep} has no healthcheck, but a dependent \
                     requires service_healthy"
                ));
            }
            // "starting" (or anything else): keep polling.
            Some(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "dependency {dep} did not become healthy within {HEALTH_WAIT_SECS}s"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Wait for a one-shot dependency to exit successfully.
async fn wait_completed(api: &ApiClient, id: &str, dep: &str) -> Result<()> {
    let out: serde_json::Value = api
        .request_json("POST", &format!("/containers/{id}/wait"), None)
        .await
        .with_context(|| format!("wait on dependency {dep}"))?;
    let code = out["StatusCode"].as_i64().unwrap_or(-1);
    if code == 0 {
        Ok(())
    } else {
        Err(anyhow!("dependency {dep} exited with status {code}"))
    }
}

pub async fn down(
    api: &ApiClient,
    file_opt: Option<&str>,
    proj_opt: Option<&str>,
    remove_volumes: bool,
) -> Result<()> {
    let (compose_path, compose) = resolve_compose_file(file_opt)?;
    let project = resolve_project_name(proj_opt, &compose_path);

    println!("[+] Stopping and removing containers for \"{project}\"");

    let containers: Vec<serde_json::Value> = api.get_json("/containers/json?all=1").await?;
    for c in containers {
        let labels = c.get("Labels").and_then(|l| l.as_object());
        if let Some(lbl) = labels {
            if lbl
                .get("com.docker.compose.project")
                .and_then(|v| v.as_str())
                == Some(&project)
            {
                let id = c["Id"].as_str().unwrap_or_default();
                let name = c["Names"][0].as_str().unwrap_or(id).trim_start_matches('/');
                let stop_res = api
                    .request_raw("POST", &format!("/containers/{id}/stop?t=2"), None)
                    .await;
                if stop_res.is_ok() {
                    println!(" ✔ Container {name}  Stopped");
                }
                let del_res = api
                    .request_raw("DELETE", &format!("/containers/{id}?force=1"), None)
                    .await;
                if del_res.is_ok() {
                    println!(" ✔ Container {name}  Removed");
                } else if let Err(e) = del_res {
                    eprintln!(" ✖ Container {name}  Remove failed: {e}");
                }
            }
        }
    }

    let net_name = format!("{project}_default");
    let net_del = api
        .request_raw("DELETE", &format!("/networks/{net_name}"), None)
        .await;
    if net_del.is_ok() {
        println!(" ✔ Network {net_name}  Removed");
    }

    if remove_volumes {
        for vname in compose.volumes.keys() {
            let full_vname = format!("{project}_{vname}");
            let vol_del = api
                .request_raw("DELETE", &format!("/volumes/{full_vname}"), None)
                .await;
            if vol_del.is_ok() {
                println!(" ✔ Volume {full_vname}  Removed");
            }
        }
    }

    Ok(())
}

pub async fn ps(
    api: &ApiClient,
    file_opt: Option<&str>,
    proj_opt: Option<&str>,
    all: bool,
    profiles: &[String],
) -> Result<()> {
    let (compose_path, _) = resolve_compose_file(file_opt)?;
    let project = resolve_project_name(proj_opt, &compose_path);
    let active = active_profiles(profiles);
    if active.is_empty() {
        println!("Profiles: (none active)");
    } else {
        println!("Profiles: {}", active.join(", "));
    }

    let all_flag = if all { 1 } else { 0 };
    let containers: Vec<serde_json::Value> = api
        .get_json(&format!("/containers/json?all={all_flag}"))
        .await?;

    println!(
        "{:<25} {:<20} {:<15} {:<25} PORTS",
        "NAME", "IMAGE", "SERVICE", "STATUS"
    );

    for c in containers {
        let labels = c.get("Labels").and_then(|l| l.as_object());
        if let Some(lbl) = labels {
            if lbl
                .get("com.docker.compose.project")
                .and_then(|v| v.as_str())
                == Some(&project)
            {
                let name = c["Names"][0]
                    .as_str()
                    .unwrap_or("?")
                    .trim_start_matches('/');
                let image = c["Image"].as_str().unwrap_or("?");
                let service = lbl
                    .get("com.docker.compose.service")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let status = c["Status"].as_str().unwrap_or("?");
                let mut ports = Vec::new();
                if let Some(arr) = c.get("Ports").and_then(|p| p.as_array()) {
                    for p in arr {
                        if let (Some(pub_p), Some(priv_p), Some(typ)) = (
                            p.get("PublicPort").and_then(|v| v.as_i64()),
                            p.get("PrivatePort").and_then(|v| v.as_i64()),
                            p.get("Type").and_then(|v| v.as_str()),
                        ) {
                            ports.push(format!("0.0.0.0:{pub_p}->{priv_p}/{typ}"));
                        }
                    }
                }
                println!(
                    "{:<25} {:<20} {:<15} {:<25} {}",
                    name,
                    image,
                    service,
                    status,
                    ports.join(", ")
                );
            }
        }
    }
    Ok(())
}

pub async fn logs(
    api: &ApiClient,
    file_opt: Option<&str>,
    proj_opt: Option<&str>,
    follow: bool,
    services: &[String],
) -> Result<()> {
    let (compose_path, _) = resolve_compose_file(file_opt)?;
    let project = resolve_project_name(proj_opt, &compose_path);

    let containers: Vec<serde_json::Value> = api.get_json("/containers/json?all=1").await?;
    let mut matched = Vec::new();

    for c in &containers {
        let labels = c.get("Labels").and_then(|l| l.as_object());
        if let Some(lbl) = labels {
            if lbl
                .get("com.docker.compose.project")
                .and_then(|v| v.as_str())
                == Some(&project)
            {
                let sname = lbl
                    .get("com.docker.compose.service")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if services.is_empty() || services.contains(&sname) {
                    let id = c["Id"].as_str().unwrap_or_default().to_string();
                    let name = c["Names"][0]
                        .as_str()
                        .unwrap_or(&id)
                        .trim_start_matches('/')
                        .to_string();
                    matched.push((sname, name, id));
                }
            }
        }
    }

    if matched.is_empty() {
        println!("No containers found for project {project}");
        return Ok(());
    }

    if !follow {
        for (_sname, cname, id) in matched {
            let resp = api
                .request_raw(
                    "GET",
                    &format!("/containers/{id}/logs?stdout=1&stderr=1&tail=all"),
                    None,
                )
                .await?;
            let mut pending = resp.to_vec();
            while pending.len() >= 8 {
                let len =
                    u32::from_be_bytes([pending[4], pending[5], pending[6], pending[7]]) as usize;
                if pending.len() < 8 + len {
                    break;
                }
                let (_, payload) = crate::demux(&pending[..8 + len]);
                for line in String::from_utf8_lossy(payload).lines() {
                    println!("{cname} | {line}");
                }
                pending.drain(..8 + len);
            }
            if !pending.is_empty() {
                for line in String::from_utf8_lossy(&pending).lines() {
                    println!("{cname} | {line}");
                }
            }
        }
        return Ok(());
    }

    let mut tasks = Vec::new();
    for (_sname, cname, id) in matched {
        let api = api.clone();
        tasks.push(tokio::spawn(async move {
            let resp = api
                .request(
                    "GET",
                    &format!("/containers/{id}/logs?stdout=1&stderr=1&follow=1&tail=50"),
                    None,
                )
                .await;
            if let Ok(resp) = resp {
                let mut body = Box::pin(resp.into_body());
                let mut pending: Vec<u8> = Vec::new();
                while let Some(Ok(frame)) = body.frame().await {
                    let data = frame.data_ref().map(|b| b.as_ref()).unwrap_or(&[]);
                    pending.extend_from_slice(data);
                    while pending.len() >= 8 {
                        let len =
                            u32::from_be_bytes([pending[4], pending[5], pending[6], pending[7]])
                                as usize;
                        if pending.len() < 8 + len {
                            break;
                        }
                        let (_, payload) = crate::demux(&pending[..8 + len]);
                        for line in String::from_utf8_lossy(payload).lines() {
                            println!("{cname} | {line}");
                        }
                        pending.drain(..8 + len);
                    }
                }
            }
        }));
    }

    futures::future::join_all(tasks).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(deps: Option<DependsOnSpec>) -> ServiceConfig {
        ServiceConfig {
            depends_on: deps,
            ..Default::default()
        }
    }

    #[test]
    fn pull_policy_matrix() {
        use PullAction::*;
        // Default: build only when there is no image to pull.
        assert_eq!(decide_pull(None, true, true, false), Ok(PullIfMissing));
        assert_eq!(decide_pull(None, false, true, false), Ok(Build));
        assert_eq!(
            decide_pull(Some("missing"), true, false, false),
            Ok(PullIfMissing)
        );
        assert_eq!(
            decide_pull(Some("always"), true, true, false),
            Ok(PullAlways)
        );
        assert_eq!(decide_pull(Some("always"), false, true, false), Ok(Build));
        assert_eq!(
            decide_pull(Some("never"), true, false, false),
            Ok(RequireLocal)
        );
        assert_eq!(decide_pull(Some("build"), true, true, false), Ok(Build));
        assert_eq!(
            decide_pull(Some("build"), true, false, false),
            Ok(PullIfMissing)
        );
        // CLI --build always wins.
        assert_eq!(decide_pull(Some("never"), true, true, true), Ok(Build));
        // Unknown policies fail closed, never silent `missing`.
        assert!(decide_pull(Some("sometimes"), true, false, false).is_err());
    }

    #[test]
    fn condition_parsing() {
        assert!(dependency_conditions(None).unwrap().is_empty());
        let list = DependsOnSpec::List(vec!["db".into()]);
        assert_eq!(
            dependency_conditions(Some(&list)).unwrap(),
            vec![("db".to_string(), DepCondition::Started)]
        );
        let map = DependsOnSpec::Map(HashMap::from([
            (
                "db".to_string(),
                serde_json::json!({"condition": "service_healthy"}),
            ),
            (
                "mig".to_string(),
                serde_json::json!({"condition": "service_completed_successfully"}),
            ),
            ("cache".to_string(), serde_json::json!("service_started")),
        ]));
        assert_eq!(
            dependency_conditions(Some(&map)).unwrap(),
            vec![
                ("cache".to_string(), DepCondition::Started),
                ("db".to_string(), DepCondition::Healthy),
                ("mig".to_string(), DepCondition::Completed),
            ]
        );
        let bad = DependsOnSpec::Map(HashMap::from([(
            "db".to_string(),
            serde_json::json!({"condition": "service_eventually"}),
        )]));
        assert!(dependency_conditions(Some(&bad)).is_err());
    }

    #[test]
    fn topo_orders_dependencies_first() {
        let services = HashMap::from([
            (
                "web".to_string(),
                svc(Some(DependsOnSpec::List(vec!["db".into()]))),
            ),
            ("db".to_string(), svc(None)),
        ]);
        let order = topological_sort(&services).unwrap();
        assert!(order.iter().position(|s| s == "db") < order.iter().position(|s| s == "web"));
    }

    fn parse_compose(yaml: &str) -> ComposeFile {
        serde_yaml::from_str(yaml).expect("fixture must parse")
    }

    /// Unique scratch dir per test (rootless-safe: plain files, no daemon).
    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ingot-compose-test-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn profiles_gate_services() {
        let file = parse_compose(
            r#"
services:
  web:
    image: busybox:latest
  debug:
    image: busybox:latest
    profiles: [tools]
  extra:
    image: busybox:latest
    profiles: ["tools", "extra"]
"#,
        );
        let none: Vec<String> = vec![];
        assert!(service_enabled(&file.services["web"], &none));
        assert!(!service_enabled(&file.services["debug"], &none));
        let tools = vec!["tools".to_string()];
        assert!(service_enabled(&file.services["web"], &tools));
        assert!(service_enabled(&file.services["debug"], &tools));
        // Any-match: one active profile suffices for multi-profile services.
        assert!(service_enabled(&file.services["extra"], &tools));
        let other = vec!["unrelated".to_string()];
        assert!(!service_enabled(&file.services["extra"], &other));
    }

    #[test]
    fn profiles_merge_cli_and_env() {
        let cli = vec!["a".to_string(), "b,a".to_string()];
        // CLI flags merge with COMPOSE_PROFILES, comma-split, deduped.
        assert_eq!(
            active_profiles_from(&cli, Some("b, c ,")),
            vec!["a", "b", "c"]
        );
        assert_eq!(active_profiles_from(&[], None), Vec::<String>::new());
    }

    #[test]
    fn extends_local_file_merges_with_override_winning() {
        let dir = scratch_dir("extends");
        std::fs::write(
            dir.join("base.yaml"),
            r#"
services:
  app:
    image: busybox:1.0
    command: sleep 3600
    environment:
      FOO: base
      KEEP: "1"
"#,
        )
        .unwrap();
        let main_path = dir.join("compose.yaml");
        std::fs::write(
            &main_path,
            r#"
services:
  app:
    extends:
      file: base.yaml
      service: app
    image: busybox:2.0
    environment:
      FOO: override
"#,
        )
        .unwrap();
        let raw: ComposeFile =
            serde_yaml::from_str(&std::fs::read_to_string(&main_path).unwrap()).unwrap();
        let merged = apply_extends(&main_path, &raw).unwrap();
        let app = &merged.services["app"];
        // Override wins whole keys (shallow merge).
        assert_eq!(app.image.as_deref(), Some("busybox:2.0"));
        assert_eq!(
            app.command.as_ref().unwrap().to_vec(),
            vec!["sleep", "3600"]
        );
        let env = app.environment.clone().unwrap().to_vec();
        assert!(env.contains(&"FOO=override".to_string()), "{env:?}");
        // Shallow: the base-only KEEP entry does not survive a replaced map.
        assert!(!env.join(",").contains("KEEP"), "{env:?}");
        assert!(app.extends.is_none());
    }

    #[test]
    fn extends_same_file_and_chain() {
        let file = parse_compose(
            r#"
services:
  base:
    image: busybox:latest
    user: "1000"
  mid:
    extends: {service: base}
    command: sleep 1
  leaf:
    extends: {service: mid}
    working_dir: /app
"#,
        );
        let merged = apply_extends(Path::new("compose.yaml"), &file).unwrap();
        let leaf = &merged.services["leaf"];
        assert_eq!(leaf.image.as_deref(), Some("busybox:latest"));
        assert_eq!(leaf.user.as_deref(), Some("1000"));
        assert_eq!(leaf.working_dir.as_deref(), Some("/app"));
    }

    #[test]
    fn extends_rejects_remote_and_missing() {
        let file = parse_compose(
            r#"
services:
  app:
    extends:
      file: https://example.com/base.yaml
      service: app
"#,
        );
        let err = apply_extends(Path::new("compose.yaml"), &file).unwrap_err();
        assert!(format!("{err:#}").contains("remote URL"), "{err:#}");

        let file = parse_compose(
            r#"
services:
  app:
    extends:
      file: does-not-exist.yaml
      service: app
"#,
        );
        let err = apply_extends(Path::new("compose.yaml"), &file).unwrap_err();
        assert!(format!("{err:#}").contains("not found"), "{err:#}");

        let file = parse_compose(
            r#"
services:
  a:
    extends: {service: b}
  b:
    extends: {service: a}
"#,
        );
        let err = apply_extends(Path::new("compose.yaml"), &file).unwrap_err();
        assert!(format!("{err:#}").contains("cycle"), "{err:#}");
    }

    #[test]
    fn deploy_limits_map_to_create_fields() {
        let file = parse_compose(
            r#"
services:
  web:
    image: busybox:latest
    deploy:
      resources:
        limits:
          cpus: "0.50"
          memory: 512M
        reservations:
          cpus: "0.25"
          memory: 256M
  plain:
    image: busybox:latest
"#,
        );
        // 0.5 CPU -> 500M NanoCpus, 512MiB -> bytes; reservations ignored.
        assert_eq!(
            deploy_limits(file.services["web"].deploy.as_ref(), "web"),
            Ok((500_000_000, 512 * 1024 * 1024))
        );
        assert_eq!(
            deploy_limits(file.services["plain"].deploy.as_ref(), "plain"),
            Ok((0, 0))
        );
        assert_eq!(deploy_limits(None, "web"), Ok((0, 0)));
    }

    #[test]
    fn deploy_limits_reject_bad_values_naming_the_field() {
        for (yaml, field) in [
            (r#"cpus: lots"#, "deploy.resources.limits.cpus"),
            (r#"memory: 10XB"#, "deploy.resources.limits.memory"),
            (r#"memory: -5"#, "deploy.resources.limits.memory"),
        ] {
            let limits: ResourceLimits = serde_yaml::from_str(yaml).unwrap();
            let deploy = DeployConfig {
                resources: Some(DeployResources {
                    limits: Some(limits),
                    reservations: None,
                }),
            };
            let err = deploy_limits(Some(&deploy), "web").unwrap_err();
            assert!(err.contains(field), "missing {field:?} in {err:?}");
            assert!(err.contains("service web"), "{err:?}");
        }
        // Numeric forms also accepted.
        let limits: ResourceLimits = serde_yaml::from_str("cpus: 2\nmemory: 1024\n").unwrap();
        let deploy = DeployConfig {
            resources: Some(DeployResources {
                limits: Some(limits),
                reservations: None,
            }),
        };
        assert_eq!(
            deploy_limits(Some(&deploy), "web"),
            Ok((2_000_000_000, 1024))
        );
    }

    #[test]
    fn secrets_short_and_long_mount_read_only() {
        let dir = scratch_dir("secrets");
        std::fs::write(dir.join("db-pass.txt"), "s3cret").unwrap();
        let file = parse_compose(
            r#"
services:
  web:
    image: busybox:latest
    secrets:
      - db-pass
      - source: db-pass
        target: custom
        mode: 0o440
        uid: "1000"
        gid: "1000"
  worker:
    image: busybox:latest
    secrets:
      - source: env-only
  broken:
    image: busybox:latest
    secrets:
      - missing
secrets:
  db-pass:
    file: ./db-pass.txt
  env-only:
    environment: DB_PASS
"#,
        );
        let mounts = credential_mounts(
            "secrets",
            &file.services["web"].secrets,
            &file.secrets,
            "web",
            &dir,
        )
        .unwrap();
        assert_eq!(mounts.len(), 2);
        assert!(
            mounts[0].ends_with(":/run/secrets/db-pass:ro"),
            "{mounts:?}"
        );
        assert!(
            mounts[0].starts_with(dir.to_string_lossy().as_ref()),
            "{mounts:?}"
        );
        assert!(mounts[1].ends_with(":/run/secrets/custom:ro"), "{mounts:?}");
        // environment-sourced: explicit 501-style reason naming the service.
        let err = credential_mounts(
            "secrets",
            &file.services["worker"].secrets,
            &file.secrets,
            "worker",
            &dir,
        )
        .unwrap_err();
        assert!(err.contains("service worker"), "{err:?}");
        assert!(err.contains("501"), "{err:?}");
        // Undefined top-level name: explicit per-service error.
        let err = credential_mounts(
            "secrets",
            &file.services["broken"].secrets,
            &file.secrets,
            "broken",
            &dir,
        )
        .unwrap_err();
        assert!(err.contains("service broken"), "{err:?}");
        assert!(err.contains("missing"), "{err:?}");
    }

    #[test]
    fn configs_mount_at_root() {
        let dir = scratch_dir("configs");
        std::fs::write(dir.join("app.conf"), "key=1").unwrap();
        let file = parse_compose(
            r#"
services:
  web:
    image: busybox:latest
    configs:
      - source: app-conf
        target: app.conf
configs:
  app-conf:
    file: ./app.conf
"#,
        );
        let mounts = credential_mounts(
            "configs",
            &file.services["web"].configs,
            &file.configs,
            "web",
            &dir,
        )
        .unwrap();
        assert_eq!(mounts.len(), 1);
        assert!(mounts[0].ends_with(":/app.conf:ro"), "{mounts:?}");
    }
}
