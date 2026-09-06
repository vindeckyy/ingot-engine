//! Docker Compose implementation for Ingot CLI.
//! Supports `ingot compose up`, `down`, `ps`, `logs`.

use crate::client::ApiClient;
use anyhow::{anyhow, Context, Result};
use http_body_util::BodyExt;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ServiceConfig {
    pub image: Option<String>,
    pub build: Option<BuildSpec>,
    pub container_name: Option<String>,
    #[serde(default)]
    pub command: Option<StringOrList>,
    #[serde(default)]
    pub entrypoint: Option<StringOrList>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub environment: Option<EnvSpec>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub depends_on: Option<DependsOnSpec>,
    #[serde(default)]
    pub restart: Option<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BuildSpec {
    Simple(String),
    Detailed {
        context: Option<String>,
        dockerfile: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize, Default)]
// Compose-spec surface: honored by a future Phase 9 unit.
#[allow(dead_code)]
pub struct ComposeVolumeConfig {
    pub driver: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
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

pub async fn up(
    api: &ApiClient,
    file_opt: Option<&str>,
    proj_opt: Option<&str>,
    detach: bool,
    force_build: bool,
) -> Result<()> {
    let (compose_path, compose) = resolve_compose_file(file_opt)?;
    let project = resolve_project_name(proj_opt, &compose_path);
    let compose_dir = compose_path.parent().unwrap_or_else(|| Path::new("."));

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
    let _ = api
        .post::<serde_json::Value>("/networks/create", Some(net_body))
        .await;

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
        let _ = api
            .post::<serde_json::Value>("/volumes/create", Some(vol_body))
            .await;
    }

    // 3. Dependency order
    let sorted_services = topological_sort(&compose.services)?;

    let mut started_containers = Vec::new();

    // 4. Create & start each service container
    for service_name in &sorted_services {
        let s = &compose.services[service_name];

        // Determine image
        let image = if force_build || (s.image.is_none() && s.build.is_some()) {
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
            if api
                .get_json::<serde_json::Value>(&inspect_path)
                .await
                .is_err()
            {
                println!("Pulling {img}...");
                crate::commands::pull(api, img, None).await?;
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
        started_containers.push((service_name.clone(), cname));
    }

    if detach {
        return Ok(());
    }

    println!("[+] All services started. Press Ctrl+C to stop.");
    let services: Vec<String> = compose.services.keys().cloned().collect();
    logs(api, file_opt, proj_opt, true, &services).await
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
                let _ = api
                    .request_raw("POST", &format!("/containers/{id}/stop?t=2"), None)
                    .await;
                let _ = api
                    .request_raw("DELETE", &format!("/containers/{id}?force=1"), None)
                    .await;
                println!(" ✔ Container {name}  Removed");
            }
        }
    }

    let net_name = format!("{project}_default");
    let _ = api
        .request_raw("DELETE", &format!("/networks/{net_name}"), None)
        .await;
    println!(" ✔ Network {net_name}  Removed");

    if remove_volumes {
        for vname in compose.volumes.keys() {
            let full_vname = format!("{project}_{vname}");
            let _ = api
                .request_raw("DELETE", &format!("/volumes/{full_vname}"), None)
                .await;
            println!(" ✔ Volume {full_vname}  Removed");
        }
    }

    Ok(())
}

pub async fn ps(
    api: &ApiClient,
    file_opt: Option<&str>,
    proj_opt: Option<&str>,
    all: bool,
) -> Result<()> {
    let (compose_path, _) = resolve_compose_file(file_opt)?;
    let project = resolve_project_name(proj_opt, &compose_path);

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
