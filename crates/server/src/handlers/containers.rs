//! /containers/* — create, start, stop, kill, wait, inspect, list, logs,
//! pause/unpause, restart, remove.

use crate::handlers::{bad_request, not_found, server_error};
use crate::state::SharedState;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use futures::StreamExt;
use ingot_api::{
    ContainerConfig, ContainerCreateBody, ContainerInspect, ContainerPathStat, ContainerState,
    ContainerSummary, ContainersPruneReport, EndpointSettings, GraphDriverData, MountPoint,
    NetworkSettingsInspect, Port, PortMapping, SummaryHostConfig, SummaryNetworkSettings,
    WaitResponse,
};
use ingot_runtime::overlay;
use ingot_runtime::record::StateStatus;
use ingot_store::paths::DataPaths;
use serde_json::json;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use tokio::sync::broadcast;

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct CreateQuery {
    name: Option<String>,
    platform: Option<String>,
}

/// POST /containers/create
pub async fn create(
    State(state): State<SharedState>,
    Query(q): Query<CreateQuery>,
    body: axum::body::Bytes,
) -> Response {
    let req: ContainerCreateBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!("create body rejected: {e}; body_len={}", body.len());
            return bad_request(format!("invalid container config: {e}"));
        }
    };
    let mgr = match state.containers.as_ref() {
        Some(m) => m,
        None => return server_error("container manager not ready"),
    };
    let image_name = req.Image.clone();
    match mgr.create(&image_name, req, q.name, q.platform).await {
        Ok(handle) => {
            let id = handle.id();
            (
                StatusCode::CREATED,
                axum::Json(json!({
                    "Id": id,
                    "Warnings": [],
                })),
            )
                .into_response()
        }
        // Typed mapping per the error taxonomy (Plan Phase 0, unit 0.2):
        // validation/rejected options are 400, unknown names/ids 404,
        // name conflicts 409, unexpected failures 500.
        Err(e) => match e {
            ingot_runtime::error::CreateError::Conflict(name) => crate::handlers::conflict(
                format!("Conflict. The container name \"/{name}\" is already in use"),
            ),
            ingot_runtime::error::CreateError::NotFound(msg) => {
                crate::handlers::not_found(format!("{msg:#}"))
            }
            ingot_runtime::error::CreateError::BadRequest(msg)
            | ingot_runtime::error::CreateError::Unsupported(msg) => {
                crate::handlers::bad_request(format!("{msg:#}"))
            }
            ingot_runtime::error::CreateError::Internal(e) => {
                crate::handlers::server_error(format!("{e:#}"))
            }
            ingot_runtime::error::CreateError::Io(e) => {
                crate::handlers::server_error(format!("{e:#}"))
            }
        },
    }
}

/// POST /containers/{id}/start
pub async fn start(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    match mgr.start(&id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => not_found_or(format!("{e:#}")),
    }
}

fn not_found_or(msg: String) -> Response {
    if msg.contains("No such container") {
        not_found(msg)
    } else {
        server_error(msg)
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct StopQuery {
    #[serde(rename = "t")]
    timeout: Option<i64>,
    signal: Option<String>,
}

/// POST /containers/{id}/stop
pub async fn stop(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<StopQuery>,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    if let Some(t) = q.timeout {
        if t < 0 {
            return bad_request("stop timeout must not be negative");
        }
    }
    // `?signal=` overrides the container's StopSignal for this stop.
    let signal = match q.signal.as_deref() {
        None => None,
        Some(s) => match ingot_runtime::error::parse_signal(s) {
            Ok(n) => Some(n),
            Err(e) => return bad_request(format!("invalid stop signal: {e}")),
        },
    };
    match mgr.stop(&id, q.timeout, signal).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => not_found_or(format!("{e:#}")),
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct KillQuery {
    signal: Option<String>,
}

/// POST /containers/{id}/kill
pub async fn kill(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<KillQuery>,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    // Strict parsing (unit 2.2): unknown signals are 400, never silent
    // SIGTERM. No signal defaults to SIGKILL, matching docker.
    let sig = match q.signal.as_deref() {
        None => libc::SIGKILL,
        Some(s) => match ingot_runtime::error::parse_signal(s) {
            Ok(n) => n,
            Err(e) => return bad_request(format!("invalid signal: {e}")),
        },
    };
    match mgr.kill(&id, sig).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("No such container") {
                crate::handlers::not_found(msg)
            } else if msg.contains("not running") {
                crate::handlers::conflict(msg)
            } else {
                crate::handlers::server_error(msg)
            }
        }
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct WaitQuery {
    condition: Option<String>,
}

/// POST /containers/{id}/wait
pub async fn wait(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(_q): Query<WaitQuery>,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let handle = match mgr.get(&id).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("No such container: {id}")),
    };
    if !handle.is_running() {
        let code = handle.state.lock().unwrap().exit_code;
        return axum::Json(WaitResponse {
            StatusCode: code,
            Error: None,
        })
        .into_response();
    }
    let mut rx = handle.subscribe_exit();
    match rx.recv().await {
        Ok(code) => axum::Json(WaitResponse {
            StatusCode: code,
            Error: None,
        })
        .into_response(),
        Err(e) => server_error(format!("wait: {e}")),
    }
}

/// `GET /containers/json` filter set (Plan Phase 1, unit 1.2).
/// Unknown filter keys are an explicit 400, never a silent ignore.
#[derive(Debug, Default)]
struct ListFilters {
    status: Vec<String>,
    name: Vec<String>,
    label: Vec<String>,
    ancestor: Vec<String>,
    network: Vec<String>,
    volume: Vec<String>,
}

// `Response` is large by nature; this is a cold error path, not a hot loop.
#[allow(clippy::result_large_err)]
fn parse_list_filters(raw: Option<&str>) -> Result<ListFilters, Response> {
    let mut f = ListFilters::default();
    let Some(raw) = raw else { return Ok(f) };
    if raw.trim().is_empty() {
        return Ok(f);
    }
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| bad_request(format!("invalid filters: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| bad_request("invalid filters: expected a JSON object"))?;
    for (k, vals) in obj {
        let vals: Vec<String> = vals
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        match k.as_str() {
            "status" => f.status = vals,
            "name" => f.name = vals,
            "label" => f.label = vals,
            "ancestor" => f.ancestor = vals,
            "network" => f.network = vals,
            "volume" => f.volume = vals,
            // Explicitly unsupported (documented): id, before/since,
            // exited, health, isolation, is-task.
            other => {
                return Err(bad_request(format!(
                    "invalid filter '{other}' (supported: status, name, label, ancestor, network, volume)"
                )));
            }
        }
    }
    Ok(f)
}

fn match_label(labels: &HashMap<String, String>, want: &str) -> bool {
    match want.split_once('=') {
        Some((k, v)) => labels.get(k).is_some_and(|got| got == v),
        None => labels.contains_key(want),
    }
}

/// GET /containers/json
pub async fn list(State(state): State<SharedState>, Query(q): Query<ListQuery>) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let all = q.all.unwrap_or(false);
    let filters = match parse_list_filters(q.filters.as_deref()) {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    let mut out: Vec<ContainerSummary> = Vec::new();
    for record in mgr.list_records().await {
        let st: ingot_runtime::record::ContainerState =
            if let Ok(Some(h)) = mgr.get(&record.id).await {
                h.state.lock().unwrap().clone()
            } else {
                ingot_store::read_json(&state.paths.container_state(&record.id)).unwrap_or_default()
            };
        let running = st.status == StateStatus::Running;
        if !all && !running && q.limit.is_none() {
            continue;
        }
        let status = match st.status {
            StateStatus::Running => {
                let up = uptime_str(&st.started_at);
                match &st.health {
                    Some(h) if h.Status == "healthy" => format!("Up {up} (healthy)"),
                    Some(h) if h.Status == "unhealthy" => format!("Up {up} (unhealthy)"),
                    Some(h) if h.Status == "starting" => format!("Up {up} (health: starting)"),
                    _ => format!("Up {up}"),
                }
            }
            StateStatus::Exited => {
                let at = st.finished_at.clone();
                let ago = uptime_str(&at);
                format!("Exited ({}) {} ago", st.exit_code, ago)
            }
            StateStatus::Created => "Created".to_string(),
            StateStatus::Paused => "Up (Paused)".to_string(),
            other => other.as_str().to_string(),
        };
        // Filters (unit 1.2): every key is AND, values within a key are OR.
        if !filters.status.is_empty() && !filters.status.iter().any(|s| s == st.status.as_str()) {
            continue;
        }
        if !filters.name.is_empty() && !filters.name.iter().any(|n| record.name.contains(n)) {
            continue;
        }
        if !filters.label.is_empty()
            && !filters
                .label
                .iter()
                .any(|l| match_label(&record.config.Labels, l))
        {
            continue;
        }
        if !filters.ancestor.is_empty()
            && !filters.ancestor.iter().any(|a| {
                record.image_name == *a
                    || record.image_id == *a
                    || record.image_id.strip_prefix("sha256:").unwrap_or("") == a
            })
        {
            continue;
        }
        if !filters.network.is_empty()
            && !filters.network.iter().any(|n| {
                record
                    .endpoints
                    .iter()
                    .any(|e| e.network_name == *n || e.network_id == *n)
            })
        {
            continue;
        }
        if !filters.volume.is_empty()
            && !filters
                .volume
                .iter()
                .any(|v| record.mounts.iter().any(|m| m.source == *v || m.name == *v))
        {
            continue;
        }
        let mut ports: Vec<Port> = record
            .hostconfig
            .PortBindings
            .iter()
            .flat_map(|(k, v)| {
                let (private, typ) = parse_port_key(k);
                v.iter().map(move |b| Port {
                    IP: if b.HostIp.is_empty() {
                        "0.0.0.0".to_string()
                    } else {
                        b.HostIp.clone()
                    },
                    PrivatePort: private,
                    PublicPort: b.HostPort.parse().ok(),
                    Type: typ.clone(),
                })
            })
            .collect();
        // Overlay live rules for ephemeral/`-P` mappings (see inspect).
        if let Some(netmgr) = state.networks.as_ref() {
            for r in netmgr.published_for(&record.id).await {
                let ip = if r.host_ip.is_empty() {
                    "0.0.0.0".to_string()
                } else {
                    r.host_ip.clone()
                };
                let known = ports.iter().any(|p| {
                    p.PrivatePort == r.container_port
                        && p.Type == r.proto
                        && p.PublicPort == Some(r.host_port)
                });
                if known {
                    continue;
                }
                if let Some(slot) = ports.iter_mut().find(|p| {
                    p.PrivatePort == r.container_port && p.Type == r.proto && p.PublicPort.is_none()
                }) {
                    slot.PublicPort = Some(r.host_port);
                    slot.IP = ip;
                } else {
                    ports.push(Port {
                        IP: ip,
                        PrivatePort: r.container_port,
                        PublicPort: Some(r.host_port),
                        Type: r.proto.clone(),
                    });
                }
            }
        }
        let networks = record
            .endpoints
            .iter()
            .map(|e| {
                (
                    e.network_name.clone(),
                    EndpointSettings {
                        IPAddress: e.ip.clone(),
                        Gateway: e.gateway.clone(),
                        NetworkID: e.network_id.clone(),
                        Aliases: e.aliases.clone(),
                        ..Default::default()
                    },
                )
            })
            .collect();
        out.push(ContainerSummary {
            Id: record.id.clone(),
            Names: vec![format!("/{}", record.name)],
            Image: record.image_name.clone(),
            ImageID: record.image_id.clone(),
            Command: record.cmd_display.clone(),
            Created: chrono::DateTime::parse_from_rfc3339(&record.created)
                .map(|d| d.timestamp())
                .unwrap_or(0),
            Ports: ports,
            Labels: record.config.Labels.clone(),
            State: st.status.as_str().into(),
            Status: status,
            HostConfig: Some(SummaryHostConfig {
                NetworkMode: record.hostconfig.NetworkMode.clone(),
            }),
            NetworkSettings: Some(SummaryNetworkSettings { Networks: networks }),
            Mounts: Some(
                record
                    .mounts
                    .iter()
                    .map(|m| MountPoint {
                        typ: m.typ.clone(),
                        Name: m.name.clone(),
                        Source: m.source.clone(),
                        Destination: m.destination.clone(),
                        Driver: if m.typ == "volume" {
                            "local".into()
                        } else {
                            String::new()
                        },
                        Mode: if m.read_only {
                            "ro".into()
                        } else {
                            "rw".into()
                        },
                        RW: !m.read_only,
                        Propagation: String::new(),
                    })
                    .collect(),
            ),
        });
    }
    if let Some(l) = q.limit {
        out.truncate(l as usize);
    }
    axum::Json(out).into_response()
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct ListQuery {
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    all: Option<bool>,
    limit: Option<i64>,
    // Accepted for API compatibility; per-container size accounting lands
    // in Plan Phase 1 (unit 1.2, with /system/df).
    #[allow(dead_code)]
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    size: Option<bool>,
    filters: Option<String>,
}

fn parse_port_key(k: &str) -> (u16, String) {
    match k.split_once('/') {
        Some((p, t)) => (p.parse().unwrap_or(0), t.to_string()),
        None => (k.parse().unwrap_or(0), "tcp".to_string()),
    }
}

/// Overlay live published rules onto request-based port rendering:
/// ephemeral/auto-assigned host ports and `-P` expansions exist only in
/// the network manager's published set. Explicit bindings already carry
/// their host port and are left untouched.
async fn overlay_published_ports(
    state: &SharedState,
    container_id: &str,
    ports: &mut HashMap<String, Option<Vec<PortMapping>>>,
) {
    let Some(netmgr) = state.networks.as_ref() else {
        return;
    };
    for r in netmgr.published_for(container_id).await {
        let key = format!("{}/{}", r.container_port, r.proto);
        let mapping = PortMapping {
            HostIp: r.host_ip.clone(),
            HostPort: r.host_port.to_string(),
        };
        match ports.get_mut(&key) {
            Some(Some(v)) => {
                if v.iter()
                    .any(|m| m.HostIp == mapping.HostIp && m.HostPort == mapping.HostPort)
                {
                    continue;
                }
                if let Some(slot) = v.iter_mut().find(|m| m.HostPort.is_empty()) {
                    *slot = mapping;
                } else {
                    v.push(mapping);
                }
            }
            _ => {
                ports.insert(key, Some(vec![mapping]));
            }
        }
    }
}

fn uptime_str(since: &str) -> String {
    let started = chrono::DateTime::parse_from_rfc3339(since)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let secs = (chrono::Utc::now() - started).num_seconds().max(0);
    if secs < 60 {
        format!("{secs} seconds")
    } else if secs < 3600 {
        let m = secs / 60;
        format!("{m} minute{}", if m == 1 { "" } else { "s" })
    } else if secs < 86400 {
        let h = secs / 3600;
        format!("{h} hour{}", if h == 1 { "" } else { "s" })
    } else {
        let d = secs / 86400;
        format!("{d} day{}", if d == 1 { "" } else { "s" })
    }
}

/// GET /containers/{id}/json
pub async fn inspect(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let handle = match mgr.get(&id).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("No such container: {id}")),
    };
    let record = handle.record.lock().unwrap().clone();
    let st = handle.state.lock().unwrap().clone();
    let mut mounts: Vec<MountPoint> = record
        .mounts
        .iter()
        .map(|m| MountPoint {
            typ: m.typ.clone(),
            Name: m.name.clone(),
            Source: m.source.clone(),
            Destination: m.destination.clone(),
            Driver: if m.typ == "volume" {
                "local".into()
            } else {
                String::new()
            },
            Mode: if m.read_only {
                "ro".into()
            } else {
                "rw".into()
            },
            RW: !m.read_only,
            Propagation: "rprivate".into(),
        })
        .collect();
    mounts.sort_by(|a, b| a.Destination.cmp(&b.Destination));

    let mut ports: HashMap<String, Option<Vec<PortMapping>>> = HashMap::new();
    for (k, v) in &record.hostconfig.PortBindings {
        ports.insert(
            k.clone(),
            Some(
                v.iter()
                    .map(|b| PortMapping {
                        HostIp: b.HostIp.clone(),
                        HostPort: b.HostPort.clone(),
                    })
                    .collect(),
            ),
        );
    }
    // Overlay live published rules: ephemeral/auto-assigned host ports
    // and `-P` expansions exist only in the network manager.
    overlay_published_ports(&state, &record.id, &mut ports).await;

    let argv = record.argv();
    let networks = record
        .endpoints
        .iter()
        .map(|e| {
            (
                e.network_name.clone(),
                EndpointSettings {
                    IPAddress: e.ip.clone(),
                    Gateway: e.gateway.clone(),
                    NetworkID: e.network_id.clone(),
                    Aliases: e.aliases.clone(),
                    ..Default::default()
                },
            )
        })
        .collect();

    let inspect = ContainerInspect {
        Id: record.id.clone(),
        Created: record.created.clone(),
        Path: argv.first().cloned().unwrap_or_default(),
        Args: argv.iter().skip(1).cloned().collect(),
        State: ContainerState {
            Status: st.status.as_str().into(),
            Running: st.status == StateStatus::Running,
            Paused: st.status == StateStatus::Paused,
            Restarting: false,
            OOMKilled: st.oom_killed,
            Dead: st.status == StateStatus::Dead,
            Pid: st.pid,
            ExitCode: st.exit_code,
            Error: st.error.clone(),
            StartedAt: st.started_at.clone(),
            FinishedAt: st.finished_at.clone(),
            Health: st.health.clone(),
        },
        Image: record.image_id.clone(),
        ResolvConfPath: state
            .paths
            .container_resolv(&record.id)
            .display()
            .to_string(),
        HostnamePath: state
            .paths
            .container_hostname(&record.id)
            .display()
            .to_string(),
        HostsPath: state
            .paths
            .container_hosts(&record.id)
            .display()
            .to_string(),
        LogPath: state.paths.container_log(&record.id).display().to_string(),
        Name: format!("/{}", record.name),
        RestartCount: st.restart_count,
        Driver: "overlay2".into(),
        Platform: "linux".into(),
        MountLabel: String::new(),
        ProcessLabel: String::new(),
        AppArmorProfile: String::new(),
        ExecIDs: None,
        HostConfig: record.hostconfig.clone(),
        GraphDriver: GraphDriverData {
            Name: "overlay2".into(),
            Data: HashMap::new(),
        },
        Mounts: mounts,
        Config: ContainerConfig {
            Hostname: record.config.Hostname.clone(),
            Image: record.image_name.clone(),
            ..record.config.clone()
        },
        NetworkSettings: NetworkSettingsInspect {
            Ports: ports,
            IPAddress: record
                .endpoints
                .first()
                .map(|e| e.ip.clone())
                .unwrap_or_default(),
            IPPrefixLen: 16,
            Gateway: record
                .endpoints
                .first()
                .map(|e| e.gateway.clone())
                .unwrap_or_default(),
            Bridge: state.config.default_bridge_name.clone(),
            SandboxKey: format!("/var/run/netns/{}", record.id),
            Networks: networks,
            ..Default::default()
        },
    };
    axum::Json(inspect).into_response()
}

/// DELETE /containers/{id}?force=&v=
#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct RemoveQuery {
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    force: Option<bool>,
    // Accepted for API compatibility; anonymous-volume removal on rm lands
    // in Plan Phase 7 (unit 7.3).
    #[allow(dead_code)]
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    v: Option<bool>,
    // Accepted for API compatibility; legacy links are unsupported and
    // ignored (documented in Plan Phase 1).
    #[allow(dead_code)]
    link: Option<bool>,
}

pub async fn remove(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<RemoveQuery>,
) -> Response {
    if q.link == Some(true) {
        return bad_request("legacy links are not supported");
    }
    let mgr = state.containers.as_ref().unwrap();
    match mgr
        .remove(&id, q.force.unwrap_or(false), q.v.unwrap_or(false))
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => not_found_or(format!("{e:#}")),
    }
}

/// POST /containers/{id}/pause | /unpause
fn pause_state_error(msg: String) -> Response {
    if msg.contains("No such container") {
        not_found(msg)
    } else if msg.contains("already paused")
        || msg.contains("not running")
        || msg.contains("not paused")
    {
        crate::handlers::conflict(msg)
    } else {
        server_error(msg)
    }
}

pub async fn pause(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    match mgr.pause(&id, true).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => pause_state_error(format!("{e:#}")),
    }
}

pub async fn unpause(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    match mgr.pause(&id, false).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => pause_state_error(format!("{e:#}")),
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct LogsQuery {
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    follow: Option<bool>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    stdout: Option<bool>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    stderr: Option<bool>,
    since: Option<String>,
    until: Option<String>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    timestamps: Option<bool>,
    tail: Option<String>,
}

/// GET /containers/{id}/logs — json-file driver with docker's multiplexed
/// framing for non-tty containers.
pub async fn logs(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let handle = match mgr.get(&id).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("No such container: {id}")),
    };
    let record = handle.record.lock().unwrap().clone();
    let want_out = q.stdout.unwrap_or(false) || q.stderr.is_none();
    let want_err = q.stderr.unwrap_or(false) || q.stdout.is_none();
    let tail_all = matches!(q.tail.as_deref(), None | Some("all") | Some(""));
    let tail_n: usize = if tail_all {
        usize::MAX
    } else {
        q.tail
            .as_deref()
            .and_then(|t| t.parse().ok())
            .unwrap_or(usize::MAX)
    };
    let since = q
        .since
        .as_deref()
        .and_then(parse_log_time)
        .map(|d| d.timestamp());
    let until = q
        .until
        .as_deref()
        .and_then(parse_log_time)
        .map(|d| d.timestamp());
    let timestamps = q.timestamps.unwrap_or(false);

    // Read historical lines.
    let log_path = state.paths.container_log(&record.id);
    let raw = std::fs::read(&log_path).unwrap_or_default();
    let mut lines: Vec<(u8, Vec<u8>, String)> = Vec::new();
    for line in raw.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) {
            let stream = if v["stream"] == "stderr" {
                ingot_runtime::stdio::STREAM_STDERR
            } else {
                ingot_runtime::stdio::STREAM_STDOUT
            };
            let time = v["time"].as_str().unwrap_or("").to_string();
            let ts = parse_log_time(&time).map(|d| d.timestamp()).unwrap_or(0);
            if since.is_some_and(|s| ts < s) {
                continue;
            }
            if until.is_some_and(|u| ts > u) {
                continue;
            }
            let log_text = v["log"].as_str().unwrap_or("").to_string();
            let data = if timestamps && !log_text.is_empty() {
                let mut out = format!("{time} ").into_bytes();
                out.extend_from_slice(log_text.as_bytes());
                out
            } else {
                log_text.into_bytes()
            };
            let keep = (stream == ingot_runtime::stdio::STREAM_STDOUT && want_out)
                || (stream == ingot_runtime::stdio::STREAM_STDERR && want_err);
            if keep {
                lines.push((stream, data, time));
            }
        }
    }
    if !tail_all && lines.len() > tail_n {
        lines.drain(..lines.len() - tail_n);
    }

    let tty = record.config.Tty;
    let mut body_bytes: Vec<u8> = Vec::new();
    for (stream, data, _time) in &lines {
        if tty {
            body_bytes.extend_from_slice(data);
            if !data.ends_with(b"\n") {
                body_bytes.push(b'\n');
            }
        } else {
            body_bytes.extend_from_slice(&ingot_runtime::stdio::frame(*stream, data));
        }
    }

    if !q.follow.unwrap_or(false) {
        return Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                "application/vnd.docker.multiplexed-stream",
            )
            .body(Body::from(body_bytes))
            .unwrap();
    }

    // Follow: initial lines + live stream.
    let rx = handle.stdio.subscribe();
    let initial: Vec<Result<axum::body::Bytes, std::io::Error>> =
        vec![Ok(axum::body::Bytes::from(body_bytes))];
    let stream = futures::stream::iter(initial).chain(futures::stream::unfold(
        (rx, until, timestamps),
        move |(mut rx, until, timestamps)| async move {
            loop {
                if until.is_some_and(|u| chrono::Utc::now().timestamp() > u) {
                    return None;
                }
                match rx.recv().await {
                    Ok((stream, data)) => {
                        let keep = (stream == ingot_runtime::stdio::STREAM_STDOUT && want_out)
                            || (stream == ingot_runtime::stdio::STREAM_STDERR && want_err);
                        if !keep {
                            continue;
                        }
                        let data = if timestamps {
                            let ts = ingot_util::now_rfc3339();
                            let mut out = format!("{ts} ").into_bytes();
                            out.extend_from_slice(&data);
                            out
                        } else {
                            data
                        };
                        let frame = if tty {
                            let mut out = data;
                            if !out.ends_with(b"\n") {
                                out.push(b'\n');
                            }
                            axum::body::Bytes::from(out)
                        } else {
                            ingot_runtime::stdio::frame(stream, &data)
                        };
                        return Some((Ok(frame), (rx, until, timestamps)));
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => {
                        return Some((
                            Err(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "closed",
                            )),
                            (rx, until, timestamps),
                        ));
                    }
                }
            }
        },
    ));
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "application/vnd.docker.multiplexed-stream",
        )
        .body(Body::from_stream(stream))
        .unwrap()
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct RestartQuery {
    #[serde(rename = "t")]
    timeout: Option<i64>,
}

/// POST /containers/{id}/restart
pub async fn restart(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<RestartQuery>,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    match mgr.restart(&id, q.timeout).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("No such container") {
                not_found(msg)
            } else {
                server_error(msg)
            }
        }
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct TopQuery {
    pub ps_args: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ContainerTopResponse {
    #[serde(rename = "Titles")]
    pub titles: Vec<String>,
    #[serde(rename = "Processes")]
    pub processes: Vec<Vec<String>>,
}

/// GET /containers/{id}/top
pub async fn top(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(_q): Query<TopQuery>,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let handle = match mgr.get(&id).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("No such container: {id}")),
    };
    let st = handle.state.lock().unwrap().clone();
    if st.status != StateStatus::Running {
        return (
            StatusCode::CONFLICT,
            axum::Json(json!({"message": format!("Container {id} is not running")})),
        )
            .into_response();
    }

    let record = handle.record.lock().unwrap().clone();
    let titles = vec![
        "UID".into(),
        "PID".into(),
        "PPID".into(),
        "C".into(),
        "STIME".into(),
        "TTY".into(),
        "TIME".into(),
        "CMD".into(),
    ];

    let procs_path = format!("/sys/fs/cgroup/ingot.slice/{}/cgroup.procs", record.id);
    let mut pids = Vec::new();
    if let Ok(content) = std::fs::read_to_string(&procs_path) {
        for line in content.lines() {
            if let Ok(p) = line.trim().parse::<i64>() {
                pids.push(p);
            }
        }
    }
    if pids.is_empty() && st.pid > 0 {
        pids.push(st.pid);
    }

    let mut processes = Vec::new();
    for pid in pids {
        let status_path = format!("/proc/{pid}/status");
        let cmdline_path = format!("/proc/{pid}/cmdline");

        let mut uid = "0".to_string();
        let mut ppid = "0".to_string();

        if let Ok(status_str) = std::fs::read_to_string(&status_path) {
            for line in status_str.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(first_uid) = rest.split_whitespace().next() {
                        uid = if first_uid == "0" {
                            "root".into()
                        } else {
                            first_uid.to_string()
                        };
                    }
                } else if let Some(rest) = line.strip_prefix("PPid:") {
                    if let Some(first_ppid) = rest.split_whitespace().next() {
                        ppid = first_ppid.to_string();
                    }
                }
            }
        }

        let cmd = if let Ok(cmd_bytes) = std::fs::read(&cmdline_path) {
            let parts: Vec<&str> = cmd_bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| std::str::from_utf8(s).ok())
                .collect();
            if parts.is_empty() {
                format!("[{pid}]")
            } else {
                parts.join(" ")
            }
        } else {
            format!("[{pid}]")
        };

        processes.push(vec![
            uid,
            pid.to_string(),
            ppid,
            "0".to_string(),
            "00:00".to_string(),
            "?".to_string(),
            "00:00:00".to_string(),
            cmd,
        ]);
    }

    axum::Json(ContainerTopResponse { titles, processes }).into_response()
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct StatsQuery {
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    pub stream: Option<bool>,
    #[serde(
        rename = "one-shot",
        deserialize_with = "ingot_api::de::flexible_bool",
        default
    )]
    pub one_shot: Option<bool>,
}

/// Parse the RFC 3339 timestamps used in json-file log records.
fn parse_log_time(s: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(s).ok()
}

fn sample_stats(
    id: &str,
    name: &str,
    pid: i64,
    prev: Option<&ingot_api::ContainerStats>,
) -> ingot_api::ContainerStats {
    let slice_dir = std::path::PathBuf::from(format!("/sys/fs/cgroup/ingot.slice/{id}"));

    let usage = std::fs::read_to_string(slice_dir.join("memory.current"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let limit = std::fs::read_to_string(slice_dir.join("memory.max"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            if let Ok(mem) = std::fs::read_to_string("/proc/meminfo") {
                for line in mem.lines() {
                    if let Some(rest) = line.strip_prefix("MemTotal:") {
                        let kb = rest
                            .trim()
                            .trim_end_matches(" kB")
                            .parse::<u64>()
                            .unwrap_or(0);
                        return kb * 1024;
                    }
                }
            }
            1024 * 1024 * 1024
        });

    let pids_current = std::fs::read_to_string(slice_dir.join("pids.current"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(if pid > 0 { 1 } else { 0 });

    let mut cpu_usec = 0u64;
    let mut system_usec = 0u64;
    let mut user_usec = 0u64;
    if let Ok(cpu_stat) = std::fs::read_to_string(slice_dir.join("cpu.stat")) {
        for line in cpu_stat.lines() {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("usage_usec"), Some(val)) => cpu_usec = val.parse().unwrap_or(0),
                (Some("user_usec"), Some(val)) => user_usec = val.parse().unwrap_or(0),
                (Some("system_usec"), Some(val)) => system_usec = val.parse().unwrap_or(0),
                _ => {}
            }
        }
    }

    let mut system_cpu_usage = 0u64;
    if let Ok(stat) = std::fs::read_to_string("/proc/stat") {
        if let Some(first_line) = stat.lines().next() {
            if first_line.starts_with("cpu ") {
                let ticks: u64 = first_line
                    .split_whitespace()
                    .skip(1)
                    .filter_map(|s| s.parse::<u64>().ok())
                    .sum();
                system_cpu_usage = ticks.saturating_mul(10_000_000);
            }
        }
    }

    let online_cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1);

    let total_usage = cpu_usec.saturating_mul(1000);

    let mut networks = HashMap::new();
    if pid > 0 {
        if let Ok(net_dev) = std::fs::read_to_string(format!("/proc/{pid}/net/dev")) {
            for line in net_dev.lines().skip(2) {
                if let Some((iface, metrics)) = line.split_once(':') {
                    let iface = iface.trim().to_string();
                    if iface != "lo" {
                        let cols: Vec<u64> = metrics
                            .split_whitespace()
                            .filter_map(|s| s.parse::<u64>().ok())
                            .collect();
                        if cols.len() >= 16 {
                            networks.insert(
                                iface,
                                ingot_api::NetworkStats {
                                    rx_bytes: cols[0],
                                    rx_packets: cols[1],
                                    rx_errors: cols[2],
                                    rx_dropped: cols[3],
                                    tx_bytes: cols[8],
                                    tx_packets: cols[9],
                                    tx_errors: cols[10],
                                    tx_dropped: cols[11],
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    let now_str = ingot_util::now_rfc3339();
    let preread = prev
        .map(|p| p.read.clone())
        .unwrap_or_else(|| now_str.clone());

    ingot_api::ContainerStats {
        id: id.to_string(),
        name: format!("/{}", name),
        read: now_str.clone(),
        preread,
        pids_stats: ingot_api::PidsStats {
            current: pids_current,
            limit: 0,
        },
        networks,
        memory_stats: ingot_api::MemoryStats {
            usage,
            max_usage: usage,
            limit,
            stats: serde_json::json!({}),
        },
        cpu_stats: ingot_api::CpuStats {
            cpu_usage: ingot_api::CpuUsage {
                total_usage,
                percpu_usage: vec![],
                usage_in_kernelmode: system_usec.saturating_mul(1000),
                usage_in_usermode: user_usec.saturating_mul(1000),
            },
            system_cpu_usage,
            online_cpus,
            throttling_data: Default::default(),
        },
        precpu_stats: prev.map(|p| p.cpu_stats.clone()).unwrap_or_else(|| {
            // First sample: pre == current so the delta (and thus CPU %)
            // is zero, matching docker stats' first read.
            ingot_api::CpuStats {
                cpu_usage: ingot_api::CpuUsage {
                    total_usage,
                    percpu_usage: vec![],
                    usage_in_kernelmode: system_usec.saturating_mul(1000),
                    usage_in_usermode: user_usec.saturating_mul(1000),
                },
                system_cpu_usage,
                online_cpus,
                throttling_data: Default::default(),
            }
        }),
    }
}

/// GET /containers/{id}/stats
pub async fn stats(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<StatsQuery>,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let handle = match mgr.get(&id).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("No such container: {id}")),
    };
    let (cid, cname, pid) = {
        let rec = handle.record.lock().unwrap();
        let st = handle.state.lock().unwrap();
        (rec.id.clone(), rec.name.clone(), st.pid)
    };

    let stream_mode = q.stream.unwrap_or(true) && !q.one_shot.unwrap_or(false);

    if !stream_mode {
        let stats = sample_stats(&cid, &cname, pid, None);
        return axum::Json(stats).into_response();
    }

    let stream = futures::stream::unfold(
        (None::<ingot_api::ContainerStats>, cid, cname, pid),
        |(prev_sample, cid, cname, pid)| async move {
            let cur = sample_stats(&cid, &cname, pid, prev_sample.as_ref());
            let next_prev = Some(cur.clone());
            let json_bytes = serde_json::to_vec(&cur).unwrap_or_default();
            let mut chunk = json_bytes;
            chunk.push(b'\n');
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            Some((
                Ok::<_, std::io::Error>(axum::body::Bytes::from(chunk)),
                (next_prev, cid, cname, pid),
            ))
        },
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .unwrap()
}

/// POST /containers/prune
pub async fn prune(State(state): State<SharedState>) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let records = mgr.list_records().await;

    let mut deleted = Vec::new();
    for r in records {
        let is_running = if let Ok(Some(h)) = mgr.get(&r.id).await {
            h.is_running()
        } else {
            false
        };
        if !is_running {
            if let Ok(()) = mgr.remove(&r.id, false, false).await {
                deleted.push(r.id);
            }
        }
    }

    let report = ContainersPruneReport {
        ContainersDeleted: if deleted.is_empty() {
            None
        } else {
            Some(deleted)
        },
        SpaceReclaimed: 0,
    };
    axum::Json(report).into_response()
}

struct OverlayGuard<'a> {
    paths: &'a DataPaths,
    container_id: &'a str,
    needs_unmount: bool,
}

impl<'a> Drop for OverlayGuard<'a> {
    fn drop(&mut self) {
        if self.needs_unmount {
            let _ = overlay::unmount_rootfs(self.paths, self.container_id);
        }
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct ArchiveGetQuery {
    pub path: String,
}

/// GET /containers/{id}/archive
pub async fn archive_get(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<ArchiveGetQuery>,
) -> Response {
    archive_handle(state, id, q.path, false).await
}

/// HEAD /containers/{id}/archive
pub async fn archive_head(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<ArchiveGetQuery>,
) -> Response {
    archive_handle(state, id, q.path, true).await
}

fn tar_dir_recursive<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    real_path: &std::path::Path,
    archive_prefix: &std::path::Path,
    seen_inodes: &mut std::collections::HashMap<(u64, u64), std::path::PathBuf>,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    builder.follow_symlinks(false);
    for entry in std::fs::read_dir(real_path)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let sub_archive = if archive_prefix.as_os_str().is_empty() {
            std::path::PathBuf::from(&file_name)
        } else {
            archive_prefix.join(&file_name)
        };
        let sym_meta = std::fs::symlink_metadata(entry.path())?;
        if sym_meta.file_type().is_symlink() {
            builder.append_path_with_name(entry.path(), &sub_archive)?;
        } else if sym_meta.is_dir() {
            builder.append_dir(&sub_archive, entry.path())?;
            tar_dir_recursive(builder, &entry.path(), &sub_archive, seen_inodes)?;
        } else {
            if sym_meta.nlink() > 1 {
                let key = (sym_meta.dev(), sym_meta.ino());
                if let Some(target_path) = seen_inodes.get(&key) {
                    let mut header = tar::Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Link);
                    header.set_size(0);
                    header.set_mode(sym_meta.permissions().mode());
                    let _ = header.set_link_name(target_path);
                    header.set_cksum();
                    builder.append_data(&mut header, &sub_archive, std::io::empty())?;
                    continue;
                }
                seen_inodes.insert(key, sub_archive.clone());
            }
            builder.append_path_with_name(entry.path(), &sub_archive)?;
        }
    }
    Ok(())
}

async fn archive_handle(
    state: SharedState,
    id: String,
    path_param: String,
    head_only: bool,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let handle = match mgr.get(&id).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("No such container: {id}")),
    };
    let record = handle.record.lock().unwrap().clone();
    let is_running = handle.is_running();

    if path_param.is_empty() {
        return bad_request("Path cannot be empty");
    }

    if !is_running {
        let img_id = record.image_id.trim_start_matches("sha256:");
        let image = match mgr.images.load(img_id).await {
            Ok(Some(img)) => img,
            _ => return server_error("Failed to load container image"),
        };
        if let Err(e) = overlay::mount_rootfs(&mgr.paths, &record.id, &image.diff_ids) {
            return server_error(format!("Failed to mount container rootfs: {e}"));
        }
    }

    let _guard = OverlayGuard {
        paths: &mgr.paths,
        container_id: &record.id,
        needs_unmount: !is_running,
    };

    let merged = mgr.paths.overlay_merged(&record.id);
    let resolved = match ingot_util::resolve_in_root(&merged, std::path::Path::new(&path_param)) {
        Ok(r) => r,
        Err(_) => {
            return not_found(format!(
                "Could not find the file {path_param} in container {id}"
            ));
        }
    };
    let target = resolved.proc_path().to_path_buf();

    let meta = match std::fs::symlink_metadata(&target) {
        Ok(m) => m,
        Err(_) => {
            return not_found(format!(
                "Could not find the file {path_param} in container {id}"
            ))
        }
    };

    let rel_path = path_param.trim_start_matches('/');
    let name = std::path::Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(rel_path)
        .to_string();
    let name = if name.is_empty() {
        ".".to_string()
    } else {
        name
    };

    let mode = meta.permissions().mode();
    let size = meta.len() as i64;
    let mtime = meta
        .modified()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
        .unwrap_or_default();
    let link_target = if meta.file_type().is_symlink() {
        std::fs::read_link(&target)
            .ok()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    let stat = ContainerPathStat {
        name: name.clone(),
        size,
        mode,
        mtime,
        link_target,
    };
    let stat_json = serde_json::to_string(&stat).unwrap_or_default();
    let stat_b64 = base64::engine::general_purpose::STANDARD.encode(stat_json);

    if head_only {
        return Response::builder()
            .status(StatusCode::OK)
            .header("X-Docker-Container-Path-Stat", stat_b64)
            .body(Body::empty())
            .unwrap();
    }

    let mut tar_builder = tar::Builder::new(Vec::new());
    if meta.is_dir() {
        let _ = tar_builder.append_dir(&name, &target);
        let mut seen_inodes = std::collections::HashMap::new();
        if let Err(e) = tar_dir_recursive(
            &mut tar_builder,
            &target,
            std::path::Path::new(&name),
            &mut seen_inodes,
        ) {
            return server_error(format!("Failed to archive directory: {e}"));
        }
    } else if meta.file_type().is_symlink() {
        if let Err(e) = tar_builder.append_path_with_name(&target, &name) {
            return server_error(format!("Failed to archive symlink: {e}"));
        }
    } else {
        let mut f = match std::fs::File::open(&target) {
            Ok(f) => f,
            Err(e) => return server_error(format!("Failed to open file: {e}")),
        };
        if let Err(e) = tar_builder.append_file(&name, &mut f) {
            return server_error(format!("Failed to archive file: {e}"));
        }
    }

    let tar_bytes = match tar_builder.into_inner() {
        Ok(b) => b,
        Err(e) => return server_error(format!("Failed to finalize tar: {e}")),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-tar")
        .header("X-Docker-Container-Path-Stat", stat_b64)
        .body(Body::from(tar_bytes))
        .unwrap()
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct ArchivePutQuery {
    pub path: String,
    #[serde(rename = "noOverwriteDirNonDir")]
    pub no_overwrite_dir_non_dir: Option<bool>,
    #[serde(rename = "copyUIDGID")]
    pub copy_uid_gid: Option<bool>,
}

/// PUT /containers/{id}/archive
pub async fn archive_put(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<ArchivePutQuery>,
    body: axum::body::Body,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let handle = match mgr.get(&id).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("No such container: {id}")),
    };
    let record = handle.record.lock().unwrap().clone();
    let is_running = handle.is_running();

    if q.path.is_empty() {
        return bad_request("Path cannot be empty");
    }

    let temp_file =
        match crate::handlers::stream_body_to_temp_file(body, 10 * 1024 * 1024 * 1024).await {
            Ok(f) => f,
            Err(resp) => return resp,
        };
    let file = match temp_file.reopen() {
        Ok(f) => f,
        Err(e) => return server_error(format!("failed to reopen temp archive: {e}")),
    };

    if !is_running {
        let img_id = record.image_id.trim_start_matches("sha256:");
        let image = match mgr.images.load(img_id).await {
            Ok(Some(img)) => img,
            _ => return server_error("Failed to load container image"),
        };
        if let Err(e) = overlay::mount_rootfs(&mgr.paths, &record.id, &image.diff_ids) {
            return server_error(format!("Failed to mount container rootfs: {e}"));
        }
    }

    let _guard = OverlayGuard {
        paths: &mgr.paths,
        container_id: &record.id,
        needs_unmount: !is_running,
    };

    let merged = mgr.paths.overlay_merged(&record.id);
    let dest_res =
        match ingot_util::ensure_dir_in_root(&merged, std::path::Path::new(&q.path), 0o755) {
            Ok(r) => r,
            Err(e) => {
                return bad_request(format!(
                    "Failed to resolve target directory {:?} in container: {e}",
                    q.path
                ));
            }
        };
    let target = dest_res.proc_path().to_path_buf();

    let mut archive = tar::Archive::new(std::io::BufReader::new(file));
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(e) => return bad_request(format!("invalid tar archive: {e}")),
    };
    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => return bad_request(format!("invalid tar entry: {e}")),
        };
        if let Err(e) = entry.unpack_in(&target) {
            return bad_request(format!("failed to unpack archive entry: {e}"));
        }
    }

    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_filters_parse() {
        let f = parse_list_filters(None).unwrap();
        assert!(f.status.is_empty());
        let f = parse_list_filters(Some("")).unwrap();
        assert!(f.name.is_empty());
        let f = parse_list_filters(Some(
            r#"{"status":["running","exited"],"name":["web"],"label":["app=x","tier"],"ancestor":["busybox"],"network":["bridge"],"volume":["data"]}"#,
        ))
        .unwrap();
        assert_eq!(f.status, vec!["running", "exited"]);
        assert_eq!(f.name, vec!["web"]);
        assert_eq!(f.label, vec!["app=x", "tier"]);
        assert_eq!(f.ancestor, vec!["busybox"]);
        assert_eq!(f.network, vec!["bridge"]);
        assert_eq!(f.volume, vec!["data"]);
    }

    #[test]
    fn list_filters_reject_malformed_and_unknown() {
        assert!(parse_list_filters(Some("{nope")).is_err());
        assert!(parse_list_filters(Some("[1,2]")).is_err());
        assert!(parse_list_filters(Some(r#"{"id":["abc"]}"#)).is_err());
        assert!(parse_list_filters(Some(r#"{"exited":[0]}"#)).is_err());
    }

    #[test]
    fn label_matching() {
        let labels: HashMap<String, String> =
            [("app".to_string(), "x".to_string())].into_iter().collect();
        assert!(match_label(&labels, "app"));
        assert!(match_label(&labels, "app=x"));
        assert!(!match_label(&labels, "app=y"));
        assert!(!match_label(&labels, "missing"));
    }
}
