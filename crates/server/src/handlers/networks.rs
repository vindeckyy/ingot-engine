//! /networks — list, inspect, create, remove, connect, disconnect, prune.

use crate::handlers::{bad_request, docker_error, not_found, server_error};
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ingot_api::{
    EndpointContainer, Ipam, IpamConfig, NetworkCreateBody, NetworkCreateResponse, NetworkInspect,
    NetworkSummary,
};
use ingot_runtime::record::StateStatus;
use std::collections::HashMap;

/// GET /networks
pub async fn list(State(state): State<SharedState>) -> Response {
    let mgr = state.networks.as_ref().unwrap();
    let mut out: Vec<NetworkSummary> = Vec::new();
    for n in mgr.list().await {
        out.push(NetworkSummary {
            Name: n.name.clone(),
            Id: n.id.clone(),
            Created: n.created.clone(),
            Scope: "local".into(),
            Driver: n.driver.clone(),
            EnableIPv6: false,
            Internal: n.internal,
            Attachable: n.attachable,
            Ingress: false,
            IPAM: ipam_of(&n),
            Options: n.options.clone(),
            Labels: n.labels.clone(),
        });
    }
    axum::Json(out).into_response()
}

fn ipam_of(n: &ingot_network::NetworkRecord) -> Ipam {
    Ipam {
        Driver: "default".into(),
        Config: Some(vec![IpamConfig {
            Subnet: n.subnet.clone(),
            Gateway: n.gateway.clone(),
            ..Default::default()
        }]),
        Options: None,
    }
}

/// GET /networks/{id}
pub async fn inspect(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    let mgr = state.networks.as_ref().unwrap();
    let n = match mgr.get(&id).await {
        Some(n) => n,
        None => return not_found(format!("network {id} not found")),
    };
    // Containers attached to this network.
    let mut containers: HashMap<String, EndpointContainer> = HashMap::new();
    for record in state.containers.as_ref().unwrap().list_records().await {
        for ep in &record.endpoints {
            if ep.network_id == n.id {
                containers.insert(
                    record.id.clone(),
                    EndpointContainer {
                        Name: record.name.clone(),
                        EndpointID: String::new(),
                        MacAddress: ep.mac.clone(),
                        IPv4Address: format!("{}/16", ep.ip),
                        IPv6Address: String::new(),
                    },
                );
            }
        }
    }
    let inspect = NetworkInspect {
        Name: n.name.clone(),
        Id: n.id.clone(),
        Created: n.created.clone(),
        Scope: "local".into(),
        Driver: n.driver.clone(),
        EnableIPv6: false,
        IPAM: ipam_of(&n),
        Internal: n.internal,
        Attachable: n.attachable,
        Ingress: false,
        ConfigFrom: ingot_api::ConfigFrom {
            Network: String::new(),
        },
        ConfigOnly: false,
        Containers: containers,
        Options: n.options.clone(),
        Labels: n.labels.clone(),
    };
    axum::Json(inspect).into_response()
}

/// POST /networks/create
pub async fn create(State(state): State<SharedState>, body: axum::body::Bytes) -> Response {
    let mgr = state.networks.as_ref().unwrap();
    let body: NetworkCreateBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return bad_request(format!("invalid network config: {e}")),
    };
    if body.EnableIPv6 {
        return bad_request("IPv6 networks are not supported");
    }
    if body.Ingress {
        return bad_request("ingress networks are not supported");
    }
    if !body.Driver.is_empty() && body.Driver != "bridge" {
        return bad_request(format!(
            "unsupported network driver {:?}; only bridge is supported",
            body.Driver
        ));
    }
    if !body.IPAM.Driver.is_empty() && body.IPAM.Driver != "default" {
        return bad_request(format!(
            "unsupported IPAM driver {:?}; only default is supported",
            body.IPAM.Driver
        ));
    }
    if body.IPAM.Options.as_ref().is_some_and(|o| !o.is_empty()) {
        return bad_request("IPAM options are not supported");
    }
    let subnet = body.IPAM.Config.as_ref().and_then(|c| {
        c.first().and_then(|x| {
            if x.Subnet.is_empty() {
                None
            } else {
                Some(x.Subnet.clone())
            }
        })
    });
    let gateway = body.IPAM.Config.as_ref().and_then(|c| {
        c.first().and_then(|x| {
            if x.Gateway.is_empty() {
                None
            } else {
                Some(x.Gateway.clone())
            }
        })
    });
    match mgr
        .create_network(
            &body.Name,
            &body.Driver,
            body.Internal,
            subnet,
            gateway,
            body.Labels,
            body.Options,
        )
        .await
    {
        Ok(rec) => (
            StatusCode::CREATED,
            axum::Json(NetworkCreateResponse {
                Id: rec.id,
                Warning: String::new(),
            }),
        )
            .into_response(),
        // Validation failures are client errors (400); name/subnet
        // conflicts are 409. create_network phrases validation as
        // "invalid ..." by convention.
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.starts_with("invalid ") {
                crate::handlers::bad_request(msg)
            } else {
                crate::handlers::docker_error(StatusCode::CONFLICT, msg)
            }
        }
    }
}

/// DELETE /networks/{id}
pub async fn remove(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    let mgr = state.networks.as_ref().unwrap();
    let Some(n) = mgr.get(&id).await else {
        return not_found(format!("network {id} not found"));
    };
    if n.name == "bridge" {
        return docker_error(
            StatusCode::FORBIDDEN,
            format!("{} is a pre-defined network and cannot be removed", n.name),
        );
    }
    // Fail closed while any container holds an endpoint here, running
    // or stopped: removing the bridge underneath would strand its veth
    // and orphan the recorded lease.
    let holders = attached_containers(&state.paths, &n.id);
    if !holders.is_empty() {
        return docker_error(
            StatusCode::CONFLICT,
            format!(
                "network {} has active endpoints: {}",
                n.name,
                holders.join(", ")
            ),
        );
    }
    match mgr.remove_network(&id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => not_found(format!("{e:#}")),
    }
}

/// Names of containers with an endpoint record on this network, read
/// from disk so stopped containers count too. Unparseable entries are
/// skipped: a corrupt record must not block removal of an otherwise
/// empty network (the rm path itself stays fail-closed on real state).
fn attached_containers(paths: &ingot_store::paths::DataPaths, net_id: &str) -> Vec<String> {
    let mut holders = Vec::new();
    let Ok(entries) = std::fs::read_dir(paths.containers()) else {
        return holders;
    };
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path().join("config.json")) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let attached = v
            .get("endpoints")
            .and_then(|e| e.as_array())
            .is_some_and(|eps| {
                eps.iter()
                    .any(|ep| ep.get("network_id").and_then(|i| i.as_str()) == Some(net_id))
            });
        if attached {
            holders.push(
                v.get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("?")
                    .to_string(),
            );
        }
    }
    holders.sort();
    holders
}

/// POST /networks/{id}/connect — attach a *running* container now; created
/// containers get their endpoints at start (their config records the intent).
pub async fn connect(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let netmgr = state.networks.as_ref().unwrap();
    let conmgr = state.containers.as_ref().unwrap();
    let Some(n) = netmgr.get(&id).await else {
        return not_found(format!("network {id} not found"));
    };
    let body: ingot_api::NetworkConnectBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return bad_request(format!("invalid connect body: {e}")),
    };
    let handle = match conmgr.get(&body.Container).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("no such container: {}", body.Container)),
    };
    let record = handle.record.lock().unwrap().clone();
    // Live attach wires a veth into the container's netns, so the
    // container must be running. (Stopped-container intent queueing is a
    // follow-up; today this failed later with an opaque 500.)
    if handle.state.lock().unwrap().status != StateStatus::Running {
        return docker_error(
            StatusCode::CONFLICT,
            format!(
                "container {} is not running: start it before connecting network {}",
                record.name, n.name
            ),
        );
    }
    // A second connect is a no-op nowhere: it would lease a second IP
    // and strand a second veth under one interface name.
    if record.endpoints.iter().any(|e| e.network_id == n.id) {
        return docker_error(
            StatusCode::CONFLICT,
            format!(
                "container {} is already connected to network {}",
                record.name, n.name
            ),
        );
    }
    let aliases = body
        .EndpointConfig
        .as_ref()
        .map(|e| e.Aliases.clone())
        .unwrap_or_default();
    let requested_ip = body
        .EndpointConfig
        .as_ref()
        .and_then(|e| e.IPAMConfig.as_ref())
        .map(|c| c.IPv4Address.clone())
        .filter(|s| !s.is_empty());
    let req = ingot_network::AttachRequest {
        container_id: record.id.clone(),
        container_name: record.name.clone(),
        hostname: record.config.Hostname.clone(),
        network: n.name.clone(),
        pid: handle.state.lock().unwrap().pid,
        netns_path: state
            .paths
            .netns_bind(&record.id)
            .to_string_lossy()
            .to_string(),
        aliases,
        dns_search: record.hostconfig.DnsSearch.clone(),
        requested_ip,
        // Appended after the existing endpoints: eth{len}.
        if_index: record.endpoints.len(),
    };
    match netmgr.attach(&req).await {
        Ok(ep) => {
            handle
                .record
                .lock()
                .unwrap()
                .endpoints
                .push(ingot_runtime::record::EndpointRecord {
                    network_id: ep.network_id.clone(),
                    network_name: ep.network_name.clone(),
                    ip: ep.ip.clone(),
                    gateway: ep.gateway.clone(),
                    mac: ep.mac.clone(),
                    aliases: ep.aliases.clone(),
                    requested_ip: None,
                });
            let _ = ingot_store::write_json_atomic(
                &state.paths.container_config(&record.id),
                &*handle.record.lock().unwrap(),
            );
            StatusCode::OK.into_response()
        }
        Err(e) => server_error(format!("{e:#}")),
    }
}

/// POST /networks/{id}/disconnect
pub async fn disconnect(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let netmgr = state.networks.as_ref().unwrap();
    let conmgr = state.containers.as_ref().unwrap();
    let Some(n) = netmgr.get(&id).await else {
        return not_found(format!("network {id} not found"));
    };
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    // Field names mirror the Engine API connect/disconnect body verbatim.
    #[allow(non_snake_case)]
    struct Body {
        Container: String,
        Force: bool,
    }
    let body: Body = serde_json::from_slice(&body).unwrap_or_default();
    let handle = match conmgr.get(&body.Container).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("no such container: {}", body.Container)),
    };
    let (rid, name, hostname, ep) = {
        let mut rec = handle.record.lock().unwrap();
        let found = rec.endpoints.iter().position(|e| e.network_id == n.id);
        match found {
            Some(i) => (
                rec.id.clone(),
                rec.name.clone(),
                rec.config.Hostname.clone(),
                rec.endpoints.remove(i),
            ),
            None => return bad_request(format!("container not attached to network {}", n.name)),
        }
    };
    // Persist the detachment: the endpoint record is the source of truth
    // for the boot lease sweep, so a memory-only removal would resurrect
    // a dead endpoint (with no lease) on the next daemon start.
    let _ = ingot_store::write_json_atomic(
        &state.paths.container_config(&rid),
        &*handle.record.lock().unwrap(),
    );
    let mut keys = vec![name, hostname];
    keys.extend(ep.aliases.clone());
    // Each network has its own DNS registry, so detaching here only
    // affects this network; surviving endpoints keep their own
    // registrations untouched.
    netmgr.detach(&n.id, &ep.ip, &rid, &keys).await;
    StatusCode::OK.into_response()
}

/// POST /networks/prune
pub async fn prune(State(state): State<SharedState>, Query(_q): Query<PruneQuery>) -> Response {
    let mgr = state.networks.as_ref().unwrap();
    let mut deleted: Vec<String> = Vec::new();
    for n in mgr.list().await {
        // Same in-use guard as remove: prune skips attached networks
        // instead of ripping the bridge out from under containers.
        if n.name != "bridge"
            && attached_containers(&state.paths, &n.id).is_empty()
            && mgr.remove_network(&n.name).await.is_ok()
        {
            deleted.push(n.name);
        }
    }
    axum::Json(ingot_api::NetworkPruneResponse {
        NetworksDeleted: deleted,
    })
    .into_response()
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct PruneQuery {
    filters: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &std::path::Path, id: &str, body: &str) {
        let d = dir.join(id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("config.json"), body).unwrap();
    }

    #[test]
    fn attached_containers_scans_disk_records() {
        let dir = std::env::temp_dir().join(format!("net-holders-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("data");
        std::fs::create_dir_all(root.join("containers")).unwrap();
        let paths = ingot_store::paths::DataPaths::new(root, dir.clone());
        cfg(
            &paths.containers(),
            "aaa",
            r#"{"name":"web","endpoints":[{"network_id":"net-1","ip":"10.0.0.2"}]}"#,
        );
        cfg(
            &paths.containers(),
            "bbb",
            r#"{"name":"db","endpoints":[{"network_id":"net-2","ip":"10.0.1.2"}]}"#,
        );
        cfg(&paths.containers(), "corrupt", "not json{{{");
        assert_eq!(
            attached_containers(&paths, "net-1"),
            vec!["web".to_string()]
        );
        assert_eq!(attached_containers(&paths, "net-2"), vec!["db".to_string()]);
        assert!(attached_containers(&paths, "net-9").is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
