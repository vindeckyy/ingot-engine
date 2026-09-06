//! /networks — list, inspect, create, remove, connect, disconnect, prune.

use crate::handlers::{bad_request, not_found, server_error};
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ingot_api::{
    EndpointContainer, Ipam, IpamConfig, NetworkCreateBody, NetworkCreateResponse, NetworkInspect,
    NetworkSummary,
};
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
        ConfigFrom: ingot_api::ConfigFrom { Network: String::new() },
        ConfigOnly: false,
        Containers: containers,
        Options: n.options.clone(),
        Labels: n.labels.clone(),
    };
    axum::Json(inspect).into_response()
}

/// POST /networks/create
pub async fn create(
    State(state): State<SharedState>,
    body: axum::body::Bytes,
) -> Response {
    let mgr = state.networks.as_ref().unwrap();
    let body: NetworkCreateBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return bad_request(format!("invalid network config: {e}")),
    };
    let subnet = body.IPAM.Config.as_ref().and_then(|c| c.first().and_then(|x| {
        if x.Subnet.is_empty() { None } else { Some(x.Subnet.clone()) }
    }));
    let gateway = body.IPAM.Config.as_ref().and_then(|c| c.first().and_then(|x| {
        if x.Gateway.is_empty() { None } else { Some(x.Gateway.clone()) }
    }));
    match mgr
        .create_network(&body.Name, &body.Driver, body.Internal, subnet, gateway, body.Labels, body.Options)
        .await
    {
        Ok(rec) => axum::Json(NetworkCreateResponse {
            Id: rec.id,
            Warning: String::new(),
        })
        .into_response(),
        Err(e) => crate::handlers::docker_error(StatusCode::CONFLICT, format!("{e:#}")),
    }
}

/// DELETE /networks/{id}
pub async fn remove(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    let mgr = state.networks.as_ref().unwrap();
    match mgr.remove_network(&id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => not_found(format!("{e:#}")),
    }
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
    let aliases = body
        .EndpointConfig
        .as_ref()
        .map(|e| e.Aliases.clone())
        .unwrap_or_default();
    let req = ingot_network::AttachRequest {
        container_id: record.id.clone(),
        container_name: record.name.clone(),
        hostname: record.config.Hostname.clone(),
        network: n.name.clone(),
        pid: handle.state.lock().unwrap().pid,
        netns_path: state.paths.netns_bind(&record.id).to_string_lossy().to_string(),
        aliases,
    };
    match netmgr.attach(&req).await {
        Ok(ep) => {
            handle.record.lock().unwrap().endpoints.push(
                ingot_runtime::record::EndpointRecord {
                    network_id: ep.network_id.clone(),
                    network_name: ep.network_name.clone(),
                    ip: ep.ip.clone(),
                    gateway: ep.gateway.clone(),
                    mac: ep.mac.clone(),
                    aliases: ep.aliases.clone(),
                },
            );
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
    struct Body {
        Container: String,
        Force: bool,
    }
    let body: Body = serde_json::from_slice(&body).unwrap_or_default();
    let handle = match conmgr.get(&body.Container).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("no such container: {}", body.Container)),
    };
    let (rid, ep) = {
        let mut rec = handle.record.lock().unwrap();
        let found = rec.endpoints.iter().position(|e| e.network_id == n.id);
        match found {
            Some(i) => (rec.id.clone(), rec.endpoints.remove(i)),
            None => return bad_request(format!("container not attached to network {}", n.name)),
        }
    };
    netmgr.detach(&n.id, &ep.ip, &rid).await;
    StatusCode::OK.into_response()
}

/// POST /networks/prune
pub async fn prune(
    State(state): State<SharedState>,
    Query(_q): Query<PruneQuery>,
) -> Response {
    let mgr = state.networks.as_ref().unwrap();
    let mut deleted: Vec<String> = Vec::new();
    for n in mgr.list().await {
        if n.name != "bridge" {
            if mgr.remove_network(&n.name).await.is_ok() {
                deleted.push(n.name);
            }
        }
    }
    axum::Json(ingot_api::NetworkPruneResponse { NetworksDeleted: deleted }).into_response()
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct PruneQuery {
    filters: Option<String>,
}
