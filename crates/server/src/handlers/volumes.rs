//! /volumes — list, create, inspect, remove, prune (M5 wiring: local driver).

use crate::handlers::{bad_request, not_found, server_error};
use crate::state::SharedState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ingot_api::{VolumeCreateBody, VolumeListInfo, VolumePruneResponse};
use ingot_volume::VolumeManager;

fn get_vm(state: &SharedState) -> VolumeManager {
    state
        .volumes
        .as_ref()
        .map(|v| (**v).clone())
        .unwrap_or_else(|| VolumeManager::new(state.paths.clone()).unwrap())
}

/// GET /volumes
pub async fn list(State(state): State<SharedState>) -> Response {
    let vm = get_vm(&state);
    match vm.list() {
        Ok(volumes) => axum::Json(VolumeListInfo { Volumes: volumes, Warnings: vec![] }).into_response(),
        Err(e) => server_error(format!("list volumes: {e}")),
    }
}

/// POST /volumes/create
pub async fn create(State(state): State<SharedState>, body: axum::body::Bytes) -> Response {
    let body: VolumeCreateBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return bad_request(format!("invalid volume body: {e}")),
    };
    let vm = get_vm(&state);
    let name = if body.Name.is_empty() { None } else { Some(body.Name.as_str()) };
    let driver = if body.Driver.is_empty() { None } else { Some(body.Driver.as_str()) };
    match vm.create(name, driver, body.Labels, body.DriverOpts) {
        Ok(vol) => axum::Json(vol).into_response(),
        Err(e) => server_error(format!("create volume: {e}")),
    }
}

/// GET /volumes/{name}
pub async fn inspect(State(state): State<SharedState>, Path(name): Path<String>) -> Response {
    let vm = get_vm(&state);
    match vm.get(&name) {
        Ok(Some(vol)) => axum::Json(vol).into_response(),
        Ok(None) => not_found(format!("no such volume: {name}")),
        Err(e) => server_error(format!("inspect volume: {e}")),
    }
}

/// DELETE /volumes/{name}
pub async fn remove(State(state): State<SharedState>, Path(name): Path<String>) -> Response {
    let vm = get_vm(&state);
    match vm.remove(&name) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            if e.to_string().contains("no such volume") {
                not_found(format!("no such volume: {name}"))
            } else {
                server_error(format!("remove volume: {e}"))
            }
        }
    }
}

/// POST /volumes/prune
pub async fn prune(State(state): State<SharedState>) -> Response {
    let vm = get_vm(&state);
    match vm.prune() {
        Ok(deleted) => axum::Json(VolumePruneResponse { VolumesDeleted: deleted, Reclaimable: Some(0) }).into_response(),
        Err(e) => server_error(format!("prune volumes: {e}")),
    }
}
