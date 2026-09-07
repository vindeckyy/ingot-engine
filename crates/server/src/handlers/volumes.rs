//! /volumes — list, create, inspect, remove, prune (M5 wiring: local driver).

use crate::handlers::{bad_request, not_found, server_error};
use crate::state::SharedState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ingot_api::{VolumeCreateBody, VolumeListInfo, VolumePruneResponse};
use ingot_volume::VolumeManager;
use std::collections::HashMap;

/// Filter-object parsing shared with images.rs (unit 4.4).
#[allow(clippy::result_large_err)]
fn parse_filter_map(raw: Option<&String>) -> Result<HashMap<String, Vec<String>>, Response> {
    match raw {
        None => Ok(Default::default()),
        Some(s) if s.trim().is_empty() => Ok(Default::default()),
        Some(s) => match serde_json::from_str::<serde_json::Value>(s) {
            Ok(serde_json::Value::Object(m)) => {
                let mut out: HashMap<String, Vec<String>> = HashMap::new();
                for (k, v) in m {
                    out.insert(
                        k,
                        match v {
                            serde_json::Value::Array(a) => a
                                .iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect(),
                            serde_json::Value::String(s) => vec![s],
                            _ => Vec::new(),
                        },
                    );
                }
                Ok(out)
            }
            _ => Err(bad_request("invalid filters: expected a JSON object")),
        },
    }
}

/// Parse `until` to a unix timestamp: unix int, RFC 3339, or Go duration
/// like `24h` meaning that long ago.
fn parse_until_filter(v: &str) -> Result<i64, String> {
    let v = v.trim();
    if v.is_empty() {
        return Err("empty value".to_string());
    }
    if let Ok(ts) = v.parse::<i64>() {
        if ts >= 0 {
            return Ok(ts);
        }
        return Err("negative timestamp".to_string());
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(v) {
        return Ok(dt.timestamp());
    }
    parse_go_duration(v)
        .map(|d| chrono::Utc::now().timestamp().saturating_sub(d))
        .ok_or_else(|| "want a unix timestamp, RFC 3339 time, or Go duration like 24h".to_string())
}

fn parse_go_duration(v: &str) -> Option<i64> {
    let mut total = 0i64;
    let mut num = String::new();
    let mut any = false;
    for c in v.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else {
            let n: i64 = num.parse().ok()?;
            let secs = match c {
                'h' => n.checked_mul(3600)?,
                'm' => n.checked_mul(60)?,
                's' => n,
                _ => return None,
            };
            total = total.checked_add(secs)?;
            num.clear();
            any = true;
        }
    }
    if !num.is_empty() || !any {
        return None;
    }
    Some(total)
}

/// Scan every container record's mounts for named volumes. A stopped
/// container still holds its volume, so both running and stopped count.
fn in_use_volumes(paths: &ingot_store::paths::DataPaths) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(paths.containers()) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path().join("config.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(rec) = serde_json::from_str::<ingot_runtime::record::ContainerRecord>(&text) else {
            continue;
        };
        for m in &rec.mounts {
            if m.typ == "volume" && !m.name.is_empty() {
                out.push(m.name.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

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
        Ok(volumes) => axum::Json(VolumeListInfo {
            Volumes: volumes,
            Warnings: vec![],
        })
        .into_response(),
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
    let name = if body.Name.is_empty() {
        None
    } else {
        if let Err(e) = ingot_util::validate_resource_name(&body.Name) {
            return bad_request(format!("invalid volume name {:?}: {e}", body.Name));
        }
        Some(body.Name.as_str())
    };
    let driver = if body.Driver.is_empty() {
        None
    } else {
        if body.Driver != "local" {
            return bad_request(format!(
                "volume driver {:?} is not supported (only 'local' is supported)",
                body.Driver
            ));
        }
        Some(body.Driver.as_str())
    };
    match vm.create(name, driver, body.Labels, body.DriverOpts) {
        Ok(vol) => {
            let mut attrs = HashMap::new();
            attrs.insert("name".to_string(), vol.Name.clone());
            state.events.publish(ingot_api::EventMessage::new(
                "volume", "create", &vol.Name, attrs,
            ));
            (StatusCode::CREATED, axum::Json(vol)).into_response()
        }
        Err(e) => bad_request(format!("create volume: {e}")),
    }
}

/// GET /volumes/{name}
pub async fn inspect(State(state): State<SharedState>, Path(name): Path<String>) -> Response {
    if let Err(e) = ingot_util::validate_resource_name(&name) {
        return bad_request(format!("invalid volume name {name:?}: {e}"));
    }
    let vm = get_vm(&state);
    match vm.get(&name) {
        Ok(Some(vol)) => axum::Json(vol).into_response(),
        Ok(None) => not_found(format!("no such volume: {name}")),
        Err(e) => server_error(format!("inspect volume: {e}")),
    }
}

/// DELETE /volumes/{name}
pub async fn remove(State(state): State<SharedState>, Path(name): Path<String>) -> Response {
    if let Err(e) = ingot_util::validate_resource_name(&name) {
        return bad_request(format!("invalid volume name {name:?}: {e}"));
    }
    let vm = get_vm(&state);
    match vm.remove(&name) {
        Ok(_) => {
            let mut attrs = HashMap::new();
            attrs.insert("name".to_string(), name.clone());
            state.events.publish(ingot_api::EventMessage::new(
                "volume", "destroy", &name, attrs,
            ));
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            if e.to_string().contains("no such volume") {
                not_found(format!("no such volume: {name}"))
            } else {
                server_error(format!("remove volume: {e}"))
            }
        }
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct PruneQuery {
    filters: Option<String>,
}

/// POST /volumes/prune
pub async fn prune(State(state): State<SharedState>, Query(q): Query<PruneQuery>) -> Response {
    let filters = match parse_filter_map(q.filters.as_ref()) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let mut until: Option<i64> = None;
    let mut label_filter: HashMap<String, String> = HashMap::new();
    for (k, vals) in &filters {
        match k.as_str() {
            "until" => {
                for v in vals {
                    match parse_until_filter(v) {
                        Ok(ts) => until = Some(ts),
                        Err(e) => return bad_request(format!("invalid until filter: {e}")),
                    }
                }
            }
            "label" => {
                for v in vals {
                    if let Some((k, v)) = v.split_once('=') {
                        label_filter.insert(k.to_string(), v.to_string());
                    } else {
                        label_filter.insert(v.to_string(), String::new());
                    }
                }
            }
            other => {
                return bad_request(format!(
                    "invalid filter '{other}' (supported: until, label)"
                ))
            }
        }
    }
    let protected = in_use_volumes(&state.paths);
    let protected_refs: Vec<&str> = protected.iter().map(|s| s.as_str()).collect();
    let vm = get_vm(&state);
    match vm.prune(&protected_refs, until, &label_filter) {
        Ok(deleted) => axum::Json(VolumePruneResponse {
            VolumesDeleted: deleted,
            Reclaimable: Some(0),
        })
        .into_response(),
        Err(e) => server_error(format!("prune volumes: {e}")),
    }
}
