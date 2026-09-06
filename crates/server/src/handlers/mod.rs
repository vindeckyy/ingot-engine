pub mod system;
pub mod events;
pub mod system_stub;
pub mod containers;
pub mod attach_exec;
pub mod build;
pub mod images;
pub mod networks;
pub mod volumes;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Docker-style error body: `{"message": "..."}`.
pub fn docker_error(status: StatusCode, msg: impl std::fmt::Display) -> Response {
    (status, axum::Json(json!({"message": msg.to_string()}))).into_response()
}

pub fn not_found(msg: impl std::fmt::Display) -> Response {
    docker_error(StatusCode::NOT_FOUND, msg)
}

pub fn bad_request(msg: impl std::fmt::Display) -> Response {
    docker_error(StatusCode::BAD_REQUEST, msg)
}

pub fn server_error(msg: impl std::fmt::Display) -> Response {
    docker_error(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

pub fn not_implemented(msg: impl std::fmt::Display) -> Response {
    docker_error(StatusCode::NOT_IMPLEMENTED, msg)
}

/// Catch-all for unknown routes (e.g. Engine API endpoints we do not serve yet).
pub async fn not_implemented_fallback(req: axum::http::Request<axum::body::Body>) -> Response {
    docker_error(
        StatusCode::NOT_IMPLEMENTED,
        format!("endpoint {} is not implemented by ingot yet", req.uri().path()),
    )
}
