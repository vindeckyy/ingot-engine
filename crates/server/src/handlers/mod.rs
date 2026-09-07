pub mod attach_exec;
pub mod build;
pub mod containers;
pub mod events;
pub mod images;
pub mod networks;
pub mod secrets;
pub mod system;
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

/// Error taxonomy (Plan Phase 0, unit 0.2):
/// - 400 (`bad_request`): malformed input, invalid option values.
/// - 404 (`not_found`): unknown container/image/network/volume name or id.
/// - 409 (`conflict`): name already in use, in-use resource removal.
/// - 500 (`server_error`): truly unexpected daemon-side failures only.
/// - 501 (`not_implemented`): accepted API surface not yet implemented.
pub fn conflict(msg: impl std::fmt::Display) -> Response {
    docker_error(StatusCode::CONFLICT, msg)
}

/// Catch-all for unknown routes (e.g. Engine API endpoints we do not serve yet).
pub async fn not_implemented_fallback(req: axum::http::Request<axum::body::Body>) -> Response {
    docker_error(
        StatusCode::NOT_IMPLEMENTED,
        format!(
            "endpoint {} is not implemented by ingot yet",
            req.uri().path()
        ),
    )
}

/// Stream request body into a temporary file while enforcing max_bytes limit.
pub async fn stream_body_to_temp_file(
    body: axum::body::Body,
    max_bytes: u64,
) -> Result<tempfile::NamedTempFile, Response> {
    use futures::StreamExt;
    use std::io::Write;

    let named_temp = tempfile::NamedTempFile::new()
        .map_err(|e| server_error(format!("create temp file: {e}")))?;
    // BufWriter 256KB: avoids a write(2) per body chunk.
    let mut writer = std::io::BufWriter::with_capacity(256 * 1024, named_temp);
    let mut total_bytes: u64 = 0;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => return Err(bad_request(format!("read request body: {e}"))),
        };
        total_bytes = total_bytes.saturating_add(chunk.len() as u64);
        if total_bytes > max_bytes {
            return Err(docker_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("request body exceeded size limit of {max_bytes} bytes"),
            ));
        }
        if let Err(e) = writer.write_all(&chunk) {
            return Err(server_error(format!("write temp file: {e}")));
        }
    }
    if let Err(e) = writer.flush() {
        return Err(server_error(format!("flush temp file: {e}")));
    }
    writer
        .into_inner()
        .map_err(|e| server_error(format!("flush temp file: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    async fn shape(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("error body readable");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("error body is JSON");
        assert!(
            v.get("message").and_then(|m| m.as_str()).is_some(),
            "error body must carry a string `message`: {v}"
        );
        (status, v)
    }

    #[tokio::test]
    async fn error_taxonomy_shapes() {
        let (s, v) = shape(bad_request("bad")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["message"], "bad");

        let (s, _) = shape(not_found("missing")).await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        let (s, v) = shape(conflict("in use")).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(v["message"], "in use");

        let (s, _) = shape(server_error("boom")).await;
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);

        let (s, _) = shape(not_implemented("later")).await;
        assert_eq!(s, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn fallback_names_the_endpoint() {
        let req = axum::http::Request::builder()
            .uri("/v1.44/plugins/list")
            .body(Body::empty())
            .unwrap();
        let (s, v) = shape(not_implemented_fallback(req).await).await;
        assert_eq!(s, StatusCode::NOT_IMPLEMENTED);
        assert!(v["message"]
            .as_str()
            .unwrap()
            .contains("/v1.44/plugins/list"));
    }
}
