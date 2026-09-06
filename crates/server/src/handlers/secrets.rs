//! POST /secrets — stage build secrets for one build.
//!
//! Body: JSON object mapping secret id → value. Values live in daemon
//! memory only, addressed by a one-time token the client passes back in
//! the `x-ingot-secret-token` header on POST /build (a header, never a
//! query param, so tokens stay out of access logs). There is deliberately
//! no GET: values are write-and-consume, never listed or returned.

use crate::handlers::bad_request;
use crate::state::SharedState;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;

/// Caps: secrets are small credentials, not file transfer.
const MAX_SECRET_IDS: usize = 64;
const MAX_SECRET_TOTAL_BYTES: usize = 1024 * 1024;

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

pub async fn create(State(state): State<SharedState>, body: axum::body::Bytes) -> Response {
    let values: HashMap<String, String> = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(format!("invalid secrets JSON: {e}")),
    };
    if values.is_empty() || values.len() > MAX_SECRET_IDS {
        return bad_request(format!(
            "secrets: need 1–{MAX_SECRET_IDS} ids, got {}",
            values.len()
        ));
    }
    let total: usize = values.values().map(String::len).sum();
    if total > MAX_SECRET_TOTAL_BYTES {
        return bad_request(format!(
            "secrets: {total} bytes over the {MAX_SECRET_TOTAL_BYTES}-byte limit"
        ));
    }
    for id in values.keys() {
        if !valid_id(id) {
            // The VALID ids are fine to name; the offending one is not
            // echoed back (it may itself be sensitive).
            return bad_request("secrets: invalid id (use 1–128 chars of A–Z a–z 0–9 _ - .)");
        }
    }
    let token = state.build_secrets.lock().await.insert(values);
    // The token authenticates one build; the VALUES never leave the
    // daemon except bind-mounted into the steps that declare them.
    axum::Json(serde_json::json!({"token": token})).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_charset() {
        assert!(valid_id("db-password.1_x"));
        assert!(!valid_id(""));
        assert!(!valid_id("has space"));
        assert!(!valid_id("has/slash"));
        assert!(!valid_id("../escape"));
        assert!(!valid_id(&"x".repeat(129)));
    }
}
