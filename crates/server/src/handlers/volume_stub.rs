use crate::state::SharedState;
use axum::extract::State;
use axum::response::{IntoResponse, Response};

pub async fn list(State(_s): State<SharedState>) -> Response {
    "{\"Volumes\":[],\"Warnings\":[]}".into_response()
}
pub async fn create() -> Response { crate::handlers::not_implemented("volume create lands in M5") }
