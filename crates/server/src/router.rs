//! Router assembly.
//!
//! The docker CLI prefixes every route with the negotiated version, e.g.
//! `/v1.44/containers/json`. axum layers run *after* routing, so a URI-
//! rewriting middleware cannot work; instead we nest the API router under
//! every version prefix from MinAPIVersion..=API_VERSION (the CLI always
//! picks min(its own max, our advertised 1.44)), plus the bare paths.

use crate::handlers;
use crate::state::SharedState;
use axum::routing::{any, delete, get, post};
use axum::Router;

fn api_routes() -> Router<SharedState> {
    Router::new()
        // system
        .route("/_ping", any(handlers::system::ping))
        .route("/version", get(handlers::system::version))
        .route("/info", get(handlers::system::info))
        .route("/events", get(handlers::events::events))
        .route("/system/df", get(handlers::system_stub::system_df))
        // containers (M2)
        .route("/containers/json", get(handlers::containers::list))
        .route("/containers/create", post(handlers::containers::create))
        .route("/containers/{id}/json", get(handlers::containers::inspect))
        .route("/containers/{id}/start", post(handlers::containers::start))
        .route("/containers/{id}/stop", post(handlers::containers::stop))
        .route("/containers/{id}/kill", post(handlers::containers::kill))
        .route("/containers/{id}/wait", post(handlers::containers::wait))
        .route("/containers/{id}/pause", post(handlers::containers::pause))
        .route("/containers/{id}/unpause", post(handlers::containers::unpause))
        .route("/containers/{id}/restart", post(handlers::containers::restart))
        .route("/containers/{id}/top", get(handlers::containers::top))
        .route("/containers/{id}/stats", get(handlers::containers::stats))
        .route("/containers/{id}/logs", get(handlers::containers::logs))
        .route("/containers/{id}/attach", post(handlers::attach_exec::attach))
        .route("/build", post(handlers::build::build))
        .route("/containers/{id}/exec", post(handlers::attach_exec::exec_create))
        .route("/exec/{id}/start", post(handlers::attach_exec::exec_start))
        .route("/exec/{id}/json", get(handlers::attach_exec::exec_inspect))
        .route("/containers/prune", post(handlers::containers::prune))
        .route("/containers/{id}/archive", get(handlers::containers::archive_get).head(handlers::containers::archive_head).put(handlers::containers::archive_put))
        .route("/containers/{id}", delete(handlers::containers::remove))
        // images (M1, M7)
        .route("/images/json", get(handlers::images::list))
        .route("/images/create", post(handlers::images::create))
        .route("/images/prune", post(handlers::images::prune))
        .route("/images/get", get(handlers::images::get_tar))
        .route("/images/{name}/get", get(handlers::images::get_tar_single))
        .route("/images/load", post(handlers::images::load_tar))
        .route("/images/{name}/json", get(handlers::images::inspect))
        .route("/images/{name}/history", get(handlers::images::history))
        .route("/images/{name}/tag", post(handlers::images::tag))
        .route("/images/{name}", delete(handlers::images::remove))
        // networks (M3)
        .route("/networks", get(handlers::networks::list))
        .route("/networks/create", post(handlers::networks::create))
        .route("/networks/prune", post(handlers::networks::prune))
        .route("/networks/{id}", get(handlers::networks::inspect).delete(handlers::networks::remove))
        .route("/networks/{id}/connect", post(handlers::networks::connect))
        .route("/networks/{id}/disconnect", post(handlers::networks::disconnect))
        // volumes (M5)
        .route("/volumes", get(handlers::volumes::list).post(handlers::volumes::create))
        .route("/volumes/create", post(handlers::volumes::create))
        .route("/volumes/prune", post(handlers::volumes::prune))
        .route("/volumes/{name}", get(handlers::volumes::inspect).delete(handlers::volumes::remove))
}

pub fn build_router(state: SharedState) -> Router {
    let mut router = Router::new().merge(api_routes());
    for minor in 24..=44 {
        let prefix = format!("/v1.{}", minor);
        router = router.nest(&prefix, api_routes());
    }
    router
        .layer(axum::extract::DefaultBodyLimit::disable())
        .fallback(handlers::not_implemented_fallback)
        .with_state(state)
}

