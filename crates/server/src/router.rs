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
        .route("/system/df", get(handlers::system::df))
        // containers (M2)
        .route("/containers/json", get(handlers::containers::list))
        .route("/containers/create", post(handlers::containers::create))
        .route("/containers/{id}/json", get(handlers::containers::inspect))
        .route("/containers/{id}/start", post(handlers::containers::start))
        .route("/containers/{id}/stop", post(handlers::containers::stop))
        .route("/containers/{id}/kill", post(handlers::containers::kill))
        .route("/containers/{id}/wait", post(handlers::containers::wait))
        .route("/containers/{id}/pause", post(handlers::containers::pause))
        .route(
            "/containers/{id}/unpause",
            post(handlers::containers::unpause),
        )
        .route(
            "/containers/{id}/restart",
            post(handlers::containers::restart),
        )
        .route("/containers/{id}/top", get(handlers::containers::top))
        .route("/containers/{id}/stats", get(handlers::containers::stats))
        .route("/containers/{id}/logs", get(handlers::containers::logs))
        .route(
            "/containers/{id}/attach",
            post(handlers::attach_exec::attach),
        )
        .route(
            "/build",
            post(handlers::build::build)
                .layer(axum::extract::DefaultBodyLimit::max(512 * 1024 * 1024)),
        )
        .route(
            "/secrets",
            post(handlers::secrets::create)
                .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)),
        )
        .route(
            "/containers/{id}/exec",
            post(handlers::attach_exec::exec_create),
        )
        .route("/exec/{id}/start", post(handlers::attach_exec::exec_start))
        .route("/exec/{id}/json", get(handlers::attach_exec::exec_inspect))
        .route("/containers/prune", post(handlers::containers::prune))
        .route(
            "/containers/{id}/archive",
            get(handlers::containers::archive_get)
                .head(handlers::containers::archive_head)
                .put(handlers::containers::archive_put)
                .layer(axum::extract::DefaultBodyLimit::max(
                    10 * 1024 * 1024 * 1024,
                )),
        )
        .route("/containers/{id}", delete(handlers::containers::remove))
        // images (M1, M7)
        .route("/images/json", get(handlers::images::list))
        .route("/images/create", post(handlers::images::create))
        .route("/images/prune", post(handlers::images::prune))
        .route("/images/get", get(handlers::images::get_tar))
        .route("/images/{name}/get", get(handlers::images::get_tar_single))
        .route(
            "/images/load",
            post(handlers::images::load_tar).layer(axum::extract::DefaultBodyLimit::max(
                10 * 1024 * 1024 * 1024,
            )),
        )
        .route("/images/{name}/json", get(handlers::images::inspect))
        .route("/images/{name}/history", get(handlers::images::history))
        .route("/images/{name}/tag", post(handlers::images::tag))
        .route("/images/{name}/push", post(handlers::images::push))
        .route("/images/{name}", delete(handlers::images::remove))
        // networks (M3)
        .route("/networks", get(handlers::networks::list))
        .route("/networks/create", post(handlers::networks::create))
        .route("/networks/prune", post(handlers::networks::prune))
        .route(
            "/networks/{id}",
            get(handlers::networks::inspect).delete(handlers::networks::remove),
        )
        .route("/networks/{id}/connect", post(handlers::networks::connect))
        .route(
            "/networks/{id}/disconnect",
            post(handlers::networks::disconnect),
        )
        // volumes (M5)
        .route(
            "/volumes",
            get(handlers::volumes::list).post(handlers::volumes::create),
        )
        .route("/volumes/create", post(handlers::volumes::create))
        .route("/volumes/prune", post(handlers::volumes::prune))
        .route(
            "/volumes/{name}",
            get(handlers::volumes::inspect).delete(handlers::volumes::remove),
        )
}

pub fn build_router(state: SharedState) -> Router {
    // Build once, clone for bare + versioned mounts. A prefix-stripping
    // middleware cannot work: axum layers run after routing, so versioned
    // nesting stays explicit. Every minor from MIN_API_VERSION to
    // API_VERSION is served (the CLI always picks min(its max, our
    // advertised 1.44)); anything else falls through to the 501 fallback.
    let routes = api_routes();
    let mut router = Router::new().merge(routes.clone());
    for minor in supported_minors() {
        router = router.nest(&format!("/v1.{minor}"), routes.clone());
    }
    router
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(axum::middleware::from_fn(trace_requests))
        .fallback(handlers::not_implemented_fallback)
        .with_state(state)
}

/// Served version minors, derived from the advertised constants so the
/// router can never drift from `/version` (unit 1.4).
fn supported_minors() -> std::ops::RangeInclusive<u32> {
    fn minor(v: &str) -> u32 {
        v.split_once('.')
            .and_then(|(_, m)| m.parse().ok())
            .unwrap_or(44)
    }
    minor(ingot_api::MIN_API_VERSION)..=minor(ingot_api::API_VERSION)
}

/// Per-request span (Plan Phase 0, unit 0.3): method + path + status +
/// latency on every Engine API call. Only the path is logged, never the
/// query string or body — credentials, tokens, and env secrets must never
/// appear in daemon logs (see also `DaemonState` handlers).
async fn trace_requests(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use tracing::Instrument;
    // Fast path: skip span+alloc for hot polls (ping, stats polling).
    let path = req.uri().path();
    if path == "/_ping" || path.ends_with("/_ping") {
        return next.run(req).await;
    }
    let method = req.method().clone();
    let path = path.to_string();
    let span = tracing::info_span!("engine_api", %method, path = %path);
    let start = std::time::Instant::now();
    let resp = next.run(req).instrument(span).await;
    tracing::debug!(
        method = %method,
        path = %path,
        status = resp.status().as_u16(),
        latency_ms = start.elapsed().as_millis(),
        "engine request"
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{DaemonConfig, DaemonState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Rootless daemon state: image store + registry only, no container,
    /// network, or volume managers (Tier 1 — no root needed).
    fn test_state(tag: &str) -> SharedState {
        let dir =
            std::env::temp_dir().join(format!("ingot-router-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = ingot_store::paths::DataPaths::new(&dir, dir.join("run"));
        paths.create_all().unwrap();
        let daemon =
            DaemonState::new(paths, DaemonConfig::default()).expect("daemon state builds rootless");
        let state = std::sync::Arc::new(daemon);
        // Stash the dir for cleanup via a leaked guard is overkill; the
        // temp dir is namespaced per-test and tiny.
        let _ = state.paths.root.clone();
        state
    }

    async fn get(router: Router, uri: &str) -> (StatusCode, serde_json::Value, String) {
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        (status, json, text)
    }

    #[tokio::test]
    async fn version_prefix_parity() {
        let state = test_state("prefix");
        // Every served minor answers ping + version identically (unit 1.4);
        // the advertised constants always agree with the router.
        for minor in super::supported_minors() {
            let uri = format!("/v1.{minor}/_ping");
            let (s, _, text) = get(build_router(state.clone()), &uri).await;
            assert_eq!(s, StatusCode::OK, "ping on {uri}");
            assert_eq!(text, "OK");

            let uri = format!("/v1.{minor}/version");
            let (s, v, _) = get(build_router(state.clone()), &uri).await;
            assert_eq!(s, StatusCode::OK, "version on {uri}");
            assert_eq!(v["ApiVersion"], ingot_api::API_VERSION);
            assert_eq!(v["MinAPIVersion"], ingot_api::MIN_API_VERSION);
        }

        // Bare paths keep working too.
        let (s, _, text) = get(build_router(state.clone()), "/_ping").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(text, "OK");
    }

    #[tokio::test]
    async fn unknown_routes_are_explicit_501() {
        let state = test_state("fallback");
        for uri in [
            "/v1.44/plugins/list",
            "/v1.30/swarm/xxx",
            "/nope",
            // Outside the served range (below min / above max).
            "/v1.23/version",
            "/v1.45/version",
            "/v2/version",
        ] {
            let (s, v, _) = get(build_router(state.clone()), uri).await;
            assert_eq!(s, StatusCode::NOT_IMPLEMENTED, "{uri}");
            assert!(
                v["message"]
                    .as_str()
                    .unwrap_or("")
                    .contains("not implemented"),
                "{uri}: {v}"
            );
        }
    }

    #[tokio::test]
    async fn df_and_info_serve_without_managers() {
        let state = test_state("dfinfo");
        let (s, v, _) = get(build_router(state.clone()), "/v1.44/system/df").await;
        assert_eq!(s, StatusCode::OK);
        for key in [
            "LayersSize",
            "Images",
            "Containers",
            "Volumes",
            "BuildCache",
        ] {
            assert!(v.get(key).is_some(), "df has {key}: {v}");
        }
        let (s, v, _) = get(build_router(state.clone()), "/v1.44/info").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["Driver"], "overlay2");
        assert!(v.get("Containers").is_some());
        let _ = std::fs::remove_dir_all(&state.paths.root);
    }
}
