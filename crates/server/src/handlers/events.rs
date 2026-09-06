//! GET /events — long-lived chunked JSON stream of daemon events.

use crate::state::SharedState;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct EventsQuery {
    pub since: Option<String>,
    pub until: Option<String>,
    pub filters: Option<String>,
}

pub async fn events(
    State(state): State<SharedState>,
    Query(_q): Query<EventsQuery>,
) -> Response {
    use std::sync::atomic::Ordering;
    state.event_listeners.fetch_add(1, Ordering::Relaxed);
    let rx = state.events.subscribe();
    let listener = state.clone();
    let stream = tokio_stream_wrapped(rx).map(move |ev| {
        let _ = &listener;
        match ev {
            Ok(ev) => {
                let mut line = serde_json::to_string(&ev).unwrap_or_default();
                line.push('\n');
                Ok::<_, std::io::Error>(axum::body::Bytes::from(line))
            }
            Err(broadcast_closed) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("event bus closed: {broadcast_closed}"),
            )),
        }
    });
    let body = Body::from_stream(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap()
}

fn tokio_stream_wrapped(
    mut rx: tokio::sync::broadcast::Receiver<ingot_api::EventMessage>,
) -> impl futures::Stream<Item = Result<ingot_api::EventMessage, tokio::sync::broadcast::error::RecvError>> {
    futures::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => return Some((Ok(ev), rx)),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(e @ tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Some((Err(e), rx));
                }
            }
        }
    })
}

/// Filter parsing helper shared by list endpoints: `{"dangling":["true"]}`.
pub fn parse_filters(raw: &Option<String>) -> HashMap<String, Vec<String>> {
    raw.as_deref()
        .map(|s| serde_json::from_str(s).unwrap_or_default())
        .unwrap_or_default()
}
