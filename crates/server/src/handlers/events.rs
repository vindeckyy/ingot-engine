//! GET /events — long-lived chunked JSON stream of daemon events.

use crate::state::SharedState;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use ingot_api::EventMessage;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct EventsQuery {
    pub since: Option<String>,
    pub until: Option<String>,
    pub filters: Option<String>,
}

#[derive(Debug, Default)]
struct EventFilter {
    since: Option<i64>,
    until: Option<i64>,
    types: HashSet<String>,
    actions: HashSet<String>,
    /// (key, value); empty value matches existence.
    labels: Vec<(String, String)>,
}

pub async fn events(State(state): State<SharedState>, Query(q): Query<EventsQuery>) -> Response {
    use std::sync::atomic::Ordering;
    let filter = match parse_filter(q) {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    state.event_listeners.fetch_add(1, Ordering::Relaxed);
    let rx = state.events.subscribe();
    let stream = event_stream(rx, filter);
    let body = Body::from_stream(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap()
}

/// Unfold a broadcast receiver into JSON lines, applying since/until/filters.
fn event_stream(
    rx: tokio::sync::broadcast::Receiver<EventMessage>,
    filter: EventFilter,
) -> impl futures::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send + 'static {
    futures::stream::unfold((rx, filter), |(mut rx, filter)| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if filter.until.is_some_and(|u| ev.time > u) {
                        return None;
                    }
                    if !matches_filter(&ev, &filter) {
                        continue;
                    }
                    let mut line = serde_json::to_string(&ev).unwrap_or_default();
                    line.push('\n');
                    return Some((Ok(axum::body::Bytes::from(line)), (rx, filter)));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return None;
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

#[allow(clippy::result_large_err)]
fn parse_filter(q: EventsQuery) -> Result<EventFilter, Response> {
    let mut f = EventFilter::default();
    if let Some(s) = q.since {
        f.since = Some(parse_time(&s).map_err(crate::handlers::bad_request)?);
    }
    if let Some(u) = q.until {
        f.until = Some(parse_time(&u).map_err(crate::handlers::bad_request)?);
    }
    for (k, vals) in parse_filters(&q.filters) {
        match k.as_str() {
            "type" => f.types.extend(vals),
            "event" => f.actions.extend(vals),
            "label" => {
                for v in vals {
                    if let Some((key, val)) = v.split_once('=') {
                        f.labels.push((key.to_string(), val.to_string()));
                    } else {
                        f.labels.push((v, String::new()));
                    }
                }
            }
            other => {
                return Err(crate::handlers::bad_request(format!(
                    "invalid event filter '{other}' (supported: type, event, label)"
                )))
            }
        }
    }
    Ok(f)
}

fn parse_time(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty time".to_string());
    }
    if let Ok(ts) = s.parse::<i64>() {
        if ts >= 0 {
            return Ok(ts);
        }
        return Err("negative timestamp".to_string());
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.timestamp());
    }
    Err("want a unix timestamp or RFC 3339 time".to_string())
}

fn matches_filter(ev: &EventMessage, f: &EventFilter) -> bool {
    if f.since.is_some_and(|ts| ev.time < ts) {
        return false;
    }
    if !f.types.is_empty() && !f.types.contains(&ev.Type) {
        return false;
    }
    if !f.actions.is_empty() && !f.actions.contains(&ev.Action) {
        return false;
    }
    for (k, v) in &f.labels {
        let got = ev.Actor.Attributes.get(k);
        match got {
            Some(g) if v.is_empty() || g == v => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn ev(typ: &str, action: &str, label: Option<(&str, &str)>) -> EventMessage {
        let mut attrs = HashMap::new();
        if let Some((k, v)) = label {
            attrs.insert(k.to_string(), v.to_string());
        }
        EventMessage::new(typ, action, "id", attrs)
    }

    #[test]
    fn filter_matches_type_and_action() {
        let mut f = EventFilter::default();
        f.types.insert("container".to_string());
        f.actions.insert("create".to_string());
        assert!(matches_filter(&ev("container", "create", None), &f));
        assert!(!matches_filter(&ev("image", "create", None), &f));
        assert!(!matches_filter(&ev("container", "die", None), &f));
    }

    #[test]
    fn filter_matches_labels() {
        let mut f = EventFilter::default();
        f.labels.push(("app".to_string(), "web".to_string()));
        assert!(matches_filter(
            &ev("container", "create", Some(("app", "web"))),
            &f
        ));
        assert!(!matches_filter(
            &ev("container", "create", Some(("app", "db"))),
            &f
        ));
        assert!(!matches_filter(&ev("container", "create", None), &f));
    }

    #[test]
    fn label_without_value_matches_existence() {
        let mut f = EventFilter::default();
        f.labels.push(("track".to_string(), String::new()));
        assert!(matches_filter(
            &ev("container", "create", Some(("track", "x"))),
            &f
        ));
        assert!(!matches_filter(
            &ev("container", "create", Some(("other", "x"))),
            &f
        ));
    }

    #[test]
    fn parse_time_accepts_timestamp_and_rfc3339() {
        assert_eq!(parse_time("0").unwrap(), 0);
        assert!(parse_time("2024-01-01T00:00:00Z").is_ok());
        assert!(parse_time("nope").is_err());
    }

    #[test]
    fn parse_filter_uses_query_fields() {
        let q = EventsQuery {
            since: Some("0".into()),
            until: Some("1700000000".into()),
            filters: Some(
                r#"{"type":["container"],"event":["create","start"],"label":["app=web","env="]}"#
                    .into(),
            ),
        };
        let f = parse_filter(q).unwrap();
        assert_eq!(f.since, Some(0));
        assert_eq!(f.until, Some(1700000000));
        assert!(f.types.contains("container"));
        assert!(f.actions.contains("create"));
        assert!(f.actions.contains("start"));
        assert!(f.labels.contains(&("app".to_string(), "web".to_string())));
        assert!(f.labels.contains(&("env".to_string(), String::new())));
    }

    #[test]
    fn parse_filter_rejects_unknown_keys() {
        let q = EventsQuery {
            filters: Some(r#"{"foo":["bar"]}"#.into()),
            ..Default::default()
        };
        assert!(parse_filter(q).is_err());
    }

    #[tokio::test]
    async fn event_stream_filters_and_stops_at_until() {
        let (tx, rx1) = tokio::sync::broadcast::channel(8);
        let rx2 = tx.subscribe();

        let mut filter = EventFilter::default();
        filter.types.insert("container".to_string());
        filter.until = Some(i64::MAX);

        let stream = event_stream(rx1, filter);
        tokio::pin!(stream);

        tx.send(EventMessage::new(
            "container",
            "create",
            "a",
            HashMap::new(),
        ))
        .unwrap();
        tx.send(EventMessage::new("image", "pull", "b", HashMap::new()))
            .unwrap();

        let first = stream.next().await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&first).contains("container"));

        // Drop the second subscriber to close the broadcast.
        let _ = rx2;
        drop(tx);
        let next = stream.next().await;
        assert!(next.is_none(), "stream should end when the bus closes");
    }
}
