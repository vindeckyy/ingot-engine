//! Connection-hijacking endpoints: /containers/{id}/attach and /exec/*.
//!
//! Docker upgrades the HTTP connection to a raw duplex stream (101 UPGRADED)
//! and then speaks the multiplexed frame protocol (8-byte headers) when the
//! container has no TTY.

use crate::handlers::{bad_request, not_found, server_error};
use crate::state::SharedState;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use hyper::http as http;
use axum::response::{IntoResponse, Response};
use ingot_runtime::stdio::{frame, StdioHub, STREAM_STDERR, STREAM_STDOUT};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Bridge hyper 1.x's `Upgraded` (hyper::rt::Read/Write) into tokio's
/// AsyncRead/AsyncWrite so we can use `tokio::io::split` on it.
struct TokioUpgraded(hyper::upgrade::Upgraded);

impl tokio::io::AsyncRead for TokioUpgraded {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        tbuf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let slice = tbuf.initialize_unfilled();
        let mut hbuf = hyper::rt::ReadBuf::new(slice);
        match hyper::rt::Read::poll_read(std::pin::Pin::new(&mut self.0), cx, hbuf.unfilled()) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let n = hbuf.filled().len();
        unsafe {
            tbuf.assume_init(n);
        }
        tbuf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for TokioUpgraded {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        hyper::rt::Write::poll_write(std::pin::Pin::new(&mut self.0), cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        hyper::rt::Write::poll_flush(std::pin::Pin::new(&mut self.0), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        hyper::rt::Write::poll_shutdown(std::pin::Pin::new(&mut self.0), cx)
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct AttachQuery {
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    stdin: Option<bool>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    stdout: Option<bool>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    stderr: Option<bool>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    stream: Option<bool>,
    #[serde(deserialize_with = "ingot_api::de::flexible_bool", default)]
    logs: Option<bool>,
}

/// POST /containers/{id}/attach — hijack, then bridge stdio.
pub async fn attach(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<AttachQuery>,
    mut req: axum::extract::Request,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let handle = match mgr.get(&id).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("No such container: {id}")),
    };
    let record = handle.record.lock().unwrap().clone();
    let tty = record.config.Tty;

    let want_in = q.stdin.unwrap_or(false);
    let want_out = q.stdout.unwrap_or(false);
    let want_err = q.stderr.unwrap_or(false);
    let do_stream = q.stream.unwrap_or(false);

    // The OnUpgrade future resolves once the 101 response below is written.
    let upgrade = hyper::upgrade::on(&mut req);

    // Register the live stream BEFORE the 101 response so no output races.
    let rx = handle.stdio.subscribe();
    let log_path = state.paths.container_log(&record.id);

    tokio::spawn(async move {
        let sock = match upgrade.await {
            Ok(s) => TokioUpgraded(s),
            Err(e) => {
                tracing::debug!("attach upgrade failed: {e}");
                return;
            }
        };
        let hub = handle.stdio.clone();

        // Replay history when requested (docker logs=1 semantics).
        let mut sock = sock;
        if q.logs.unwrap_or(false) {
            let initial = read_log_frames(&log_path, tty, want_out, want_err);
            if !initial.is_empty() && sock.write_all(&initial).await.is_err() {
                return;
            }
        }

        // hub → client
        let (mut rsock, mut wsock) = tokio::io::split(sock);
        let writer = tokio::spawn(async move {
            let mut rx = rx;
            loop {
                match rx.recv().await {
                    Ok((stream, data)) => {
                        let keep = (stream == STREAM_STDOUT && want_out)
                            || (stream == STREAM_STDERR && want_err);
                        if !keep {
                            continue;
                        }
                        let payload = if tty {
                            bytes::Bytes::from(data)
                        } else {
                            frame(stream, &data)
                        };
                        if wsock.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            let _ = wsock.shutdown().await;
        });

        // client → stdin
        if want_in && do_stream {
            let hub2 = hub.clone();
            let mut r = rsock;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            hub2.send_stdin(buf[..n].to_vec()).await;
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        // Exit when the container exits.
        let mut exit_rx = handle.subscribe_exit();
        let _ = exit_rx.recv().await;
        writer.abort();
    });

    // 101 UPGRADED — docker raw stream from here on.
    Response::builder()
        .status(101)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "tcp")
        .header(header::CONTENT_TYPE, "application/vnd.docker.raw-stream")
        .body(Body::empty())
        .unwrap()
}

fn read_log_frames(log_path: &std::path::Path, tty: bool, want_out: bool, want_err: bool) -> Vec<u8> {
    let raw = std::fs::read(log_path).unwrap_or_default();
    let mut out = Vec::new();
    for line in raw.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) {
            let stream = if v["stream"] == "stderr" { STREAM_STDERR } else { STREAM_STDOUT };
            let keep = (stream == STREAM_STDOUT && want_out) || (stream == STREAM_STDERR && want_err);
            if !keep {
                continue;
            }
            let data = v["log"].as_str().unwrap_or("").as_bytes();
            if tty {
                out.extend_from_slice(data);
            } else {
                out.extend_from_slice(&frame(stream, data));
            }
        }
    }
    out
}

// ---------------- exec ----------------

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct ExecCreateQuery {
    #[serde(default)]
    name: Option<String>,
}

/// POST /containers/{id}/exec
pub async fn exec_create(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let handle = match mgr.get(&id).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("No such container: {id}")),
    };
    let body: ingot_api::ExecCreateBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return bad_request(format!("invalid exec config: {e}")),
    };
    if body.Cmd.is_empty() {
        return bad_request("No exec command specified");
    }
    let log_path = state.paths.container_log(&handle.id());
    let session = std::sync::Arc::new(ingot_runtime::exec::ExecSession::new(
        handle.id(),
        body.Cmd.clone(),
        body.Tty,
        body.Detach,
        body.User.clone(),
        body.WorkingDir.clone(),
        body.Env.clone(),
        log_path,
    ));
    let eid = session.id.clone();
    mgr.register_exec(session);
    (StatusCode::CREATED, axum::Json(json!({ "Id": eid }))).into_response()
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct ExecStartBody {
    #[serde(default)]
    Detach: bool,
    #[serde(default)]
    Tty: bool,
}

/// POST /exec/{id}/start — hijacked unless Detach.
pub async fn exec_start(
    State(state): State<SharedState>,
    Path(eid): Path<String>,
    mut req: axum::extract::Request,
) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let session = match mgr.exec_session(&eid) {
        Some(s) => s,
        None => return not_found(format!("No such exec instance: {eid}")),
    };
    let (parts, req_body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(req_body, 64 * 1024).await {
        Ok(b) => b,
        Err(e) => return server_error(format!("read exec start body: {e}")),
    };
    let body: ExecStartBody = if body_bytes.is_empty() {
        Default::default()
    } else {
        serde_json::from_slice(&body_bytes).unwrap_or_default()
    };
    // Rebuild the request so the OnUpgrade extension survives body parsing.
    let mut rebuilt = http::Request::from_parts(parts, Body::empty());
    let container = match mgr.get(&session.container_id).await {
        Ok(Some(h)) => h,
        _ => return not_found(format!("No such container: {}", session.container_id)),
    };
    if !container.is_running() {
        return bad_request("Container is not running");
    }

    if body.Detach || session.detach {
        // Fire and forget.
        let s = session.clone();
        let c = container.clone();
        let paths = state.paths.clone();
        if let Err(e) = ingot_runtime::exec::start_exec(s, c, paths) {
            return server_error(format!("{e:#}"));
        }
        return StatusCode::OK.into_response();
    }

    let upgrade = hyper::upgrade::on(&mut rebuilt);
    let tty = session.tty;
    let rx = session.stdio.subscribe();
    let session2 = session.clone();
    let container2 = container.clone();

    tokio::spawn(async move {
        let sock = match upgrade.await {
            Ok(s) => TokioUpgraded(s),
            Err(e) => {
                tracing::debug!("exec upgrade failed: {e}");
                return;
            }
        };
        let (mut rsock, mut wsock) = tokio::io::split(sock);

        // hub → client
        let writer = tokio::spawn(async move {
            let mut rx = rx;
            loop {
                match rx.recv().await {
                    Ok((stream, data)) => {
                        let payload = if tty {
                            bytes::Bytes::from(data)
                        } else {
                            frame(stream, &data)
                        };
                        if wsock.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            let _ = wsock.shutdown().await;
        });

        // client → stdin
        {
            let mut r = rsock;
            let session3 = session2.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            session3.send_stdin(buf[..n].to_vec()).await;
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        // Wait for the exec to finish.
        let mut exit_rx = session2.subscribe_exit();
        let _ = exit_rx.recv().await;
        writer.abort();
        let _ = container2;
    });

    // Kick off the process now that the stream is wired.
    let paths = state.paths.clone();
    if let Err(e) = ingot_runtime::exec::start_exec(session, container, paths) {
        return server_error(format!("{e:#}"));
    }

    Response::builder()
        .status(101)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "tcp")
        .header(header::CONTENT_TYPE, "application/vnd.docker.raw-stream")
        .body(Body::empty())
        .unwrap()
}

/// GET /exec/{id}/json
pub async fn exec_inspect(State(state): State<SharedState>, Path(eid): Path<String>) -> Response {
    let mgr = state.containers.as_ref().unwrap();
    let session = match mgr.exec_session(&eid) {
        Some(s) => s,
        None => return not_found(format!("No such exec instance: {eid}")),
    };
    let st = session.state.lock().unwrap().clone();
    let inspect = ingot_api::ExecInspect {
        CanRemove: true,
        ContainerID: session.container_id.clone(),
        DetachKeys: String::new(),
        ExitCode: st.exit_code as i64,
        ID: session.id.clone(),
        OpenStderr: true,
        OpenStdin: true,
        OpenStdout: true,
        ProcessConfig: ingot_api::ExecProcessConfig {
            arguments: session.cmd.iter().skip(1).cloned().collect(),
            entrypoint: session.cmd.first().cloned().unwrap_or_default(),
            privileged: false,
            tty: session.tty,
            user: session.user.clone(),
        },
        Running: st.running,
        Pid: st.pid,
    };
    axum::Json(inspect).into_response()
}
