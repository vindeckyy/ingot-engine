//! `POST /images/{name}/push` end to end: a stored image is pushed to a
//! minimal `TcpListener` fake registry (auth challenge, blob upload,
//! manifest PUT), and the progress stream reports the manifest digest.

use ingot_server::router::build_router;
use ingot_server::state::{DaemonConfig, DaemonState, SharedState};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

#[derive(Default)]
struct Received {
    token_auths: Vec<Option<String>>,
    blobs: HashMap<String, Vec<u8>>,
    manifests: Vec<(String, String, Vec<u8>)>,
}

struct Fake {
    addr: SocketAddr,
    received: Arc<Mutex<Received>>,
    _task: tokio::task::JoinHandle<()>,
}

async fn read_request(
    reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Option<(String, String, HashMap<String, String>)> {
    let mut line = String::new();
    if reader.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = HashMap::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await.ok()?;
        let trimmed = line.trim_end().to_string();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    Some((method, path, headers))
}

async fn respond(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    status: &str,
    extra: &[(&str, String)],
    body: &[u8],
) {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let _ = writer.write_all(out.as_bytes()).await;
    let _ = writer.write_all(body).await;
}

async fn spawn_fake() -> Fake {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Received::default()));
    let task = {
        let received = received.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let received = received.clone();
                tokio::spawn(async move {
                    let (read, mut write) = stream.into_split();
                    let mut reader = tokio::io::BufReader::new(read);
                    let Some((method, path, headers)) = read_request(&mut reader).await else {
                        return;
                    };
                    if headers
                        .get("expect")
                        .is_some_and(|v| v.to_lowercase().contains("100-continue"))
                    {
                        let _ = write.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
                    }
                    let len: usize = headers
                        .get("content-length")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let mut body = vec![0u8; len];
                    if len > 0 && reader.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let (path_no_q, query) = match path.split_once('?') {
                        Some((p, q)) => (p, q),
                        None => (path.as_str(), ""),
                    };
                    if method == "GET" && path_no_q == "/token" {
                        received
                            .lock()
                            .unwrap()
                            .token_auths
                            .push(headers.get("authorization").cloned());
                        respond(
                            &mut write,
                            "200 OK",
                            &[("Content-Type", "application/json".into())],
                            b"{\"token\":\"fake-token\"}",
                        )
                        .await;
                        return;
                    }
                    if headers.get("authorization").map(String::as_str) != Some("Bearer fake-token")
                    {
                        let challenge = format!(
                            "Bearer realm=\"http://{addr}/token\",service=\"fake\",scope=\"repository:x:pull,push\""
                        );
                        respond(
                            &mut write,
                            "401 Unauthorized",
                            &[("WWW-Authenticate", challenge)],
                            b"",
                        )
                        .await;
                        return;
                    }
                    if method == "HEAD" {
                        respond(&mut write, "404 Not Found", &[], b"").await;
                        return;
                    }
                    if method == "POST" && path_no_q.ends_with("/blobs/uploads/") {
                        let repo = path_no_q
                            .trim_start_matches("/v2/")
                            .trim_end_matches("/blobs/uploads/");
                        let location = format!("/v2/{repo}/blobs/uploads/sess-1");
                        respond(&mut write, "202 Accepted", &[("Location", location)], b"").await;
                        return;
                    }
                    if method == "PUT" && path_no_q.contains("/blobs/uploads/") {
                        let digest = query
                            .split('&')
                            .find_map(|kv| {
                                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                                (k == "digest").then(|| v.to_string())
                            })
                            .unwrap_or_default();
                        received.lock().unwrap().blobs.insert(digest, body);
                        respond(&mut write, "201 Created", &[], b"").await;
                        return;
                    }
                    if method == "PUT" && path_no_q.contains("/manifests/") {
                        let stripped = path_no_q.trim_start_matches("/v2/");
                        let (repo, reference) = stripped.split_once("/manifests/").unwrap();
                        received.lock().unwrap().manifests.push((
                            repo.to_string(),
                            reference.to_string(),
                            body,
                        ));
                        // No Docker-Content-Digest: the client falls back to
                        // its computed digest (also covering that path).
                        respond(&mut write, "201 Created", &[], b"").await;
                        return;
                    }
                    respond(&mut write, "404 Not Found", &[], b"unknown").await;
                });
            }
        })
    };
    Fake {
        addr,
        received,
        _task: task,
    }
}

fn test_state(tag: &str) -> (SharedState, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("ingot-push-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let paths = ingot_store::paths::DataPaths::new(&dir, dir.join("run"));
    paths.create_all().unwrap();
    let daemon = DaemonState::new(paths, DaemonConfig::default()).unwrap();
    (Arc::new(daemon), dir)
}

fn registry_auth_header(username: &str, password: &str) -> String {
    use base64::Engine;
    let body = serde_json::json!({"username": username, "password": password});
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&body).unwrap())
}

async fn seed_image(state: &SharedState, tag_key: &str) -> (String, String) {
    let config_bytes = br#"{"architecture":"amd64","os":"linux","config":{}}"#.to_vec();
    let config_hex = ingot_util::sha256_hex(&config_bytes);
    let config_digest = format!("sha256:{config_hex}");
    let layer_bytes = b"e2e-layer-bytes".to_vec();
    let layer_digest = format!("sha256:{}", ingot_util::sha256_hex(&layer_bytes));
    for (digest, bytes) in [
        (&config_digest, &config_bytes),
        (&layer_digest, &layer_bytes),
    ] {
        let dest = state.paths.blob(digest);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, bytes).unwrap();
    }
    let record = ingot_image::ImageRecord {
        id: config_hex,
        architecture: "amd64".into(),
        os: "linux".into(),
        repo_tags: vec![tag_key.to_string()],
        layer_blobs: vec![layer_digest.clone()],
        ..Default::default()
    };
    state.images.put_image(&record).await.unwrap();
    (config_digest, layer_digest)
}

#[tokio::test]
async fn push_stored_image_to_fake_registry() {
    let fake = spawn_fake().await;
    let port = fake.addr.port();
    let (state, dir) = test_state("ok");
    let tag_key = format!("127.0.0.1:{port}/team/app:t1");
    let (config_digest, layer_digest) = seed_image(&state, &tag_key).await;

    let name = format!("127.0.0.1:{port}%2Fteam%2Fapp");
    let uri = format!("/v1.44/images/{name}/push?tag=t1");
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(&uri)
        .header("X-Registry-Auth", registry_auth_header("u", "p"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = build_router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap();
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&bytes)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!lines.is_empty());
    assert!(
        lines.iter().all(|v| v.get("error").is_none()),
        "progress must carry no errors: {lines:?}"
    );
    let last = lines.last().unwrap();
    let status = last["status"].as_str().unwrap_or("");
    assert!(status.starts_with("t1: digest: sha256:"), "{lines:?}");
    assert_eq!(last["aux"]["Tag"], "t1");

    let rec = fake.received.lock().unwrap();
    // Config + layer blobs arrived byte-identical.
    assert_eq!(rec.blobs.len(), 2);
    assert_eq!(
        rec.blobs.get(&config_digest).unwrap(),
        br#"{"architecture":"amd64","os":"linux","config":{}}"#
    );
    assert_eq!(rec.blobs.get(&layer_digest).unwrap(), b"e2e-layer-bytes");
    // One manifest addressed at the pushed repo and tag.
    assert_eq!(rec.manifests.len(), 1);
    let (repo, reference, manifest) = &rec.manifests[0];
    assert_eq!(repo, "team/app");
    assert_eq!(reference, "t1");
    let v: serde_json::Value = serde_json::from_slice(manifest).unwrap();
    assert_eq!(v["config"]["digest"], config_digest);
    assert_eq!(v["layers"][0]["digest"], layer_digest);
    // The daemon's X-Registry-Auth reached the token endpoint as Basic.
    use base64::Engine;
    let want = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("u:p")
    );
    assert!(rec.token_auths.iter().any(|a| a.as_deref() == Some(&want)));
    drop(rec);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn push_unknown_image_is_404() {
    let (state, dir) = test_state("missing");
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1.44/images/definitely-not-here/push?tag=t1")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = build_router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["message"]
        .as_str()
        .unwrap_or("")
        .contains("No such image"));
    let _ = std::fs::remove_dir_all(&dir);
}
