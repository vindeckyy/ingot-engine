//! Push integration tests against a minimal `TcpListener` fake registry
//! (no axum/hyper): auth challenge, blob upload (initiate + PUT,
//! monolithic fallback), and manifest PUT.

use ingot_registry::{ImageRef, RegistryClient};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Received {
    token_auths: Vec<Option<String>>,
    initiates: Vec<String>,
    blobs: HashMap<String, Vec<u8>>,
    manifests: Vec<(String, String, String, Vec<u8>)>,
    manifest_puts: usize,
}

struct Fake {
    addr: SocketAddr,
    received: Arc<Mutex<Received>>,
    _task: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
struct FakeConfig {
    existing: HashSet<String>,
    no_initiate: bool,
    fail_manifest_once: bool,
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

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

fn digest_of(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

async fn spawn_fake(config: FakeConfig) -> Fake {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Received::default()));
    let fail_once = Arc::new(AtomicBool::new(config.fail_manifest_once));
    let uploads = Arc::new(AtomicU64::new(0));
    let task = {
        let received = received.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let received = received.clone();
                let fail_once = fail_once.clone();
                let uploads = uploads.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    let (read, mut write) = stream.into_split();
                    let mut reader = tokio::io::BufReader::new(read);
                    let Some((method, path, headers)) = read_request(&mut reader).await else {
                        return;
                    };
                    // reqwest may wait for `100 Continue` on streaming PUTs.
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
                    let query_of = |key: &str| {
                        query.split('&').find_map(|kv| {
                            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                            (k == key).then(|| v.to_string())
                        })
                    };
                    // Token endpoint: no auth needed, records what it saw.
                    if method == "GET" && path_no_q == "/token" {
                        received
                            .lock()
                            .unwrap()
                            .token_auths
                            .push(headers.get("authorization").cloned());
                        let token = b"{\"token\":\"fake-token\",\"expires_in\":3600}";
                        respond(
                            &mut write,
                            "200 OK",
                            &[("Content-Type", "application/json".into())],
                            token,
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
                    let segs: Vec<&str> = path_no_q.split('/').collect();
                    // HEAD /v2/<repo>/blobs/<digest>
                    if method == "HEAD"
                        && segs.len() >= 5
                        && segs[1] == "v2"
                        && segs[segs.len() - 2] == "blobs"
                    {
                        let digest = segs[segs.len() - 1].to_string();
                        if config.existing.contains(&digest) {
                            respond(&mut write, "200 OK", &[], b"").await;
                        } else {
                            respond(
                                &mut write,
                                "404 Not Found",
                                &[],
                                br#"{"errors":[{"code":"BLOB_UNKNOWN","message":"blob unknown"}]}"#,
                            )
                            .await;
                        }
                        return;
                    }
                    // POST /v2/<repo>/blobs/uploads[/]
                    if method == "POST"
                        && (path_no_q.ends_with("/blobs/uploads/")
                            || path_no_q.ends_with("/blobs/uploads"))
                    {
                        if let Some(digest) = query_of("digest") {
                            received.lock().unwrap().blobs.insert(digest.clone(), body);
                            respond(
                                &mut write,
                                "201 Created",
                                &[("Docker-Content-Digest", digest)],
                                b"",
                            )
                            .await;
                        } else if config.no_initiate {
                            respond(&mut write, "404 Not Found", &[], b"").await;
                        } else {
                            let n = uploads.fetch_add(1, Ordering::SeqCst);
                            let repo = path_no_q
                                .trim_start_matches("/v2/")
                                .trim_end_matches("/blobs/uploads/");
                            let location = format!("/v2/{repo}/blobs/uploads/sess-{n}");
                            received.lock().unwrap().initiates.push(location.clone());
                            respond(&mut write, "202 Accepted", &[("Location", location)], b"")
                                .await;
                        }
                        return;
                    }
                    // PUT <upload-location>?digest=
                    if method == "PUT" && path_no_q.contains("/blobs/uploads/") {
                        if let Some(digest) = query_of("digest") {
                            received.lock().unwrap().blobs.insert(digest.clone(), body);
                            respond(
                                &mut write,
                                "201 Created",
                                &[("Docker-Content-Digest", digest)],
                                b"",
                            )
                            .await;
                        } else {
                            respond(&mut write, "400 Bad Request", &[], b"missing digest").await;
                        }
                        return;
                    }
                    // PUT /v2/<repo>/manifests/<ref>
                    if method == "PUT" && path_no_q.contains("/manifests/") {
                        received.lock().unwrap().manifest_puts += 1;
                        if fail_once.swap(false, Ordering::SeqCst) {
                            respond(&mut write, "500 Internal Server Error", &[], b"boom").await;
                            return;
                        }
                        let stripped = path_no_q.trim_start_matches("/v2/");
                        let (repo, reference) = stripped.split_once("/manifests/").unwrap();
                        let (repo, reference) = (repo.to_string(), reference.to_string());
                        let ctype = headers.get("content-type").cloned().unwrap_or_default();
                        let digest = digest_of(&body);
                        received
                            .lock()
                            .unwrap()
                            .manifests
                            .push((repo, reference, ctype, body));
                        respond(
                            &mut write,
                            "201 Created",
                            &[("Docker-Content-Digest", digest)],
                            b"",
                        )
                        .await;
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

fn image_for(fake: &Fake, repo: &str, tag: &str) -> ImageRef {
    ImageRef::parse(&format!("127.0.0.1:{}/{repo}:{tag}", fake.addr.port())).unwrap()
}

fn base_config() -> FakeConfig {
    FakeConfig {
        existing: HashSet::new(),
        no_initiate: false,
        fail_manifest_once: false,
    }
}

#[tokio::test]
async fn blob_upload_roundtrip() {
    let fake = spawn_fake(base_config()).await;
    let image = image_for(&fake, "team/app", "t1");
    let client = RegistryClient::new();
    let bytes = b"fake-layer-bytes".to_vec();
    let digest = digest_of(&bytes);

    assert!(!client.blob_exists(&image, &digest, None).await.unwrap());
    assert!(client
        .push_blob_bytes(&image, &digest, bytes.clone(), None)
        .await
        .unwrap());
    let rec = fake.received.lock().unwrap();
    assert_eq!(rec.blobs.get(&digest), Some(&bytes));
    assert_eq!(rec.initiates.len(), 1);
    assert_eq!(rec.token_auths.len(), 1);
    assert_eq!(rec.token_auths[0], None);
}

#[tokio::test]
async fn blob_upload_skips_when_exists() {
    let bytes = b"already-there".to_vec();
    let digest = digest_of(&bytes);
    let mut config = base_config();
    config.existing.insert(digest.clone());
    let fake = spawn_fake(config).await;
    let image = image_for(&fake, "team/app", "t1");
    let client = RegistryClient::new();

    assert!(client.blob_exists(&image, &digest, None).await.unwrap());
    assert!(!client
        .push_blob_bytes(&image, &digest, bytes, None)
        .await
        .unwrap());
    let rec = fake.received.lock().unwrap();
    assert!(rec.blobs.is_empty());
    assert!(rec.initiates.is_empty());
}

#[tokio::test]
async fn blob_upload_file_streams_chunks() {
    let fake = spawn_fake(base_config()).await;
    let image = image_for(&fake, "team/app", "t1");
    let client = RegistryClient::new();
    // Larger than one 128KB stream chunk, so the file path is exercised.
    let bytes: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let digest = digest_of(&bytes);
    let dir = std::env::temp_dir().join(format!("ingot-push-file-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("layer");
    std::fs::write(&path, &bytes).unwrap();

    assert!(client
        .push_blob_file(&image, &digest, &path, None)
        .await
        .unwrap());
    let rec = fake.received.lock().unwrap();
    assert_eq!(rec.blobs.get(&digest), Some(&bytes));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn blob_upload_monolithic_fallback() {
    let mut config = base_config();
    config.no_initiate = true;
    let fake = spawn_fake(config).await;
    let image = image_for(&fake, "team/app", "t1");
    let client = RegistryClient::new();
    let bytes = b"monolithic-bytes".to_vec();
    let digest = digest_of(&bytes);

    assert!(client
        .push_blob_bytes(&image, &digest, bytes.clone(), None)
        .await
        .unwrap());
    let rec = fake.received.lock().unwrap();
    assert_eq!(rec.blobs.get(&digest), Some(&bytes));
    assert!(rec.initiates.is_empty());
}

#[tokio::test]
async fn manifest_put_roundtrip() {
    let fake = spawn_fake(base_config()).await;
    let image = image_for(&fake, "team/app", "t1");
    let client = RegistryClient::new();
    let body = br#"{"schemaVersion":2,"config":{"digest":"sha256:abc"}}"#;

    let digest = client
        .push_manifest(
            &image,
            "t1",
            "application/vnd.oci.image.manifest.v1+json",
            body,
            None,
        )
        .await
        .unwrap();
    assert_eq!(digest, digest_of(body));
    let rec = fake.received.lock().unwrap();
    assert_eq!(rec.manifests.len(), 1);
    let (repo, reference, ctype, got) = &rec.manifests[0];
    assert_eq!(repo, "team/app");
    assert_eq!(reference, "t1");
    assert_eq!(ctype, "application/vnd.oci.image.manifest.v1+json");
    assert_eq!(got, body);
}

#[tokio::test]
async fn manifest_put_retries_server_error() {
    let mut config = base_config();
    config.fail_manifest_once = true;
    let fake = spawn_fake(config).await;
    let image = image_for(&fake, "team/app", "t1");
    let client = RegistryClient::new();

    let digest = client
        .push_manifest(&image, "t1", "application/json", b"{}", None)
        .await
        .unwrap();
    assert_eq!(digest, digest_of(b"{}"));
    assert_eq!(fake.received.lock().unwrap().manifest_puts, 2);
}

#[tokio::test]
async fn token_request_carries_basic_credentials() {
    use base64::Engine;
    let fake = spawn_fake(base_config()).await;
    let image = image_for(&fake, "team/app", "t1");
    let client = RegistryClient::new();
    let auth = ingot_api::AuthConfig {
        username: "user".into(),
        password: "s3cret".into(),
        ..Default::default()
    };
    let bytes = b"cred-blob".to_vec();
    let digest = digest_of(&bytes);
    client
        .push_blob_bytes(&image, &digest, bytes, Some(&auth))
        .await
        .unwrap();
    let rec = fake.received.lock().unwrap();
    let want = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("user:s3cret")
    );
    assert!(rec.token_auths.iter().any(|a| a.as_deref() == Some(&want)));
}
