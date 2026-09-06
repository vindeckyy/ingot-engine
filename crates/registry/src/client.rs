//! Registry v2 HTTP client.
//!
//! Pull flow (per OCI distribution spec + Docker Hub auth):
//!   1. GET /v2/<repo>/manifests/<ref> → 401 with WWW-Authenticate challenge
//!   2. GET <realm>?service=<svc>&scope=repository:<repo>:pull → {token}
//!   3. retry with Authorization: Bearer
//!   4. resolve index/manifest-list → linux/amd64 manifest
//!   5. stream config + layer blobs from /v2/<repo>/blobs/<digest>

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use ingot_api::AuthConfig;
use serde::Deserialize;
use sha2::Digest;
use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::reference::ImageRef;

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json";

#[derive(Debug, Clone)]
pub struct PlatformManifest {
    /// The platform image manifest digest.
    pub manifest_digest: String,
    pub media_type: String,
    /// Config blob digest (== image id).
    pub config_digest: String,
    /// Ordered layers, base-first.
    pub layers: Vec<Descriptor>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    #[serde(default)]
    pub media_type: String,
    pub digest: String,
    #[serde(default)]
    pub size: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct RawManifest {
    #[serde(default)]
    mediaType: String,
    #[serde(default)]
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
    #[serde(default)]
    manifests: Vec<IndexEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct IndexEntry {
    mediaType: String,
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Debug, Clone, Deserialize)]
struct Platform {
    architecture: Option<String>,
    os: Option<String>,
}

pub struct RegistryClient {
    http: reqwest::Client,
    tokens: tokio::sync::Mutex<HashMap<String, String>>,
}

/// Async writer that hashes what it writes; used for digest verification of
/// streamed blobs.
struct HashingWriter<W: AsyncWrite + Unpin> {
    inner: W,
    hasher: sha2::Sha256,
    written: u64,
}

impl<W: AsyncWrite + Unpin> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, hasher: sha2::Sha256::new(), written: 0 }
    }
    fn finish(self) -> (String, u64) {
        (hex::encode(self.hasher.finalize()), self.written)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for HashingWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let n = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

enum Challenge {
    Bearer { realm: String, service: String, scope: String },
    Basic,
}

impl RegistryClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("ingot/{}", ingot_api::ENGINE_VERSION))
            .redirect(reqwest::redirect::Policy::limited(6))
            .build()
            .expect("reqwest client");
        RegistryClient { http, tokens: tokio::sync::Mutex::new(HashMap::new()) }
    }

    fn endpoint(image: &ImageRef) -> String {
        match image.registry.as_str() {
            "docker.io" => "https://registry-1.docker.io".into(),
            r => format!("https://{r}"),
        }
    }

    fn parse_challenge(header: &str) -> Result<Challenge> {
        let header = header.trim();
        if let Some(rest) = header.strip_prefix("Bearer") {
            let mut realm = String::new();
            let mut service = String::new();
            let mut scope = String::new();
            for part in rest.split(',') {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=') {
                    let v = v.trim_matches('"');
                    match k.trim() {
                        "realm" => realm = v.to_string(),
                        "service" => service = v.to_string(),
                        "scope" => scope = v.to_string(),
                        _ => {}
                    }
                }
            }
            if realm.is_empty() {
                return Err(anyhow!("malformed bearer challenge: {header}"));
            }
            Ok(Challenge::Bearer { realm, service, scope })
        } else if header.starts_with("Basic") {
            Ok(Challenge::Basic)
        } else {
            Err(anyhow!("unsupported auth challenge: {header}"))
        }
    }

    fn basic_auth_value(auth: &AuthConfig) -> String {
        use base64::Engine;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", auth.username, auth.password))
        )
    }

    async fn bearer_token(
        &self,
        scope: &str,
        realm: &str,
        service: &str,
        auth: Option<&AuthConfig>,
    ) -> Result<String> {
        let cache_key = format!(
            "{realm}|{service}|{scope}|{}",
            auth.map(|a| a.username.clone()).unwrap_or_default()
        );
        if let Some(t) = self.tokens.lock().await.get(&cache_key) {
            return Ok(t.clone());
        }
        let mut url = format!("{realm}?service={}", pct_encode(service));
        if !scope.is_empty() {
            url.push_str(&format!("&scope={}", pct_encode(scope)));
        }
        let mut req = self.http.get(&url);
        if let Some(a) = auth {
            if !a.username.is_empty() {
                req = req.header(reqwest::header::AUTHORIZATION, Self::basic_auth_value(a));
            }
        }
        let resp = req.send().await.context("registry token request")?;
        let status = resp.status();
        let body = resp.bytes().await?;
        if !status.is_success() {
            return Err(anyhow!("token request failed ({status}): {}", truncate(&String::from_utf8_lossy(&body), 200)));
        }
        let v: serde_json::Value = serde_json::from_slice(&body).context("parse token response")?;
        let token = v
            .get("token")
            .or_else(|| v.get("access_token"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow!("token response missing token field"))?
            .to_string();
        self.tokens.lock().await.insert(cache_key, token.clone());
        Ok(token)
    }

    /// GET/HEAD a registry URL, performing the auth challenge dance.
    async fn authed_request(
        &self,
        image: &ImageRef,
        method: reqwest::Method,
        path: &str,
        accept: Option<&str>,
        auth: Option<&AuthConfig>,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", Self::endpoint(image), path);
        let send = |client: &reqwest::Client, method: reqwest::Method, url: &str, bearer: Option<&str>, basic: Option<&String>| {
            let mut req = client.request(method.clone(), url);
            if let Some(a) = accept {
                req = req.header(reqwest::header::ACCEPT, a);
            }
            if let Some(b) = bearer {
                req = req.bearer_auth(b);
            }
            if let Some(b) = basic {
                req = req.header(reqwest::header::AUTHORIZATION, b);
            }
            req
        };

        let resp = send(&self.http, method.clone(), &url, None, None)
            .send()
            .await
            .with_context(|| format!("{method} {url}"))?;
        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }
        let header = resp
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow!("401 without WWW-Authenticate from {url}"))?
            .to_string();
        match Self::parse_challenge(&header)? {
            Challenge::Bearer { realm, service, scope } => {
                let scope = if scope.is_empty() {
                    format!("repository:{}:pull", image.api_repo())
                } else {
                    scope
                };
                let token = self.bearer_token(&scope, &realm, &service, auth).await?;
                Ok(send(&self.http, method.clone(), &url, Some(&token), None)
                    .send()
                    .await
                    .with_context(|| format!("{method} {url} (authed)"))?)
            }
            Challenge::Basic => {
                let basic = auth.filter(|a| !a.username.is_empty()).map(Self::basic_auth_value);
                Ok(send(&self.http, method, &url, None, basic.as_ref()).send().await?)
            }
        }
    }

    /// Fetch and resolve the manifest: follows index → platform manifest.
    /// Returns (platform manifest, top-level digest that was addressed).
    pub async fn fetch_manifest(
        &self,
        image: &ImageRef,
        auth: Option<&AuthConfig>,
    ) -> Result<(PlatformManifest, String)> {
        let reference = image
            .digest
            .clone()
            .or_else(|| image.tag.clone())
            .ok_or_else(|| anyhow!("reference has neither tag nor digest"))?;
        let path = format!("/v2/{}/manifests/{}", image.api_repo(), reference);
        let resp = self.authed_request(image, reqwest::Method::GET, &path, Some(MANIFEST_ACCEPT), auth).await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(manifest_error(status.as_u16(), &body, image));
        }
        let header_digest = body_digest_header(&resp).ok();
        let body = resp.bytes().await?;
        let top_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));
        let raw: RawManifest =
            serde_json::from_slice(&body).with_context(|| format!("parse manifest for {}", image.display_ref()))?;

        if !raw.manifests.is_empty() {
            let entry = pick_platform(&raw.manifests).ok_or_else(|| {
                anyhow!("no linux/amd64 manifest in index for {}", image.display_ref())
            })?;
            let sub_path = format!("/v2/{}/manifests/{}", image.api_repo(), entry.digest);
            let sub = self
                .authed_request(image, reqwest::Method::GET, &sub_path, Some(MANIFEST_ACCEPT), auth)
                .await?;
            let sub_status = sub.status();
            let sub_body = if sub_status.is_success() {
                sub.bytes().await?
            } else {
                let b = sub.text().await.unwrap_or_default();
                return Err(anyhow!("platform manifest fetch failed ({sub_status}): {b}"));
            };
            let mut m: RawManifest =
                serde_json::from_slice(&sub_body).context("parse platform manifest")?;
            let sub_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&sub_body)));
            m.mediaType = entry.mediaType.clone();
            let config = m.config.ok_or_else(|| anyhow!("manifest has no config"))?;
            return Ok((
                PlatformManifest {
                    manifest_digest: sub_digest,
                    media_type: m.mediaType,
                    config_digest: config.digest,
                    layers: m.layers,
                },
                top_digest,
            ));
        }

        let config = raw.config.ok_or_else(|| anyhow!("manifest has no config"))?;
        Ok((
            PlatformManifest {
                manifest_digest: top_digest.clone(),
                media_type: raw.mediaType,
                config_digest: config.digest,
                layers: raw.layers,
            },
            top_digest,
        ))
    }

    /// Stream a blob to `dest`, verifying sha256 while writing. Skips when
    /// the content-addressed store already holds it. Returns bytes written.
    pub async fn fetch_blob_to_file(
        &self,
        image: &ImageRef,
        digest: &str,
        dest: &Path,
        auth: Option<&AuthConfig>,
    ) -> Result<u64> {
        if dest.exists() {
            return Ok(std::fs::metadata(dest)?.len());
        }
        let path = format!("/v2/{}/blobs/{}", image.api_repo(), digest);
        let resp = self.authed_request(image, reqwest::Method::GET, &path, None, auth).await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("blob {digest} fetch failed ({}): {}", status, truncate(&body, 300)));
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = dest.with_extension("part");
        let file = tokio::fs::File::create(&tmp).await?;
        let mut writer = HashingWriter::new(file);
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            writer.write_all(&chunk).await?;
        }
        writer.flush().await?;
        writer.shutdown().await?;
        let (actual, written) = writer.finish();
        let expected = digest.strip_prefix("sha256:").unwrap_or(digest);
        if actual != expected {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(anyhow!("digest mismatch for {digest}: received sha256:{actual}"));
        }
        tokio::fs::rename(&tmp, dest).await?;
        Ok(written)
    }

    pub async fn head_blob(
        &self,
        image: &ImageRef,
        digest: &str,
        auth: Option<&AuthConfig>,
    ) -> Result<Option<i64>> {
        let path = format!("/v2/{}/blobs/{}", image.api_repo(), digest);
        let resp = self
            .authed_request(image, reqwest::Method::HEAD, &path, None, auth)
            .await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        Ok(resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok()))
    }
}

fn body_digest_header(resp: &reqwest::Response) -> Result<String> {
    resp.headers()
        .get("Docker-Content-Digest")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("no Docker-Content-Digest header"))
}

fn pick_platform(entries: &[IndexEntry]) -> Option<IndexEntry> {
    entries
        .iter()
        .find(|e| {
            e.platform
                .as_ref()
                .map(|p| p.os.as_deref() == Some("linux") && p.architecture.as_deref() == Some("amd64"))
                .unwrap_or(false)
        })
        .or_else(|| {
            entries
                .iter()
                .find(|e| e.platform.as_ref().map(|p| p.os.as_deref() == Some("linux")).unwrap_or(false))
        })
        .cloned()
}

fn manifest_error(status: u16, body: &str, image: &ImageRef) -> anyhow::Error {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body.as_bytes()) {
        if let Some(errors) = v.get("errors").and_then(|e| e.as_array()) {
            for e in errors {
                let code = e.get("code").and_then(|c| c.as_str()).unwrap_or("");
                if code == "MANIFEST_UNKNOWN" || code == "NAME_UNKNOWN" {
                    return anyhow!(
                        "pull access denied for {}, repository does not exist or may require authorization",
                        image.display_ref()
                    );
                }
            }
        }
    }
    anyhow!("manifest fetch for {} failed ({status}): {}", image.display_ref(), truncate(body, 300))
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n { s.to_string() } else { format!("{}…", &s[..n]) }
}

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
