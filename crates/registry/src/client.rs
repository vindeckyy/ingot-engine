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
    /// Registry base URL that served the manifest (canonical or mirror):
    /// blobs for this pull must come from the same host.
    pub endpoint: String,
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
// Field names mirror the OCI image spec JSON verbatim.
#[allow(non_snake_case)]
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
// Field names mirror the OCI image index JSON verbatim.
#[allow(non_snake_case)]
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
    /// Resume a hash over bytes already on disk (`written` prefix bytes).
    fn with_hasher(inner: W, hasher: sha2::Sha256, written: u64) -> Self {
        Self {
            inner,
            hasher,
            written,
        }
    }
    fn finish(self) -> (String, u64) {
        (hex::encode(self.hasher.finalize()), self.written)
    }
}

/// Fetch attempts per endpoint: 1 initial + 3 retries (blobs and manifests).
const MAX_FETCH_ATTEMPTS: u32 = 4;

/// TCP/TLS handshake bound per request: a dead host fails fast into
/// mirror fallback / retry instead of wedging the pull.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Idle bound between body chunks: a stalled mid-body connection becomes
/// a retryable transport error (resume continues the `.part` file).
const READ_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Total bound for small metadata reads (manifests, tokens).
const METADATA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Backoff before blob retry `attempt` (1-based): 1s, 2s, 4s, capped at 8s.
fn blob_backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs(1u64 << attempt.saturating_sub(1).min(3))
}

/// One attempt's failure: whether retrying can help, the error itself, and
/// an optional server-requested wait (`Retry-After`).
struct AttemptError {
    retryable: bool,
    retry_after: std::time::Duration,
    source: anyhow::Error,
}

impl AttemptError {
    fn fatal(source: anyhow::Error) -> Self {
        Self {
            retryable: false,
            retry_after: std::time::Duration::ZERO,
            source,
        }
    }
    fn retryable(source: anyhow::Error) -> Self {
        Self {
            retryable: true,
            retry_after: std::time::Duration::ZERO,
            source,
        }
    }
    fn retryable_after(source: anyhow::Error, retry_after: std::time::Duration) -> Self {
        Self {
            retryable: true,
            retry_after,
            source,
        }
    }
    /// Transport failures (refused/timeout/TLS/DNS, mid-body stalls) are
    /// always worth one more attempt.
    fn transport(source: anyhow::Error) -> Self {
        Self {
            retryable: is_transport_error(&source),
            retry_after: std::time::Duration::ZERO,
            source,
        }
    }
}

/// True when the error chain contains a transport-level failure rather
/// than an HTTP response or local error. Used for mirror fallback (4.2)
/// and blob retries (4.3).
fn is_transport_error(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<reqwest::Error>().is_some()
            || c.downcast_ref::<tokio::time::error::Elapsed>().is_some()
    })
}

/// Bound a small metadata read; elapsed time counts as transport-level
/// (detected via [`is_transport_error`]).
async fn metadata_bytes(resp: reqwest::Response) -> anyhow::Result<bytes::Bytes> {
    match tokio::time::timeout(METADATA_TIMEOUT, resp.bytes()).await {
        Err(elapsed) => Err(anyhow::Error::new(elapsed)),
        Ok(Err(e)) => Err(anyhow::Error::new(e)),
        Ok(Ok(b)) => Ok(b),
    }
}

/// `Retry-After` (delta seconds) from response headers, capped at 30s.
fn retry_after_secs(headers: &reqwest::header::HeaderMap) -> std::time::Duration {
    let secs = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);
    std::time::Duration::from_secs(secs.min(30))
}

/// Attach the request context to a transport error, plus the TLS hint
/// (unit 4.2) when the failure implicates certificates or the handshake.
fn with_transport_hint(context: String, e: reqwest::Error) -> anyhow::Error {
    // Preserve `e` in the chain: `is_transport_error` (mirror fallback,
    // blob retry) detects it there.
    match tls_hint_for_message(&format!("{e:?}")) {
        Some(hint) => anyhow::Error::new(e).context(format!("{context} ({hint})")),
        None => anyhow::Error::new(e).context(context),
    }
}

/// Actionable hint for TLS failures (unit 4.2): appended to transport
/// errors whose message implicates certificates or the handshake.
fn tls_hint_for_message(msg: &str) -> Option<&'static str> {
    let lower = msg.to_lowercase();
    if [
        "certificate",
        "unknown issuer",
        "self signed",
        "handshake",
        "ssl",
        "tls",
    ]
    .iter()
    .any(|n| lower.contains(n))
    {
        Some("TLS: check system CA certificates, proxy settings and clock; registries with self-signed certificates are unsupported")
    } else {
        None
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
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

enum Challenge {
    Bearer {
        realm: String,
        service: String,
        scope: String,
    },
    Basic,
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("ingot/{}", ingot_api::ENGINE_VERSION))
            .redirect(reqwest::redirect::Policy::limited(6))
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .expect("reqwest client");
        RegistryClient {
            http,
            tokens: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    fn endpoint(image: &ImageRef) -> String {
        match image.registry.as_str() {
            "docker.io" => "https://registry-1.docker.io".into(),
            r => base_url(r),
        }
    }

    /// Registry base URLs to try in order: `INGOT_REGISTRY_MIRRORS`
    /// (comma-separated `host[:port]` or full URLs) first, then the
    /// canonical endpoint. The first host that serves the manifest wins
    /// for the whole pull; fallback only covers transport-level failures
    /// (refused/timeout/TLS/DNS), never HTTP responses.
    fn candidate_endpoints(image: &ImageRef) -> Vec<String> {
        let mut out = Vec::new();
        for m in registry_mirrors() {
            let base = if m.contains("://") {
                m.trim_end_matches('/').to_string()
            } else {
                base_url(&m)
            };
            if !out.contains(&base) {
                out.push(base);
            }
        }
        let canon = Self::endpoint(image);
        if !out.contains(&canon) {
            out.push(canon);
        }
        out
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
            Ok(Challenge::Bearer {
                realm,
                service,
                scope,
            })
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
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", auth.username, auth.password))
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
        // Real `Elapsed` errors stay in the chain so mirror fallback and
        // blob retry recognize the stall as transport-level.
        let resp = tokio::time::timeout(METADATA_TIMEOUT, req.send())
            .await
            .map_err(anyhow::Error::new)
            .and_then(|r| {
                r.map_err(|e| with_transport_hint("registry token request".to_string(), e))
            })?;
        let status = resp.status();
        let body = metadata_bytes(resp).await?;
        if !status.is_success() {
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                let who = auth.map(|a| a.username.clone()).filter(|u| !u.is_empty());
                if who.is_none() {
                    return Err(anyhow!(
                        "repository requires authentication ({status}); run `ig login` (or pass credentials) and retry"
                    ));
                }
            }
            return Err(anyhow!(
                "token request failed ({status}): {}",
                truncate(&String::from_utf8_lossy(&body), 200)
            ));
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
    /// `endpoint` is the registry base URL (canonical or mirror).
    /// `range_from` resumes a blob download (`Range: bytes=<n>-`).
    // Eight params by design: one call site per HTTP verb shape would add
    // more code than the extra parameter.
    #[allow(clippy::too_many_arguments)]
    async fn authed_request(
        &self,
        image: &ImageRef,
        endpoint: &str,
        method: reqwest::Method,
        path: &str,
        accept: Option<&str>,
        auth: Option<&AuthConfig>,
        range_from: Option<u64>,
    ) -> Result<reqwest::Response> {
        let url = format!("{endpoint}{path}");
        let send = |client: &reqwest::Client,
                    method: reqwest::Method,
                    url: &str,
                    bearer: Option<&str>,
                    basic: Option<&String>| {
            let mut req = client.request(method.clone(), url);
            if let Some(a) = accept {
                req = req.header(reqwest::header::ACCEPT, a);
            }
            if let Some(from) = range_from {
                req = req.header(reqwest::header::RANGE, format!("bytes={from}-"));
            }
            if let Some(b) = bearer {
                req = req.bearer_auth(b);
            }
            if let Some(b) = basic {
                req = req.header(reqwest::header::AUTHORIZATION, b);
            }
            req
        };

        // The send resolves at response headers; bodies stream afterwards
        // under their own bounds, so this cannot cut slow blobs short.
        let resp = tokio::time::timeout(
            METADATA_TIMEOUT,
            send(&self.http, method.clone(), &url, None, None).send(),
        )
        .await
        .map_err(anyhow::Error::new)
        .and_then(|r| r.map_err(|e| with_transport_hint(format!("{method} {url}"), e)))?;
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
            Challenge::Bearer {
                realm,
                service,
                scope,
            } => {
                let scope = if scope.is_empty() {
                    format!("repository:{}:pull", image.api_repo())
                } else {
                    scope
                };
                let token = self.bearer_token(&scope, &realm, &service, auth).await?;
                let sent = tokio::time::timeout(
                    METADATA_TIMEOUT,
                    send(&self.http, method.clone(), &url, Some(&token), None).send(),
                )
                .await;
                Ok(sent.map_err(anyhow::Error::new).and_then(|r| {
                    r.map_err(|e| with_transport_hint(format!("{method} {url} (authed)"), e))
                })?)
            }
            Challenge::Basic => {
                let basic = auth
                    .filter(|a| !a.username.is_empty())
                    .map(Self::basic_auth_value);
                Ok(send(&self.http, method, &url, None, basic.as_ref())
                    .send()
                    .await?)
            }
        }
    }

    /// Fetch and resolve the manifest: follows index → platform manifest.
    /// Returns (platform manifest, top-level digest that was addressed).
    /// `platform` overrides the daemon default (Plan Phase 4, unit 4.1).
    pub async fn fetch_manifest(
        &self,
        image: &ImageRef,
        auth: Option<&AuthConfig>,
        platform: Option<(String, String)>,
    ) -> Result<(PlatformManifest, String)> {
        let reference = image
            .digest
            .clone()
            .or_else(|| image.tag.clone())
            .ok_or_else(|| anyhow!("reference has neither tag nor digest"))?;
        let endpoints = Self::candidate_endpoints(image);
        let mut transport_errors = Vec::new();
        for endpoint in &endpoints {
            match self
                .fetch_manifest_from(image, auth, platform.clone(), endpoint, &reference)
                .await
            {
                Ok(ok) => return Ok(ok),
                Err(e) if is_transport_error(&e) => {
                    transport_errors.push(format!("{endpoint}: {e:#}"));
                }
                Err(e) => return Err(e),
            }
        }
        Err(anyhow!(
            "all {} registries unreachable for {}: {}",
            endpoints.len(),
            image.display_ref(),
            transport_errors.join("; ")
        ))
    }

    /// Single-endpoint manifest fetch + index resolution (see
    /// [`Self::fetch_manifest`] for the fallback policy). Transient
    /// failures (transport, 429/5xx) retry with backoff; anything else
    /// (auth, missing ref/platform, parse) fails fast.
    async fn fetch_manifest_from(
        &self,
        image: &ImageRef,
        auth: Option<&AuthConfig>,
        platform: Option<(String, String)>,
        endpoint: &str,
        reference: &str,
    ) -> Result<(PlatformManifest, String)> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self
                .fetch_manifest_once(image, auth, platform.clone(), endpoint, reference)
                .await
            {
                Ok(ok) => return Ok(ok),
                Err(e) if e.retryable && attempt < MAX_FETCH_ATTEMPTS => {
                    tokio::time::sleep(blob_backoff(attempt)).await;
                }
                Err(e) => return Err(e.source),
            }
        }
    }

    async fn fetch_manifest_once(
        &self,
        image: &ImageRef,
        auth: Option<&AuthConfig>,
        platform: Option<(String, String)>,
        endpoint: &str,
        reference: &str,
    ) -> Result<(PlatformManifest, String), AttemptError> {
        let path = format!("/v2/{}/manifests/{}", image.api_repo(), reference);
        let resp = self
            .authed_request(
                image,
                endpoint,
                reqwest::Method::GET,
                &path,
                Some(MANIFEST_ACCEPT),
                auth,
                None,
            )
            .await
            .map_err(AttemptError::transport)?;
        let status = resp.status();
        if !status.is_success() {
            // Status (not the body) drives the retry decision, so a stalled
            // error body degrades to empty rather than wedging the pull.
            let body = tokio::time::timeout(METADATA_TIMEOUT, resp.text())
                .await
                .map(|r| r.unwrap_or_default())
                .unwrap_or_default();
            let err = manifest_error(status.as_u16(), &body, image);
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                return Err(AttemptError::retryable(err));
            }
            return Err(AttemptError::fatal(err));
        }
        let header_digest = body_digest_header(&resp).ok();
        let body = metadata_bytes(resp)
            .await
            .map_err(AttemptError::transport)?;
        let top_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));
        // Fail closed on integrity mismatch (never retry: TLS makes random
        // corruption ~impossible, so a mismatch is a hostile or buggy
        // registry, not a flaky network).
        if let Some(pinned) = image.digest.as_deref() {
            if pinned != top_digest {
                return Err(AttemptError::fatal(anyhow!(
                    "digest mismatch for {}: pinned {pinned} but registry served {top_digest}",
                    image.display_ref()
                )));
            }
        }
        if let Some(header) = header_digest {
            if header != top_digest {
                return Err(AttemptError::fatal(anyhow!(
                    "Docker-Content-Digest {header} does not match manifest body {top_digest} for {}",
                    image.display_ref()
                )));
            }
        }
        let raw: RawManifest = serde_json::from_slice(&body)
            .with_context(|| format!("parse manifest for {}", image.display_ref()))
            .map_err(AttemptError::fatal)?;

        if !raw.manifests.is_empty() {
            let (want_os, want_arch) = platform.unwrap_or_else(daemon_platform);
            let entry = pick_platform(&raw.manifests, &want_os, &want_arch).ok_or_else(|| {
                AttemptError::fatal(anyhow!(
                    "no {want_os}/{want_arch} manifest in index for {} (available: {})",
                    image.display_ref(),
                    available_platforms(&raw.manifests)
                ))
            })?;
            let sub_path = format!("/v2/{}/manifests/{}", image.api_repo(), entry.digest);
            let sub = self
                .authed_request(
                    image,
                    endpoint,
                    reqwest::Method::GET,
                    &sub_path,
                    Some(MANIFEST_ACCEPT),
                    auth,
                    None,
                )
                .await
                .map_err(AttemptError::transport)?;
            let sub_status = sub.status();
            let sub_body = if sub_status.is_success() {
                metadata_bytes(sub).await.map_err(AttemptError::transport)?
            } else {
                let b = tokio::time::timeout(METADATA_TIMEOUT, sub.text())
                    .await
                    .map(|r| r.unwrap_or_default())
                    .unwrap_or_default();
                let err = anyhow!("platform manifest fetch failed ({sub_status}): {b}");
                if sub_status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || sub_status.is_server_error()
                {
                    return Err(AttemptError::retryable(err));
                }
                return Err(AttemptError::fatal(err));
            };
            let mut m: RawManifest = serde_json::from_slice(&sub_body)
                .context("parse platform manifest")
                .map_err(AttemptError::fatal)?;
            let sub_digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&sub_body)));
            // The index names the platform manifest by digest: fail closed
            // when the registry serves anything else for it.
            if sub_digest != entry.digest {
                return Err(AttemptError::fatal(anyhow!(
                    "platform manifest digest mismatch for {}: index names {} but registry served {sub_digest}",
                    image.display_ref(),
                    entry.digest
                )));
            }
            m.mediaType = entry.mediaType.clone();
            let config = m
                .config
                .ok_or_else(|| AttemptError::fatal(anyhow!("manifest has no config")))?;
            return Ok((
                PlatformManifest {
                    manifest_digest: sub_digest,
                    media_type: m.mediaType,
                    config_digest: config.digest,
                    layers: m.layers,
                    endpoint: endpoint.to_string(),
                },
                top_digest,
            ));
        }

        let config = raw
            .config
            .ok_or_else(|| AttemptError::fatal(anyhow!("manifest has no config")))?;
        Ok((
            PlatformManifest {
                manifest_digest: top_digest.clone(),
                media_type: raw.mediaType,
                config_digest: config.digest,
                layers: raw.layers,
                endpoint: endpoint.to_string(),
            },
            top_digest,
        ))
    }

    /// Stream a blob to `dest`, verifying sha256 while writing. Skips when
    /// the content-addressed store already holds it. Transient failures
    /// (transport errors, 429/5xx) retry with backoff; interrupted
    /// downloads resume via Range from the leftover `.part` file.
    /// `endpoint` must be the manifest's endpoint (same host for the pull).
    /// Returns bytes written.
    pub async fn fetch_blob_to_file(
        &self,
        image: &ImageRef,
        digest: &str,
        dest: &Path,
        auth: Option<&AuthConfig>,
        endpoint: &str,
    ) -> Result<u64> {
        if dest.exists() {
            return Ok(std::fs::metadata(dest)?.len());
        }
        let path = format!("/v2/{}/blobs/{}", image.api_repo(), digest);
        let expected = digest.strip_prefix("sha256:").unwrap_or(digest).to_string();
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self
                .fetch_blob_attempt(image, &path, digest, &expected, dest, auth, endpoint)
                .await
            {
                Ok(n) => return Ok(n),
                Err(e) if e.retryable && attempt < MAX_FETCH_ATTEMPTS => {
                    let wait = e.retry_after.min(blob_backoff(attempt));
                    tokio::time::sleep(wait).await;
                }
                Err(e) => return Err(e.source),
            }
        }
    }

    /// One blob download attempt. Failures carry whether a retry makes sense.
    // Eight params by design: the attempt needs the full download context;
    // bundling it would add a type without removing a parameter.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_blob_attempt(
        &self,
        image: &ImageRef,
        path: &str,
        digest: &str,
        expected: &str,
        dest: &Path,
        auth: Option<&AuthConfig>,
        endpoint: &str,
    ) -> Result<u64, AttemptError> {
        use tokio::io::AsyncReadExt;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AttemptError::fatal(e.into()))?;
        }
        let tmp = dest.with_extension("part");
        // Resume offset: bytes already on disk from an interrupted attempt.
        let resume_from = tokio::fs::metadata(&tmp)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let range = if resume_from > 0 {
            Some(resume_from)
        } else {
            None
        };
        let resp = self
            .authed_request(
                image,
                endpoint,
                reqwest::Method::GET,
                path,
                None,
                auth,
                range,
            )
            .await
            .map_err(AttemptError::transport)?;
        let status = resp.status();
        if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
            // Blob is smaller than our leftover: start over next attempt.
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(AttemptError::retryable(anyhow!(
                "blob {digest}: range unsatisfiable, restarting"
            )));
        }
        if !status.is_success() {
            let retry_after = retry_after_secs(resp.headers());
            let body = tokio::time::timeout(METADATA_TIMEOUT, resp.text())
                .await
                .map(|r| r.unwrap_or_default())
                .unwrap_or_default();
            let err = anyhow!(
                "blob {digest} fetch failed ({}): {}",
                status,
                truncate(&body, 300)
            );
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                return Err(AttemptError::retryable_after(err, retry_after));
            }
            return Err(AttemptError::fatal(err));
        }
        // 206 continues the leftover file; anything else restarts it.
        let append = status == reqwest::StatusCode::PARTIAL_CONTENT && resume_from > 0;
        let mut hasher = sha2::Sha256::new();
        let mut written = 0u64;
        if append {
            let mut prefix = tokio::fs::File::open(&tmp)
                .await
                .map_err(|e| AttemptError::fatal(e.into()))?;
            let mut buf = vec![0u8; 65536];
            loop {
                let n = prefix
                    .read(&mut buf)
                    .await
                    .map_err(|e| AttemptError::fatal(e.into()))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                written += n as u64;
            }
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(&tmp)
            .await
            .map_err(|e| AttemptError::fatal(e.into()))?;
        let mut writer = HashingWriter::with_hasher(file, hasher, written);
        let mut stream = resp.bytes_stream();
        loop {
            let next = tokio::time::timeout(READ_IDLE_TIMEOUT, stream.next()).await;
            let chunk = match next {
                Err(_) => {
                    // No reqwest source to detect: idleness itself is the
                    // retryable condition.
                    return Err(AttemptError::retryable(anyhow!(
                        "blob {digest}: stalled mid-body, retrying"
                    )));
                }
                Ok(None) => break,
                Ok(Some(c)) => c.map_err(|e| AttemptError::transport(e.into()))?,
            };
            writer
                .write_all(&chunk)
                .await
                .map_err(|e| AttemptError::fatal(e.into()))?;
        }
        writer
            .flush()
            .await
            .map_err(|e| AttemptError::fatal(e.into()))?;
        writer
            .shutdown()
            .await
            .map_err(|e| AttemptError::fatal(e.into()))?;
        let (actual, total) = writer.finish();
        if actual != expected {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(AttemptError::retryable(anyhow!(
                "digest mismatch for {digest}: received sha256:{actual}"
            )));
        }
        tokio::fs::rename(&tmp, dest)
            .await
            .map_err(|e| AttemptError::fatal(e.into()))?;
        Ok(total)
    }

    pub async fn head_blob(
        &self,
        image: &ImageRef,
        digest: &str,
        auth: Option<&AuthConfig>,
    ) -> Result<Option<i64>> {
        let path = format!("/v2/{}/blobs/{}", image.api_repo(), digest);
        let resp = self
            .authed_request(
                image,
                &Self::endpoint(image),
                reqwest::Method::HEAD,
                &path,
                None,
                auth,
                None,
            )
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

/// The platform this daemon runs: images must match it to execute.
/// Maps Rust target arches to OCI/Go names (`x86_64` → `amd64`, …).
pub fn daemon_platform() -> (String, String) {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "riscv64" => "riscv64",
        other => other,
    };
    ("linux".to_string(), arch.to_string())
}

/// Parse a `--platform` value (`os/arch` or bare `arch`, os defaults to
/// `linux`). Rejects empty parts and extra slashes with a docker-style hint.
pub fn parse_platform(s: &str) -> Result<(String, String)> {
    let s = s.trim().to_lowercase();
    let (os, arch) = match s.split_once('/') {
        Some((o, a)) => (o.to_string(), a.to_string()),
        None => ("linux".to_string(), s.clone()),
    };
    let valid = |p: &str| {
        !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    };
    if !valid(&os) || !valid(&arch) || arch.contains('/') {
        return Err(anyhow!(
            "invalid platform {s:?}: want [os/]arch (for example \"linux/amd64\")"
        ));
    }
    Ok((os, arch))
}

fn platform_matches(entry: &IndexEntry, want_os: &str, want_arch: &str) -> bool {
    entry
        .platform
        .as_ref()
        .map(|p| p.os.as_deref() == Some(want_os) && p.architecture.as_deref() == Some(want_arch))
        .unwrap_or(false)
}

fn pick_platform(entries: &[IndexEntry], want_os: &str, want_arch: &str) -> Option<IndexEntry> {
    // Exact match only: pulling a foreign-arch image would fail at exec
    // time, so a missing platform is a clear error, not a silent fallback.
    entries
        .iter()
        .find(|e| platform_matches(e, want_os, want_arch))
        .cloned()
}

/// Base URL for a bare registry `host[:port]`. Loopback registries use
/// plain HTTP, matching docker's insecure-localhost default (and making
/// local fixture registries work); everything else is HTTPS.
fn base_url(host: &str) -> String {
    // Bare IPv6 (`::1`) contains colons, so only strip a port suffix when
    // there is exactly one colon outside brackets.
    let name = if host.starts_with('[') {
        host.split(']').next().unwrap_or(host)
    } else if host.bytes().filter(|&b| b == b':').count() == 1 {
        host.split(':').next().unwrap_or(host)
    } else {
        host
    };
    if name == "localhost" || name == "127.0.0.1" || name == "::1" {
        format!("http://{host}")
    } else {
        format!("https://{host}")
    }
}

/// Mirror list from `INGOT_REGISTRY_MIRRORS` (comma-separated
/// `host[:port]` or full URLs), in priority order.
fn registry_mirrors() -> Vec<String> {
    registry_mirrors_from(std::env::var("INGOT_REGISTRY_MIRRORS").ok().as_deref())
}

fn registry_mirrors_from(env: Option<&str>) -> Vec<String> {
    env.map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

/// Human-readable `os/arch` list of an index, for missing-platform errors.
fn available_platforms(entries: &[IndexEntry]) -> String {
    let mut v: Vec<String> = entries
        .iter()
        .filter_map(|e| {
            e.platform.as_ref().map(|p| {
                format!(
                    "{}/{}",
                    p.os.as_deref().unwrap_or("?"),
                    p.architecture.as_deref().unwrap_or("?")
                )
            })
        })
        .collect();
    v.sort();
    v.dedup();
    if v.is_empty() {
        "(no platform metadata)".to_string()
    } else {
        v.join(", ")
    }
}

fn manifest_error(status: u16, body: &str, image: &ImageRef) -> anyhow::Error {
    // Auth failures get actionable, credential-free messages (Plan Phase 1,
    // unit 1.4): never echo tokens, passwords, or auth headers.
    if status == 401 {
        return anyhow!(
            "unauthorized for {}: bad or missing credentials (check `docker login` for this registry)",
            image.display_ref()
        );
    }
    if status == 403 {
        return anyhow!(
            "denied for {}: the credentials lack pull access to this repository",
            image.display_ref()
        );
    }
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
    anyhow!(
        "manifest fetch for {} failed ({status}): {}",
        image.display_ref(),
        truncate(body, 300)
    )
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img() -> ImageRef {
        ImageRef::parse("busybox:latest").unwrap()
    }

    fn entry(os: &str, arch: &str, digest: &str) -> IndexEntry {
        IndexEntry {
            mediaType: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: digest.to_string(),
            platform: Some(Platform {
                architecture: Some(arch.to_string()),
                os: Some(os.to_string()),
            }),
        }
    }

    #[test]
    fn daemon_platform_is_sane() {
        let (os, arch) = daemon_platform();
        assert_eq!(os, "linux");
        assert!(!arch.is_empty());
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, "amd64");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, "arm64");
    }

    #[test]
    fn parse_platform_shapes() {
        assert_eq!(
            parse_platform("linux/amd64").unwrap(),
            ("linux".to_string(), "amd64".to_string())
        );
        assert_eq!(
            parse_platform("amd64").unwrap(),
            ("linux".to_string(), "amd64".to_string())
        );
        assert_eq!(
            parse_platform(" Linux/ARM64 ").unwrap(),
            ("linux".to_string(), "arm64".to_string())
        );
        for bad in ["", "/", "linux/", "/amd64", "a/b/c", "linux/amd 64"] {
            assert!(parse_platform(bad).is_err(), "{bad:?} must fail");
        }
    }

    #[test]
    fn pick_platform_exact_only() {
        let entries = vec![
            entry("linux", "amd64", "sha256:aaa"),
            entry("linux", "arm64", "sha256:bbb"),
            entry("windows", "amd64", "sha256:ccc"),
        ];
        let got = pick_platform(&entries, "linux", "arm64").unwrap();
        assert_eq!(got.digest, "sha256:bbb");
        // No silent fallback to another arch or os.
        assert!(pick_platform(&entries, "linux", "riscv64").is_none());
        assert!(pick_platform(&entries, "windows", "arm64").is_none());
        // Entries without platform metadata never match.
        let mut noplat = entries.clone();
        noplat.push(IndexEntry {
            mediaType: "x".to_string(),
            digest: "sha256:ddd".to_string(),
            platform: None,
        });
        assert!(pick_platform(&noplat, "linux", "s390x").is_none());
    }

    #[test]
    fn base_url_scheme_rules() {
        assert_eq!(base_url("example.com"), "https://example.com");
        assert_eq!(base_url("example.com:5000"), "https://example.com:5000");
        assert_eq!(base_url("localhost:5000"), "http://localhost:5000");
        assert_eq!(base_url("127.0.0.1:5000"), "http://127.0.0.1:5000");
        assert_eq!(base_url("::1"), "http://::1");
    }

    #[test]
    fn mirror_list_parsing() {
        assert!(registry_mirrors_from(None).is_empty());
        assert!(registry_mirrors_from(Some("")).is_empty());
        assert_eq!(
            registry_mirrors_from(Some("a:5000, https://b/c/ , ,c")),
            vec!["a:5000", "https://b/c/", "c"]
        );
    }

    #[test]
    fn blob_backoff_grows_and_caps() {
        assert_eq!(blob_backoff(1), std::time::Duration::from_secs(1));
        assert_eq!(blob_backoff(2), std::time::Duration::from_secs(2));
        assert_eq!(blob_backoff(3), std::time::Duration::from_secs(4));
        assert_eq!(blob_backoff(99), std::time::Duration::from_secs(8));
    }

    #[test]
    fn tls_hint_matches_cert_failures() {
        assert!(tls_hint_for_message("x509: certificate has expired").is_some());
        assert!(tls_hint_for_message("tls: handshake failure").is_some());
        assert!(tls_hint_for_message("connection refused").is_none());
        assert!(tls_hint_for_message("404 Not Found").is_none());
    }

    #[test]
    fn retry_after_parses_and_caps() {
        use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
        let mut h = HeaderMap::new();
        assert_eq!(retry_after_secs(&h), std::time::Duration::ZERO);
        h.insert(RETRY_AFTER, HeaderValue::from_static("5"));
        assert_eq!(retry_after_secs(&h), std::time::Duration::from_secs(5));
        h.insert(RETRY_AFTER, HeaderValue::from_static("9999"));
        assert_eq!(retry_after_secs(&h), std::time::Duration::from_secs(30));
        h.insert(RETRY_AFTER, HeaderValue::from_static("soon"));
        assert_eq!(retry_after_secs(&h), std::time::Duration::ZERO);
    }

    #[test]
    fn available_platforms_lists_index() {
        let entries = vec![entry("linux", "arm64", "a"), entry("linux", "amd64", "b")];
        assert_eq!(available_platforms(&entries), "linux/amd64, linux/arm64");
        assert_eq!(available_platforms(&[]), "(no platform metadata)");
    }

    #[test]
    fn auth_failures_are_actionable_and_redacted() {
        // 401/403 map to login guidance, never echoing bodies or secrets.
        for (status, needle) in [(401u16, "docker login"), (403u16, "pull access")] {
            let e = manifest_error(status, r#"{"errors":[{"code":"DENIED"}]}"#, &img()).to_string();
            assert!(e.contains(needle), "{status}: {e}");
            assert!(!e.contains("DENIED"), "{status} must not echo body: {e}");
        }
        // Unknown repos keep the docker-style access-denied hint.
        let e = manifest_error(
            404,
            r#"{"errors":[{"code":"NAME_UNKNOWN","message":"nope"}]}"#,
            &img(),
        )
        .to_string();
        assert!(e.contains("may require authorization"), "{e}");
        // Other failures truncate the body.
        let e = manifest_error(500, &"x".repeat(1000), &img()).to_string();
        assert!(e.len() < 600, "body must be truncated: {}", e.len());
    }
}
