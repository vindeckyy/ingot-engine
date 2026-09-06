//! HTTP-over-Unix-socket client for talking to ingotd.
//! Mirrors how the docker CLI resolves DOCKER_HOST.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::Response;
use hyper_util::client::legacy::connect::Connection;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::net::UnixStream;

pub fn default_socket() -> PathBuf {
    // INGOT_HOST=unix:///path, else docker's DOCKER_HOST if it points at a
    // unix socket, else our default path.
    for var in ["INGOT_HOST", "DOCKER_HOST"] {
        if let Ok(h) = std::env::var(var) {
            if let Some(p) = h.strip_prefix("unix://") {
                return PathBuf::from(p);
            }
        }
    }
    PathBuf::from("/run/ingot/ingot.sock")
}

#[derive(Clone)]
struct UdsConnector {
    path: PathBuf,
}

impl tower_service::Service<hyper::Uri> for UdsConnector {
    type Response = UdsStream;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: hyper::Uri) -> Self::Future {
        let path = self.path.clone();
        Box::pin(async move {
            let stream = UnixStream::connect(&path).await?;
            Ok(UdsStream(TokioIo::new(stream)))
        })
    }
}

/// Newtype wrapper: the legacy client requires its connector's response to
/// implement hyper's Read/Write plus `Connection`, and we can't impl those on
/// the foreign TokioIo directly.
pub struct UdsStream(TokioIo<UnixStream>);

impl hyper::rt::Read for UdsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UdsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for UdsStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

pub type UdsClient = Client<UdsConnector, Full<Bytes>>;

#[derive(Clone)]
pub struct ApiClient {
    pub socket: PathBuf,
    client: UdsClient,
}

impl ApiClient {
    pub fn connect(socket: impl AsRef<Path>) -> Result<Self> {
        let socket = socket.as_ref().to_path_buf();
        if !socket.exists() {
            anyhow::bail!(
                "cannot connect to the ingot daemon at unix://{} — is ingotd running?",
                socket.display()
            );
        }
        let client =
            Client::builder(TokioExecutor::new()).build(UdsConnector { path: socket.clone() });
        Ok(ApiClient { socket, client })
    }

    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let bytes = self.request_raw("GET", path, None).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub async fn get_text(&self, path: &str) -> Result<String> {
        let bytes = self.request_raw("GET", path, None).await?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    pub async fn post<T>(&self, path: &str, body: Option<serde_json::Value>) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let raw = match body {
            Some(v) => Some(serde_json::to_vec(&v)?),
            None => None,
        };
        let bytes = self.request_raw("POST", path, raw).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub async fn request_json(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<serde_json::Value> {
        let bytes = self.request_raw(method, path, body).await?;
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("bad JSON from daemon: {e}"))
    }

    pub async fn request_raw(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Bytes> {
        let resp = self
            .request(method, path, body)
            .await
            .with_context(|| format!("{method} {path}"))?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            return Err(parse_error_body(status.as_u16(), &bytes));
        }
        Ok(bytes)
    }

    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Response<Incoming>> {
        let uri = format!("http://ingot{path}");
        let mut req = hyper::Request::builder()
            .method(method)
            .uri(uri)
            .header("Host", "ingot");
        let body = match body {
            Some(b) => Full::new(Bytes::from(b)),
            None => Full::new(Bytes::new()),
        };
        let req = req.body(body)?;
        self.client.request(req).await.map_err(|e| anyhow!("{e}"))
    }
}

pub fn parse_error_body(status: u16, bytes: &[u8]) -> anyhow::Error {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(msg) = v.get("message").and_then(|m| m.as_str()) {
            return anyhow!("Error response from daemon ({}): {}", status, msg);
        }
    }
    anyhow!(
        "Error response from daemon ({}): {}",
        status,
        String::from_utf8_lossy(bytes)
    )
}

/// Read a newline-delimited JSON stream (pull/build progress) and hand each
/// line to `on_line`. Returns when the response body ends.
pub async fn stream_lines(
    resp: Response<Incoming>,
    mut on_line: impl FnMut(&serde_json::Value),
) -> Result<()> {
    let mut body = resp.into_body();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        let data = frame.data_ref().map(|b| b.as_ref()).unwrap_or(&[]);
        for line in String::from_utf8_lossy(data).lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                on_line(&v);
            }
        }
    }
    Ok(())
}
