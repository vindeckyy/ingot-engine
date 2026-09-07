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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for UdsStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

type UdsClient = Client<UdsConnector, Full<Bytes>>;

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
        let client = Client::builder(TokioExecutor::new()).build(UdsConnector {
            path: socket.clone(),
        });
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
        self.request_with_headers(method, path, body, &[]).await
    }

    pub async fn request_with_headers(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        headers: &[(&str, &str)],
    ) -> Result<Response<Incoming>> {
        let uri = format!("http://ingot{path}");
        let mut req = hyper::Request::builder()
            .method(method)
            .uri(uri)
            .header("Host", "ingot");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
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
    let status = resp.status();
    let mut body = resp.into_body();
    if !status.is_success() {
        let bytes = body.collect().await?.to_bytes();
        return Err(parse_error_body(status.as_u16(), &bytes));
    }
    let mut buffer = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            buffer.extend_from_slice(data.as_ref());
            while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                let line_bytes: Vec<u8> = buffer.drain(..=pos).collect();
                let line = String::from_utf8_lossy(&line_bytes);
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
                        on_line(&v);
                    }
                }
            }
        }
    }
    if !buffer.is_empty() {
        let line = String::from_utf8_lossy(&buffer);
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
                on_line(&v);
            }
        }
    }
    Ok(())
}

pub struct UpgradedConnection {
    pub stream: UnixStream,
    pub leftover: Vec<u8>,
}

impl ApiClient {
    pub async fn upgrade_stream(
        &self,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<UpgradedConnection> {
        let mut stream = UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("connect to {}", self.socket.display()))?;
        let body_bytes = body.unwrap_or_default();
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: ingot\r\n\
             Connection: Upgrade\r\n\
             Upgrade: tcp\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n",
            body_bytes.len()
        );
        stream.write_all(req.as_bytes()).await?;
        if !body_bytes.is_empty() {
            stream.write_all(&body_bytes).await?;
        }

        let mut buf = Vec::new();
        let mut temp = [0u8; 1024];
        let header_end;
        loop {
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                return Err(anyhow!("server closed connection during upgrade handshake"));
            }
            buf.extend_from_slice(&temp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = pos + 4;
                break;
            }
        }

        let header_bytes = &buf[..header_end];
        let header_str = String::from_utf8_lossy(header_bytes);
        let status_line = header_str.lines().next().unwrap_or("");
        if !status_line.contains("101") {
            let rest = &buf[header_end..];
            return Err(anyhow!(
                "upgrade request failed: {} - {}",
                status_line,
                String::from_utf8_lossy(rest)
            ));
        }

        let leftover = buf[header_end..].to_vec();
        Ok(UpgradedConnection { stream, leftover })
    }
}

struct RawModeGuard {
    orig: libc::termios,
    fd: i32,
    active: bool,
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
            }
        }
    }
}

fn set_raw_mode() -> Option<RawModeGuard> {
    let fd = 0; // stdin
    unsafe {
        if libc::isatty(fd) == 0 {
            return None;
        }
        let mut orig = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut orig) != 0 {
            return None;
        }
        let mut raw = orig;
        libc::cfmakeraw(&mut raw);
        if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
            return None;
        }
        Some(RawModeGuard {
            orig,
            fd,
            active: true,
        })
    }
}

pub async fn run_attached_stream(
    conn: UpgradedConnection,
    tty: bool,
    interactive: bool,
) -> Result<()> {
    let _raw_guard = if interactive && tty {
        set_raw_mode()
    } else {
        None
    };

    let (mut read_stream, mut write_stream) = conn.stream.into_split();

    let stdin_task = if interactive {
        Some(tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 1024];
            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if write_stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = write_stream.shutdown().await;
        }))
    } else {
        None
    };

    use std::io::Write;
    let mut pending = conn.leftover;
    let mut read_buf = [0u8; 8192];
    loop {
        if !pending.is_empty() {
            if tty {
                let _ = std::io::stdout().write_all(&pending);
                let _ = std::io::stdout().flush();
                pending.clear();
            } else {
                while pending.len() >= 8 {
                    let stream_type = pending[0];
                    let len = u32::from_be_bytes([pending[4], pending[5], pending[6], pending[7]])
                        as usize;
                    if pending.len() < 8 + len {
                        break;
                    }
                    let payload = &pending[8..8 + len];
                    if stream_type == 2 {
                        let _ = std::io::stderr().write_all(payload);
                        let _ = std::io::stderr().flush();
                    } else {
                        let _ = std::io::stdout().write_all(payload);
                        let _ = std::io::stdout().flush();
                    }
                    pending.drain(..8 + len);
                }
            }
        }

        match read_stream.read(&mut read_buf).await {
            Ok(0) => break,
            Ok(n) => {
                pending.extend_from_slice(&read_buf[..n]);
            }
            Err(_) => break,
        }
    }

    if let Some(t) = stdin_task {
        t.abort();
    }
    Ok(())
}
