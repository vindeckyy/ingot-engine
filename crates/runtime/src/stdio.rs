//! Container stdio hub: json-file log driver + live attach subscribers +
//! stdin fan-in. Mirrors docker's `json-file` log format.

use bytes::Bytes;
use serde_json::json;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc};

/// Stream tag for multiplexed frames.
pub const STREAM_STDIN: u8 = 0;
pub const STREAM_STDOUT: u8 = 1;
pub const STREAM_STDERR: u8 = 2;

#[derive(Clone)]
pub struct StdioHub {
    /// log file path (json-file driver)
    log_path: std::path::PathBuf,
    /// live subscribers of (stream, bytes)
    tx: broadcast::Sender<(u8, Vec<u8>)>,
    stdin_tx: mpsc::Sender<Vec<u8>>,
}

impl StdioHub {
    /// Create a hub; `stdin` recv end is returned for the pump task to feed
    /// the container's stdin pipe.
    pub fn new(log_path: std::path::PathBuf) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, _) = broadcast::channel(1024);
        let (stdin_tx, stdin_rx) = mpsc::channel(256);
        let hub = StdioHub { log_path, tx, stdin_tx };
        (hub, stdin_rx)
    }

    /// Called by the stdout/stderr pump.
    pub fn write_output(&self, stream: u8, data: &[u8]) {
        append_log(&self.log_path, stream, data);
        let _ = self.tx.send((stream, data.to_vec()));
    }

    /// Forward stdin bytes to the container's stdin pipe.
    pub async fn send_stdin(&self, data: Vec<u8>) {
        let _ = self.stdin_tx.send(data).await;
    }

    /// Close stdin (container sees EOF).
    pub async fn close_stdin(&self) {
        drop(self.stdin_tx.clone());
    }

    pub fn subscribe(&self) -> broadcast::Receiver<(u8, Vec<u8>)> {
        self.tx.subscribe()
    }
}

pub fn append_log(log_path: &std::path::Path, stream: u8, data: &[u8]) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
        let line = json!({
            "log": String::from_utf8_lossy(data),
            "stream": if stream == STREAM_STDERR { "stderr" } else { "stdout" },
            "time": ingot_util::now_rfc3339(),
        });
        let _ = writeln!(f, "{line}");
    }
}

/// Async pump (pty master) → hub.
pub async fn pump_pipe(
    mut pipe: tokio::net::UnixStream,
    stream: u8,
    hub: StdioHub,
) {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; 8192];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => hub.write_output(stream, &buf[..n]),
        }
    }
}

/// Blocking pump: pipe fd → hub (run inside spawn_blocking). Uses REAL pipes
/// so /proc/self/fd/N reopens work for container processes (nginx log
/// symlinks point there; reopening a socket via procfs fails with ENODEV).
pub fn pump_pipe_blocking(mut pipe: std::fs::File, stream: u8, hub: StdioHub) {
    use std::io::Read;
    let mut buf = vec![0u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => hub.write_output(stream, &buf[..n]),
        }
    }
}

/// Blocking pump: hub stdin requests → pipe fd (run inside spawn_blocking).
pub fn pump_stdin_blocking(mut rx: mpsc::Receiver<Vec<u8>>, mut pipe: std::fs::File) {
    use std::io::Write;
    while let Some(data) = rx.blocking_recv() {
        if pipe.write_all(&data).is_err() {
            break;
        }
    }
}

/// Encode a docker multiplexed stream frame (8-byte header).
/// [0]=stream type, [1..4]=zero, [4..8]=big-endian u32 length.
pub fn frame(stream: u8, data: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(8 + data.len());
    out.push(stream);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    Bytes::from(out)
}

/// Decode a multiplexed frame stream (used by CLI clients of /attach).
pub fn demux(buf: &[u8]) -> (u8, &[u8]) {
    if buf.len() < 8 {
        return (STREAM_STDOUT, buf);
    }
    let stream = buf[0];
    let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let end = (8 + len).min(buf.len());
    (stream, &buf[8..end])
}

pub type SharedHub = Arc<StdioHub>;
