//! Container stdio hub: json-file log driver + live attach subscribers +
//! stdin fan-in. Mirrors docker's `json-file` log format.

use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

/// Stream tag for multiplexed frames.
pub const STREAM_STDIN: u8 = 0;
pub const STREAM_STDOUT: u8 = 1;
pub const STREAM_STDERR: u8 = 2;

/// Parsed `json-file` rotation policy from `HostConfig.LogConfig.config`
/// (`max-size`, `max-file`; docker parity). `None` means unbounded,
/// which is also the docker default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRotation {
    /// Rotate when the active file would exceed this many bytes.
    pub max_bytes: u64,
    /// Total log files kept, including the active one (≥ 1).
    pub max_files: u32,
}

/// Parse docker `max-size` values: plain bytes, `k`/`m`/`g` suffixes
/// (case-insensitive, docker spelling), or `-1` for unlimited.
pub fn parse_max_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s == "-1" {
        return None;
    }
    let (num, mult) = match s.strip_suffix(['k', 'K']) {
        Some(n) => (n, 1024u64),
        None => match s.strip_suffix(['m', 'M']) {
            Some(n) => (n, 1024 * 1024),
            None => match s.strip_suffix(['g', 'G']) {
                Some(n) => (n, 1024 * 1024 * 1024),
                None => (s, 1),
            },
        },
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

/// Resolve the rotation policy for a container from its validated log
/// opts. Unparseable opts yield `None` (fail-open to unbounded): create-
/// time validation rejects them first, so this path only serves records
/// written before the validation existed.
pub fn rotation_from_config(
    config: &std::collections::HashMap<String, String>,
) -> Option<LogRotation> {
    parse_log_rotation(config).unwrap_or(None)
}

/// Parse and validate the rotation subset of log opts. Unknown keys are
/// rejected by the caller (never silently ignored).
pub fn parse_log_rotation(
    config: &std::collections::HashMap<String, String>,
) -> Result<Option<LogRotation>, String> {
    let size = config.get("max-size").map(|s| s.as_str()).unwrap_or("");
    let files = config.get("max-file").map(|s| s.as_str()).unwrap_or("");
    if size.is_empty() && files.is_empty() {
        return Ok(None);
    }
    let max_bytes = if size.is_empty() || size == "-1" {
        u64::MAX
    } else {
        parse_max_size(size).ok_or_else(|| format!("invalid max-size {size:?}"))?
    };
    let max_files = if files.is_empty() {
        1u32
    } else {
        files
            .parse::<u32>()
            .ok()
            .filter(|n| *n >= 1)
            .ok_or_else(|| format!("invalid max-file {files:?} (must be >= 1)"))?
    };
    if max_bytes == u64::MAX && files.is_empty() {
        return Ok(None);
    }
    Ok(Some(LogRotation {
        max_bytes,
        max_files,
    }))
}

struct LogFile {
    writer: std::io::BufWriter<std::fs::File>,
    /// Bytes in the active file (seeded from metadata at open).
    written: u64,
    rotation: Option<LogRotation>,
}

fn open_log_file(path: &std::path::Path) -> (std::io::BufWriter<std::fs::File>, u64) {
    let written = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(|f| std::io::BufWriter::with_capacity(32 * 1024, f))
        .unwrap_or_else(|_| {
            let tmp = std::fs::File::create("/dev/null").expect("/dev/null");
            std::io::BufWriter::with_capacity(32 * 1024, tmp)
        });
    (file, written)
}

#[derive(Clone)]
pub struct StdioHub {
    /// log file path (json-file driver)
    log_path: std::path::PathBuf,
    /// held append handle: open once, BufWriter, avoids open+close per chunk.
    log_file: std::sync::Arc<std::sync::Mutex<LogFile>>,
    /// live subscribers of (stream, bytes)
    tx: broadcast::Sender<(u8, Vec<u8>)>,
    stdin_tx: mpsc::Sender<Vec<u8>>,
}

#[derive(serde::Serialize)]
struct LogLine<'a> {
    log: std::borrow::Cow<'a, str>,
    stream: &'a str,
    time: String,
}

impl StdioHub {
    /// Create a hub; `stdin` recv end is returned for the pump task to feed
    /// the container's stdin pipe.
    pub fn new(log_path: std::path::PathBuf) -> (Self, mpsc::Receiver<Vec<u8>>) {
        Self::with_rotation(log_path, None)
    }

    /// Create a hub with a parsed rotation policy (`None` = unbounded,
    /// the docker default).
    pub fn with_rotation(
        log_path: std::path::PathBuf,
        rotation: Option<LogRotation>,
    ) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, _) = broadcast::channel(256);
        let (stdin_tx, stdin_rx) = mpsc::channel(256);
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let (file, written) = open_log_file(&log_path);
        let hub = StdioHub {
            log_path,
            log_file: std::sync::Arc::new(std::sync::Mutex::new(LogFile {
                writer: file,
                written,
                rotation,
            })),
            tx,
            stdin_tx,
        };
        (hub, stdin_rx)
    }

    /// Called by the stdout/stderr pump.
    pub fn write_output(&self, stream: u8, data: &[u8]) {
        self.append_log(stream, data);
        // Skip the copy when nobody is attached/following.
        if self.tx.receiver_count() > 0 {
            let _ = self.tx.send((stream, data.to_vec()));
        }
    }

    /// Rotate the active log when the policy says so. Caller holds the
    /// lock; the writer is flushed and replaced, never shared across
    /// the rename.
    fn rotate_locked(log: &mut LogFile, path: &std::path::Path) {
        use std::io::Write;
        let Some(rot) = log.rotation else {
            return;
        };
        let _ = log.writer.flush();
        // Shift log.N-1 → log.N down to log → log.1, dropping the
        // oldest; total files kept (active + rotated) is max_files.
        let keep = rot.max_files.max(1) as usize;
        if keep > 1 {
            let oldest = path.with_extension(format!("log.{keep}"));
            let _ = std::fs::remove_file(&oldest);
            for i in (1..keep).rev() {
                let from = if i == 1 {
                    path.to_path_buf()
                } else {
                    path.with_extension(format!("log.{i}"))
                };
                let to = path.with_extension(format!("log.{}", i + 1));
                let _ = std::fs::rename(&from, &to);
            }
        }
        let (file, _) = open_log_file(path);
        log.writer = file;
        log.written = 0;
    }

    fn append_log(&self, stream: u8, data: &[u8]) {
        use std::io::Write;
        let line = LogLine {
            log: String::from_utf8_lossy(data),
            stream: if stream == STREAM_STDERR {
                "stderr"
            } else {
                "stdout"
            },
            time: ingot_util::now_rfc3339(),
        };
        if let Ok(mut log) = self.log_file.lock() {
            // Serialize first so the size check counts encoded bytes.
            let mut buf = Vec::new();
            if serde_json::to_writer(&mut buf, &line).is_err() {
                return;
            }
            buf.push(b'\n');
            if let Some(rot) = log.rotation {
                if log.written.saturating_add(buf.len() as u64) > rot.max_bytes {
                    Self::rotate_locked(&mut log, &self.log_path);
                }
            }
            let _ = log.writer.write_all(&buf);
            log.written = log.written.saturating_add(buf.len() as u64);
            // Flush so /logs readers see bytes immediately; still a single
            // write syscall per chunk vs open+write+close before.
            let _ = log.writer.flush();
        }
    }

    /// Flush buffered log bytes (called on container stop/exit paths).
    pub fn flush(&self) {
        use std::io::Write;
        if let Ok(mut log) = self.log_file.lock() {
            let _ = log.writer.flush();
        }
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

    pub fn log_path(&self) -> &std::path::Path {
        &self.log_path
    }
}

impl Drop for StdioHub {
    fn drop(&mut self) {
        // Last clone dropping flushes buffered log bytes.
        if std::sync::Arc::strong_count(&self.log_file) <= 1 {
            use std::io::Write;
            if let Ok(mut log) = self.log_file.lock() {
                let _ = log.writer.flush();
            }
        }
    }
}

pub fn append_log(log_path: &std::path::Path, stream: u8, data: &[u8]) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let line = LogLine {
            log: String::from_utf8_lossy(data),
            stream: if stream == STREAM_STDERR {
                "stderr"
            } else {
                "stdout"
            },
            time: ingot_util::now_rfc3339(),
        };
        let _ = serde_json::to_writer(&mut f, &line);
        let _ = writeln!(f);
    }
}

/// Async pump (pty master) → hub.
pub async fn pump_pipe(mut pipe: tokio::net::UnixStream, stream: u8, hub: StdioHub) {
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

/// Real os pipe (O_CLOEXEC): returns (read_fd, write_fd).
/// Single shared definition (was triplicated across exec/step/manager).
pub(crate) fn os_pipe_pair() -> anyhow::Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "pipe2: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((fds[0], fds[1]))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn max_size_shapes() {
        assert_eq!(parse_max_size("1024"), Some(1024));
        assert_eq!(parse_max_size("10k"), Some(10 * 1024));
        assert_eq!(parse_max_size("10M"), Some(10 * 1024 * 1024));
        assert_eq!(parse_max_size("2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_max_size("-1"), None);
        assert_eq!(parse_max_size("bogus"), None);
        assert_eq!(parse_max_size("10x"), None);
        assert_eq!(parse_max_size(""), None);
    }

    #[test]
    fn rotation_policy_parsing() {
        assert_eq!(parse_log_rotation(&cfg(&[])).unwrap(), None);
        let r = parse_log_rotation(&cfg(&[("max-size", "10m"), ("max-file", "5")])).unwrap();
        assert_eq!(
            r,
            Some(LogRotation {
                max_bytes: 10 * 1024 * 1024,
                max_files: 5,
            })
        );
        // max-file alone pins the file count; size stays unbounded.
        let r = parse_log_rotation(&cfg(&[("max-file", "3")])).unwrap();
        assert_eq!(r.unwrap().max_files, 3);
        assert!(parse_log_rotation(&cfg(&[("max-size", "huge")])).is_err());
        assert!(parse_log_rotation(&cfg(&[("max-file", "0")])).is_err());
        assert!(parse_log_rotation(&cfg(&[("max-file", "-1")])).is_err());
    }

    #[test]
    fn hub_rotates_and_preserves_lines() {
        let dir = std::env::temp_dir().join(format!("ingot-logrot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctr-json.log");
        // Sized so all 20 lines fit in max_files files: rotation must
        // trigger (active file stays bounded) without dropping lines.
        let rotation = LogRotation {
            max_bytes: 800,
            max_files: 3,
        };
        let (hub, _rx) = StdioHub::with_rotation(path.clone(), Some(rotation));
        for i in 0..20 {
            hub.write_output(
                STREAM_STDOUT,
                format!("line-{i:02}-padding-0123456789").as_bytes(),
            );
        }
        drop(hub);
        // Active file plus at most max_files-1 rotated siblings exist.
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        files.sort();
        assert!(
            files.len() <= 3,
            "rotation must cap files at max_files: {files:?}"
        );
        assert!(files.iter().any(|f| f == "ctr-json.log"), "{files:?}");
        assert!(
            files.iter().any(|f| f.starts_with("ctr-json.log.")),
            "expected at least one rotated sibling: {files:?}"
        );
        // Every surviving line still parses as a json-file record.
        let mut lines = 0;
        for f in &files {
            let raw = std::fs::read(dir.join(f)).unwrap();
            for line in raw.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                let v: serde_json::Value = serde_json::from_slice(line).unwrap();
                assert!(v.get("log").is_some() && v.get("time").is_some());
                lines += 1;
            }
        }
        assert_eq!(lines, 20, "no log lines may be lost to rotation");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hub_caps_files_under_pressure() {
        let dir = std::env::temp_dir().join(format!("ingot-logcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctr-json.log");
        let rotation = LogRotation {
            max_bytes: 200,
            max_files: 2,
        };
        let (hub, _rx) = StdioHub::with_rotation(path.clone(), Some(rotation));
        for i in 0..30 {
            hub.write_output(
                STREAM_STDOUT,
                format!("line-{i:02}-padding-0123456789").as_bytes(),
            );
        }
        drop(hub);
        let files: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert_eq!(files.len(), 2, "oldest logs must be dropped past max_files");
        let active = std::fs::metadata(&path).unwrap().len();
        assert!(
            active <= 200 + 256,
            "active file stays near max_bytes: {active}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hub_without_policy_never_rotates() {
        let dir = std::env::temp_dir().join(format!("ingot-lognorot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctr-json.log");
        let (hub, _rx) = StdioHub::new(path);
        for i in 0..10 {
            hub.write_output(STREAM_STDERR, format!("err-{i}").as_bytes());
        }
        drop(hub);
        let files: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert_eq!(files.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
