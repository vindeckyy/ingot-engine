//! Client-side registry credentials (`ig login` / `ig logout`).
//!
//! Stored per registry host in `$XDG_CONFIG_HOME/ingot/auth.json`
//! (mode 0600). Pulls attach the matching entry as `X-Registry-Auth`;
//! credentials are never sent to another host.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::os::unix::fs::OpenOptionsExt;

/// Canonical key for a registry: hub aliases collapse to `docker.io`.
pub fn normalize_server(server: &str) -> String {
    let s = server.trim().to_lowercase();
    let s = s.split("://").last().unwrap_or(&s);
    // `split` always yields at least one item.
    let host = s.split('/').next().unwrap_or_default().to_string();
    match host.as_str() {
        "index.docker.io" | "registry-1.docker.io" => "docker.io".to_string(),
        _ => host,
    }
}

/// Registry host for an image spec: first path segment when it looks like
/// a host (docker's rule), else the Docker Hub default.
pub fn registry_host_for_image(image: &str) -> String {
    let first = image.split('/').next().unwrap_or("");
    if first.contains('.') || first.contains(':') || first == "localhost" {
        normalize_server(first)
    } else {
        "docker.io".to_string()
    }
}

pub fn auth_file_path() -> Result<std::path::PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(std::path::PathBuf::from(xdg).join("ingot/auth.json"));
        }
    }
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME is not set"))?;
    Ok(std::path::PathBuf::from(home).join(".config/ingot/auth.json"))
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct StoredAuth {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    /// Docker-config compat: base64(`user:pass`), honored on read.
    #[serde(default)]
    auth: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct AuthFile {
    #[serde(default)]
    auths: HashMap<String, StoredAuth>,
}

fn load_file() -> Result<AuthFile> {
    let path = auth_file_path()?;
    if !path.exists() {
        return Ok(AuthFile::default());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn save_file(file: &AuthFile) -> Result<()> {
    use std::io::Write;
    let path = auth_file_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(file)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("write {}", path.display()))?
        .write_all(&bytes)?;
    Ok(())
}

pub fn store(server: &str, username: &str, password: &str) -> Result<()> {
    if username.is_empty() {
        return Err(anyhow!("username must not be empty"));
    }
    let mut file = load_file()?;
    file.auths.insert(
        normalize_server(server),
        StoredAuth {
            username: username.to_string(),
            password: password.to_string(),
            auth: String::new(),
        },
    );
    save_file(&file)
}

/// Remove stored credentials. Returns whether any were present.
pub fn remove(server: &str) -> Result<bool> {
    let mut file = load_file()?;
    let removed = file.auths.remove(&normalize_server(server)).is_some();
    if removed {
        save_file(&file)?;
    }
    Ok(removed)
}

fn credentials_for(server: &str) -> Result<Option<(String, String)>> {
    let file = load_file()?;
    let key = normalize_server(server);
    let Some(entry) = file.auths.get(&key) else {
        return Ok(None);
    };
    if !entry.username.is_empty() || !entry.password.is_empty() {
        return Ok(Some((entry.username.clone(), entry.password.clone())));
    }
    // Docker-config `auth` field: base64(`user:pass`).
    if !entry.auth.is_empty() {
        use base64::Engine;
        if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(entry.auth.trim()) {
            if let Ok(s) = String::from_utf8(raw) {
                if let Some((u, p)) = s.split_once(':') {
                    return Ok(Some((u.to_string(), p.to_string())));
                }
            }
        }
    }
    Ok(None)
}

/// `X-Registry-Auth` value (base64 JSON) for an image's registry, when the
/// store holds credentials for it.
pub fn auth_header_for_image(image: &str) -> Result<Option<String>> {
    use base64::Engine;
    let server = registry_host_for_image(image);
    let Some((username, password)) = credentials_for(&server)? else {
        return Ok(None);
    };
    let body = serde_json::json!({
        "username": username,
        "password": password,
        "serveraddress": server,
    });
    Ok(Some(
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&body)?),
    ))
}

/// Read a password from the terminal with echo disabled. Falls back to a
/// plain stdin line when `/dev/tty` is unavailable.
pub fn read_password(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    if let Ok(tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        use std::os::unix::io::AsRawFd;
        let fd = tty.as_raw_fd();
        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut orig) } == 0 {
            let mut noecho = orig;
            noecho.c_lflag &= !libc::ECHO;
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &noecho) } == 0 {
                eprint!("{prompt}");
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                let mut reader = std::io::BufReader::new(&tty);
                let r = reader.read_line(&mut line);
                unsafe {
                    libc::tcsetattr(fd, libc::TCSANOW, &orig);
                }
                eprintln!();
                r.context("read password")?;
                return Ok(line.trim_end_matches(['\r', '\n']).to_string());
            }
        }
    }
    eprint!("{prompt} (input will echo) ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("read password")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn server_normalization() {
        assert_eq!(normalize_server("example.com:5000"), "example.com:5000");
        assert_eq!(normalize_server("https://example.com/v2/"), "example.com");
        assert_eq!(normalize_server("index.docker.io"), "docker.io");
        assert_eq!(normalize_server("registry-1.docker.io"), "docker.io");
        assert_eq!(normalize_server("DOCKER.IO"), "docker.io");
    }

    #[test]
    fn image_registry_hosts() {
        assert_eq!(registry_host_for_image("busybox"), "docker.io");
        assert_eq!(registry_host_for_image("library/busybox:1.36"), "docker.io");
        assert_eq!(registry_host_for_image("ghcr.io/o/i:tag"), "ghcr.io");
        assert_eq!(
            registry_host_for_image("localhost:5000/i"),
            "localhost:5000"
        );
        assert_eq!(registry_host_for_image("myhost.local/i"), "myhost.local");
    }

    #[test]
    fn store_roundtrip_and_header() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("ingot-auth-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("XDG_CONFIG_HOME", &dir);
        // Missing file reads empty; logout of nothing reports false.
        assert!(auth_header_for_image("busybox").unwrap().is_none());
        assert!(!remove("docker.io").unwrap());
        // Store under an alias, read back under the canonical name.
        store("index.docker.io", "user", "s3cret").unwrap();
        let header = auth_header_for_image("library/busybox:latest")
            .unwrap()
            .unwrap();
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&header)
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["username"], "user");
        assert_eq!(v["password"], "s3cret");
        // Permissions are owner-only.
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(dir.join("ingot/auth.json"))
                .unwrap()
                .permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        // Other registries are isolated; logout removes.
        assert!(auth_header_for_image("ghcr.io/o/i").unwrap().is_none());
        assert!(remove("docker.io").unwrap());
        assert!(auth_header_for_image("busybox").unwrap().is_none());
        std::env::remove_var("XDG_CONFIG_HOME");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
