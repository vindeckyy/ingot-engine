//! Unix-socket serving loop.
//!
//! # Security Warning
//! Access to the Ingot API socket grants full control over the container engine,
//! which runs as root with host-level privileges (namespaces, cgroups, mounts,
//! iptables). Any user with access to this socket is effectively root on the host.
//! Peer-credential authorization is not a substitute for this warning. Restrict
//! socket access accordingly (defaulting to 0600 root-only, or an approved group
//! with mode 0660).

use crate::router::build_router;
use crate::state::SharedState;
use anyhow::{Context, Result};
use std::path::Path;

/// Bind the API socket, apply docker-parity permissions, and serve forever.
/// Defaults to mode 0600 (root-only). If a socket group is specified,
/// it is set to root:<group> with mode 0660. World-writable (0666) is forbidden.
pub async fn serve(state: SharedState, socket: &Path, socket_group: Option<&str>) -> Result<()> {
    let sock_path = socket;
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }

    // A stale socket from a crashed daemon prevents bind.
    cleanup_stale_socket(sock_path)?;

    let listener = tokio::net::UnixListener::bind(sock_path)
        .with_context(|| format!("bind {}", sock_path.display()))?;
    apply_socket_perms(sock_path, socket_group)?;
    tracing::info!("listening on {}", sock_path.display());

    let app = build_router(state);
    axum::serve(listener, app).await.context("server loop")
}

/// Remove stale Unix socket if one exists.
/// Checks with `symlink_metadata` and ensures it is an actual Unix socket
/// before removing. Refuses to remove symlinks or non-socket files.
pub fn cleanup_stale_socket(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() {
                anyhow::bail!(
                    "configured socket path {} exists and is not a socket; refusing to remove",
                    path.display()
                );
            }
            std::fs::remove_file(path)
                .with_context(|| format!("remove stale socket {}", path.display()))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("check socket metadata at {}", path.display()))
        }
    }
    Ok(())
}

/// Apply permissions to the API socket.
///
/// If `socket_group` is provided, looks up the group GID (failing if not found),
/// sets ownership to root:group, and permissions to 0660.
/// If `socket_group` is None, sets permissions to 0600 (root-only).
/// Never sets world-writable 0666.
pub fn apply_socket_perms(path: &Path, socket_group: Option<&str>) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())?;

    if let Some(group_name) = socket_group {
        let gid = group_gid(group_name)
            .ok_or_else(|| anyhow::anyhow!("configured socket group '{group_name}' not found"))?;
        let rc = unsafe { libc::chown(cpath.as_ptr(), 0, gid) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("chown 0:{gid} {}", path.display()));
        }
        let rc = unsafe { libc::chmod(cpath.as_ptr(), 0o660) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("chmod 0660 {}", path.display()));
        }
    } else {
        let rc = unsafe { libc::chmod(cpath.as_ptr(), 0o600) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("chmod 0600 {}", path.display()));
        }
    }
    Ok(())
}

pub fn group_gid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    unsafe {
        let g = libc::getgrnam(cname.as_ptr());
        if g.is_null() {
            None
        } else {
            Some((*g).gr_gid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn test_cleanup_stale_socket_refuses_regular_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("fake.sock");
        std::fs::write(&file_path, "not a socket").unwrap();

        let err = cleanup_stale_socket(&file_path).unwrap_err();
        assert!(err.to_string().contains("not a socket"), "err: {err}");
        assert!(file_path.exists());
    }

    #[test]
    fn test_cleanup_stale_socket_refuses_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "content").unwrap();
        let symlink_path = dir.path().join("symlink.sock");
        std::os::unix::fs::symlink(&target, &symlink_path).unwrap();

        let err = cleanup_stale_socket(&symlink_path).unwrap_err();
        assert!(err.to_string().contains("not a socket"), "err: {err}");
        assert!(target.exists());
    }

    #[test]
    fn test_cleanup_stale_socket_removes_socket() {
        let dir = TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        drop(listener);

        assert!(sock_path.exists());
        cleanup_stale_socket(&sock_path).unwrap();
        assert!(!sock_path.exists());
    }

    #[test]
    fn test_apply_socket_perms_defaults_to_0600() {
        let dir = TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        apply_socket_perms(&sock_path, None).unwrap();
        let perms = std::fs::metadata(&sock_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_apply_socket_perms_missing_group_errors() {
        let dir = TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        let err = apply_socket_perms(&sock_path, Some("nonexistent-group-xyz-123")).unwrap_err();
        assert!(err.to_string().contains("not found"), "err: {err}");
    }
}
