//! Unix-socket serving loop.

use crate::router::build_router;
use crate::state::SharedState;
use anyhow::{Context, Result};
use std::path::Path;

/// Bind the API socket, apply docker-parity permissions, and serve forever.
/// The docker CLI talks to a socket owned root:docker with mode 0660; we try
/// the same for an `ingot`/`docker` group and fall back to 0666.
pub async fn serve(state: SharedState, socket: &Path) -> Result<()> {
    let sock_path = socket;
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    // A stale socket from a crashed daemon prevents bind.
    let _ = std::fs::remove_file(sock_path);

    let listener = tokio::net::UnixListener::bind(sock_path)
        .with_context(|| format!("bind {}", sock_path.display()))?;
    apply_socket_perms(sock_path)?;
    tracing::info!("listening on {}", sock_path.display());

    let app = build_router(state);
    axum::serve(listener, app).await.context("server loop")
}

fn apply_socket_perms(path: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let desired: &[&str] = &["ingot", "docker"];
    let mut set = false;
    for group in desired {
        if let Some(gid) = group_gid(group) {
            if unsafe { libc::chown(cpath.as_ptr(), 0, gid) } == 0 {
                set = true;
                break;
            }
        }
    }
    let mode = if set { 0o660 } else { 0o666 };
    unsafe { libc::chmod(cpath.as_ptr(), mode) };
    Ok(())
}

fn group_gid(name: &str) -> Option<u32> {
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
