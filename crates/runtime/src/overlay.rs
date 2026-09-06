//! Overlayfs snapshot management for container rootfs.

use anyhow::{Context, Result};
use ingot_store::paths::DataPaths;
use std::path::Path;

/// Mount overlayfs for a container: image layers as lowerdirs, container
/// diff/work dirs as upper/work. Mounted in the daemon's mount namespace —
/// the container child inherits it via clone(CLONE_NEWNS).
pub fn mount_rootfs(paths: &DataPaths, container_id: &str, diff_ids: &[String]) -> Result<()> {
    for sub in ["diff", "work", "merged"] {
        std::fs::create_dir_all(paths.overlay_container(container_id).join(sub))?;
    }
    // overlayfs lowerdir lists TOP-most first; diff_ids are base-first, so
    // reverse (newest layer first, base last).
    let lowers: Vec<String> = diff_ids
        .iter()
        .rev()
        .map(|d| {
            paths
                .layers()
                .join(d.trim_start_matches("sha256:"))
                .to_string_lossy()
                .to_string()
        })
        .collect();
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowers.join(":"),
        paths.overlay_diff(container_id).display(),
        paths.overlay_work(container_id).display(),
    );
    let merged = paths.overlay_merged(container_id);
    do_mount("overlay", &merged, &opts)
        .with_context(|| format!("overlay mount for container {container_id}"))
}

pub fn unmount_rootfs(paths: &DataPaths, container_id: &str) -> Result<()> {
    let merged = paths.overlay_merged(container_id);
    if Path::new(&merged).exists() {
        nix::mount::umount2(&merged, nix::mount::MntFlags::MNT_DETACH)
            .map_err(|e| anyhow::anyhow!("umount {}: {e}", merged.display()))?;
    }
    Ok(())
}

/// Generic overlay mount (builder + general use): lowerdirs TOP-most first.
pub fn mount_overlay(
    lowerdirs_top_first: &[String],
    merged: &Path,
    upper: &Path,
    work: &Path,
) -> Result<()> {
    for sub in [merged, upper, work] {
        std::fs::create_dir_all(sub)?;
    }
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowerdirs_top_first.join(":"),
        upper.display(),
        work.display()
    );
    do_mount("overlay", merged, &opts)
        .with_context(|| format!("overlay mount at {}", merged.display()))
}

pub fn umount(merged: &Path) -> Result<()> {
    if Path::new(merged).exists() {
        nix::mount::umount2(merged, nix::mount::MntFlags::MNT_DETACH)
            .map_err(|e| anyhow::anyhow!("umount {}: {e}", merged.display()))?;
    }
    Ok(())
}

fn do_mount(fstype: &str, target: &Path, data: &str) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let fs = std::ffi::CString::new(fstype)?;
    let dir = std::ffi::CString::new(target.as_os_str().as_bytes())?;
    let data_c = std::ffi::CString::new(data)?;
    let null = std::ffi::CString::new("")?;
    let rc = unsafe {
        libc::mount(
            null.as_ptr(),
            dir.as_ptr(),
            fs.as_ptr(),
            libc::MS_NOSUID,
            data_c.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "mount {fstype} at {}: {}",
            target.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
