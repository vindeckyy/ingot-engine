//! One-shot command execution inside a rootfs — used by the image builder's
//! RUN instructions. Same namespace/child machinery as container start, minus
//! records, cgroups and stdio plumbing (output is captured).

use crate::child::ChildContext;
use crate::overlay;
use anyhow::{anyhow, Result};
use ingot_store::paths::DataPaths;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;

pub struct StepOptions {
    /// Overlay lowerdirs, TOP-most first.
    pub lowerdirs: Vec<String>,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: String,
    /// Scratch root for this step's merged/diff/work dirs.
    pub work_root: PathBuf,
    pub context_root: PathBuf,
    /// Extra bind mounts: (source, destination-in-container).
    pub binds: Vec<(PathBuf, String)>,
    /// Read-only bind mounts, remounted MS_RDONLY after the bind
    /// (build secrets: readable inside the step, never writable).
    pub binds_ro: Vec<(PathBuf, String)>,
}

/// Run `argv` in the prepared rootfs. Returns (exit code, combined output).
pub fn run_step(paths: &DataPaths, id: &str, opts: StepOptions) -> Result<(i32, String)> {
    let merged = opts.work_root.join("merged");
    std::fs::create_dir_all(&merged)?;
    overlay::mount_overlay(
        &opts.lowerdirs,
        &merged,
        &opts.work_root.join("diff"),
        &opts.work_root.join("work"),
    )?;

    // /etc files for the build env.
    std::fs::create_dir_all(merged.join("etc"))?;
    let etc = opts.work_root.join("etc");
    std::fs::create_dir_all(&etc)?;
    std::fs::write(etc.join("resolv.conf"), host_resolv())?;
    std::fs::write(etc.join("hosts"), "127.0.0.1\tlocalhost\n")?;
    std::fs::write(etc.join("hostname"), format!("{}\n", id))?;

    // Bind mounts (e.g. build context) into the rootfs. File sources
    // get a file target (parent dirs + touch); directory sources get a
    // directory target. Read-only mounts are remounted MS_RDONLY after
    // the bind so the step cannot alter (or truncate) the source.
    for (src, dest, readonly) in opts
        .binds
        .iter()
        .map(|(s, d)| (s, d, false))
        .chain(opts.binds_ro.iter().map(|(s, d)| (s, d, true)))
    {
        let target = merged.join(dest.trim_start_matches('/'));
        if src.is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::File::create(&target)?;
        } else {
            std::fs::create_dir_all(&target)?;
        }
        bind_one(src, &target, dest)?;
        if readonly {
            let d = std::ffi::CString::new(target.as_os_str().as_encoded_bytes().to_vec())?;
            let rc = unsafe {
                libc::mount(
                    std::ptr::null(),
                    d.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                    std::ptr::null(),
                )
            };
            if rc != 0 {
                return Err(anyhow!(
                    "bind(ro) {} → {}: {}",
                    src.display(),
                    dest,
                    std::io::Error::last_os_error()
                ));
            }
        }
    }

    let (ready_tx, ready_rx) = std::os::unix::net::UnixStream::pair()?;
    let (out_r, out_w) = crate::stdio::os_pipe_pair()?;
    let (in_r, in_w) = crate::stdio::os_pipe_pair()?;
    // Child stdin is immediate EOF: close the write end for real (a plain
    // `drop` on a raw fd would leak it).
    unsafe {
        libc::close(in_w);
    }

    let env: Vec<String> = opts
        .env
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .chain(std::iter::once(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ))
        .chain(std::iter::once("HOME=/root".to_string()))
        .collect();

    let ctx = ChildContext {
        ready_pipe_rd: ready_rx.as_raw_fd(),
        exec_pipe_wr: -1,
        stdin_fd: in_r,
        stdout_fd: out_w,
        stderr_fd: out_w, // combined like docker build
        merged: std::ffi::CString::new(merged.as_os_str().as_encoded_bytes().to_vec())?,
        hostname: std::ffi::CString::new("build")?,
        resolv: std::ffi::CString::new(
            etc.join("resolv.conf")
                .as_os_str()
                .as_encoded_bytes()
                .to_vec(),
        )?,
        hosts: std::ffi::CString::new(etc.join("hosts").as_os_str().as_encoded_bytes().to_vec())?,
        hostname_file: std::ffi::CString::new(
            etc.join("hostname").as_os_str().as_encoded_bytes().to_vec(),
        )?,
        argv: opts
            .argv
            .iter()
            .map(|a| std::ffi::CString::new(a.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()?,
        envp: env
            .iter()
            .map(|e| std::ffi::CString::new(e.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()?,
        workdir: std::ffi::CString::new(if opts.workdir.is_empty() {
            "/"
        } else {
            &opts.workdir
        })?,
        user_raw: std::ffi::CString::new("")?,
        uid: u32::MAX,
        gid: u32::MAX,
        extra_gids: vec![],
        cap_add: vec![],
        cap_drop: vec![],
        privileged: false,
        no_new_privs: true,
        readonly_rootfs: false,
        bring_lo_up: false,
        has_netns: true,
        tty: false,
        shm_size: 0,
        tmpfs: vec![],
        sysctls: vec![],
        ulimits: vec![],
    };

    let ctx_ptr = ctx.into_raw() as *mut libc::c_void;
    let clone_flags = libc::SIGCHLD
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWNET;
    let pid = unsafe {
        const STACK: usize = 8 * 1024 * 1024;
        let mut stack = vec![0u8; STACK];
        let top = ((stack.as_mut_ptr() as usize) + STACK - 16) & !0xF;
        libc::clone(
            crate::child::clone_entry,
            top as *mut libc::c_void,
            clone_flags,
            ctx_ptr,
        )
    };
    if pid < 0 {
        unsafe {
            libc::close(out_w);
            libc::close(in_r);
            libc::close(out_r);
            ChildContext::from_raw(ctx_ptr as *mut ChildContext);
        };
        return Err(anyhow!("clone failed: {}", std::io::Error::last_os_error()));
    }
    drop(ready_rx);
    {
        use std::io::Write;
        let mut tx = ready_tx;
        let _ = tx.write_all(b"g"); // no network setup needed for build steps
    }
    unsafe {
        libc::close(out_w);
        libc::close(in_r);
    }

    // Capture output on a thread while we wait.
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut f = unsafe { std::fs::File::from_raw_fd(out_r) };
        let mut out = Vec::new();
        let _ = f.read_to_end(&mut out);
        out
    });

    let mut status = 0;
    let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = if rc == pid {
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            1
        }
    } else {
        -1
    };
    let output = String::from_utf8_lossy(&reader.join().unwrap_or_default()).to_string();

    for (_, dest) in opts.binds.iter().chain(opts.binds_ro.iter()).rev() {
        let target = merged.join(dest.trim_start_matches('/'));
        let _ = nix::mount::umount2(&target, nix::mount::MntFlags::MNT_DETACH);
    }
    overlay::umount(&merged)?;
    let _ = paths;
    Ok((code, output))
}

/// One MS_BIND mount of `src` onto `target`.
fn bind_one(src: &std::path::Path, target: &std::path::Path, dest: &str) -> Result<()> {
    let s = std::ffi::CString::new(src.as_os_str().as_encoded_bytes().to_vec())?;
    let d = std::ffi::CString::new(target.as_os_str().as_encoded_bytes().to_vec())?;
    let rc = unsafe {
        libc::mount(
            s.as_ptr(),
            d.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(anyhow!(
            "bind {} → {}: {}",
            src.display(),
            dest,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn host_resolv() -> String {
    std::fs::read_to_string("/etc/resolv.conf").unwrap_or_else(|_| "nameserver 8.8.8.8\n".into())
}
