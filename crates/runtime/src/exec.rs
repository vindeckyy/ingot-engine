//! `exec`: run a command inside a running container's namespaces.
//!
//! Joining a PID namespace requires forking after setns (the caller stays in
//! its old pidns until it forks), hence the fork1 → setns(pid) → fork2 dance,
//! mirroring runc.

use crate::manager::ContainerHandle;
use crate::stdio::{pump_pipe, StdioHub, STREAM_STDERR, STREAM_STDOUT};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Close all fds except `keep`. Iterates /proc/self/fd instead of
/// blindly closing 3..=4096 (usually <50 fds, not 4093 syscalls).
fn close_all_fds(keep: &[i32]) {
    if let Ok(rd) = std::fs::read_dir("/proc/self/fd") {
        let mut to_close = Vec::new();
        for entry in rd.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(fd) = name.parse::<i32>() {
                    if fd >= 3 && !keep.contains(&fd) {
                        to_close.push(fd);
                    }
                }
            }
        }
        for fd in to_close {
            unsafe {
                libc::close(fd);
            }
        }
        return;
    }
    for fd in 3..=4096i32 {
        if !keep.contains(&fd) {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ExecState {
    pub running: bool,
    pub exit_code: i64,
    pub pid: i64,
}

pub struct ExecSession {
    pub id: String,
    pub container_id: String,
    pub cmd: Vec<String>,
    pub tty: bool,
    pub detach: bool,
    pub user: String,
    pub workdir: String,
    pub env: Vec<String>,
    pub created: String,
    pub state: Mutex<ExecState>,
    pub stdio: Arc<StdioHub>,
    stdin_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    stdin_rx: Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    exit_tx: broadcast::Sender<i64>,
}

impl ExecSession {
    /// Take the stdin receiver (called once by start_exec).
    pub fn take_stdin_rx(&self) -> Option<tokio::sync::mpsc::Receiver<Vec<u8>>> {
        self.stdin_rx.lock().unwrap().take()
    }
}

impl ExecSession {
    // Eight fields by design: mirrors the Engine API exec-create body plus
    // the log path, so bundling them would add a type without removing a
    // parameter.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        container_id: String,
        cmd: Vec<String>,
        tty: bool,
        detach: bool,
        user: String,
        workdir: String,
        env: Vec<String>,
        log_path: std::path::PathBuf,
    ) -> Self {
        use crate::stdio::STREAM_STDIN;
        let _ = STREAM_STDIN;
        let (hub, _log_rx) = StdioHub::new(log_path);
        let (stdin_tx, stdin_rx) = tokio::sync::mpsc::channel(256);
        ExecSession {
            id: ingot_util::random_token(),
            container_id,
            cmd,
            tty,
            detach,
            user,
            workdir,
            env,
            created: ingot_util::now_rfc3339(),
            state: Mutex::new(ExecState::default()),
            stdio: Arc::new(hub),
            stdin_tx,
            stdin_rx: Mutex::new(Some(stdin_rx)),
            exit_tx: broadcast::channel(8).0,
        }
    }

    /// Send stdin bytes to the exec'd process.
    pub async fn send_stdin(&self, data: Vec<u8>) {
        let _ = self.stdin_tx.send(data).await;
    }
}

impl ExecSession {
    pub fn subscribe_exit(&self) -> broadcast::Receiver<i64> {
        self.exit_tx.subscribe()
    }
}

/// Kick off the exec'd process. Pipes/pumps are wired here; `wait` joins.
pub fn start_exec(
    session: Arc<ExecSession>,
    handle: Arc<ContainerHandle>,
    paths: ingot_store::paths::DataPaths,
) -> Result<()> {
    let (container_pid, container_id) = {
        let st = handle.state.lock().unwrap();
        if st.status != crate::record::StateStatus::Running {
            return Err(anyhow!("container is not running"));
        }
        (st.pid, handle.id())
    };

    // Verify cgroup identity to defend against PID reuse
    let cgroup_path = format!("/proc/{container_pid}/cgroup");
    let cgroup_content = std::fs::read_to_string(&cgroup_path)
        .with_context(|| format!("failed to read {cgroup_path}"))?;
    if !cgroup_content.contains(&container_id) {
        return Err(anyhow!(
            "exec target pid {container_pid} cgroup does not match container {container_id}"
        ));
    }

    // Open the container's namespace fds while it is alive.
    let ns = |name: &str| -> Result<std::fs::File> {
        Ok(std::fs::File::open(format!(
            "/proc/{container_pid}/ns/{name}"
        ))?)
    };
    let pid_fd = ns("pid")?;
    let mnt_fd = ns("mnt")?;
    let net_fd = ns("net")?;
    let ipc_fd = ns("ipc")?;
    let uts_fd = ns("uts")?;

    // Pre-build everything the forked children need (no allocs post-fork).
    let argv: Vec<std::ffi::CString> = session
        .cmd
        .iter()
        .map(|c| std::ffi::CString::new(c.as_str()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| anyhow!("invalid command bytes"))?;
    if argv.is_empty() {
        return Err(anyhow!("exec: empty command"));
    }
    let mut env: Vec<String> = handle.record.lock().unwrap().config.Env.clone();
    env.extend(session.env.clone());
    env.retain(|e| e.contains('='));
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }
    let envp: Vec<std::ffi::CString> = env
        .iter()
        .map(|e| std::ffi::CString::new(e.as_str()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let workdir = std::ffi::CString::new(if session.workdir.is_empty() {
        "/"
    } else {
        session.workdir.as_str()
    })?;
    let (uid, gid) = parse_user(&session.user, &handle);
    // Exec sessions run with the container's capability set and resource
    // limits, not the daemon's (Plan Phase 3, units 3.1/3.4).
    let (exec_cap_add, exec_cap_drop, exec_privileged, exec_ulimits, exec_seccomp) = {
        let rec = handle.record.lock().unwrap();
        let seccomp = !rec.hostconfig.Privileged
            && !rec
                .hostconfig
                .SecurityOpt
                .iter()
                .any(|s| s == "seccomp=unconfined" || s == "seccomp:unconfined");
        (
            rec.hostconfig.CapAdd.clone(),
            rec.hostconfig.CapDrop.clone(),
            rec.hostconfig.Privileged,
            crate::error::parse_ulimits(&rec.hostconfig)
                .map_err(|e| anyhow!("invalid ulimits: {e}"))?,
            seccomp,
        )
    };

    if exec_seccomp && !exec_privileged {
        let _ = crate::seccomp::get_default_bpf_program();
    }

    let cg_fd = unsafe {
        let cg_path = std::ffi::CString::new(format!(
            "/sys/fs/cgroup/ingot.slice/{container_id}/cgroup.procs"
        ))?;
        libc::open(cg_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC)
    };
    // Pin the container's root before forking: after setns into the mount
    // namespace `/` may resolve to a stale pre-pivot tree.
    let root_dir: std::fs::File = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(format!("/proc/{container_pid}/root"))?
    };

    // Stdio pipes.
    let (in_r, in_w) = tokio::net::UnixStream::pair()?;
    let (out_r, out_w) = tokio::net::UnixStream::pair()?;
    let (err_r, err_w) = tokio::net::UnixStream::pair()?;

    let child_in = unsafe { libc::dup(in_r.as_raw_fd()) };
    let child_out = unsafe { libc::dup(out_w.as_raw_fd()) };
    let child_err = unsafe { libc::dup(err_w.as_raw_fd()) };

    // stdin pump (stdin channel → container stdin) unless detached.
    if !session.detach {
        let Some(mut rx) = session.take_stdin_rx() else {
            return Err(anyhow!("exec stdin already consumed"));
        };
        let writer_in = in_w;
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut writer_in = writer_in;
            while let Some(data) = rx.recv().await {
                if writer_in.write_all(&data).await.is_err() {
                    break;
                }
            }
            let _ = writer_in.shutdown().await;
        });
        // Output pumps (hub ← container stdout/stderr).
        let hub = session.stdio.clone();
        tokio::spawn(pump_pipe(out_r, STREAM_STDOUT, (*hub).clone()));
        let hub2 = session.stdio.clone();
        tokio::spawn(pump_pipe(err_r, STREAM_STDERR, (*hub2).clone()));
    } else {
        std::mem::forget((out_r, err_r));
        std::mem::forget(in_w);
    }

    // Pointer arrays must be built inside the spawned closure (raw pointers
    // are not Send); the CStrings themselves are.

    // The fork dance happens on a blocking thread.
    let ids = NsFds {
        pid: pid_fd,
        mnt: mnt_fd,
        net: net_fd,
        ipc: ipc_fd,
        uts: uts_fd,
        root: root_dir,
    };
    let in_fd = child_in;
    let out_fd = child_out;
    let err_fd = child_err;
    let wd = workdir;
    let cap_add = exec_cap_add;
    let cap_drop = exec_cap_drop;
    let privileged = exec_privileged;
    let seccomp = exec_seccomp;
    let ulimits_for_exec = exec_ulimits;
    let argv_for_exec = argv;
    let envp_for_exec = envp;

    {
        let mut st = session.state.lock().unwrap();
        st.running = true;
    }

    let join = tokio::task::spawn_blocking(move || unsafe {
        let argv = argv_for_exec;
        let envp = envp_for_exec;
        let argv_ptrs: Vec<*const libc::c_char> = argv
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp_ptrs: Vec<*const libc::c_char> = envp
            .iter()
            .map(|e| e.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let prog = argv[0].as_ptr();
        // fork1: enters pidns via setns, then forks the real child.
        let report = |msg: &[u8]| {
            libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
        };
        let pid1 = libc::fork();
        if pid1 == 0 {
            // child1
            if libc::setns(ids.pid.as_raw_fd(), libc::CLONE_NEWPID) != 0 {
                let e = std::io::Error::last_os_error();
                let msg = format!("exec: setns pid failed: {e}\n").into_bytes();
                report(&msg);
                libc::_exit(126);
            }
            let pid2 = libc::fork();
            if pid2 == 0 {
                // child2: actual exec
                if cg_fd >= 0 {
                    libc::write(cg_fd, b"0\n".as_ptr() as *const libc::c_void, 2);
                    libc::close(cg_fd);
                }
                let nsjoin = |fd: i32, nstype: i32, what: &str| {
                    if libc::setns(fd, nstype) != 0 {
                        let e = std::io::Error::last_os_error();
                        let msg = format!("exec: setns {what} failed: {e}\n").into_bytes();
                        report(&msg);
                        libc::_exit(126);
                    }
                };
                nsjoin(ids.net.as_raw_fd(), libc::CLONE_NEWNET, "net");
                nsjoin(ids.ipc.as_raw_fd(), libc::CLONE_NEWIPC, "ipc");
                nsjoin(ids.uts.as_raw_fd(), libc::CLONE_NEWUTS, "uts");
                nsjoin(ids.mnt.as_raw_fd(), libc::CLONE_NEWNS, "mnt");
                // Enter the container's root through the pinned fd: path
                // `/` in this namespace can resolve to a stale pre-pivot
                // tree. Runs before caps drop (chroot needs privilege).
                {
                    let rfd = ids.root.as_raw_fd();
                    if libc::fchdir(rfd) != 0 || libc::chroot(c".".as_ptr()) != 0 {
                        let e = std::io::Error::last_os_error();
                        let msg =
                            format!("exec: chroot to container root failed: {e}\n").into_bytes();
                        report(&msg);
                        libc::_exit(126);
                    }
                    libc::close(rfd);
                }
                // Container ulimits, like init's (raising hard limits needs
                // the privilege still held here, before caps drop).
                for (name, soft, hard) in &ulimits_for_exec {
                    if let Err(what) = crate::child::apply_rlimit(name, *soft, *hard) {
                        let msg = format!("exec: ulimit {name} failed: {what}\n").into_bytes();
                        report(&msg);
                        libc::_exit(126);
                    }
                }
                libc::dup2(in_fd, 0);
                libc::dup2(out_fd, 1);
                libc::dup2(err_fd, 2);
                // Close every inherited daemon fd except stdio. Prefer
                // close_range (single syscall) over ~4093 closes.
                let keep = [0, 1, 2, in_fd, out_fd, err_fd];
                close_all_fds(&keep);
                // Drop to the container's capability set while fully
                // privileged: bounding drops need CAP_SETPCAP (unit 3.1).
                let keep = crate::child::compute_keep(&cap_add, &cap_drop, privileged);
                if let Some(k) = keep.as_ref() {
                    if !crate::child::confine_caps(k) {
                        report(b"exec: dropping capabilities failed\n");
                        libc::_exit(126);
                    }
                }
                if uid != u32::MAX {
                    // Keep Permitted across the switch; the uid change
                    // clears Effective, re-asserted below.
                    libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
                    libc::setgroups(0, std::ptr::null());
                    libc::setresgid(gid as libc::gid_t, gid as libc::gid_t, gid as libc::gid_t);
                    libc::setresuid(uid as libc::uid_t, uid as libc::uid_t, uid as libc::uid_t);
                    if let Some(k) = keep.as_ref() {
                        if !crate::child::restore_effective(k) {
                            report(b"exec: restoring capabilities failed\n");
                            libc::_exit(126);
                        }
                    }
                }
                // Mirror container init (child.rs step 9): a non-privileged
                // exec must not regain dropped caps (or anything else) at
                // the execve below. NO_NEW_PRIVS is inherited and one-way.
                if !privileged {
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                        report(b"exec: setting NO_NEW_PRIVS failed\n");
                        libc::_exit(126);
                    }
                    if seccomp {
                        if let Err(e) = crate::seccomp::apply_default_seccomp() {
                            let msg = format!("exec: apply seccomp failed: {e}\n").into_bytes();
                            report(&msg);
                            libc::_exit(126);
                        }
                    }
                }
                if libc::chdir(wd.as_ptr()) != 0 {
                    // workdir may be missing; fall back to /
                    libc::chdir(c"/".as_ptr());
                }
                // PATH resolution for bare names (busybox applets etc.).
                let prog_bytes = argv[0].as_bytes();
                if prog_bytes.contains(&b'/') {
                    libc::execve(prog, argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
                } else {
                    let path_env = envp
                        .iter()
                        .find_map(|e| {
                            let b = e.as_bytes();
                            if b.starts_with(b"PATH=") {
                                Some(b[5..].to_vec())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| {
                            b"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_vec()
                        });
                    for dir in path_env.split(|&b| b == b':') {
                        let mut cand = if dir.is_empty() {
                            b"/".to_vec()
                        } else {
                            dir.to_vec()
                        };
                        if !cand.ends_with(b"/") {
                            cand.push(b'/');
                        }
                        cand.extend_from_slice(prog_bytes);
                        if let Ok(cs) = std::ffi::CString::new(cand) {
                            libc::execve(cs.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
                        }
                    }
                }
                let e = std::io::Error::last_os_error();
                let msg = format!("exec: execve failed: {e}\n").into_bytes();
                report(&msg);
                libc::_exit(if e.raw_os_error() == Some(libc::ENOENT) {
                    127
                } else {
                    126
                });
            } else if pid2 > 0 {
                if cg_fd >= 0 {
                    libc::close(cg_fd);
                }
                // child1: wait for child2, mirror its exit status.
                let mut status = 0;
                libc::waitpid(pid2, &mut status, 0);
                let code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    1
                };
                libc::_exit(code);
            } else {
                if cg_fd >= 0 {
                    libc::close(cg_fd);
                }
                libc::_exit(126);
            }
        }
        if cg_fd >= 0 {
            libc::close(cg_fd);
        }
        if pid1 < 0 {
            return Err(anyhow!("fork failed: {}", std::io::Error::last_os_error()));
        }
        // daemon-side wait on child1
        let mut status = 0;
        let rc = libc::waitpid(pid1, &mut status, 0);
        let code: i64 = if rc == pid1 {
            if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status) as i64
            } else if libc::WIFSIGNALED(status) {
                (128 + libc::WTERMSIG(status)) as i64
            } else {
                1
            }
        } else {
            -1
        };
        let _ = paths; // keep signature symmetric
        Ok(code)
    });

    let session2 = session.clone();
    tokio::spawn(async move {
        let result = join.await;
        let code: i64 = result.unwrap_or(Err(anyhow!("join failed"))).unwrap_or(-1);
        {
            let mut st = session2.state.lock().unwrap();
            st.running = false;
            st.exit_code = code;
        }
        let _ = session2.exit_tx.send(code);
    });

    Ok(())
}

fn parse_user(user: &str, handle: &ContainerHandle) -> (u32, u32) {
    let _ = handle;
    if user.is_empty() {
        return (u32::MAX, u32::MAX);
    }
    let (u, g) = user.split_once(':').unwrap_or((user, ""));
    match (u.parse::<u32>(), g.parse::<u32>()) {
        (Ok(uid), Ok(gid)) => (uid, gid),
        (Ok(uid), Err(_)) if g.is_empty() => (uid, uid),
        _ => (u32::MAX, u32::MAX),
    }
}

/// Owns the namespace fds so they stay open for the life of the fork dance.
struct NsFds {
    pid: std::fs::File,
    mnt: std::fs::File,
    net: std::fs::File,
    ipc: std::fs::File,
    uts: std::fs::File,
    /// Open handle on the container init's root (`/proc/<pid>/root`): the
    /// mount namespace can contain a stale pre-pivot tree at `/`, so exec
    /// chroots through this fd to see the same root as init.
    root: std::fs::File,
}
