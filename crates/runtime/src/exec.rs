//! `exec`: run a command inside a running container's namespaces.
//!
//! Joining a PID namespace requires forking after setns (the caller stays in
//! its old pidns until it forks), hence the fork1 → setns(pid) → fork2 dance,
//! mirroring runc.

use crate::manager::ContainerHandle;
use crate::stdio::{pump_pipe, StdioHub, STREAM_STDERR, STREAM_STDOUT};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

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
    let container_pid = {
        let st = handle.state.lock().unwrap();
        if st.status != crate::record::StateStatus::Running {
            return Err(anyhow!("container is not running"));
        }
        st.pid
    };

    // Open the container's namespace fds while it is alive.
    let ns = |name: &str| -> Result<std::fs::File> {
        Ok(std::fs::File::open(format!("/proc/{container_pid}/ns/{name}"))?)
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
    let ids = NsFds { pid: pid_fd, mnt: mnt_fd, net: net_fd, ipc: ipc_fd, uts: uts_fd };
    let in_fd = child_in;
    let out_fd = child_out;
    let err_fd = child_err;
    let wd = workdir;
    let uid = uid;
    let gid = gid;
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
            unsafe {
                libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len());
            }
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
                libc::dup2(in_fd, 0);
                libc::dup2(out_fd, 1);
                libc::dup2(err_fd, 2);
                // Close every inherited daemon fd except stdio.
                let keep = [0, 1, 2, in_fd, out_fd, err_fd];
                for fd in 3..=4096i32 {
                    if !keep.contains(&fd) {
                        libc::close(fd);
                    }
                }
                if uid != u32::MAX {
                    libc::setgroups(0, std::ptr::null());
                    libc::setresgid(gid as libc::gid_t, gid as libc::gid_t, gid as libc::gid_t);
                    libc::setresuid(uid as libc::uid_t, uid as libc::uid_t, uid as libc::uid_t);
                }
                if libc::chdir(wd.as_ptr()) != 0 {
                    // workdir may be missing; fall back to /
                    libc::chdir(b"/\0".as_ptr() as *const libc::c_char);
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
                        .unwrap_or_else(|| b"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_vec());
                    for dir in path_env.split(|&b| b == b':') {
                        let mut cand = if dir.is_empty() { b"/".to_vec() } else { dir.to_vec() };
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
                libc::_exit(if e.raw_os_error() == Some(libc::ENOENT) { 127 } else { 126 });
            } else if pid2 > 0 {
                // child1: wait for child2, mirror its exit status.
                let mut status = 0;
                libc::waitpid(pid2, &mut status, 0);
                let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 1 };
                libc::_exit(code);
            } else {
                libc::_exit(126);
            }
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
/// Real os pipe (O_CLOEXEC): (read_fd, write_fd).
fn os_pipe_pair() -> Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(anyhow!("pipe2: {}", std::io::Error::last_os_error()));
    }
    Ok((fds[0], fds[1]))
}

struct NsFds {
    pid: std::fs::File,
    mnt: std::fs::File,
    net: std::fs::File,
    ipc: std::fs::File,
    uts: std::fs::File,
}
