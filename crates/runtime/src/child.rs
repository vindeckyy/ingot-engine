//! The child-side container init: runs after clone() inside the new
//! namespaces, sets up the rootfs, then execve's the user command.
//!
//! All allocations happen BEFORE clone (in `ChildContext::prepare`) — after
//! clone the child only makes syscalls, avoiding malloc locks held by other
//! daemon threads in the CoW memory snapshot.

use anyhow::{anyhow, Result};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

/// Docker's default capability set.
pub const DEFAULT_CAPS: &[&str] = &[
    "CHOWN",
    "DAC_OVERRIDE",
    "FSETID",
    "FOWNER",
    "MKNOD",
    "NET_RAW",
    "SETGID",
    "SETUID",
    "SETFCAP",
    "SETPCAP",
    "NET_BIND_SERVICE",
    "SYS_CHROOT",
    "KILL",
    "AUDIT_WRITE",
];

/// All capabilities (used with --privileged).
pub const ALL_CAPS: &[&str] = &[
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID",
    "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW",
    "IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT",
    "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD",
    "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG",
    "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF", "CHECKPOINT_RESTORE",
];

pub fn cap_name_to_bit(name: &str) -> Option<u64> {
    let upper = name.trim().trim_start_matches("CAP_").to_uppercase();
    ALL_CAPS.iter().position(|c| *c == upper).map(|i| 1u64 << i)
}

/// Everything the child needs, laid out before clone().
pub struct ChildContext {
    /// Parent writes 'g' when network setup is done, 'e' on failure.
    pub ready_pipe_rd: i32,
    pub stdin_fd: i32,
    pub stdout_fd: i32,
    pub stderr_fd: i32,
    pub merged: CString,
    pub hostname: CString,
    pub resolv: CString,
    pub hosts: CString,
    pub hostname_file: CString,
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    pub workdir: CString,
    /// "uid" | "uid:gid" | "uid:gid,gid..." — resolution into numbers happens
    /// in the parent (numeric fast path) or child (container /etc/passwd).
    pub user_raw: CString,
    pub uid: u32, // resolved or u32::MAX when unresolved
    pub gid: u32,
    pub extra_gids: Vec<u32>,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub privileged: bool,
    pub no_new_privs: bool,
    pub readonly_rootfs: bool,
    pub bring_lo_up: bool,
    pub has_netns: bool,
    pub tty: bool,
}

impl ChildContext {
    /// Box + leak for passing across clone().
    pub fn into_raw(self) -> *mut ChildContext {
        Box::into_raw(Box::new(self))
    }
    /// Reclaim after a failed clone.
    ///
    /// # Safety
    /// `ptr` must come from `into_raw` and not be used by a child.
    pub unsafe fn from_raw(ptr: *mut ChildContext) -> Box<ChildContext> {
        Box::from_raw(ptr)
    }
}

/// Entry point used by the manager's clone() call.
pub extern "C" fn clone_entry(arg: *mut libc::c_void) -> i32 {
    trampoline(arg)
}

extern "C" fn trampoline(arg: *mut libc::c_void) -> i32 {
    let ctx = unsafe { Box::from_raw(arg as *mut ChildContext) };
    match child_main(&ctx) {
        Ok(()) => unreachable!("child_main returned after execve"),
        Err(code) => code,
    }
}

/// Report a fatal init failure on the container's stderr, then bail.
fn fail(code: i32, msg: &str) -> Result<(), i32> {
    let err = std::io::Error::last_os_error();
    let mut line = format!("ingot-init: {msg}: {err}\n").into_bytes();
    unsafe {
        libc::write(2, line.as_mut_ptr() as *const libc::c_void, line.len());
    }
    line.clear();
    Err(code)
}

/// Run the container init; on error returns the exit code to _exit with.
fn child_main(ctx: &ChildContext) -> Result<(), i32> {
    // 1. Wait for network setup from the parent.
    let mut sig = [0u8; 1];
    if unsafe { libc::read(ctx.ready_pipe_rd, sig.as_mut_ptr() as *mut libc::c_void, 1) } != 1
        || sig[0] != b'g'
    {
        return fail(126, "did not receive network-ready signal");
    }

    // 2. New mount namespace: everything below is private to this container.
    mount_null("/", None, libc::MS_PRIVATE | libc::MS_REC, None).map_err(|e| fail(e, "remount / private").err().unwrap())?;

    let merged = ctx.merged.to_str().unwrap_or("/");

    // 3. Bind /etc files prepared by the daemon.
    bind_file(ctx.resolv.as_bytes(), format!("{merged}/etc/resolv.conf").as_bytes()).map_err(|e| fail(e, "bind resolv.conf").err().unwrap())?;
    bind_file(ctx.hosts.as_bytes(), format!("{merged}/etc/hosts").as_bytes()).map_err(|e| fail(e, "bind hosts").err().unwrap())?;
    bind_file(ctx.hostname_file.as_bytes(), format!("{merged}/etc/hostname").as_bytes()).map_err(|e| fail(e, "bind hostname").err().unwrap())?;

    // 4. /dev
    let dev = format!("{merged}/dev");
    mkdirs(&dev);
    if ctx.privileged {
        bind_dir(b"/dev", dev.as_bytes()).map_err(|e| fail(e, "bind /dev (privileged)").err().unwrap())?;
    } else {
        mount_tmpfs(&dev, "nr_inodes=1024000,mode=755").map_err(|e| fail(e, "tmpfs /dev").err().unwrap())?;
        mkdirs(&format!("{dev}/pts"));
        mkdirs(&format!("{dev}/shm"));
        mount_devpts(&format!("{dev}/pts")).map_err(|e| fail(e, "devpts").err().unwrap())?;
        mount_tmpfs(&format!("{dev}/shm"), "mode=1777,size=65536k").map_err(|e| fail(e, "shm").err().unwrap())?;
        for (name, major, minor, mode) in [
            ("null", 1, 3, 0o666u32),
            ("zero", 1, 5, 0o666),
            ("full", 1, 7, 0o666),
            ("random", 1, 8, 0o666),
            ("urandom", 1, 9, 0o666),
            ("tty", 5, 0, 0o666),
        ] {
            mknod(&format!("{dev}/{name}"), libc::S_IFCHR | mode, major, minor).map_err(|e| fail(e, "mknod {name}").err().unwrap())?;
        }
        // /dev/fd, /dev/stdin, ... → /proc/self/fd
        symlink("/proc/self/fd", &format!("{dev}/fd"));
        symlink("/proc/self/fd/0", &format!("{dev}/stdin"));
        symlink("/proc/self/fd/1", &format!("{dev}/stdout"));
        symlink("/proc/self/fd/2", &format!("{dev}/stderr"));
        symlink("/dev/pts/ptmx", &format!("{dev}/ptmx"));
    }

    // 5. /proc, /sys, cgroup
    mkdirs(&format!("{merged}/proc"));
    mount_fs("proc", &format!("{merged}/proc"), libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV, "").map_err(|e| fail(e, "mount /proc").err().unwrap())?;
    mkdirs(&format!("{merged}/sys"));
    mount_fs("sysfs", &format!("{merged}/sys"), libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV | libc::MS_RDONLY, "").map_err(|e| fail(e, "mount /sys").err().unwrap())?;
    let cg_dir = format!("{merged}/sys/fs/cgroup");
    mkdirs(&cg_dir);
    mount_fs("cgroup2", &cg_dir, libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV | libc::MS_RDONLY, "").map_err(|e| fail(e, "mount cgroup2").err().unwrap())?;

    // 6. Bring loopback up when there is no external net setup (none network).
    if ctx.bring_lo_up {
        lo_up();
    }

    // 7. pivot_root into the overlay merged dir.
    if unsafe { libc::chdir(ctx.merged.as_ptr()) } != 0 {
        return fail(125, "chdir merged rootfs");
    }
    // Make the new root a mount point (bind to itself), then pivot.
    mount_null(".", None, libc::MS_BIND | libc::MS_REC, None).map_err(|e| fail(e, "self-bind rootfs").err().unwrap())?;
    mkdirs("./oldroot");
    if unsafe { libc::syscall(libc::SYS_pivot_root, b".\0".as_ptr(), b"./oldroot\0".as_ptr()) } != 0 {
        return fail(125, "pivot_root");
    }
    if unsafe { libc::chdir(b"/\0".as_ptr() as *const libc::c_char) } != 0 {
        return fail(125, "chdir / after pivot");
    }
    umount_detach("/oldroot");
    let _ = rmdir("/oldroot");

    if ctx.readonly_rootfs {
        mount_null("/", None, libc::MS_RDONLY | libc::MS_REMOUNT | libc::MS_BIND | libc::MS_REC, None)
            .map_err(|e| fail(e, "readonly remount").err().unwrap())?;
    }

    // 8. Hostname (UTS namespace was created at clone).
    unsafe {
        libc::sethostname(ctx.hostname.as_ptr(), ctx.hostname.to_bytes().len());
    }

    // 9. Identity + capabilities.
    let (uid, gid, extra) = resolve_user(ctx);
    apply_caps(ctx)?;

    if uid != u32::MAX {
        // Keep capabilities across the uid switch.
        unsafe {
            libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0);
            let mut groups: Vec<libc::gid_t> = extra.iter().map(|&g| g as libc::gid_t).collect();
            libc::setgroups(groups.len(), groups.as_mut_ptr());
            libc::setresgid(gid as libc::gid_t, gid as libc::gid_t, gid as libc::gid_t);
            libc::setresuid(uid as libc::uid_t, uid as libc::uid_t, uid as libc::uid_t);
        }
        apply_caps(ctx)?; // re-assert after switching (KEEPcaps preserves permitted)
    }

    if ctx.no_new_privs {
        unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        }
    }

    // 10. Working directory.
    if unsafe { libc::chdir(ctx.workdir.as_ptr()) } != 0 {
        return fail(127, "chdir workdir");
    }

    // 11. stdio.
    unsafe {
        libc::dup2(ctx.stdin_fd, 0);
        libc::dup2(ctx.stdout_fd, 1);
        if !ctx.tty {
            libc::dup2(ctx.stderr_fd, 2);
        }
    }

    // 12. Exec — with PATH resolution like runc/libcontainer: a bare name
    // (busybox applets!) is searched in the container's PATH.
    let argv: Vec<*const libc::c_char> = ctx
        .argv
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp: Vec<*const libc::c_char> = ctx
        .envp
        .iter()
        .map(|e| e.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let prog = ctx.argv[0].as_bytes();
    if prog.contains(&b'/') {
        unsafe {
            libc::execve(ctx.argv[0].as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        let err = std::io::Error::last_os_error();
        let msg = format!("execve {:?} failed: {err}", ctx.argv[0]);
        return fail(if err.raw_os_error() == Some(libc::ENOENT) { 127 } else { 126 }, &msg);
    }
    let path_env = ctx
        .envp
        .iter()
        .find_map(|e| {
            let b = e.to_bytes();
            b.strip_prefix(b"PATH=").map(|p| p.to_vec())
        })
        .unwrap_or_else(|| b"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_vec());
    let mut last_err = 0u32;
    for dir in path_env.split(|&b| b == b':') {
        let candidate = if dir.is_empty() {
            let mut c = b"/".to_vec();
            c.extend_from_slice(prog);
            c
        } else {
            let mut c = dir.to_vec();
            if !c.ends_with(b"/") {
                c.push(b'/');
            }
            c.extend_from_slice(prog);
            c
        };
        if let Ok(cs) = CString::new(candidate) {
            unsafe {
                libc::execve(cs.as_ptr(), argv.as_ptr(), envp.as_ptr());
            }
            last_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        }
    }
    let msg = format!(
        "exec: {:?} not found in PATH (last error {last_err})",
        ctx.argv[0]
    );
    fail(127, &msg)
}

fn resolve_user(ctx: &ChildContext) -> (u32, u32, Vec<u32>) {
    if ctx.uid != u32::MAX {
        return (ctx.uid, ctx.gid, ctx.extra_gids.clone());
    }
    // Resolve names against the container's own /etc/passwd, /etc/group.
    let raw = ctx.user_raw.to_string_lossy();
    if raw.is_empty() {
        return (0, 0, vec![]);
    }
    let (user_part, group_part) = raw.split_once(':').unwrap_or((&raw, ""));
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let mut uid = 0u32;
    let mut primary_gid = 0u32;
    let mut found = user_part.is_empty() || user_part == "root";
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[0] == user_part {
            uid = fields[2].parse().unwrap_or(0);
            primary_gid = fields[3].parse().unwrap_or(0);
            found = true;
            break;
        }
    }
    if !found && user_part.parse::<u32>().is_ok() {
        uid = user_part.parse().unwrap();
        found = true;
    }
    let mut gid = primary_gid;
    let mut extra = Vec::new();
    if !group_part.is_empty() {
        let group_db = std::fs::read_to_string("/etc/group").unwrap_or_default();
        let mut resolved = false;
        for line in group_db.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 && fields[0] == group_part {
                gid = fields[2].parse().unwrap_or(primary_gid);
                resolved = true;
                break;
            }
        }
        if !resolved {
            if let Ok(g) = group_part.parse::<u32>() {
                gid = g;
            }
        }
        for g in group_part.split(',').skip(1) {
            if let Ok(x) = g.parse::<u32>() {
                extra.push(x);
            }
        }
        let _ = extra.pop(); // the first entry is the primary gid
    }
    if !found {
        return (u32::MAX, u32::MAX, vec![]);
    }
    (uid, gid, extra)
}

fn apply_caps(ctx: &ChildContext) -> Result<(), i32> {
    use std::str::FromStr;
    if ctx.privileged {
        return Ok(()); // keep everything the daemon has
    }
    let mut keep: std::collections::HashSet<caps::Capability> = Default::default();
    for name in DEFAULT_CAPS {
        if let Ok(c) = caps::Capability::from_str(&format!("CAP_{name}")) {
            keep.insert(c);
        }
    }
    for name in &ctx.cap_add {
        let full = if name.starts_with("CAP_") {
            name.to_uppercase()
        } else {
            format!("CAP_{}", name.to_uppercase())
        };
        if let Ok(c) = caps::Capability::from_str(&full) {
            keep.insert(c);
        }
    }
    for name in &ctx.cap_drop {
        let full = if name.starts_with("CAP_") { name.clone() } else { format!("CAP_{}", name.to_uppercase()) };
        if let Ok(c) = caps::Capability::from_str(&full) {
            keep.remove(&c);
        }
    }
    for cset in [caps::CapSet::Effective, caps::CapSet::Permitted, caps::CapSet::Inheritable] {
        if caps::set(None, cset, &keep).is_err() {
            return Err(125);
        }
    }
    // Bounding set: drop everything not kept (one-way).
    for c in caps::all().difference(&keep) {
        let _ = caps::drop(None, caps::CapSet::Bounding, *c);
    }
    Ok(())
}

// ---- thin syscall wrappers returning Result<(), i32> ----

fn mount_null(source: &str, fstype: Option<&str>, flags: u64, data: Option<&str>) -> Result<(), i32> {
    let src = CString::new(source).unwrap();
    let fs = fstype.map(|f| CString::new(f).unwrap());
    let data_c = data.map(|d| CString::new(d).unwrap());
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            src.as_ptr(), // target = source for our uses ("/", ".")
            fs.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()),
            flags,
            data_c.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()) as *const libc::c_void,
        )
    };
    (rc == 0).then_some(()).ok_or(125)
}

fn mount_fs(fstype: &str, target: &str, flags: u64, data: &str) -> Result<(), i32> {
    let fs = CString::new(fstype).unwrap();
    let tgt = CString::new(target.as_bytes()).unwrap();
    let d = CString::new(data).unwrap();
    let null = CString::new("").unwrap();
    let rc = unsafe {
        libc::mount(
            null.as_ptr(),
            tgt.as_ptr(),
            fs.as_ptr(),
            flags,
            d.as_ptr() as *const libc::c_void,
        )
    };
    (rc == 0).then_some(()).ok_or(125)
}

fn mount_tmpfs(target: &str, data: &str) -> Result<(), i32> {
    // NOTE: no MS_NODEV here — /dev holds device nodes that must open.
    mount_fs("tmpfs", target, libc::MS_NOSUID, data)
}

fn mount_devpts(target: &str) -> Result<(), i32> {
    mount_fs(
        "devpts",
        target,
        libc::MS_NOSUID | libc::MS_NOEXEC,
        "newinstance,ptmxmode=0666,mode=620",
    )
}

fn bind_file(src: &[u8], target: &[u8]) -> Result<(), i32> {
    // Create an empty target if missing (mount(2) requires it).
    let t = std::path::Path::new(std::ffi::OsStr::from_bytes(target));
    if !t.exists() {
        let _ = std::fs::File::create(t);
    }
    let s = CString::new(src.to_vec()).unwrap();
    let d = CString::new(target.to_vec()).unwrap();
    let rc = unsafe {
        libc::mount(
            s.as_ptr(),
            d.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    (rc == 0).then_some(()).ok_or(125)
}

fn bind_dir(src: &[u8], target: &[u8]) -> Result<(), i32> {
    let s = CString::new(src.to_vec()).unwrap();
    let d = CString::new(target.to_vec()).unwrap();
    let rc = unsafe {
        libc::mount(
            s.as_ptr(),
            d.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    (rc == 0).then_some(()).ok_or(125)
}

fn mkdirs(path: &str) {
    let _ = std::fs::create_dir_all(path);
}

fn mknod(path: &str, mode: u32, major: u32, minor: u32) -> Result<(), i32> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::path::Path::new(path);
    if p.exists() {
        let _ = std::fs::remove_file(p);
    }
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::mknod(c.as_ptr(), mode, libc::makedev(major, minor)) };
    (rc == 0).then_some(()).ok_or(125)
}

fn symlink(target: &str, path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::os::unix::fs::symlink(target, path);
}

fn umount_detach(path: &str) {
    let c = CString::new(path).unwrap();
    unsafe {
        libc::umount2(c.as_ptr(), libc::MNT_DETACH);
    }
}

fn rmdir(path: &str) -> Result<(), i32> {
    let c = CString::new(path).unwrap();
    let rc = unsafe { libc::rmdir(c.as_ptr()) };
    (rc == 0).then_some(()).ok_or(125)
}

/// Bring loopback up inside a fresh netns (used when there is no veth setup).
fn lo_up() {
    // ioctl SIOCSIFFLAGS on a raw socket — minimal netlink-free path.
    use std::os::unix::io::AsRawFd;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return;
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = b"lo\0";
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), ifr.ifr_name.as_mut_ptr() as *mut u8, name.len());
        let sock = fd;
        // Read current flags
        if libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr) == 0 {
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
            libc::ioctl(sock, libc::SIOCSIFFLAGS, &mut ifr);
        }
        libc::close(sock);
    }
    let _ = fd;
}

