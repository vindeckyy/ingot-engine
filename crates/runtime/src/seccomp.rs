//! Default seccomp allowlist and BPF compilation for Ingot containers.
//!
//! Restricts syscalls for untrusted container workloads. The default policy
//! returns `EPERM` for any unallowed system call, matching Docker default
//! behavior while preserving container diagnosability.
//!
//! Dangerous syscalls (reboot, kexec_load, module loading, swapon, iopl, etc.)
//! are blocked and return `EPERM`.

use anyhow::Result;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
use std::collections::BTreeMap;
use std::sync::OnceLock;

static DEFAULT_FILTER: OnceLock<BpfProgram> = OnceLock::new();

/// Reviewable list of allowed syscalls on x86_64.
/// Any syscall not in this list returns EPERM.
pub const ALLOWED_SYSCALLS_X86_64: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_open,
    libc::SYS_close,
    libc::SYS_stat,
    libc::SYS_fstat,
    libc::SYS_lstat,
    libc::SYS_poll,
    libc::SYS_lseek,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_brk,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_ioctl,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_access,
    libc::SYS_pipe,
    libc::SYS_select,
    libc::SYS_sched_yield,
    libc::SYS_mremap,
    libc::SYS_msync,
    libc::SYS_mincore,
    libc::SYS_madvise,
    libc::SYS_shmget,
    libc::SYS_shmat,
    libc::SYS_shmctl,
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_pause,
    libc::SYS_nanosleep,
    libc::SYS_getitimer,
    libc::SYS_alarm,
    libc::SYS_setitimer,
    libc::SYS_getpid,
    libc::SYS_sendfile,
    libc::SYS_socket,
    libc::SYS_connect,
    libc::SYS_accept,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_shutdown,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_socketpair,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    libc::SYS_clone,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_execve,
    libc::SYS_exit,
    libc::SYS_wait4,
    libc::SYS_kill,
    libc::SYS_uname,
    libc::SYS_semget,
    libc::SYS_semop,
    libc::SYS_semctl,
    libc::SYS_shmdt,
    libc::SYS_msgget,
    libc::SYS_msgsnd,
    libc::SYS_msgrcv,
    libc::SYS_msgctl,
    libc::SYS_fcntl,
    libc::SYS_flock,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_truncate,
    libc::SYS_ftruncate,
    libc::SYS_getdents,
    libc::SYS_getcwd,
    libc::SYS_chdir,
    libc::SYS_fchdir,
    libc::SYS_rename,
    libc::SYS_mkdir,
    libc::SYS_rmdir,
    libc::SYS_creat,
    libc::SYS_link,
    libc::SYS_unlink,
    libc::SYS_symlink,
    libc::SYS_readlink,
    libc::SYS_chmod,
    libc::SYS_fchmod,
    libc::SYS_chown,
    libc::SYS_fchown,
    libc::SYS_lchown,
    libc::SYS_umask,
    libc::SYS_gettimeofday,
    libc::SYS_getrlimit,
    libc::SYS_getrusage,
    libc::SYS_sysinfo,
    libc::SYS_times,
    libc::SYS_getuid,
    libc::SYS_syslog,
    libc::SYS_getgid,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_geteuid,
    libc::SYS_getegid,
    libc::SYS_setpgid,
    libc::SYS_getpgrp,
    libc::SYS_setsid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_getgroups,
    libc::SYS_setgroups,
    libc::SYS_setresuid,
    libc::SYS_getresuid,
    libc::SYS_setresgid,
    libc::SYS_getresgid,
    libc::SYS_getpgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_getsid,
    libc::SYS_capget,
    libc::SYS_capset,
    libc::SYS_rt_sigpending,
    libc::SYS_rt_sigtimedwait,
    libc::SYS_rt_sigqueueinfo,
    libc::SYS_rt_sigsuspend,
    libc::SYS_sigaltstack,
    libc::SYS_utime,
    // mknod/mknodat intentionally ABSENT: with no device-cgroup backstop,
    // device-node creation would allow host block-device access. Opt out
    // with seccomp=unconfined (plus --cap-add MKNOD).
    libc::SYS_personality,
    libc::SYS_ustat,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_getpriority,
    libc::SYS_setpriority,
    libc::SYS_sched_setparam,
    libc::SYS_sched_getparam,
    libc::SYS_sched_setscheduler,
    libc::SYS_sched_getscheduler,
    libc::SYS_sched_get_priority_max,
    libc::SYS_sched_get_priority_min,
    libc::SYS_sched_rr_get_interval,
    libc::SYS_mlock,
    libc::SYS_munlock,
    libc::SYS_mlockall,
    libc::SYS_munlockall,
    libc::SYS_vhangup,
    libc::SYS_prctl,
    libc::SYS_arch_prctl,
    libc::SYS_adjtimex,
    libc::SYS_setrlimit,
    libc::SYS_chroot,
    libc::SYS_sync,
    libc::SYS_gettid,
    libc::SYS_readahead,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_getxattr,
    libc::SYS_lgetxattr,
    libc::SYS_fgetxattr,
    libc::SYS_listxattr,
    libc::SYS_llistxattr,
    libc::SYS_flistxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_fremovexattr,
    libc::SYS_tkill,
    libc::SYS_time,
    libc::SYS_futex,
    libc::SYS_sched_setaffinity,
    libc::SYS_sched_getaffinity,
    libc::SYS_io_setup,
    libc::SYS_io_destroy,
    libc::SYS_io_getevents,
    libc::SYS_io_submit,
    libc::SYS_io_cancel,
    libc::SYS_epoll_create,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait,
    libc::SYS_remap_file_pages,
    libc::SYS_getdents64,
    libc::SYS_set_tid_address,
    libc::SYS_restart_syscall,
    libc::SYS_semtimedop,
    libc::SYS_fadvise64,
    libc::SYS_timer_create,
    libc::SYS_timer_settime,
    libc::SYS_timer_gettime,
    libc::SYS_timer_getoverrun,
    libc::SYS_timer_delete,
    libc::SYS_clock_settime,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_exit_group,
    libc::SYS_epoll_wait,
    libc::SYS_tgkill,
    libc::SYS_utimes,
    libc::SYS_mbind,
    libc::SYS_set_mempolicy,
    libc::SYS_get_mempolicy,
    libc::SYS_mq_open,
    libc::SYS_mq_unlink,
    libc::SYS_mq_timedsend,
    libc::SYS_mq_timedreceive,
    libc::SYS_mq_notify,
    libc::SYS_mq_getsetattr,
    libc::SYS_waitid,
    libc::SYS_ioprio_set,
    libc::SYS_ioprio_get,
    libc::SYS_inotify_init,
    libc::SYS_inotify_add_watch,
    libc::SYS_inotify_rm_watch,
    libc::SYS_openat,
    libc::SYS_mkdirat,
    // mknodat: see mknod above.
    libc::SYS_fchownat,
    libc::SYS_futimesat,
    libc::SYS_newfstatat,
    libc::SYS_unlinkat,
    libc::SYS_renameat,
    libc::SYS_linkat,
    libc::SYS_symlinkat,
    libc::SYS_readlinkat,
    libc::SYS_fchmodat,
    libc::SYS_faccessat,
    libc::SYS_pselect6,
    libc::SYS_ppoll,
    libc::SYS_unshare,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    libc::SYS_splice,
    libc::SYS_tee,
    libc::SYS_sync_file_range,
    libc::SYS_vmsplice,
    libc::SYS_utimensat,
    libc::SYS_epoll_pwait,
    libc::SYS_signalfd,
    libc::SYS_timerfd_create,
    libc::SYS_eventfd,
    libc::SYS_fallocate,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    libc::SYS_accept4,
    libc::SYS_signalfd4,
    libc::SYS_eventfd2,
    libc::SYS_epoll_create1,
    libc::SYS_dup3,
    libc::SYS_pipe2,
    libc::SYS_inotify_init1,
    libc::SYS_preadv,
    libc::SYS_pwritev,
    libc::SYS_rt_tgsigqueueinfo,
    libc::SYS_perf_event_open,
    libc::SYS_recvmmsg,
    libc::SYS_prlimit64,
    // name_to_handle_at/open_by_handle_at intentionally ABSENT: handle-based
    // opens are classic chroot/pivot escape primitives with no legitimate
    // in-container use.
    libc::SYS_clock_adjtime,
    libc::SYS_syncfs,
    libc::SYS_sendmmsg,
    libc::SYS_setns,
    libc::SYS_getcpu,
    // process_vm_readv/writev intentionally ABSENT: cross-process memory
    // access has no legitimate in-container use (container and daemon share
    // uid 0, so same-user ptrace checks would not stop a hostile reader
    // when the host Yama scope is relaxed).
    libc::SYS_sched_setattr,
    libc::SYS_sched_getattr,
    libc::SYS_renameat2,
    libc::SYS_seccomp,
    libc::SYS_getrandom,
    libc::SYS_memfd_create,
    libc::SYS_execveat,
    libc::SYS_userfaultfd,
    libc::SYS_membarrier,
    libc::SYS_mlock2,
    libc::SYS_copy_file_range,
    libc::SYS_preadv2,
    libc::SYS_pwritev2,
    libc::SYS_statx,
    libc::SYS_pidfd_send_signal,
    libc::SYS_pidfd_open,
    libc::SYS_clone3,
    libc::SYS_close_range,
    libc::SYS_openat2,
    libc::SYS_faccessat2,
];

/// Build and compile the default seccomp BPF program.
pub fn compile_default_seccomp_filter() -> Result<BpfProgram> {
    let mut rules = BTreeMap::new();
    for &sys in ALLOWED_SYSCALLS_X86_64 {
        rules.insert(sys, vec![]);
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH
            .try_into()
            .map_err(|e| anyhow::anyhow!("unsupported seccomp arch: {e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("create seccomp filter: {e}"))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| anyhow::anyhow!("compile seccomp filter: {e}"))?;

    Ok(prog)
}

/// Retrieve the cached compiled default seccomp program.
pub fn get_default_bpf_program() -> Result<&'static BpfProgram> {
    if let Some(prog) = DEFAULT_FILTER.get() {
        return Ok(prog);
    }
    let prog = compile_default_seccomp_filter()?;
    let _ = DEFAULT_FILTER.set(prog);
    Ok(DEFAULT_FILTER.get().unwrap())
}

/// Apply the default seccomp filter to the calling process.
/// Must be called after `PR_SET_NO_NEW_PRIVS`.
pub fn apply_default_seccomp() -> Result<()> {
    let prog = get_default_bpf_program()?;
    seccompiler::apply_filter(prog).map_err(|e| anyhow::anyhow!("apply seccomp filter: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_default_seccomp_filter() {
        let prog = compile_default_seccomp_filter().unwrap();
        assert!(!prog.is_empty());
    }

    /// Escape-relevant syscalls must stay denied (security sweep: every
    /// entry here is a container-escape primitive or a device-node path
    /// with no device-cgroup backstop).
    #[test]
    fn test_escape_primitives_denied() {
        for sys in [
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_mknod,
            libc::SYS_mknodat,
            libc::SYS_open_by_handle_at,
            libc::SYS_name_to_handle_at,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_kexec_load,
            libc::SYS_kexec_file_load,
            libc::SYS_reboot,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_iopl,
            libc::SYS_ioperm,
            libc::SYS_sethostname,
            libc::SYS_setdomainname,
            libc::SYS_acct,
            libc::SYS_quotactl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_keyctl,
            libc::SYS_ptrace,
            libc::SYS_kcmp,
            libc::SYS_pidfd_getfd,
            libc::SYS_fanotify_init,
            libc::SYS_lookup_dcookie,
            libc::SYS_move_pages,
            // New mount API must stay denied alongside mount(2).
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
        ] {
            assert!(
                !ALLOWED_SYSCALLS_X86_64.contains(&sys),
                "syscall {sys} must stay seccomp-denied"
            );
        }
        // io_uring is a standing kernel-exploit surface: all three doors
        // stay shut.
        for sys in [
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert!(
                !ALLOWED_SYSCALLS_X86_64.contains(&sys),
                "syscall {sys} must stay seccomp-denied"
            );
        }
    }

    #[test]
    fn test_seccomp_blocks_unauthorized_syscall() {
        // Fork a child process to test seccomp jailing so parent is unaffected
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);

        if pid == 0 {
            // In child: set NO_NEW_PRIVS and apply default seccomp
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            }
            apply_default_seccomp().expect("apply seccomp in test child");

            // Allowed syscall (getpid) succeeds
            let p = unsafe { libc::getpid() };
            assert!(p > 0);

            // Blocked syscall: reboot(0) should return EPERM
            let rc = unsafe { libc::reboot(0) };
            let err = std::io::Error::last_os_error();
            if rc != -1 || err.raw_os_error() != Some(libc::EPERM) {
                unsafe { libc::_exit(1) };
            }

            unsafe { libc::_exit(0) };
        } else {
            // In parent: wait for child
            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(waited, pid);
            assert!(libc::WIFEXITED(status), "child did not exit cleanly");
            assert_eq!(libc::WEXITSTATUS(status), 0, "child exited with error");
        }
    }
}
