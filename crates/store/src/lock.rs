//! Exclusive filesystem lock for daemon state roots.

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// Held exclusive lock for the lifetime of a daemon.
#[derive(Debug)]
pub struct DaemonLock {
    _data_lock: File,
    _run_lock: File,
    pub data_lock_path: PathBuf,
    pub run_lock_path: PathBuf,
}

impl DaemonLock {
    /// Acquire an exclusive lock on both data_root and run_root.
    /// Fails immediately with an actionable error if another process holds either lock.
    pub fn acquire(data_root: &Path, run_root: &Path) -> Result<Self> {
        let data_lock_path = data_root.join("ingotd.lock");
        let run_lock_path = run_root.join("ingotd.lock");

        let data_lock = try_flock(&data_lock_path, "data root")?;
        let run_lock = try_flock(&run_lock_path, "run root")?;

        Ok(Self {
            _data_lock: data_lock,
            _run_lock: run_lock,
            data_lock_path,
            run_lock_path,
        })
    }
}

fn try_flock(path: &Path, label: &str) -> Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {} directory {}", label, parent.display()))?;
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open {} lock file {}", label, path.display()))?;

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN)
        {
            bail!(
                "another ingotd daemon is already running (exclusive lock held on {} at {})",
                label,
                path.display()
            );
        }
        return Err(err).with_context(|| format!("acquire exclusive lock on {}", path.display()));
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_daemon_lock_mutual_exclusion() {
        let data_dir = TempDir::new().unwrap();
        let run_dir = TempDir::new().unwrap();

        // First lock acquires successfully
        let lock1 = DaemonLock::acquire(data_dir.path(), run_dir.path()).unwrap();

        // Second lock on same roots fails
        let err = DaemonLock::acquire(data_dir.path(), run_dir.path()).unwrap_err();
        assert!(err.to_string().contains("already running"), "err: {err}");

        // Drop first lock
        drop(lock1);

        // Now second lock can acquire
        let lock2 = DaemonLock::acquire(data_dir.path(), run_dir.path()).unwrap();
        drop(lock2);
    }
}
