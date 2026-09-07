//! Privileged path confinement and rootfs-relative resolution.
//!
//! Provides strict resource name validation and rootfs-relative path resolution
//! using Linux `openat2` (RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS) with an
//! `openat(O_NOFOLLOW)` component-walk fallback for older kernels.

use anyhow::{anyhow, Context, Result};
use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[allow(dead_code)]
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
#[allow(dead_code)]
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
#[allow(dead_code)]
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
#[allow(dead_code)]
const RESOLVE_CACHED: u64 = 0x20;

static OPENAT2_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
enum OwnedComponent {
    Root,
    CurDir,
    ParentDir,
    Normal(String),
}

impl OwnedComponent {
    fn from_path(path: &Path) -> Vec<Self> {
        path.components()
            .map(|c| match c {
                Component::RootDir | Component::Prefix(_) => OwnedComponent::Root,
                Component::CurDir => OwnedComponent::CurDir,
                Component::ParentDir => OwnedComponent::ParentDir,
                Component::Normal(s) => OwnedComponent::Normal(s.to_string_lossy().to_string()),
            })
            .collect()
    }
}

/// Validate resource names (volumes, networks, container base names).
/// Must match `[a-zA-Z0-9][a-zA-Z0-9_.-]*` (no path separators, no '.', '..', no control chars).
pub fn validate_resource_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("resource name cannot be empty");
    }
    if name == "." || name == ".." {
        anyhow::bail!("resource name cannot be '.' or '..'");
    }
    if name.contains('/') || name.contains('\\') {
        anyhow::bail!("resource name cannot contain path separators: {name:?}");
    }
    if name.chars().any(|c| c.is_control()) {
        anyhow::bail!("resource name cannot contain control characters: {name:?}");
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        anyhow::bail!("resource name must start with an alphanumeric character: {name:?}");
    }
    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '-' {
            anyhow::bail!("resource name contains invalid character {c:?}: {name:?}");
        }
    }
    Ok(())
}

/// Validate a container name, which allows an optional single leading `/`.
pub fn validate_container_name(name: &str) -> Result<&str> {
    let bare = name.strip_prefix('/').unwrap_or(name);
    validate_resource_name(bare)?;
    Ok(bare)
}

/// A securely resolved path inside a root directory, backed by an OwnedFd.
#[derive(Debug)]
pub struct ResolvedPath {
    fd: OwnedFd,
    proc_path: PathBuf,
}

impl ResolvedPath {
    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        let raw = fd.as_raw_fd();
        let proc_path = PathBuf::from(format!("/proc/self/fd/{raw}"));
        Self { fd, proc_path }
    }

    pub fn proc_path(&self) -> &Path {
        &self.proc_path
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }

    pub fn stat(&self) -> std::io::Result<libc::stat> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(self.fd.as_raw_fd(), &mut st) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(st)
    }

    pub fn is_dir(&self) -> bool {
        self.stat()
            .map(|st| (st.st_mode & libc::S_IFMT) == libc::S_IFDIR)
            .unwrap_or(false)
    }

    pub fn is_file(&self) -> bool {
        self.stat()
            .map(|st| (st.st_mode & libc::S_IFMT) == libc::S_IFREG)
            .unwrap_or(false)
    }

    pub fn is_symlink(&self) -> bool {
        self.stat()
            .map(|st| (st.st_mode & libc::S_IFMT) == libc::S_IFLNK)
            .unwrap_or(false)
    }

    pub fn open_file(&self, flags: i32) -> std::io::Result<std::fs::File> {
        let path_c = CString::new(self.proc_path.as_os_str().as_bytes())?;
        let raw = unsafe { libc::open(path_c.as_ptr(), flags | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(raw) })
    }
}

/// Open a root directory descriptor.
fn open_dir_fd(path: &Path) -> Result<OwnedFd> {
    let cpath =
        CString::new(path.as_os_str().as_bytes()).map_err(|e| anyhow!("invalid path: {e}"))?;
    let raw = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open root directory {}", path.display()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Probe or execute openat2 with RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS.
fn try_openat2(root_fd: RawFd, rel_path: &Path, flags: i32, mode: u32) -> Result<Option<OwnedFd>> {
    if OPENAT2_UNSUPPORTED.load(Ordering::Relaxed) {
        return Ok(None);
    }

    let mut path_bytes = rel_path.as_os_str().as_bytes().to_vec();
    if path_bytes.is_empty() {
        path_bytes.push(b'.');
    }
    let cpath = match CString::new(path_bytes) {
        Ok(c) => c,
        Err(_) => return Err(anyhow!("path contains null byte")),
    };

    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd,
            cpath.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };

    if ret >= 0 {
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(ret as RawFd) }));
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOSYS) {
        OPENAT2_UNSUPPORTED.store(true, Ordering::Relaxed);
        return Ok(None);
    }

    Err(err.into())
}

/// Linux 5.4 floor fallback: component-walk with openat(O_NOFOLLOW).
/// Ensures no symlink or '..' escapes root_fd.
fn openat_walk(root_fd: RawFd, rel_path: &Path, flags: i32, mode: u32) -> Result<OwnedFd> {
    let dev_ino = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(root_fd, &mut st) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        (st.st_dev, st.st_ino)
    };

    let root_dup = unsafe { libc::fcntl(root_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if root_dup < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut current_fd = unsafe { OwnedFd::from_raw_fd(root_dup) };

    let mut components = OwnedComponent::from_path(rel_path);
    let mut symlink_hops = 0;

    let mut i = 0;
    while i < components.len() {
        let comp = components[i].clone();
        i += 1;

        match comp {
            OwnedComponent::Root => {
                // In rootfs, leading slash resets to root
                let dup = unsafe { libc::fcntl(root_fd, libc::F_DUPFD_CLOEXEC, 0) };
                if dup < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                current_fd = unsafe { OwnedFd::from_raw_fd(dup) };
            }
            OwnedComponent::CurDir => continue,
            OwnedComponent::ParentDir => {
                // Check if current is root
                let current_stat = unsafe {
                    let mut st: libc::stat = std::mem::zeroed();
                    if libc::fstat(current_fd.as_raw_fd(), &mut st) != 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    (st.st_dev, st.st_ino)
                };
                if current_stat == dev_ino {
                    // Cannot escape root, stay at root
                    continue;
                }
                // Open parent
                let parent_raw = unsafe {
                    libc::openat(
                        current_fd.as_raw_fd(),
                        c"..".as_ptr(),
                        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                if parent_raw < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                current_fd = unsafe { OwnedFd::from_raw_fd(parent_raw) };
            }
            OwnedComponent::Normal(name) => {
                let is_last = i == components.len();
                let step_flags = if is_last {
                    flags | libc::O_CLOEXEC | libc::O_NOFOLLOW
                } else {
                    libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW
                };
                let c_name = CString::new(name.as_bytes())?;

                let next_raw = unsafe {
                    libc::openat(
                        current_fd.as_raw_fd(),
                        c_name.as_ptr(),
                        step_flags,
                        mode as libc::c_uint,
                    )
                };

                if next_raw < 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(err).with_context(|| format!("open component {:?}", name));
                }

                let next_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };

                // Check if it's a symlink
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(next_fd.as_raw_fd(), &mut st) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }

                if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                    symlink_hops += 1;
                    if symlink_hops > 40 {
                        return Err(anyhow!("too many symlink levels (symlink loop)"));
                    }

                    // Read symlink target via /proc/self/fd/<next_raw>
                    let link_target =
                        std::fs::read_link(format!("/proc/self/fd/{}", next_fd.as_raw_fd()))
                            .with_context(|| format!("readlink for component {:?}", name))?;

                    // RESOLVE_NO_MAGICLINKS check
                    let target_str = link_target.to_string_lossy();
                    if target_str.starts_with("/proc/") {
                        return Err(anyhow!("symlink targets magiclink: {target_str}"));
                    }

                    // Prepend target components
                    let mut new_comps = OwnedComponent::from_path(&link_target);
                    new_comps.extend_from_slice(&components[i..]);
                    components = new_comps;
                    i = 0;

                    // If target was absolute, reset to root_fd
                    if link_target.is_absolute() {
                        let dup = unsafe { libc::fcntl(root_fd, libc::F_DUPFD_CLOEXEC, 0) };
                        if dup < 0 {
                            return Err(std::io::Error::last_os_error().into());
                        }
                        current_fd = unsafe { OwnedFd::from_raw_fd(dup) };
                    }
                    continue;
                }

                current_fd = next_fd;
            }
        }
    }

    Ok(current_fd)
}

/// Resolve an existing file or directory strictly inside `root`.
pub fn resolve_in_root(root: &Path, rel_path: &Path) -> Result<ResolvedPath> {
    let root_fd = open_dir_fd(root)?;
    let clean_rel = clean_relative_path(rel_path)?;

    if let Some(fd) = try_openat2(root_fd.as_raw_fd(), &clean_rel, libc::O_PATH, 0)? {
        return Ok(ResolvedPath::from_owned_fd(fd));
    }

    let fd = openat_walk(root_fd.as_raw_fd(), &clean_rel, libc::O_PATH, 0)?;
    Ok(ResolvedPath::from_owned_fd(fd))
}

/// Ensure a directory exists under `root`, creating intermediate directories safely.
pub fn ensure_dir_in_root(root: &Path, rel_path: &Path, mode: u32) -> Result<ResolvedPath> {
    let clean_rel = clean_relative_path(rel_path)?;

    // If it already exists and is confined, resolve it directly
    if let Ok(res) = resolve_in_root(root, &clean_rel) {
        if res.is_dir() {
            return Ok(res);
        }
    }

    // Component-by-component safe creation
    let mut current_fd = open_dir_fd(root)?;
    for comp in clean_rel.components() {
        match comp {
            Component::Normal(name) => {
                let c_name = CString::new(name.as_bytes())?;
                let rc = unsafe {
                    libc::mkdirat(
                        current_fd.as_raw_fd(),
                        c_name.as_ptr(),
                        mode as libc::mode_t,
                    )
                };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::EEXIST) {
                        return Err(err).with_context(|| format!("mkdirat {:?}", name));
                    }
                }
                let next_raw = unsafe {
                    libc::openat(
                        current_fd.as_raw_fd(),
                        c_name.as_ptr(),
                        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                if next_raw < 0 {
                    return Err(std::io::Error::last_os_error())
                        .with_context(|| format!("openat dir {:?}", name));
                }
                current_fd = unsafe { OwnedFd::from_raw_fd(next_raw) };
            }
            Component::CurDir => continue,
            _ => anyhow::bail!(
                "unexpected path component in ensure_dir_in_root: {:?}",
                comp
            ),
        }
    }

    Ok(ResolvedPath::from_owned_fd(current_fd))
}

/// Ensure a file exists under `root`, creating parent directories safely.
pub fn ensure_file_in_root(root: &Path, rel_path: &Path, mode: u32) -> Result<ResolvedPath> {
    let clean = clean_relative_path(rel_path)?;
    let parent = clean.parent().unwrap_or(Path::new(""));
    let parent_res = ensure_dir_in_root(root, parent, 0o755)?;

    let file_name = clean
        .file_name()
        .ok_or_else(|| anyhow!("path has no file name: {}", rel_path.display()))?;
    let c_name = CString::new(file_name.as_bytes())?;

    let raw = unsafe {
        libc::openat(
            parent_res.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
            mode as libc::mode_t,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("openat file {:?}", file_name));
    }
    Ok(ResolvedPath::from_owned_fd(unsafe {
        OwnedFd::from_raw_fd(raw)
    }))
}

/// Normalize path components into a relative path without escaping `..` or leading `/`.
pub fn clean_relative_path(path: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_names() {
        assert!(validate_resource_name("my_volume-1.0").is_ok());
        assert!(validate_resource_name("alpha").is_ok());
        assert!(validate_resource_name("").is_err());
        assert!(validate_resource_name(".").is_err());
        assert!(validate_resource_name("..").is_err());
        assert!(validate_resource_name("my/volume").is_err());
        assert!(validate_resource_name("my\\volume").is_err());
        assert!(validate_resource_name("../evil").is_err());
        assert!(validate_resource_name("evil\0null").is_err());
        assert!(validate_resource_name("evil\nnewline").is_err());
        assert!(validate_resource_name("-starts-dash").is_err());
        assert!(validate_resource_name(".starts-dot").is_err());

        assert_eq!(
            validate_container_name("/my-container").unwrap(),
            "my-container"
        );
        assert_eq!(
            validate_container_name("my-container").unwrap(),
            "my-container"
        );
        assert!(validate_container_name("/../escape").is_err());
        assert!(validate_container_name("/").is_err());
    }

    #[test]
    fn path_resolution_and_confinement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        std::fs::create_dir_all(root.join("sub/dir")).unwrap();
        std::fs::write(root.join("sub/dir/file.txt"), "hello").unwrap();

        // Valid nested path
        let res = resolve_in_root(root, Path::new("sub/dir/file.txt")).unwrap();
        assert!(res.is_file());
        let content = std::fs::read_to_string(res.proc_path()).unwrap();
        assert_eq!(content, "hello");

        // Absolute path input is resolved inside root
        let res_abs = resolve_in_root(root, Path::new("/sub/dir/file.txt")).unwrap();
        assert!(res_abs.is_file());

        // Repeated slashes
        let res_slashes = resolve_in_root(root, Path::new("///sub///dir///file.txt")).unwrap();
        assert!(res_slashes.is_file());

        // Traversal '..' cannot escape root
        let res_dots = resolve_in_root(root, Path::new("../../../sub/dir/file.txt")).unwrap();
        assert!(res_dots.is_file());

        // Percent-decoded traversal test (e.g. %2e%2e%2f -> ../)
        let percent_decoded =
            percent_encoding::percent_decode_str("%2e%2e%2f%2e%2e%2fsub%2fdir%2ffile.txt")
                .decode_utf8()
                .unwrap();
        let res_percent = resolve_in_root(root, Path::new(percent_decoded.as_ref())).unwrap();
        assert!(res_percent.is_file());

        // Nonexistent file errors
        assert!(resolve_in_root(root, Path::new("does/not/exist")).is_err());

        // Symlink ancestor within root
        std::os::unix::fs::symlink("sub/dir", root.join("link_dir")).unwrap();
        let res_link = resolve_in_root(root, Path::new("link_dir/file.txt")).unwrap();
        assert!(res_link.is_file());

        // Symlink pointing outside root
        std::os::unix::fs::symlink("/etc", root.join("evil_root")).unwrap();
        // Resolving through evil_root must not access host /etc/shadow or /etc/passwd outside root
        let evil_res = resolve_in_root(root, Path::new("evil_root/shadow"));
        // Since root doesn't contain /etc/shadow, resolving inside root fails!
        assert!(evil_res.is_err());
    }

    #[test]
    fn ensure_dir_and_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        let dir_res = ensure_dir_in_root(root, Path::new("nested/deep/directory"), 0o755).unwrap();
        assert!(dir_res.is_dir());

        let file_res =
            ensure_file_in_root(root, Path::new("nested/deep/directory/test.txt"), 0o644).unwrap();
        assert!(file_res.is_file());
    }
}
