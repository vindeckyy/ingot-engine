//! Layer tar unpacking with OCI whiteout semantics:
//!   `.wh.<name>`        → char device 0:0 (overlayfs whiteout)
//!   `.wh..wh..opq`      → trusted.overlay.opaque=y on the parent dir
//! Also hashes the *uncompressed* tar to produce the diffID.

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// Stream-decompress + hash + unpack a layer blob from `blob_path`.
/// Returns the diffID (`sha256:<hex>` of the uncompressed tar).
pub fn unpack_layer(blob_path: &Path, dest_dir: &Path, media_type: &str) -> Result<String> {
    let file = std::fs::File::open(blob_path)
        .with_context(|| format!("open layer blob {}", blob_path.display()))?;
    std::fs::create_dir_all(dest_dir)?;

    let hasher = ingot_util::digest::VerifyingWriter::new(std::io::sink());
    let reader: Box<dyn Read> = if media_type.ends_with("+gzip") || media_type.contains("gzip") {
        Box::new(flate2::read::GzDecoder::new(file))
    } else if media_type.ends_with("+zstd") || media_type.contains("zstd") {
        Box::new(zstd::Decoder::new(file)?)
    } else {
        Box::new(file)
    };
    // Hash every uncompressed byte while tar consumes the stream.
    let tee = HashingReader::new(reader, hasher);
    let mut archive = tar::Archive::new(tee);
    archive.set_preserve_permissions(true);
    unpack_entries(&mut archive, dest_dir)?;
    let mut tee = archive.into_inner();
    // tar stops after the trailing zero blocks; hash the remaining bytes
    // (padding + compression trailer) so the diffID covers the whole stream.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // read() hashes what it consumes — no re-hashing here.
        match tee.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let (_, digest, _) = tee.into_inner().1.finish()?;
    Ok(format!("sha256:{digest}"))
}

/// Reader that forwards into a hashing writer (diffID while tar reads).
struct HashingReader<R: Read> {
    inner: R,
    hasher: ingot_util::digest::VerifyingWriter<std::io::Sink>,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R, hasher: ingot_util::digest::VerifyingWriter<std::io::Sink>) -> Self {
        Self { inner, hasher }
    }
    fn into_inner(self) -> (R, ingot_util::digest::VerifyingWriter<std::io::Sink>) {
        (self.inner, self.hasher)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.write_all(&buf[..n])?;
        }
        Ok(n)
    }
}

fn safe_join(root: &Path, entry_path: &str) -> Result<PathBuf> {
    clean_rel(entry_path)?.map(|rel| root.join(rel)).ok_or_else(|| anyhow!("empty entry path"))
}

/// Sanitized relative path; None for entries that denote the root itself
/// ("./", "/") which layers legitimately contain.
fn clean_rel(entry_path: &str) -> Result<Option<PathBuf>> {
    let rel = Path::new(entry_path);
    let mut clean = PathBuf::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(c) => clean.push(c),
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => return Err(anyhow!("layer entry escapes root: {entry_path}")),
        }
    }
    Ok(if clean.as_os_str().is_empty() { None } else { Some(clean) })
}

/// Header fields we need, owned (so `entry` is free for streaming reads).
struct EntryInfo {
    full: PathBuf,
    ty: tar::EntryType,
    mode: u32,
    uid: u64,
    gid: u64,
    link: Option<String>,
    devmajor: u32,
    devminor: u32,
}

fn unpack_entries<R: Read>(archive: &mut tar::Archive<R>, root: &Path) -> Result<()> {
    for entry in archive.entries()?.filter_map(|e| e.ok()) {
        let info = {
            let header = entry.header();
            let name = entry.path()?.to_string_lossy().to_string();
            let Some(full) = clean_rel(&name)?.map(|rel| root.join(rel)) else {
                continue; // "./" root entry
            };
            EntryInfo {
                full,
                ty: header.entry_type(),
                mode: header.mode()?,
                uid: header.uid()?,
                gid: header.gid()?,
                link: header.link_name()?.map(|l| l.to_string_lossy().to_string()),
                // Numeric device fields error out on non-device entries.
                devmajor: read_dev(header, true),
                devminor: read_dev(header, false),
            }
        };
        let full = &info.full;

        let base_name = full
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        if base_name == ".wh..wh..opq" {
            let parent = full.parent().ok_or_else(|| anyhow!("opq without parent"))?;
            std::fs::create_dir_all(parent)?;
            set_opaque(parent)?;
            continue;
        }
        if let Some(target) = base_name.strip_prefix(".wh.") {
            let target = target.to_string();
            let parent = full.parent().ok_or_else(|| anyhow!("whiteout without parent"))?;
            std::fs::create_dir_all(parent)?;
            // Char device 0:0 = overlayfs whiteout marker.
            let _ = std::fs::remove_file(parent.join(&target));
            let _ = std::fs::remove_file(parent.join(&base_name));
            mknod_char_zero(&parent.join(&target))?;
            continue;
        }

        match info.ty {
            tar::EntryType::Directory => {
                std::fs::create_dir_all(full)?;
                set_mode(full, info.mode);
                chown_path(full, info.uid, info.gid);
            }
            tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::GNUSparse => {
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let _ = std::fs::symlink_metadata(full).map(|md| {
                    if md.file_type().is_dir() {
                        std::fs::remove_dir(full)
                    } else {
                        std::fs::remove_file(full)
                    }
                });
                let mut out = std::fs::File::create(full)?;
                let mut entry = entry;
                std::io::copy(&mut entry, &mut out)?;
                drop(out);
                set_mode(full, info.mode);
                chown_path(full, info.uid, info.gid);
            }
            tar::EntryType::Symlink => {
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let _ = std::fs::remove_file(full);
                let target = info.link.clone().unwrap_or_default();
                std::os::unix::fs::symlink(target, full)?;
                lchown_path(full, info.uid, info.gid);
            }
            tar::EntryType::Link => {
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let _ = std::fs::remove_file(full);
                let target = info.link.clone().unwrap_or_default();
                let target_path = safe_join(root, &target)?;
                if std::fs::symlink_metadata(&target_path).is_err() {
                    return Err(anyhow!("hardlink target {target:?} missing within layer"));
                }
                std::fs::hard_link(target_path, full)?;
                chown_path(full, info.uid, info.gid);
            }
            tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo => {
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let _ = std::fs::remove_file(full);
                create_special(full, &info)?;
                chown_path(full, info.uid, info.gid);
            }
            other => {
                tracing::debug!("skipping layer entry type {other:?}: {}", full.display());
            }
        }
    }
    Ok(())
}

/// Device major/minor, zeroed for non-device entries.
fn read_dev(header: &tar::Header, major: bool) -> u32 {
    if !matches!(header.entry_type(), tar::EntryType::Char | tar::EntryType::Block) {
        return 0;
    }
    let v = if major { header.device_major() } else { header.device_minor() };
    v.ok().flatten().unwrap_or(0)
}

fn set_mode(path: &Path, mode: u32) {
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
}

fn chown_path(path: &Path, uid: u64, gid: u64) {
    use std::os::unix::ffi::OsStrExt;
    let c = match std::ffi::CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return,
    };
    unsafe {
        libc::chown(c.as_ptr(), uid as libc::uid_t, gid as libc::gid_t);
    }
}

fn lchown_path(path: &Path, uid: u64, gid: u64) {
    use std::os::unix::ffi::OsStrExt;
    let c = match std::ffi::CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return,
    };
    unsafe {
        libc::lchown(c.as_ptr(), uid as libc::uid_t, gid as libc::gid_t);
    }
}

fn mknod_char_zero(path: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let rc = unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | 0o644, libc::makedev(0, 0)) };
    if rc != 0 {
        return Err(anyhow!(
            "mknod whiteout {} failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn create_special(path: &Path, info: &EntryInfo) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let (sifmt, dev) = match info.ty {
        tar::EntryType::Char => (libc::S_IFCHR, libc::makedev(info.devmajor, info.devminor)),
        tar::EntryType::Block => (libc::S_IFBLK, libc::makedev(info.devmajor, info.devminor)),
        tar::EntryType::Fifo => (libc::S_IFIFO, 0),
        _ => return Err(anyhow!("not a special file")),
    };
    let rc = unsafe { libc::mknod(c.as_ptr(), sifmt | (info.mode & 0o7777), dev) };
    if rc != 0 {
        return Err(anyhow!(
            "mknod {} failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn set_opaque(dir: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    for name in ["trusted.overlay.opaque", "user.overlay.opaque"] {
        let rc = unsafe {
            libc::setxattr(
                c.as_ptr(),
                name.as_ptr() as *const libc::c_char,
                b"y\0".as_ptr() as *const libc::c_void,
                2,
                0,
            )
        };
        if rc == 0 {
            return Ok(());
        }
    }
    Err(anyhow!(
        "set opaque xattr on {} failed: {}",
        dir.display(),
        std::io::Error::last_os_error()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_traversal() {
        let root = Path::new("/tmp/layerroot");
        assert!(safe_join(root, "a/b/c").is_ok());
        assert!(safe_join(root, "../../etc/passwd").is_err());
        assert!(safe_join(root, "/absolute").is_ok()); // RootDir component dropped
    }
}
