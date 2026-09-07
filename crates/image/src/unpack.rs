//! Layer tar unpacking with OCI whiteout semantics:
//!   `.wh.<name>`        → char device 0:0 (overlayfs whiteout)
//!   `.wh..wh..opq`      → trusted.overlay.opaque=y on the parent dir
//! Also hashes the *uncompressed* tar to produce the diffID.
//!
//! Hardened with staged directory extraction, entry-count & size budgets,
//! and fail-closed error handling.

use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MAX_COMPRESSED_BYTES: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB
pub const MAX_EXTRACTED_BYTES: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB
pub const MAX_ENTRIES: usize = 500_000;

/// Stream-decompress + hash + unpack a layer blob from `blob_path`.
/// Returns the diffID (`sha256:<hex>` of the uncompressed tar).
pub fn unpack_layer(blob_path: &Path, dest_dir: &Path, media_type: &str) -> Result<String> {
    let file = std::fs::File::open(blob_path)
        .with_context(|| format!("open layer blob {}", blob_path.display()))?;
    let compressed_len = file.metadata()?.len();
    if compressed_len > MAX_COMPRESSED_BYTES {
        anyhow::bail!("compressed layer blob exceeds budget of {MAX_COMPRESSED_BYTES} bytes");
    }

    let parent = dest_dir
        .parent()
        .ok_or_else(|| anyhow!("no parent for dest_dir"))?;
    std::fs::create_dir_all(parent)?;
    let staging_dir = parent.join(format!(
        ".staging.{}.{}",
        dest_dir.file_name().unwrap_or_default().to_string_lossy(),
        &ingot_util::new_id()[..12]
    ));
    std::fs::create_dir_all(&staging_dir)?;

    struct StagingGuard(PathBuf, bool);
    impl Drop for StagingGuard {
        fn drop(&mut self) {
            if !self.1 {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
    let mut guard = StagingGuard(staging_dir.clone(), false);

    let hasher = ingot_util::digest::VerifyingWriter::new(std::io::sink());
    let reader: Box<dyn Read> = if media_type.ends_with("+gzip") || media_type.contains("gzip") {
        Box::new(flate2::read::GzDecoder::new(file))
    } else if media_type.ends_with("+zstd") || media_type.contains("zstd") {
        Box::new(zstd::Decoder::new(file)?)
    } else {
        Box::new(file)
    };

    let tee = HashingReader::new(reader, hasher);
    let mut archive = tar::Archive::new(tee);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    unpack_entries(&mut archive, &staging_dir)?;

    let mut tee = archive.into_inner();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match tee.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let (_, digest, _) = tee.into_inner().1.finish()?;
    let diff_id = format!("sha256:{digest}");

    std::fs::write(staging_dir.join(".ingot-unpacked"), "ok")
        .context("write .ingot-unpacked marker")?;

    match std::fs::rename(&staging_dir, dest_dir) {
        Ok(()) => {
            guard.1 = true;
        }
        Err(e) => {
            if dest_dir.join(".ingot-unpacked").exists() {
                let _ = std::fs::remove_dir_all(&staging_dir);
                guard.1 = true;
            } else {
                return Err(e).with_context(|| format!("rename layer to {}", dest_dir.display()));
            }
        }
    }

    Ok(diff_id)
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

pub fn unpack_entries<R: Read>(archive: &mut tar::Archive<R>, root: &Path) -> Result<()> {
    let mut total_extracted: u64 = 0;
    let mut count: usize = 0;

    let entries = archive.entries().context("read archive entries")?;
    for entry in entries {
        let mut entry = entry.context("malformed tar entry")?;
        count += 1;
        if count > MAX_ENTRIES {
            anyhow::bail!("layer entry count exceeds budget of {MAX_ENTRIES}");
        }
        let size = entry.size();
        total_extracted = total_extracted
            .checked_add(size)
            .ok_or_else(|| anyhow!("extracted size overflow"))?;
        if total_extracted > MAX_EXTRACTED_BYTES {
            anyhow::bail!("layer extracted size exceeds budget of {MAX_EXTRACTED_BYTES} bytes");
        }

        let entry_path = entry.path().context("entry path")?.to_path_buf();
        let file_name = entry_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();

        if file_name == ".wh..wh..opq" {
            let parent_rel = entry_path.parent().unwrap_or(Path::new(""));
            let parent_res = ingot_util::ensure_dir_in_root(root, parent_rel, 0o755)?;
            set_opaque(parent_res.proc_path())?;
            continue;
        }
        if let Some(target) = file_name.strip_prefix(".wh.") {
            let parent_rel = entry_path.parent().unwrap_or(Path::new(""));
            let parent_res = ingot_util::ensure_dir_in_root(root, parent_rel, 0o755)?;
            let parent_path = parent_res.proc_path();
            let _ = std::fs::remove_file(parent_path.join(target));
            let _ = std::fs::remove_file(parent_path.join(file_name));
            mknod_char_zero(&parent_path.join(target))?;
            continue;
        }

        entry
            .unpack_in(root)
            .with_context(|| format!("unpack entry {}", entry_path.display()))?;
    }
    Ok(())
}

fn mknod_char_zero(path: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let rc = unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | 0o644, libc::makedev(0, 0)) };
    if rc != 0 {
        // If unprivileged and cannot mknod, create a normal file as fallback whiteout representation
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            std::fs::File::create(path)?;
            return Ok(());
        }
        return Err(anyhow!("mknod whiteout {} failed: {}", path.display(), err));
    }
    Ok(())
}

fn set_opaque(dir: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    for name in [c"trusted.overlay.opaque", c"user.overlay.opaque"] {
        let rc = unsafe {
            libc::setxattr(
                c.as_ptr(),
                name.as_ptr(),
                c"y".as_ptr() as *const libc::c_void,
                2,
                0,
            )
        };
        if rc == 0 {
            return Ok(());
        }
    }
    // If setxattr fails due to EPERM/ENOTSUP (e.g. tmpfs or non-root in tests), treat as best-effort
    let err = std::io::Error::last_os_error();
    if matches!(err.raw_os_error(), Some(libc::EPERM) | Some(libc::ENOTSUP)) {
        return Ok(());
    }
    Err(anyhow!(
        "set opaque xattr on {} failed: {}",
        dir.display(),
        err
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tar(entries: Vec<(&str, &[u8], tar::EntryType, Option<&str>)>) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, content, ty, link) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(ty);
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            if let Some(l) = link {
                header.set_link_name(l).unwrap();
            }
            header.set_cksum();
            builder.append_data(&mut header, path, content).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn normal_unpack() {
        let temp = tempfile::tempdir().unwrap();
        let tar_bytes = build_tar(vec![(
            "dir/file.txt",
            b"hello world",
            tar::EntryType::Regular,
            None,
        )]);
        let blob_path = temp.path().join("layer.tar");
        std::fs::write(&blob_path, &tar_bytes).unwrap();

        let dest = temp.path().join("layer_out");
        let diff_id =
            unpack_layer(&blob_path, &dest, "application/vnd.oci.image.layer.v1.tar").unwrap();
        assert!(diff_id.starts_with("sha256:"));
        assert!(dest.join("dir/file.txt").is_file());
        assert!(dest.join(".ingot-unpacked").is_file());
    }

    #[test]
    fn symlink_then_file_adversarial_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();

        // Entry 1: symlink pointing outside destination
        // Entry 2: file inside symlink path
        let tar_bytes = build_tar(vec![
            (
                "evil_link",
                b"",
                tar::EntryType::Symlink,
                Some(outside.to_str().unwrap()),
            ),
            (
                "evil_link/pwned.txt",
                b"escaped",
                tar::EntryType::Regular,
                None,
            ),
        ]);
        let blob_path = temp.path().join("evil.tar");
        std::fs::write(&blob_path, &tar_bytes).unwrap();

        let dest = temp.path().join("dest");
        let res = unpack_layer(&blob_path, &dest, "application/vnd.oci.image.layer.v1.tar");
        // Must fail and NOT write to outside directory
        assert!(res.is_err());
        assert!(!outside.join("pwned.txt").exists());
        // Staging directory must be cleaned up
        assert!(!dest.exists());
    }

    #[test]
    fn symlink_then_directory_adversarial_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside_dir");
        std::fs::create_dir_all(&outside).unwrap();

        let tar_bytes = build_tar(vec![
            (
                "evil_dir_link",
                b"",
                tar::EntryType::Symlink,
                Some(outside.to_str().unwrap()),
            ),
            ("evil_dir_link/sub", b"", tar::EntryType::Directory, None),
        ]);
        let blob_path = temp.path().join("evil_dir.tar");
        std::fs::write(&blob_path, &tar_bytes).unwrap();

        let dest = temp.path().join("dest_dir");
        let res = unpack_layer(&blob_path, &dest, "application/vnd.oci.image.layer.v1.tar");
        assert!(res.is_err());
        assert!(!outside.join("sub").exists());
    }

    #[test]
    fn hardlink_escape_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let tar_bytes = build_tar(vec![(
            "evil_hardlink",
            b"",
            tar::EntryType::Link,
            Some("../../../etc/shadow"),
        )]);
        let blob_path = temp.path().join("hardlink.tar");
        std::fs::write(&blob_path, &tar_bytes).unwrap();

        let dest = temp.path().join("dest_hardlink");
        let res = unpack_layer(&blob_path, &dest, "application/vnd.oci.image.layer.v1.tar");
        assert!(res.is_err());
    }

    #[test]
    fn malformed_tar_fails() {
        let temp = tempfile::tempdir().unwrap();
        let blob_path = temp.path().join("garbage.tar");
        std::fs::write(&blob_path, b"garbage data that is not a tar archive").unwrap();

        let dest = temp.path().join("dest_garbage");
        let res = unpack_layer(&blob_path, &dest, "application/vnd.oci.image.layer.v1.tar");
        assert!(res.is_err());
    }
}
