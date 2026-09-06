//! Digest helpers: `sha256:<hex>` strings, streaming verification, chainID math.

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::io::Write;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// `sha256:<hex>` form.
pub fn digest_hex(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(data))
}

pub fn is_valid_digest(d: &str) -> bool {
    let Some(hexpart) = d.strip_prefix("sha256:") else {
        return false;
    };
    hexpart.len() == 64 && hexpart.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A streaming sha256 verifier that forwards bytes to a downstream writer.
/// Used to verify registry blobs against their digest while unpacking.
pub struct VerifyingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> VerifyingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    pub fn finish(self) -> Result<(W, String, u64)> {
        let digest = hex::encode(self.hasher.finalize());
        Ok((self.inner, digest, self.written))
    }

    pub fn written(&self) -> u64 {
        self.written
    }
}

impl<W: Write> Write for VerifyingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Compute the OCI chainID for layer `n` given the parent chainID and the
/// layer's diffID: `chainID(n) = sha256(chainID(n-1) + " " + diffID(n))`.
/// The first layer's chainID equals its diffID.
pub fn chain_id(parent_chain: Option<&str>, diff_id: &str) -> String {
    match parent_chain {
        None => diff_id.to_string(),
        Some(p) => format!(
            "sha256:{}",
            sha256_hex(format!("{} {}", p, diff_id).as_bytes())
        ),
    }
}

/// Parse `algo:hex` into (algo, hex).
pub fn split_digest(d: &str) -> Result<(&str, &str)> {
    d.split_once(':')
        .ok_or_else(|| anyhow!("invalid digest {d:?}: missing algorithm prefix"))
        .context("parse digest")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_ids_match_oci() {
        // Known-good vector: single layer chainID == diffID
        let d1 = "sha256:aaaa";
        assert_eq!(chain_id(None, d1), d1);
        // Two-layer chain: sha256 of "sha256:aaaa sha256:bbbb"
        let expected = format!("sha256:{}", sha256_hex(b"sha256:aaaa sha256:bbbb"));
        assert_eq!(chain_id(Some(d1), "sha256:bbbb"), expected);
    }

    #[test]
    fn verifying_writer_sums() {
        let mut w = VerifyingWriter::new(Vec::new());
        w.write_all(b"hello world").unwrap();
        let (_, digest, written) = w.finish().unwrap();
        assert_eq!(written, 11);
        assert_eq!(digest, sha256_hex(b"hello world"));
    }

    #[test]
    fn digest_validation() {
        assert!(is_valid_digest(&digest_hex(b"x")));
        assert!(!is_valid_digest("sha256:zz"));
        assert!(!is_valid_digest("md5:aaaa"));
    }
}
