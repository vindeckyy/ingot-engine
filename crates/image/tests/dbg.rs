// quick debug harness — run with: cargo test -p ingot-image --test dbg
use sha2::Digest;
use std::io::Read;

struct HashingReader<R: Read> {
    inner: R,
    hasher: sha2::Sha256,
    n: u64,
}
impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: sha2::Sha256::new(),
            n: 0,
        }
    }
}
impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
            self.n += n as u64;
        }
        Ok(n)
    }
}

// Manual-only: hashes one live-store blob for unpack debugging. Ignored in
// gates because it pins an absolute machine-state path (a routine
// `ingotd --repair` legitimately removes unreferenced blobs like this one).
#[test]
#[ignore]
fn debug_diffid() {
    let path = std::path::Path::new("/var/lib/ingot/blobs/sha256/b05093807bb0294152bb9cf86d64da722732dddaf7f8882fa1f120477dbc4db3");
    let file = std::fs::File::open(path).unwrap();
    let mut h = sha2::Sha256::new();
    let mut r = flate2::read::GzDecoder::new(file);
    let mut buf = vec![0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    println!(
        "raw gunzip: total={total} hex={}",
        hex::encode(h.finalize())
    );

    // Now via tar
    let file = std::fs::File::open(path).unwrap();
    let mut tee = HashingReader::new(flate2::read::GzDecoder::new(file));
    let mut archive = tar::Archive::new(&mut tee);
    let mut count = 0;
    for e in archive.entries().unwrap().filter_map(|e| e.ok()) {
        let _ = e.header().size();
        count += 1;
    }
    println!("tar entries read: {count}, hashed so far: {}", tee.n);
    // drain
    let mut extra = 0u64;
    loop {
        let n = tee.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        tee.hasher.update(&buf[..n]);
        extra += n as u64;
    }
    println!(
        "after drain: extra={extra} total={} hex={}",
        tee.n,
        hex::encode(tee.hasher.finalize())
    );
}
