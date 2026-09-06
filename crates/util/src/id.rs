use rand::RngCore;

/// Random lowercase hex string of `n` characters.
pub fn random_hex(n: usize) -> String {
    let bytes_len = n.div_ceil(2);
    let mut bytes = vec![0u8; bytes_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    let full = hex::encode(bytes);
    full[..n].to_string()
}

/// Random hex token used for exec ids etc.
pub fn random_token() -> String {
    random_hex(64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_len() {
        assert_eq!(random_hex(64).len(), 64);
        assert_eq!(random_hex(7).len(), 7);
        assert!(random_hex(64).chars().all(|c| c.is_ascii_hexdigit()));
    }
}
