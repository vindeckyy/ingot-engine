#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ingot_registry::ImageRef::parse(s);
        let _ = ingot_registry::RegistryClient::parse_challenge(s);
    }
});
