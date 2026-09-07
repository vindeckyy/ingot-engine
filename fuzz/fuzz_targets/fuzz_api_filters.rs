#![no_main]
use libfuzzer_sys::fuzz_target;

// `filters` query parsing must be total: any byte string degrades to a
// (possibly empty) map — it must never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ingot_api::parse_filters(&Some(s.to_string()));
    }
    let _ = ingot_api::parse_filters(&None);
});
