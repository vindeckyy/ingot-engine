#![no_main]
use libfuzzer_sys::fuzz_target;

// Manifest index parsing + platform selection must be total: any byte
// string either selects a digest, reports a single manifest, or fails
// closed — it must never panic.
fuzz_target!(|data: &[u8]| {
    let _ = ingot_registry::select_index_digest(data, "linux", "amd64");
    let _ = ingot_registry::select_index_digest(data, "windows", "arm64");
});
