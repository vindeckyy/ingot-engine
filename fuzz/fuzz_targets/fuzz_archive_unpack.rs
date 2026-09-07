#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cursor = std::io::Cursor::new(data);
    let mut archive = tar::Archive::new(cursor);
    if let Ok(temp_dir) = tempfile::tempdir() {
        let _ = ingot_image::unpack_entries(&mut archive, temp_dir.path());
    }
});
