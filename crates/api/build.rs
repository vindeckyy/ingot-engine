fn main() {
    println!("cargo:rerun-if-env-changed=INGOT_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=INGOT_BUILD_TIME");

    let commit = std::env::var("INGOT_GIT_COMMIT").unwrap_or_else(|_| {
        std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|out| {
                if out.status.success() {
                    String::from_utf8(out.stdout).ok()
                } else {
                    None
                }
            })
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "dev".to_string())
    });
    println!("cargo:rustc-env=INGOT_GIT_COMMIT={commit}");

    let build_time =
        std::env::var("INGOT_BUILD_TIME").unwrap_or_else(|_| chrono::Utc::now().to_rfc3339());
    println!("cargo:rustc-env=INGOT_BUILD_TIME={build_time}");
}
