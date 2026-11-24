fn main() {
    for name in ["NL_UPDATER_PUBLIC_KEY", "NL_UPDATER_ENDPOINT", "NL_REQUIRE_NATIVE_UPDATER"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let key = std::env::var("NL_UPDATER_PUBLIC_KEY").unwrap_or_default();
    let endpoint = std::env::var("NL_UPDATER_ENDPOINT").unwrap_or_default();
    if key.trim().is_empty() != endpoint.trim().is_empty() ||
        (std::env::var("NL_REQUIRE_NATIVE_UPDATER").as_deref() == Ok("1") && key.trim().is_empty()) {
        panic!("Native Updater: требуется пара NL_UPDATER_PUBLIC_KEY и NL_UPDATER_ENDPOINT");
    }
    if !endpoint.is_empty() && !endpoint.starts_with("https://") {
        panic!("Native Updater: endpoint должен использовать HTTPS");
    }

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
        if let Ok(output) = std::process::Command::new("xcode-select").arg("-p").output() {
            if output.status.success() {
                let developer = String::from_utf8_lossy(&output.stdout);
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx", developer.trim());
            }
        }
    }
    tauri_build::build();
}
