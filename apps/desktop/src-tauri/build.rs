use base64::{engine::general_purpose::STANDARD, Engine as _};

fn public_material(encoded: &str) -> Option<Vec<u8>> {
    let outer = STANDARD.decode(encoded.trim()).ok()?;
    let text = std::str::from_utf8(&outer).ok()?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 2 { return None; }
    let raw = STANDARD.decode(lines[1]).ok()?;
    if raw.len() != 42 || &raw[..2] != b"Ed" { return None; }
    Some(raw[10..].to_vec())
}

fn main() {
    for name in ["NL_UPDATER_PUBLIC_KEY", "NL_UPDATER_ENDPOINT", "NL_REQUIRE_NATIVE_UPDATER", "NL_UPDATER_BETA_PUBLIC_KEY", "NL_UPDATER_GITHUB_REPOSITORY", "NL_REQUIRE_BETA_UPDATER"] {
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

    let beta = std::env::var("NL_UPDATER_BETA_PUBLIC_KEY").unwrap_or_default();
    let repo = std::env::var("NL_UPDATER_GITHUB_REPOSITORY").unwrap_or_default();
    if beta.trim().is_empty() != repo.trim().is_empty() ||
        (!beta.trim().is_empty() && (key.trim().is_empty() || beta.trim() == key.trim())) ||
        (std::env::var("NL_REQUIRE_BETA_UPDATER").as_deref() == Ok("1") && beta.trim().is_empty()) {
        panic!("Beta Updater: required distinct public key and GitHub repository");
    }
    if !beta.trim().is_empty() {
        match (public_material(&key), public_material(&beta)) {
            (Some(stable), Some(beta)) if stable != beta => (),
            _ => panic!("Beta Updater: invalid or identical Ed25519 public keys"),
        }
    }
    if !repo.trim().is_empty() {
        let parts: Vec<_> = repo.trim().split('/').collect();
        if parts.len() != 2 || parts.iter().any(|part| part.is_empty() || *part == "." || *part == ".." || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))) {
            panic!("Beta Updater: expected owner/repository");
        }
        let expected = format!("https://github.com/{}/releases/latest/download/latest.json", repo.trim());
        if endpoint.trim() != expected { panic!("Stable and Beta must refer to the same GitHub repository"); }
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
