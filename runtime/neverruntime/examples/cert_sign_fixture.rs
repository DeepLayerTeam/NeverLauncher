//! Certification-only fixture signer. Never used as a production signing service.
//! The secret must be explicitly provided by the test harness (not bundled).
use runtime::{sign_manifest, Manifest};
use std::{env, fs, process};

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        eprintln!("usage: cert_sign_fixture <unsigned.json> <signed.json>");
        process::exit(2);
    }
    let seed = match env::var("NEVERLAUNCHER_CERT_TEST_SEED") {
        Ok(v) if v.len() == 64 => v,
        _ => { eprintln!("missing explicit 32-byte certification-only test seed"); process::exit(2); }
    };
    let result = (|| -> Result<String, String> {
        let bytes = fs::read(&args[1]).map_err(|e| e.to_string())?;
        let mut manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if manifest.project_id != "certification" { return Err("only certification fixtures accepted".into()); }
        let key = sign_manifest(&mut manifest, &seed, "2026-10-20T00:00:00Z")?;
        let data = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
        fs::write(&args[2], data).map_err(|e| e.to_string())?;
        Ok(key)
    })();
    match result {
        Ok(key) => println!("{key}"),
        Err(err) => { eprintln!("cert signing failed: {err}"); process::exit(1); }
    }
}
