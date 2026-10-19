//! Deterministic identity of the *resolved* v2 Java invocation.
//!
//! This is deliberately distinct from the actual OS process: the latter needs
//! a locally selected java binary and per-session authentication credentials.
//! No sensitive material is ever serialized into the identity payload.
use super::{LaunchPlan, Manifest, MinecraftLaunchCredentials};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolvedPlanIdentity {
    format: &'static str,
    signature: String,
    owner_public_key: String,
    runtime_version: &'static str,
    os: &'static str,
    arch: &'static str,
    java_major: u32,
    java_distribution: String,
    auth_mode: &'static str,
    main_class: String,
    main_module: String,
    working_directory: String,
    classpath_entries: Vec<String>,
    modulepath_entries: Vec<String>,
    environment_allowlist: Vec<String>,
    jvm_args: Vec<String>,
    game_args: Vec<String>,
}

fn normalize(value: &str, root: &Path, credentials: Option<&MinecraftLaunchCredentials>) -> String {
    let mut normalized = value.to_string();
    if let Some(credentials) = credentials {
        // Replacing before rooting matters if a token contains path separators.
        for (value, placeholder) in [
            (credentials.access_token.as_str(), "${session.accessToken}"),
            (credentials.uuid.as_str(), "${session.uuid}"),
            (credentials.username.as_str(), "${session.username}"),
        ] {
            if !value.is_empty() {
                normalized = normalized.replace(value, placeholder);
            }
        }
    }
    // Only replace a root as an entire path prefix, never the incidental
    // substring "." or "/" found inside normal JVM arguments.
    let mut roots = Vec::new();
    roots.push(root.to_string_lossy().to_string());
    if let Ok(canonical) = root.canonicalize() {
        roots.push(canonical.to_string_lossy().to_string());
    }
    roots.sort_by_key(|root| std::cmp::Reverse(root.len()));
    roots.dedup();
    for installed_root in roots {
        if installed_root.is_empty() || installed_root == "." || installed_root == "/" { continue; }
        let normalized_root = installed_root.trim_end_matches(|c: char| c == '/' || c == '\\');
        if normalized == normalized_root { normalized = "${client.root}".to_string(); }
        for separator in ["/", "\\"] {
            normalized = normalized.replace(&format!("{normalized_root}{separator}"), &format!("${{client.root}}{separator}"));
        }
    }
    normalized
}

pub(super) fn plan_digest(
    manifest: &Manifest,
    root: &Path,
    java_major: u32,
    plan: &LaunchPlan,
    credentials: Option<&MinecraftLaunchCredentials>,
) -> Result<String, String> {
    let signature = manifest.signature.as_ref()
        .ok_or("v2 deterministic launch requires an owner-signed manifest")?;
    if signature.algorithm != "Ed25519" || signature.signature.len() != 128 {
        return Err("v2 deterministic launch requires an Ed25519 owner signature".into());
    }
    let normalize = |item: &str| normalize(item, root, credentials);
    let environment_allowlist = plan.environment_allowlist.iter()
        .map(|item| if cfg!(windows) { item.to_ascii_uppercase() } else { item.clone() }).collect::<BTreeSet<_>>()
        .into_iter().collect::<Vec<_>>();
    let input = ResolvedPlanIdentity {
        format: "neverlauncher.resolved-launch-plan/1",
        signature: signature.signature.clone(),
        owner_public_key: signature.public_key.clone(),
        runtime_version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        java_major,
        java_distribution: manifest.runtime.java.distribution.clone(),
        auth_mode: if credentials.is_some() { "authenticated" } else { "offline" },
        main_class: plan.main_class.clone(),
        main_module: plan.main_module.clone(),
        working_directory: normalize(&plan.working_directory),
        classpath_entries: plan.classpath_entries.iter().map(|s| normalize(s)).collect(),
        modulepath_entries: plan.modulepath_entries.iter().map(|s| normalize(s)).collect(),
        environment_allowlist,
        jvm_args: plan.jvm_args.iter().map(|s| normalize(s)).collect(),
        game_args: plan.game_args.iter().map(|s| normalize(s)).collect(),
    };
    let bytes = serde_json::to_vec(&input).map_err(|e| format!("resolved launch plan JSON: {e}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JavaInfo, MemoryInfo, MinecraftInfo, RuntimeInfo, RuntimeLaunch, Directories};
    use std::collections::HashMap;

    fn inputs() -> (Manifest, LaunchPlan) {
        let manifest = Manifest {
            schema_version: "2.0".into(), project_id: "p".into(), profile_id: "a".into(),
            channel: "stable".into(), version: "1".into(), created_at: "fixed".into(),
            minecraft: MinecraftInfo { version: "1.21.1".into(), loader: "vanilla".into(), loader_version: "".into(), main_class: "demo.Main".into(), game_args: vec![] },
            runtime: RuntimeInfo {
                java: JavaInfo { major_version: 21, minimum_major_version: 0, recommended_major_version: 0, maximum_major_version: 0, distribution: "temurin".into(), allow_custom_path: false },
                jvm_args: vec![], memory: MemoryInfo::default(), launch: RuntimeLaunch::default(),
            }, directories: Directories::default(), files: vec![], file_rules: vec![], profile_snapshot: None,
            signature: Some(crate::SignatureInfo { algorithm: "Ed25519".into(), public_key: "0".repeat(64), signature: "a".repeat(128), signed_at: "fixed".into() }),
        };
        let plan = LaunchPlan {
            java_executable: "/different/java".into(), working_directory: "/client/one".into(), main_class: "demo.Main".into(), main_module: String::new(),
            classpath_entries: vec!["/client/one/lib/a.jar".into(), "/client/one/lib/b.jar".into()], modulepath_entries: vec![],
            environment_allowlist: vec!["LANG".into(), "TZ".into()], restrict_java_environment: true,
            jvm_args: vec!["-Xmx1024M".into()], game_args: vec!["--gameDir".into(), "/client/one".into()],
            command_preview: "private".into(), deterministic_sha256: String::new(),
        };
        (manifest, plan)
    }

    #[test]
    fn stable_across_client_root_java_executable_and_allowlist_order() {
        let (manifest, plan) = inputs();
        let a = plan_digest(&manifest, Path::new("/client/one"), 21, &plan, None).unwrap();
        let mut other = plan.clone();
        other.java_executable = "/installed/java21".into();
        other.working_directory = "/client/two".into();
        other.classpath_entries = vec!["/client/two/lib/a.jar".into(), "/client/two/lib/b.jar".into()];
        other.game_args[1] = "/client/two".into();
        other.environment_allowlist.reverse();
        assert_eq!(a, plan_digest(&manifest, Path::new("/client/two"), 21, &other, None).unwrap());
        other.classpath_entries.reverse();
        assert_ne!(a, plan_digest(&manifest, Path::new("/client/two"), 21, &other, None).unwrap());
    }

    #[test]
    fn session_credentials_never_change_static_identity() {
        let (manifest, mut plan) = inputs();
        let first = MinecraftLaunchCredentials { username: "Alice".into(), uuid: "uuid-one".into(), access_token: "private-token-one".into(), user_type: "mojang".into(), auth_server_base_url: "".into() };
        plan.game_args.extend(["--username".into(), first.username.clone(), "--uuid".into(), first.uuid.clone(), "--accessToken".into(), first.access_token.clone()]);
        let a = plan_digest(&manifest, Path::new("/client/one"), 21, &plan, Some(&first)).unwrap();
        let second = MinecraftLaunchCredentials { username: "Bob".into(), uuid: "uuid-two".into(), access_token: "private-token-two".into(), ..first.clone() };
        let mut next = plan.clone();
        for arg in &mut next.game_args {
            *arg = arg.replace(&first.username, &second.username).replace(&first.uuid, &second.uuid).replace(&first.access_token, &second.access_token);
        }
        assert_eq!(a, plan_digest(&manifest, Path::new("/client/one"), 21, &next, Some(&second)).unwrap());
        assert_ne!(a, plan_digest(&manifest, Path::new("/client/one"), 21, &next, None).unwrap());
    }

    #[test]
    fn signed_features_are_stably_ordered() {
        let (mut manifest, _) = inputs();
        manifest.runtime.launch.features = HashMap::from([("z".into(), true), ("a".into(), false)]);
        let json1 = serde_json::to_string(&manifest).unwrap();
        manifest.runtime.launch.features = HashMap::from([("a".into(), false), ("z".into(), true)]);
        let json2 = serde_json::to_string(&manifest).unwrap();
        assert_eq!(json1, json2);
        assert!(json1.contains(r#""features":{"a":false,"z":true}"#));
    }
}
