//! Регрессия: необязательное владение в схеме v2 не освобождает от проверки выбранного файла.
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn missing_selected_legacy_optional_is_not_ready() {
    let mut source: serde_json::Value = serde_json::from_str(
        include_str!("fixtures/catalog_manifest_v3_go_signed_0242.json")
    ).expect("known-good manifest fixture");
    source["schemaVersion"] = serde_json::json!("2.0");
    source.as_object_mut().expect("manifest object").remove("componentCatalog");
    let manifest: runtime::Manifest = serde_json::from_value(source).expect("legacy manifest");
    let root: PathBuf = std::env::temp_dir().join(format!(
        "neverlauncher-selected-optional-0526-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir(&root).expect("isolated test directory");
    let result = runtime::check_files_with_preset(&manifest, &root, None).await;
    std::fs::remove_dir_all(&root).expect("cleanup");
    let files = result.expect("check missing selected files");
    assert!(!files.is_empty(), "must actually inspect files");
    assert!(files.iter().all(|file| file.status == "missing"),
        "missing selected optional files must never be accepted as ready: {files:?}");
}
