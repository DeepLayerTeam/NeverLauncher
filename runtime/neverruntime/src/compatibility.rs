use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
    process::Command,
};
use tokio::fs;

const MAX_INHERITANCE_DEPTH: usize = 16;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityEnvironment {
    pub os: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os_version: String,
    #[serde(default)]
    pub features: HashMap<String, bool>,
}

impl CompatibilityEnvironment {
    pub fn current(features: HashMap<String, bool>) -> Self {
        Self {
            os: normalized_current_os().to_string(),
            arch: normalized_current_arch().to_string(),
            os_version: detect_os_version(),
            features,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityContext {
    pub username: String,
    pub uuid: String,
    pub access_token: String,
    pub user_type: String,
    pub launcher_name: String,
    pub launcher_version: String,
    pub game_directory: String,
    pub assets_directory: String,
    pub natives_directory: String,
    #[serde(default)]
    pub features: HashMap<String, bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CompatibilityResolution {
    pub requested_version: String,
    pub resolved_version: String,
    pub minecraft_type: String,
    pub main_class: String,
    pub java_major_version: Option<u32>,
    pub client_jar: String,
    pub classpath: Vec<String>,
    pub libraries: Vec<ResolvedLibrary>,
    pub natives: Vec<ResolvedNative>,
    pub jvm_args: Vec<String>,
    pub game_args: Vec<String>,
    pub assets_index: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging_file: Option<String>,
    pub metadata_paths: Vec<String>,
    pub inheritance_chain: Vec<String>,
    pub environment: CompatibilityEnvironment,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedLibrary {
    pub name: String,
    pub path: String,
    pub url: String,
    pub sha1: String,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedNative {
    pub name: String,
    pub classifier: String,
    pub path: String,
    pub url: String,
    pub sha1: String,
    pub size: u64,
    pub excludes: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct VersionMetadata {
    #[serde(default)]
    id: String,
    #[serde(default)]
    inherits_from: String,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    main_class: String,
    #[serde(default)]
    assets: String,
    #[serde(default)]
    asset_index: Option<Download>,
    #[serde(default)]
    downloads: HashMap<String, Download>,
    #[serde(default)]
    libraries: Vec<Library>,
    #[serde(default)]
    arguments: Arguments,
    #[serde(default)]
    minecraft_arguments: String,
    #[serde(default)]
    java_version: Option<JavaVersion>,
    #[serde(default)]
    logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct JavaVersion {
    #[serde(default)]
    major_version: u32,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct LoggingConfig {
    #[serde(default)]
    client: Option<LoggingClient>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct LoggingClient {
    #[serde(default)]
    argument: String,
    #[serde(default)]
    file: Download,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct Arguments {
    #[serde(default)]
    game: Vec<Argument>,
    #[serde(default)]
    jvm: Vec<Argument>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum Argument {
    Plain(String),
    Conditional(ConditionalArgument),
}

#[derive(Debug, Deserialize, Clone, Default)]
struct ConditionalArgument {
    #[serde(default)]
    rules: Vec<Rule>,
    value: ArgumentValue,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum ArgumentValue {
    One(String),
    Many(Vec<String>),
}

impl Default for ArgumentValue {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
struct Library {
    #[serde(default)]
    name: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    downloads: LibraryDownloads,
    #[serde(default)]
    natives: HashMap<String, String>,
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    extract: ExtractRules,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct ExtractRules {
    #[serde(default)]
    exclude: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct LibraryDownloads {
    #[serde(default)]
    artifact: Option<Download>,
    #[serde(default)]
    classifiers: HashMap<String, Download>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct Download {
    #[serde(default)]
    path: String,
    #[serde(default)]
    sha1: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    url: String,
    #[serde(default)]
    id: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct Rule {
    #[serde(default)]
    action: String,
    #[serde(default)]
    os: Option<RuleOs>,
    #[serde(default)]
    features: HashMap<String, bool>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RuleOs {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    arch: String,
}

#[derive(Debug, Clone, Default)]
struct MergedVersion {
    id: String,
    r#type: String,
    main_class: String,
    assets: String,
    asset_index: Option<Download>,
    client_version_id: String,
    libraries: Vec<Library>,
    arguments: Arguments,
    minecraft_arguments: String,
    java_version: Option<JavaVersion>,
    logging_client: Option<LoggingClient>,
}

pub async fn resolve_compatibility(
    root: &Path,
    requested_version: &str,
    metadata_path: Option<&str>,
    context: &CompatibilityContext,
) -> Result<CompatibilityResolution, String> {
    let requested = safe_component(requested_version)?;
    let first_path = match metadata_path.filter(|value| !value.trim().is_empty()) {
        Some(path) => normalize_relative_path(path)?,
        None => format!("versions/{requested}/{requested}.json"),
    };

    let mut layers = Vec::<(String, String, VersionMetadata)>::new();
    let mut seen = HashSet::new();
    let mut current_id = requested.clone();
    let mut current_path = first_path;

    for _ in 0..MAX_INHERITANCE_DEPTH {
        let relative_path = normalize_relative_path(&current_path)?;
        let full_path = safe_join(root, &relative_path)?;
        let bytes = fs::read(&full_path)
            .await
            .map_err(|err| format!("не удалось прочитать Minecraft metadata {}: {err}", full_path.display()))?;
        let mut metadata: VersionMetadata = serde_json::from_slice(&bytes)
            .map_err(|err| format!("Minecraft metadata {} повреждён: {err}", relative_path))?;
        if metadata.id.trim().is_empty() {
            metadata.id = current_id.clone();
        }
        let metadata_id = safe_component(&metadata.id)?;
        if !seen.insert(metadata_id.clone()) {
            return Err(format!("обнаружен цикл inheritsFrom: {metadata_id}"));
        }
        let parent = metadata.inherits_from.trim().to_string();
        layers.push((metadata_id.clone(), relative_path, metadata));
        if parent.is_empty() {
            break;
        }
        current_id = safe_component(&parent)?;
        current_path = format!("versions/{current_id}/{current_id}.json");
    }

    if !layers.last().map(|(_, _, v)| v.inherits_from.trim().is_empty()).unwrap_or(false) {
        return Err(format!("цепочка inheritsFrom превышает {MAX_INHERITANCE_DEPTH} уровней"));
    }

    layers.reverse();
    let environment = CompatibilityEnvironment::current(context.features.clone());
    let merged = merge_layers(&layers)?;
    if merged.main_class.trim().is_empty() {
        return Err("resolved Minecraft metadata не содержит mainClass".to_string());
    }

    let (libraries, natives, mut classpath) = resolve_libraries(&merged.libraries, &environment)?;
    if merged.client_version_id.trim().is_empty() {
        return Err("resolved Minecraft metadata не содержит downloads.client".to_string());
    }
    let client_version_id = safe_component(&merged.client_version_id)?;
    let client_jar = format!("versions/{client_version_id}/{client_version_id}.jar");
    classpath.push(client_jar.clone());
    dedupe_preserving_order(&mut classpath);

    let assets_index = merged
        .asset_index
        .as_ref()
        .map(|index| if index.id.trim().is_empty() { merged.assets.clone() } else { index.id.clone() })
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| merged.assets.clone());

    let classpath_absolute = classpath
        .iter()
        .map(|path| safe_join(root, path).map(|value| value.to_string_lossy().to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let classpath_value = classpath_absolute.join(if cfg!(windows) { ";" } else { ":" });
    let library_directory = safe_join(root, "libraries")?.to_string_lossy().to_string();

    let mut variables = HashMap::from([
        ("auth_player_name".to_string(), context.username.clone()),
        ("version_name".to_string(), merged.id.clone()),
        ("game_directory".to_string(), context.game_directory.clone()),
        ("assets_root".to_string(), context.assets_directory.clone()),
        ("game_assets".to_string(), context.assets_directory.clone()),
        ("assets_index_name".to_string(), assets_index.clone()),
        ("auth_uuid".to_string(), context.uuid.clone()),
        ("auth_access_token".to_string(), context.access_token.clone()),
        ("auth_session".to_string(), context.access_token.clone()),
        ("user_type".to_string(), context.user_type.clone()),
        ("version_type".to_string(), if merged.r#type.is_empty() { "release".to_string() } else { merged.r#type.clone() }),
        ("natives_directory".to_string(), context.natives_directory.clone()),
        ("launcher_name".to_string(), context.launcher_name.clone()),
        ("launcher_version".to_string(), context.launcher_version.clone()),
        ("classpath".to_string(), classpath_value),
        ("classpath_separator".to_string(), if cfg!(windows) { ";".to_string() } else { ":".to_string() }),
        ("library_directory".to_string(), library_directory),
        ("auth_xuid".to_string(), String::new()),
        ("clientid".to_string(), String::new()),
    ]);
    if let Ok(width) = std::env::var("NEVERLAUNCHER_RESOLUTION_WIDTH") {
        variables.insert("resolution_width".to_string(), width);
    }
    if let Ok(height) = std::env::var("NEVERLAUNCHER_RESOLUTION_HEIGHT") {
        variables.insert("resolution_height".to_string(), height);
    }

    let raw_game_args = if merged.arguments.game.is_empty() && !merged.minecraft_arguments.trim().is_empty() {
        split_legacy_arguments(&merged.minecraft_arguments)?
    } else {
        resolve_arguments(&merged.arguments.game, &environment)?
    };
    let raw_jvm_args = resolve_arguments(&merged.arguments.jvm, &environment)?;
    let game_args = substitute_all(raw_game_args, &variables)?;
    let mut jvm_args = substitute_all(raw_jvm_args, &variables)?;
    strip_classpath_pair(&mut jvm_args)?;

    let logging_file = if let Some(logging) = merged.logging_client.as_ref() {
        if logging.file.id.trim().is_empty() || logging.argument.trim().is_empty() {
            return Err("logging.client должен содержать file.id и argument".to_string());
        }
        let relative = normalize_relative_path(&format!("assets/log_configs/{}", logging.file.id))?;
        let absolute = safe_join(root, &relative)?.to_string_lossy().to_string();
        let argument = logging.argument.replace("${path}", &absolute);
        if argument.contains("${path}") {
            return Err("logging.client.argument содержит неразрешённый ${path}".to_string());
        }
        jvm_args.push(argument);
        Some(relative)
    } else {
        None
    };

    let metadata_paths = layers.iter().map(|(_, path, _)| path.clone()).collect::<Vec<_>>();
    let inheritance_chain = layers.iter().map(|(id, _, _)| id.clone()).collect::<Vec<_>>();

    Ok(CompatibilityResolution {
        requested_version: requested,
        resolved_version: merged.id,
        minecraft_type: if merged.r#type.is_empty() { "release".to_string() } else { merged.r#type },
        main_class: merged.main_class,
        java_major_version: merged.java_version.map(|value| value.major_version).filter(|value| *value > 0),
        client_jar,
        classpath,
        libraries,
        natives,
        jvm_args,
        game_args,
        assets_index,
        logging_file,
        metadata_paths,
        inheritance_chain,
        environment,
    })
}

fn merge_layers(layers: &[(String, String, VersionMetadata)]) -> Result<MergedVersion, String> {
    let mut merged = MergedVersion::default();
    let mut library_positions = HashMap::<String, usize>::new();

    for (layer_id, _, layer) in layers {
        merged.id = layer.id.clone();
        if !layer.r#type.trim().is_empty() {
            merged.r#type = layer.r#type.clone();
        }
        if !layer.main_class.trim().is_empty() {
            merged.main_class = layer.main_class.clone();
        }
        if !layer.assets.trim().is_empty() {
            merged.assets = layer.assets.clone();
        }
        if layer.asset_index.is_some() {
            merged.asset_index = layer.asset_index.clone();
        }
        if layer.downloads.contains_key("client") {
            merged.client_version_id = layer_id.clone();
        }
        for library in &layer.libraries {
            if library.name.trim().is_empty() {
                return Err(format!("Minecraft metadata {} содержит library без name", layer.id));
            }
            let key = library_identity(&library.name);
            if let Some(index) = library_positions.get(&key).copied() {
                merged.libraries[index] = library.clone();
            } else {
                library_positions.insert(key, merged.libraries.len());
                merged.libraries.push(library.clone());
            }
        }
        merged.arguments.game.extend(layer.arguments.game.clone());
        merged.arguments.jvm.extend(layer.arguments.jvm.clone());
        if !layer.minecraft_arguments.trim().is_empty() {
            merged.minecraft_arguments = layer.minecraft_arguments.clone();
        }
        if layer.java_version.is_some() {
            merged.java_version = layer.java_version.clone();
        }
        if layer.logging.client.is_some() {
            merged.logging_client = layer.logging.client.clone();
        }
    }
    if merged.id.trim().is_empty() {
        return Err("resolved Minecraft metadata не содержит id".to_string());
    }
    Ok(merged)
}

fn resolve_libraries(
    libraries: &[Library],
    environment: &CompatibilityEnvironment,
) -> Result<(Vec<ResolvedLibrary>, Vec<ResolvedNative>, Vec<String>), String> {
    let mut resolved = Vec::new();
    let mut natives = Vec::new();
    let mut classpath = Vec::new();

    for library in libraries {
        if !rules_allow(&library.rules, environment)? {
            continue;
        }
        let artifact = library.downloads.artifact.clone().unwrap_or_default();
        let path = if artifact.path.trim().is_empty() {
            maven_path(&library.name)?
        } else {
            normalize_relative_path(&format!("libraries/{}", artifact.path.trim_start_matches('/')))?
        };
        let url = if !artifact.url.trim().is_empty() {
            artifact.url.clone()
        } else if !library.url.trim().is_empty() {
            format!("{}/{}", library.url.trim_end_matches('/'), path.trim_start_matches("libraries/"))
        } else {
            String::new()
        };
        resolved.push(ResolvedLibrary {
            name: library.name.clone(),
            path: path.clone(),
            url,
            sha1: artifact.sha1.clone(),
            size: artifact.size,
        });
        classpath.push(path);

        if let Some(classifier_template) = native_classifier(library, environment) {
            let classifier = classifier_template.replace("${arch}", native_arch_token(&environment.arch));
            let native = library
                .downloads
                .classifiers
                .get(&classifier)
                .ok_or_else(|| format!("{}: отсутствует classifier {}", library.name, classifier))?;
            let native_path = if native.path.trim().is_empty() {
                maven_path_with_classifier(&library.name, &classifier)?
            } else {
                normalize_relative_path(&format!("libraries/{}", native.path.trim_start_matches('/')))?
            };
            let native_url = if !native.url.trim().is_empty() {
                native.url.clone()
            } else if !library.url.trim().is_empty() {
                format!(
                    "{}/{}",
                    library.url.trim_end_matches('/'),
                    native_path.trim_start_matches("libraries/")
                )
            } else {
                String::new()
            };
            natives.push(ResolvedNative {
                name: library.name.clone(),
                classifier,
                path: native_path,
                url: native_url,
                sha1: native.sha1.clone(),
                size: native.size,
                excludes: library.extract.exclude.clone(),
            });
        }
    }
    Ok((resolved, natives, classpath))
}

fn native_classifier<'a>(library: &'a Library, environment: &CompatibilityEnvironment) -> Option<&'a String> {
    let key = match environment.os.as_str() {
        "windows" => "windows",
        "linux" => "linux",
        "osx" => "osx",
        other => other,
    };
    library.natives.get(key)
}

fn resolve_arguments(arguments: &[Argument], environment: &CompatibilityEnvironment) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for argument in arguments {
        match argument {
            Argument::Plain(value) => out.push(value.clone()),
            Argument::Conditional(value) => {
                if !rules_allow(&value.rules, environment)? {
                    continue;
                }
                match &value.value {
                    ArgumentValue::One(item) => out.push(item.clone()),
                    ArgumentValue::Many(items) => out.extend(items.clone()),
                }
            }
        }
    }
    Ok(out)
}

fn rules_allow(rules: &[Rule], environment: &CompatibilityEnvironment) -> Result<bool, String> {
    if rules.is_empty() {
        return Ok(true);
    }
    let mut allowed = false;
    for rule in rules {
        if rule_matches(rule, environment)? {
            match rule.action.as_str() {
                "allow" => allowed = true,
                "disallow" => allowed = false,
                other => return Err(format!("неподдерживаемое Mojang rule action: {other}")),
            }
        }
    }
    Ok(allowed)
}

fn rule_matches(rule: &Rule, environment: &CompatibilityEnvironment) -> Result<bool, String> {
    if let Some(os) = &rule.os {
        if !os.name.trim().is_empty() && normalize_os_name(&os.name) != environment.os {
            return Ok(false);
        }
        if !os.arch.trim().is_empty() && !pattern_matches(&os.arch, &environment.arch)? {
            return Ok(false);
        }
        if !os.version.trim().is_empty() {
            if environment.os_version.trim().is_empty() || !pattern_matches(&os.version, &environment.os_version)? {
                return Ok(false);
            }
        }
    }
    for (name, expected) in &rule.features {
        if environment.features.get(name).copied().unwrap_or(false) != *expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn pattern_matches(pattern: &str, value: &str) -> Result<bool, String> {
    let anchored = format!("^(?:{pattern})$");
    Regex::new(&anchored)
        .map_err(|err| format!("некорректный regex в Mojang rule {pattern:?}: {err}"))
        .map(|regex| regex.is_match(value))
}

fn substitute_all(values: Vec<String>, variables: &HashMap<String, String>) -> Result<Vec<String>, String> {
    values.into_iter().map(|value| substitute(&value, variables)).collect()
}

fn substitute(value: &str, variables: &HashMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if index + 2 <= bytes.len() && &bytes[index..index + 2] == b"${" {
            let tail = &value[index + 2..];
            let Some(end_rel) = tail.find('}') else {
                return Err(format!("незакрытый placeholder в аргументе: {value}"));
            };
            let key = &tail[..end_rel];
            let replacement = variables
                .get(key)
                .ok_or_else(|| format!("неизвестный Minecraft placeholder ${{{key}}}"))?;
            out.push_str(replacement);
            index += 2 + end_rel + 1;
            continue;
        }
        let ch = value[index..]
            .chars()
            .next()
            .ok_or_else(|| "ошибка UTF-8 при подстановке аргумента".to_string())?;
        out.push(ch);
        index += ch.len_utf8();
    }
    Ok(out)
}

fn strip_classpath_pair(args: &mut Vec<String>) -> Result<(), String> {
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == "-cp" || args[index] == "-classpath" {
            if index + 1 >= args.len() {
                return Err("JVM arguments содержат classpath flag без значения".to_string());
            }
            args.drain(index..=index + 1);
            continue;
        }
        index += 1;
    }
    Ok(())
}

fn split_legacy_arguments(input: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut quote: Option<char> = None;
    loop {
        let Some(ch) = chars.next() else {
            break;
        };
        match quote {
            Some(marker) if ch == marker => quote = None,
            Some(_) if ch == '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            Some(_) => current.push(ch),
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }
    if quote.is_some() {
        return Err("minecraftArguments содержит незакрытую кавычку".to_string());
    }
    if !current.is_empty() {
        out.push(current);
    }
    Ok(out)
}

fn maven_path(name: &str) -> Result<String, String> {
    maven_path_internal(name, None)
}

fn maven_path_with_classifier(name: &str, classifier: &str) -> Result<String, String> {
    maven_path_internal(name, Some(classifier))
}

fn maven_path_internal(name: &str, override_classifier: Option<&str>) -> Result<String, String> {
    let mut coordinate_and_ext = name.splitn(2, '@');
    let coordinate = coordinate_and_ext.next().unwrap_or_default();
    let extension = coordinate_and_ext.next().unwrap_or("jar");
    let parts = coordinate.split(':').collect::<Vec<_>>();
    if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
        return Err(format!("некорректная Maven coordinate: {name}"));
    }
    let classifier = override_classifier.or_else(|| parts.get(3).copied());
    let group = parts[0].replace('.', "/");
    let artifact = parts[1];
    let version = parts[2];
    let suffix = classifier.filter(|value| !value.is_empty()).map(|value| format!("-{value}")).unwrap_or_default();
    normalize_relative_path(&format!("libraries/{group}/{artifact}/{version}/{artifact}-{version}{suffix}.{extension}"))
}

fn library_identity(name: &str) -> String {
    let coordinate = name.split('@').next().unwrap_or(name);
    let parts = coordinate.split(':').collect::<Vec<_>>();
    if parts.len() >= 2 {
        format!("{}:{}:{}", parts[0], parts[1], parts.get(3).copied().unwrap_or_default())
    } else {
        coordinate.to_string()
    }
}

fn dedupe_preserving_order(items: &mut Vec<String>) {
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert(item.clone()));
}

pub fn normalize_relative_path(path: &str) -> Result<String, String> {
    let path = path.replace('\\', "/");
    let candidate = Path::new(&path);
    if candidate.is_absolute() || path.is_empty() {
        return Err(format!("небезопасный compatibility path: {path}"));
    }
    let mut normalized = Vec::new();
    for component in candidate.components() {
        match component {
            Component::Normal(value) => normalized.push(value.to_string_lossy().to_string()),
            _ => return Err(format!("небезопасный compatibility path: {path}")),
        }
    }
    Ok(normalized.join("/"))
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let normalized = normalize_relative_path(relative)?;
    Ok(root.join(normalized))
}

fn safe_component(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.chars().any(|ch| ch.is_control() || matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return Err(format!("небезопасный Minecraft version id: {value}"));
    }
    Ok(trimmed.to_string())
}

fn normalized_current_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "osx",
        "windows" => "windows",
        "linux" => "linux",
        other => other,
    }
}

fn normalize_os_name(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "macos" | "darwin" | "osx" => "osx".to_string(),
        "win" | "windows" => "windows".to_string(),
        "linux" => "linux".to_string(),
        other => other.to_string(),
    }
}

fn normalized_current_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86" => "x86",
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "arm" => "arm",
        other => other,
    }
}

fn native_arch_token(arch: &str) -> &'static str {
    match arch {
        "x86" | "arm" => "32",
        _ => "64",
    }
}

fn detect_os_version() -> String {
    if let Ok(value) = std::env::var("NEVERLAUNCHER_OS_VERSION") {
        if !value.trim().is_empty() {
            return value.trim().to_string();
        }
    }
    let output = match std::env::consts::OS {
        "windows" => Command::new("cmd").args(["/C", "ver"]).output(),
        "macos" => Command::new("sw_vers").arg("-productVersion").output(),
        _ => Command::new("uname").arg("-r").output(),
    };
    let raw = output
        .ok()
        .filter(|value| value.status.success())
        .map(|value| String::from_utf8_lossy(&value.stdout).trim().to_string())
        .unwrap_or_default();

    if std::env::consts::OS == "windows" {
        // `cmd /C ver` returns a localized prefix around the numeric kernel version.
        // Mojang rules compare against Java's `os.version`, so expose only the version token.
        if let Ok(version_re) = Regex::new(r"(?P<version>\d+(?:\.\d+){1,3})") {
            if let Some(captures) = version_re.captures(&raw) {
                if let Some(version) = captures.name("version") {
                    return version.as_str().to_string();
                }
            }
        }
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as stdfs;

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("neverruntime-compat-{name}-{}", std::process::id()));
        let _ = stdfs::remove_dir_all(&root);
        stdfs::create_dir_all(&root).expect("mkdir");
        root
    }

    #[tokio::test]
    async fn resolves_inheritance_rules_classpath_and_placeholders() {
        let root = temp_root("inheritance");
        stdfs::create_dir_all(root.join("versions/1.21.1")).unwrap();
        stdfs::create_dir_all(root.join("versions/custom")).unwrap();
        stdfs::write(
            root.join("versions/1.21.1/1.21.1.json"),
            r#"{
              "id":"1.21.1","type":"release","mainClass":"net.minecraft.client.main.Main","assets":"17",
              "downloads":{"client":{"sha1":"abc","size":10,"url":"https://example/client.jar"}},
              "libraries":[
                {"name":"com.example:base:1.0","downloads":{"artifact":{"path":"com/example/base/1.0/base-1.0.jar","sha1":"aa","size":1,"url":"https://example/base.jar"}}},
                {"name":"com.example:windows-only:1.0","rules":[{"action":"allow","os":{"name":"windows"}}],"downloads":{"artifact":{"path":"com/example/windows-only/1.0/windows-only-1.0.jar"}}}
              ],
              "arguments":{"jvm":["-Djava.library.path=${natives_directory}","-cp","${classpath}"],"game":["--username","${auth_player_name}","--assetsDir","${assets_root}"]},
              "javaVersion":{"majorVersion":21}
            }"#,
        ).unwrap();
        stdfs::write(
            root.join("versions/custom/custom.json"),
            r#"{
              "id":"custom","inheritsFrom":"1.21.1","mainClass":"com.example.CustomMain",
              "libraries":[{"name":"com.example:loader:2.0","downloads":{"artifact":{"path":"com/example/loader/2.0/loader-2.0.jar"}}}],
              "arguments":{"game":["--version","${version_name}"]}
            }"#,
        ).unwrap();

        let ctx = CompatibilityContext {
            username: "Player".into(), uuid: "00000000-0000-0000-0000-000000000000".into(), access_token: "offline".into(), user_type: "legacy".into(),
            launcher_name: "NeverLauncher".into(), launcher_version: "0.10.2".into(), game_directory: root.to_string_lossy().to_string(),
            assets_directory: root.join("assets").to_string_lossy().to_string(), natives_directory: root.join("natives/custom").to_string_lossy().to_string(), features: HashMap::new(),
        };
        let result = resolve_compatibility(&root, "custom", None, &ctx).await.expect("resolve");
        assert_eq!(result.main_class, "com.example.CustomMain");
        assert_eq!(result.java_major_version, Some(21));
        assert_eq!(result.client_jar, "versions/1.21.1/1.21.1.jar");
        assert!(result.classpath.iter().any(|value| value.ends_with("base-1.0.jar")));
        assert!(result.classpath.iter().any(|value| value.ends_with("loader-2.0.jar")));
        assert_eq!(result.classpath.last().unwrap(), "versions/1.21.1/1.21.1.jar");
        assert!(!result.jvm_args.iter().any(|value| value == "-cp"));
        assert!(result.game_args.windows(2).any(|pair| pair[0] == "--username" && pair[1] == "Player"));
        assert_eq!(result.inheritance_chain, vec!["1.21.1", "custom"]);
        let _ = stdfs::remove_dir_all(root);
    }

    #[test]
    fn rules_are_last_matching_rule_wins_and_feature_aware() {
        let env = CompatibilityEnvironment { os: "windows".into(), arch: "x86_64".into(), os_version: "10.0".into(), features: HashMap::from([("is_demo_user".into(), false)]) };
        let rules: Vec<Rule> = serde_json::from_str(r#"[
          {"action":"allow"},
          {"action":"disallow","os":{"name":"linux"}},
          {"action":"allow","features":{"is_demo_user":false}}
        ]"#).unwrap();
        assert!(rules_allow(&rules, &env).unwrap());
    }

    #[test]
    fn rejects_traversal_and_bad_maven_coordinates() {
        assert!(normalize_relative_path("../evil.jar").is_err());
        assert!(normalize_relative_path("/absolute").is_err());
        assert!(maven_path("broken").is_err());
        assert_eq!(maven_path("org.example:demo:1.2.3").unwrap(), "libraries/org/example/demo/1.2.3/demo-1.2.3.jar");
    }

    #[test]
    fn legacy_argument_split_preserves_quoted_values() {
        let args = split_legacy_arguments(r#"--username Player --title "Hello world" --token 'abc def'"#).unwrap();
        assert_eq!(args, vec!["--username", "Player", "--title", "Hello world", "--token", "abc def"]);
    }
}
