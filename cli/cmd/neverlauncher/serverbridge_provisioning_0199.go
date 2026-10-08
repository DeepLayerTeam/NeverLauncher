package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const serverBridgeProvisionStateDir0199 = ".neverlauncher/server-bridge"

type bridgeDetection0199 struct {
	SchemaVersion string   `json:"schemaVersion"`
	Root          string   `json:"root"`
	Platform      string   `json:"platform"`
	Family        string   `json:"family"`
	Confidence    string   `json:"confidence"`
	Evidence      []string `json:"evidence"`
	InstallDir    string   `json:"installDir"`
	ConfigPath    string   `json:"configPath"`
	Sidecar       bool     `json:"sidecar"`
	Hybrid        string   `json:"hybrid,omitempty"`
}

type bridgeEnrollmentRequest0199 struct {
	SchemaVersion  string `json:"schemaVersion"`
	CreatedAt      string `json:"createdAt"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	ProjectID      string `json:"projectId"`
	ProfileID      string `json:"profileId"`
	KeyAlgorithm   string `json:"keyAlgorithm"`
	PublicKey      string `json:"publicKey"`
	KeyFingerprint string `json:"keyFingerprint"`
	BackendURL     string `json:"backendUrl"`
	ArtifactFile   string `json:"artifactFile,omitempty"`
	ArtifactSHA256 string `json:"artifactSha256,omitempty"`
}

type bridgeProvisionState0199 struct {
	SchemaVersion         string `json:"schemaVersion"`
	Platform              string `json:"platform"`
	Version               string `json:"version"`
	ArtifactPath          string `json:"artifactPath"`
	ArtifactSHA256        string `json:"artifactSha256"`
	ConfigPath            string `json:"configPath"`
	IdentityPath          string `json:"identityPath"`
	EnrollmentRequestPath string `json:"enrollmentRequestPath"`
	TransactionID         string `json:"transactionId"`
	InstalledAt           string `json:"installedAt"`
}

type bridgeProvisionChange0199 struct {
	Path       string `json:"path"`
	Existed    bool   `json:"existed"`
	BackupPath string `json:"backupPath,omitempty"`
}

type bridgeProvisionTransaction0199 struct {
	SchemaVersion string                      `json:"schemaVersion"`
	ID            string                      `json:"id"`
	Operation     string                      `json:"operation"`
	Platform      string                      `json:"platform"`
	StartedAt     string                      `json:"startedAt"`
	CompletedAt   string                      `json:"completedAt,omitempty"`
	RolledBackAt  string                      `json:"rolledBackAt,omitempty"`
	Changes       []bridgeProvisionChange0199 `json:"changes"`
}

type bridgeArtifact0199 struct {
	Path       string
	File       string
	Version    string
	SHA256     string
	Bytes      int64
	VerifiedBy string
}

type bridgeIdentityMaterial0199 struct {
	PublicKey   string
	Fingerprint string
}

func handleServerBridge0199(args []string) error {
	if len(args) == 0 {
		return errors.New("использование: nl сервер-мост обнаруживать|установка|регистрировать|состояние|обновление|migrate-v3|откат|хост [параметры]")
	}
	switch args[0] {
	case "detect":
		root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
		if err != nil {
			return err
		}
		detection, err := detectServerBridgePlatform0199(root, flagValue(args, "--platform", ""))
		if err != nil {
			return err
		}
		return writeOrPrintJSON(flagValue(args, "--output", ""), detection)
	case "install":
		return provisionServerBridge0199(args, false)
	case "upgrade":
		return provisionServerBridge0199(args, true)
	case "enroll":
		return enrollServerBridge0199(args)
	case "status":
		return serverBridgeProvisionStatus0199(args)
	case "migrate-v3":
		return serverBridgeMigrateV30200(args)
	case "rollback":
		return rollbackServerBridge0199(args)
	case "host":
		return handleServerBridgeHost01910(args[1:])
	default:
		return fmt.Errorf("неизвестная сервер-мост-подкоманда: %s", args[0])
	}
}

func canonicalServerRoot0199(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		raw = "."
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("сервер корень %s: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("сервер корень является не каталог: %s", abs)
	}
	return filepath.Clean(abs), nil
}

func detectServerBridgePlatform0199(root, explicit string) (bridgeDetection0199, error) {
	explicit = strings.ToLower(strings.TrimSpace(explicit))
	if explicit != "" {
		if !bridgeSupportedPlatform0199(explicit) {
			return bridgeDetection0199{}, fmt.Errorf("неподдерживаемая ServerBridge платформа: %s", explicit)
		}
		hybrid, evidence := detectHybridCore0199(root)
		if hybrid != "" {
			return bridgeDetection0199{}, fmt.Errorf("обнаружен гибридный ядро %s (%s): универсальный адаптер %s нельзя устанавливать без отдельной сертификация матрица", hybrid, strings.Join(evidence, ", "), explicit)
		}
		return bridgeDetectionForPlatform0199(root, explicit, "explicit", []string{"--platform=" + explicit}), nil
	}

	if hybrid, evidence := detectHybridCore0199(root); hybrid != "" {
		return bridgeDetection0199{}, fmt.Errorf("обнаружен несертифицированный гибридный ядро %s (%s); автоматический универсальный предоставление учётной записи отказ с блокировкой", hybrid, strings.Join(evidence, ", "))
	}

	scores := map[string]int{}
	evidence := map[string][]string{}
	add := func(platform string, score int, reason string) {
		if score > scores[platform] {
			scores[platform] = score
		}
		evidence[platform] = appendUnique0199(evidence[platform], reason)
	}

	candidates := collectServerJarCandidates0199(root)
	for _, path := range candidates {
		base := strings.ToLower(filepath.Base(path))
		if strings.HasPrefix(base, "neverlauncher-") && strings.Contains(base, "-bridge-") {
			continue
		}
		nameRules := []struct {
			marker, platform string
			score            int
		}{
			{"folia", "folia", 96}, {"purpur", "purpur", 96}, {"paper", "paper", 94},
			{"spigot", "spigot", 90}, {"craftbukkit", "bukkit", 88}, {"bukkit", "bukkit", 82},
			{"velocity", "velocity", 96}, {"waterfall", "waterfall", 96}, {"bungeecord", "bungeecord", 94}, {"bungee", "bungeecord", 82},
			{"quilt", "quilt", 96}, {"neoforge", "neoforge", 96}, {"forge", "forge", 90}, {"fabric", "fabric", 92},
			{"sponge", "sponge", 92},
		}
		for _, rule := range nameRules {
			if strings.Contains(base, rule.marker) {
				add(rule.platform, rule.score, "jar-name:"+filepath.ToSlash(relativeOrBase0199(root, path)))
			}
		}

		entries, err := readJarEntryNames0199(path, 250000)
		if err != nil {
			continue
		}
		markerRules := []struct {
			entry, platform string
			score           int
		}{
			{"io/papermc/paper/threadedregions/RegionizedServer.class", "folia", 100},
			{"org/purpurmc/purpur/PurpurConfig.class", "purpur", 100},
			{"io/papermc/paper/configuration/GlobalConfiguration.class", "paper", 99},
			{"com/destroystokyo/paper/PaperConfig.class", "paper", 98},
			{"org/spigotmc/SpigotConfig.class", "spigot", 96},
			{"org/bukkit/craftbukkit/Main.class", "bukkit", 90},
			{"com/velocitypowered/proxy/Velocity.class", "velocity", 100},
			{"io/github/waterfallmc/waterfall/conf/WaterfallConfiguration.class", "waterfall", 100},
			{"net/md_5/bungee/BungeeCord.class", "bungeecord", 96},
			{"org/quiltmc/loader/api/QuiltLoader.class", "quilt", 100},
			{"net/neoforged/fml/loading/FMLLoader.class", "neoforge", 100},
			{"net/minecraftforge/fml/loading/FMLLoader.class", "forge", 98},
			{"net/fabricmc/loader/api/FabricLoader.class", "fabric", 98},
			{"org/spongepowered/common/SpongeCommon.class", "sponge", 98},
		}
		set := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			set[entry] = struct{}{}
		}
		for _, rule := range markerRules {
			if _, ok := set[rule.entry]; ok {
				add(rule.platform, rule.score, "jar-entry:"+rule.entry)
			}
		}
		for _, metadata := range []struct {
			name, marker, platform string
			score                  int
		}{
			{"fabric.mod.json", `"quilt_loader"`, "quilt", 100},
			{"fabric.mod.json", `"fabricloader"`, "fabric", 98},
			{"META-INF/neoforge.mods.toml", "neoforge", "neoforge", 100},
			{"META-INF/mods.toml", "minecraftforge", "forge", 98},
		} {
			if _, ok := set[metadata.name]; !ok {
				continue
			}
			text, _ := readZipEntryText0199(path, metadata.name, 128*1024)
			if strings.Contains(strings.ToLower(text), strings.ToLower(metadata.marker)) {
				add(metadata.platform, metadata.score, "jar-metadata:"+metadata.name)
			}
		}
	}

	// Загрузчик структура может предоставлять unambiguous платформа даже когда launcher/server JAR является инициализировать обёртка.
	pathHints := []struct {
		rel, platform string
		score         int
	}{
		{"libraries/net/fabricmc/fabric-loader", "fabric", 97},
		{"libraries/org/quiltmc/quilt-loader", "quilt", 99},
		{"libraries/net/neoforged/neoforge", "neoforge", 99},
		{"libraries/net/minecraftforge/forge", "forge", 97},
	}
	for _, hint := range pathHints {
		if st, err := os.Stat(filepath.Join(root, filepath.FromSlash(hint.rel))); err == nil && st.IsDir() {
			add(hint.platform, hint.score, "layout:"+hint.rel)
		}
	}

	if len(scores) == 0 {
		if _, err := os.Stat(filepath.Join(root, "server.properties")); err == nil {
			add("vanilla", 70, "server.properties")
		}
	}
	if len(scores) == 0 {
		return bridgeDetection0199{}, errors.New("не удалось автоматически определить поддерживаемое Minecraft/proxy ядро; укажите --платформа только если платформа действительно входит в сертифицированный ServerBridge группа")
	}

	type ranked struct {
		platform string
		score    int
	}
	ranks := make([]ranked, 0, len(scores))
	for p, s := range scores {
		ranks = append(ranks, ranked{p, s})
	}
	sort.Slice(ranks, func(i, j int) bool {
		if ranks[i].score == ranks[j].score {
			return ranks[i].platform < ranks[j].platform
		}
		return ranks[i].score > ranks[j].score
	})
	if len(ranks) > 1 && ranks[0].score == ranks[1].score && ranks[0].platform != ranks[1].platform {
		return bridgeDetection0199{}, fmt.Errorf("ядро определяется неоднозначно: %s и %s имеют одинаковую достоверность; автоматический предоставление учётной записи остановлен", ranks[0].platform, ranks[1].platform)
	}
	confidence := "medium"
	if ranks[0].score >= 95 {
		confidence = "high"
	}
	return bridgeDetectionForPlatform0199(root, ranks[0].platform, confidence, evidence[ranks[0].platform]), nil
}

func bridgeDetectionForPlatform0199(root, platform, confidence string, evidence []string) bridgeDetection0199 {
	installDir := filepath.Join(root, "plugins")
	family := "bukkit"
	sidecar := false
	switch platform {
	case "velocity", "bungeecord", "waterfall":
		family = "proxy"
	case "fabric", "quilt", "forge", "neoforge":
		installDir = filepath.Join(root, "mods")
		family = "modloader"
	case "sponge":
		family = "sponge"
	case "vanilla":
		installDir = filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "vanilla")
		family = "vanilla-sidecar"
		sidecar = true
	}
	return bridgeDetection0199{
		SchemaVersion: "1.0", Root: root, Platform: platform, Family: family, Confidence: confidence,
		Evidence: evidence, InstallDir: installDir, ConfigPath: bridgeConfigPath0199(root, platform), Sidecar: sidecar,
	}
}

func bridgeConfigPath0199(root, platform string) string {
	switch platform {
	case "velocity":
		return filepath.Join(root, "plugins", "neverlauncher-velocity", "config.yml")
	case "bungeecord":
		return filepath.Join(root, "plugins", "NeverLauncherBungeeBridge", "config.yml")
	case "waterfall":
		return filepath.Join(root, "plugins", "NeverLauncherWaterfallBridge", "config.yml")
	case "bukkit":
		return filepath.Join(root, "plugins", "NeverLauncherBukkitBridge", "config.yml")
	case "spigot":
		return filepath.Join(root, "plugins", "NeverLauncherSpigotBridge", "config.yml")
	case "paper":
		return filepath.Join(root, "plugins", "NeverLauncherPaperBridge", "config.yml")
	case "purpur":
		return filepath.Join(root, "plugins", "NeverLauncherPurpurBridge", "config.yml")
	case "folia":
		return filepath.Join(root, "plugins", "NeverLauncherFoliaBridge", "config.yml")
	case "fabric":
		return filepath.Join(root, "config", "neverlauncher-fabric-bridge", "config.yml")
	case "quilt":
		return filepath.Join(root, "config", "neverlauncher-quilt-bridge", "config.yml")
	case "forge":
		return filepath.Join(root, "config", "neverlauncher-forge-bridge", "config.yml")
	case "neoforge":
		return filepath.Join(root, "config", "neverlauncher-neoforge-bridge", "config.yml")
	case "sponge":
		return filepath.Join(root, "config", "neverlauncher-sponge-bridge", "config.yml")
	case "vanilla":
		return filepath.Join(root, "config", "neverlauncher-vanilla-bridge", "config.yml")
	default:
		return filepath.Join(root, "config", "neverlauncher-bridge", "config.yml")
	}
}

func bridgeSupportedPlatform0199(platform string) bool {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "velocity", "bungeecord", "waterfall", "bukkit", "spigot", "paper", "purpur", "folia", "fabric", "quilt", "forge", "neoforge", "sponge", "vanilla":
		return true
	default:
		return false
	}
}

func detectHybridCore0199(root string) (string, []string) {
	markers := []string{"mohist", "arclight", "magma", "catserver", "banner", "cardboard"}
	evidence := []string{}
	for _, path := range collectServerJarCandidates0199(root) {
		lower := strings.ToLower(filepath.Base(path))
		for _, marker := range markers {
			if strings.Contains(lower, marker) {
				return marker, []string{"jar-name:" + filepath.ToSlash(relativeOrBase0199(root, path))}
			}
		}
		if len(evidence) > 16 {
			break
		}
		for _, entry := range []string{"META-INF/MANIFEST.MF", "META-INF/mods.toml", "fabric.mod.json"} {
			text, err := readZipEntryText0199(path, entry, 256*1024)
			if err != nil {
				continue
			}
			lowerText := strings.ToLower(text)
			for _, marker := range markers {
				if strings.Contains(lowerText, marker) {
					return marker, []string{"jar-metadata:" + entry, filepath.ToSlash(relativeOrBase0199(root, path))}
				}
			}
		}
	}
	return "", evidence
}

func collectServerJarCandidates0199(root string) []string {
	dirs := []string{root, filepath.Join(root, "mods"), filepath.Join(root, "plugins"), filepath.Join(root, "libraries")}
	seen := map[string]bool{}
	out := []string{}
	const maxJars = 700
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if len(out) >= maxJars {
				return filepath.SkipAll
			}
			if entry.IsDir() {
				if path != dir {
					rel, _ := filepath.Rel(dir, path)
					depth := strings.Count(filepath.ToSlash(rel), "/")
					if dir == root && depth >= 2 && !strings.HasPrefix(filepath.ToSlash(rel), "libraries/") {
						return filepath.SkipDir
					}
					if dir == filepath.Join(root, "libraries") && depth >= 6 {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(entry.Name()), ".jar") {
				return nil
			}
			clean := filepath.Clean(path)
			if !seen[clean] {
				seen[clean] = true
				out = append(out, clean)
			}
			return nil
		})
		if len(out) >= maxJars {
			break
		}
	}
	sort.Strings(out)
	return out
}

func readJarEntryNames0199(path string, max int) ([]string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	n := len(r.File)
	if n > max {
		n = max
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, r.File[i].Name)
	}
	return out, nil
}

func readZipEntryText0199(path, name string, limit int64) (string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name != name {
			continue
		}
		in, err := f.Open()
		if err != nil {
			return "", err
		}
		defer in.Close()
		b, err := io.ReadAll(io.LimitReader(in, limit))
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", os.ErrNotExist
}

func provisionServerBridge0199(args []string, requireExisting bool) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	detection, err := detectServerBridgePlatform0199(root, flagValue(args, "--platform", ""))
	if err != nil {
		return err
	}
	dryRun := flagBool(args, "--dry-run", false)
	statePath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json")
	current, currentErr := readBridgeProvisionState0199(statePath)
	if requireExisting && currentErr != nil {
		return errors.New("сервер-мост обновление требует ранее установленный управляемый мост; сначала выполните nl сервер-мост установка")
	}
	if currentErr == nil && current.Platform != "" && current.Platform != detection.Platform {
		return fmt.Errorf("управляемый мост платформа=%s, обнаруживать платформа=%s; автоматический кроссплатформенный обновление запрещён", current.Platform, detection.Platform)
	}

	bridgeVersion := strings.TrimSpace(flagValue(args, "--bridge-version", version))
	artifact, err := resolveBridgeArtifact0199(args, detection.Platform, bridgeVersion)
	if err != nil {
		return err
	}
	target := filepath.Join(detection.InstallDir, artifact.File)
	if detection.Sidecar {
		target = filepath.Join(detection.InstallDir, artifact.File)
	}
	backend := strings.TrimRight(firstNonEmpty0199(flagValue(args, "--backend", ""), os.Getenv("NEVERLAUNCHER_BACKEND_URL"), "http://127.0.0.1:8080"), "/")
	serverID := firstNonEmpty0199(flagValue(args, "--server-id", ""), os.Getenv("NEVERLAUNCHER_SERVER_ID"), detection.Platform+"-main")
	projectID := firstNonEmpty0199(flagValue(args, "--project", ""), os.Getenv("NEVERLAUNCHER_PROJECT_ID"), "default")
	profileID := firstNonEmpty0199(flagValue(args, "--profile", ""), os.Getenv("NEVERLAUNCHER_PROFILE_ID"), defaultBridgeProfile0199(detection.Platform))
	channel := firstNonEmpty0199(flagValue(args, "--channel", ""), os.Getenv("NEVERLAUNCHER_CHANNEL"), "stable")
	identityPath := filepath.Join(filepath.Dir(detection.ConfigPath), "node-identity.properties")
	if fileExists0199(detection.ConfigPath) {
		values, err := readBridgeConfigValues0199(detection.ConfigPath)
		if err != nil {
			return err
		}
		backend = strings.TrimRight(firstNonEmpty0199(values["backend.url"], backend), "/")
		serverID = firstNonEmpty0199(values["server.id"], serverID)
		projectID = firstNonEmpty0199(values["profile.projectId"], projectID)
		profileID = firstNonEmpty0199(values["profile.profileId"], profileID)
		channel = firstNonEmpty0199(values["profile.channel"], channel)
		if configuredIdentity := strings.TrimSpace(values["identity.file"]); configuredIdentity != "" {
			identityPath = configuredIdentity
			if !filepath.IsAbs(identityPath) {
				identityPath = filepath.Join(filepath.Dir(detection.ConfigPath), identityPath)
			}
			identityPath = filepath.Clean(identityPath)
		}
		for _, conflict := range []struct{ flag, actual string }{
			{"--backend", backend}, {"--server-id", serverID}, {"--project", projectID}, {"--profile", profileID}, {"--channel", channel},
		} {
			if requested := strings.TrimSpace(flagValue(args, conflict.flag, "")); requested != "" && strings.TrimRight(requested, "/") != strings.TrimRight(conflict.actual, "/") {
				return fmt.Errorf("существующий ServerBridge конфигурация %s задаёт %s=%q; запрошенный %q будет не соответствовать среда выполнения конфигурация", detection.ConfigPath, conflict.flag, conflict.actual, requested)
			}
		}
	}
	enrollmentRequestPath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "enrollment-request.json")

	oldArtifacts := existingManagedBridgeArtifacts0199(detection.InstallDir)
	plan := map[string]any{
		"schemaVersion": "1.0", "toolVersion": version, "operation": map[bool]string{false: "install", true: "upgrade"}[requireExisting],
		"dryRun": dryRun, "detection": detection,
		"artifact":                  map[string]any{"source": artifact.Path, "target": target, "version": artifact.Version, "sha256": artifact.SHA256, "bytes": artifact.Bytes, "verifiedBy": artifact.VerifiedBy},
		"configuration":             map[string]any{"path": detection.ConfigPath, "identityPath": identityPath, "backend": backend, "serverId": serverID, "projectId": projectID, "profileId": profileID, "channel": channel},
		"removeOldManagedArtifacts": oldArtifacts,
		"enrollmentRequest":         enrollmentRequestPath,
		"coreFilesModified":         false,
	}
	if dryRun {
		return writeOrPrintJSON(flagValue(args, "--output", ""), plan)
	}

	tx, err := beginBridgeTransaction0199(root, map[bool]string{false: "install", true: "upgrade"}[requireExisting], detection.Platform)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = restoreBridgeTransaction0199(root, &tx, false)
		}
	}()

	// Удалять старый управляемый мост артефакты transactionally до placing точный платформа артефакт.
	for _, old := range oldArtifacts {
		if filepath.Clean(old) == filepath.Clean(target) {
			continue
		}
		if err := txSnapshotAndRemove0199(root, &tx, old); err != nil {
			return err
		}
	}
	if err := txSnapshotPath0199(root, &tx, target); err != nil {
		return err
	}
	if err := atomicCopyFile0199(artifact.Path, target, 0o644); err != nil {
		return err
	}
	copiedHash, copiedSize, err := hashFile(target)
	if err != nil {
		return err
	}
	if !strings.EqualFold(copiedHash, artifact.SHA256) || copiedSize != artifact.Bytes {
		return errors.New("установленный ServerBridge артефакт hash/size несоответствие после атомарный копировать")
	}

	if err := txSnapshotPath0199(root, &tx, detection.ConfigPath); err != nil {
		return err
	}
	if _, err := os.Stat(detection.ConfigPath); errors.Is(err, os.ErrNotExist) {
		if err := writeBridgeConfig0199(detection.ConfigPath, backend, serverID, projectID, profileID, channel); err != nil {
			return err
		}
	}

	identityExisted := fileExists0199(identityPath)
	if !identityExisted {
		if err := txSnapshotPath0199(root, &tx, identityPath); err != nil {
			return err
		}
	}
	identity, err := loadOrCreateNodeIdentity0199(identityPath)
	if err != nil {
		return err
	}

	req := bridgeEnrollmentRequest0199{
		SchemaVersion: "1.0", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), ID: serverID, Name: firstNonEmpty0199(flagValue(args, "--name", ""), serverID),
		Kind: detection.Platform, ProjectID: projectID, ProfileID: profileID, KeyAlgorithm: "ed25519", PublicKey: identity.PublicKey,
		KeyFingerprint: identity.Fingerprint, BackendURL: backend, ArtifactFile: artifact.File, ArtifactSHA256: artifact.SHA256,
	}
	if err := txSnapshotPath0199(root, &tx, enrollmentRequestPath); err != nil {
		return err
	}
	if err := writeJSONSecure0199(enrollmentRequestPath, req, 0o644); err != nil {
		return err
	}

	if detection.Sidecar {
		if err := installVanillaSidecarLaunchers0199(root, artifact.File, &tx); err != nil {
			return err
		}
	}

	if err := txSnapshotPath0199(root, &tx, statePath); err != nil {
		return err
	}
	next := bridgeProvisionState0199{
		SchemaVersion: "1.0", Platform: detection.Platform, Version: artifact.Version, ArtifactPath: target,
		ArtifactSHA256: artifact.SHA256, ConfigPath: detection.ConfigPath, IdentityPath: identityPath,
		EnrollmentRequestPath: enrollmentRequestPath, TransactionID: tx.ID, InstalledAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeJSONSecure0199(statePath, next, 0o644); err != nil {
		return err
	}
	tx.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := persistBridgeTransaction0199(root, tx); err != nil {
		return err
	}
	committed = true

	plan["status"] = "installed"
	if requireExisting {
		plan["status"] = "upgraded"
	}
	plan["transactionId"] = tx.ID
	plan["nodeIdentity"] = map[string]any{"keyAlgorithm": "ed25519", "keyFingerprint": identity.Fingerprint, "publicKey": identity.PublicKey, "privateKey": "local-only"}
	if flagBool(args, "--enroll", false) {
		enrollArgs := []string{"enroll", "--server-root", root, "--backend", backend}
		if token := flagValue(args, "--token", ""); token != "" {
			enrollArgs = append(enrollArgs, "--token", token)
		}
		if flagBool(args, "--rotate", false) {
			enrollArgs = append(enrollArgs, "--rotate")
		}
		if err := enrollServerBridge0199(enrollArgs); err != nil {
			return fmt.Errorf("мост установленный но регистрация ошибка: %w", err)
		}
		plan["enrollment"] = "completed"
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), plan)
}

func resolveBridgeArtifact0199(args []string, platform, requestedVersion string) (bridgeArtifact0199, error) {
	explicit := strings.TrimSpace(flagValue(args, "--artifact", ""))
	artifactDir := strings.TrimSpace(flagValue(args, "--artifact-dir", ""))
	if explicit == "" && artifactDir == "" {
		candidates := []string{"artifacts/plugins", "dist", "."}
		for _, candidate := range candidates {
			if st, err := os.Stat(candidate); err == nil && st.IsDir() {
				artifactDir = candidate
				break
			}
		}
	}
	var path string
	if explicit != "" {
		path = explicit
	} else {
		if artifactDir == "" {
			return bridgeArtifact0199{}, errors.New("укажите --артефакт <JAR> или --артефакт-dir <release/artifact каталог>")
		}
		entries, err := os.ReadDir(artifactDir)
		if err != nil {
			return bridgeArtifact0199{}, err
		}
		prefix := "neverlauncher-" + platform + "-bridge-"
		suffix := ".jar"
		matches := []string{}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
				matches = append(matches, name)
			}
		}
		if len(matches) == 0 {
			return bridgeArtifact0199{}, fmt.Errorf("в %s нет артефакт для платформа=%s", artifactDir, platform)
		}
		sort.Slice(matches, func(i, j int) bool {
			return compareSemver0199(extractBridgeVersion0199(matches[i], platform), extractBridgeVersion0199(matches[j], platform)) > 0
		})
		if requestedVersion != "" && requestedVersion != "dev" {
			exact := "neverlauncher-" + platform + "-bridge-" + requestedVersion + ".jar"
			found := false
			for _, name := range matches {
				if name == exact {
					path = filepath.Join(artifactDir, name)
					found = true
					break
				}
			}
			if !found {
				return bridgeArtifact0199{}, fmt.Errorf("артефакт точная версия %s для %s не found в %s", requestedVersion, platform, artifactDir)
			}
		} else {
			path = filepath.Join(artifactDir, matches[0])
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return bridgeArtifact0199{}, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return bridgeArtifact0199{}, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return bridgeArtifact0199{}, fmt.Errorf("недопустимый мост артефакт: %s", abs)
	}
	file := filepath.Base(abs)
	expectedPrefix := "neverlauncher-" + platform + "-bridge-"
	if !strings.HasPrefix(file, expectedPrefix) || !strings.HasSuffix(file, ".jar") {
		return bridgeArtifact0199{}, fmt.Errorf("артефакт filename делает не соответствовать обнаруживать платформа %s: %s", platform, file)
	}
	artifactVersion := extractBridgeVersion0199(file, platform)
	if requestedVersion != "" && requestedVersion != "dev" && artifactVersion != requestedVersion {
		return bridgeArtifact0199{}, fmt.Errorf("артефакт версия %s делает не соответствовать запрошенный %s", artifactVersion, requestedVersion)
	}
	if err := verifyBridgeArtifactShape0199(abs, platform); err != nil {
		return bridgeArtifact0199{}, err
	}
	digest, size, err := hashFile(abs)
	if err != nil {
		return bridgeArtifact0199{}, err
	}
	verifiedBy, err := verifyBridgeArtifactReleaseMetadata0199(abs, platform, artifactVersion, digest, size)
	if err != nil {
		if !flagBool(args, "--allow-unverified-artifact", false) {
			return bridgeArtifact0199{}, err
		}
		verifiedBy = "override:--allow-unverified-artifact"
	}
	return bridgeArtifact0199{Path: abs, File: file, Version: artifactVersion, SHA256: digest, Bytes: size, VerifiedBy: verifiedBy}, nil
}

func verifyBridgeArtifactReleaseMetadata0199(path, platform, artifactVersion, digest string, size int64) (string, error) {
	dir := filepath.Dir(path)
	certPath := filepath.Join(dir, serverBridge3CertificationReleaseFile)
	if raw, err := os.ReadFile(certPath); err == nil {
		var cert serverBridge2Certification0150
		if err := json.Unmarshal(raw, &cert); err != nil {
			return "", fmt.Errorf("недопустимый %s: %w", certPath, err)
		}
		targets := serverBridgeReleaseTargetsForVersion0150(artifactVersion)
		expectedSchema := "1.0"
		if serverBridgeGARequired0200(artifactVersion) {
			expectedSchema = "1.1"
		}
		if cert.SchemaVersion != expectedSchema || cert.Release != "ServerBridge 3" || cert.Version != artifactVersion || cert.Status != "certified" || cert.ProtocolVersion != 3 || !cert.ZeroPatch || cert.NodeIdentity != "Ed25519" || !cert.OneTimeJoin || cert.TargetCount != len(targets) || len(cert.Artifacts) != len(targets) {
			return "", fmt.Errorf("%s делает не contain полный сертифицированный ServerBridge 3 группа для версия %s", certPath, artifactVersion)
		}
		if serverBridgeSecurityCertificationRequired01912(artifactVersion) {
			if cert.SecurityProfile != "serverbridge3-security-01912" || !strings.EqualFold(cert.SecurityCapabilityDigest, "088d7922033afa09c4489989fab5d71603e3425a08243a95588036f5c27505c4") || !cert.CapabilityDowngrade || !cert.CommandSignatures || !cert.EventSignatures || !cert.RuntimeInstanceBinding || !cert.OnlineKeyRotation || !serverBridgeSecurityFeaturesExact01912(cert.RequiredSecurityFeatures) {
				return "", errors.New("ServerBridge 3 безопасность сертификация метаданные несоответствие")
			}
		}
		if serverBridgeGARequired0200(artifactVersion) && (!cert.GA || !cert.ProtocolV3Frozen || !strings.EqualFold(cert.ProtocolV3FeatureDigest, serverBridgeV3FrozenFeatureDigest0200) || cert.ProtocolV2Mode != "compatibility-deprecated" || !cert.InstallerUpgradePath || cert.UnifiedOperatorAPI != "/api/v1/server-bridge/overview" || !cert.PublicCompatibilityMatrix) {
			return "", errors.New("ServerBridge 3 GA сертификация метаданные несоответствие")
		}
		for _, item := range cert.Artifacts {
			if item.ID != platform {
				continue
			}
			if item.File != filepath.Base(path) || !strings.EqualFold(item.SHA256, digest) || item.Bytes != size {
				return "", fmt.Errorf("сертифицированный метаданные несоответствие для %s", platform)
			}
			return serverBridge3CertificationReleaseFile, nil
		}
		return "", fmt.Errorf("%s делает не contain платформа %s", certPath, platform)
	}
	allowPath := filepath.Join(dir, "BRIDGE_RELEASE_ALLOWLIST.json")
	raw, err := os.ReadFile(allowPath)
	if err != nil {
		return "", errors.New("рабочий предоставление учётной записи требует sibling SERVERBRIDGE3_CERTIFICATION.JSON или BRIDGE_RELEASE_ALLOWLIST.JSON; использовать --разрешать-unverified-артефакт только для разработка")
	}
	var document serverBridgeReleaseAllowlist01912
	if err := json.Unmarshal(raw, &document); err != nil {
		return "", fmt.Errorf("недопустимый %s: %w", allowPath, err)
	}
	if document.SchemaVersion != "3.0" || document.Release != "ServerBridge 3" || document.ProtocolVersion != 3 || document.MinimumProtocolVersion != 3 || document.SecurityProfile != "serverbridge3-security-01912" || !strings.EqualFold(document.SecurityCapabilityDigest, "088d7922033afa09c4489989fab5d71603e3425a08243a95588036f5c27505c4") || !serverBridgeSecurityFeaturesExact01912(document.RequiredFeatures) {
		return "", errors.New("ServerBridge 3 релиз список разрешений безопасность метаданные несоответствие")
	}
	if serverBridgeGARequired0200(artifactVersion) && (!document.GA || !document.ProtocolV3Frozen || !strings.EqualFold(document.ProtocolV3FeatureDigest, serverBridgeV3FrozenFeatureDigest0200) || document.ProtocolV2Mode != "compatibility-deprecated") {
		return "", errors.New("ServerBridge 3 GA релиз список разрешений метаданные несоответствие")
	}
	policy := document.Releases[artifactVersion]
	if policy == nil {
		return "", fmt.Errorf("релиз список разрешений делает не contain точная версия %s", artifactVersion)
	}
	field := bridgeAllowlistField0199(platform)
	values := policy[field]
	if len(values) != 1 || !strings.EqualFold(strings.TrimSpace(values[0]), digest) {
		return "", fmt.Errorf("релиз список разрешений field %s делает не соответствовать артефакт SHA-256", field)
	}
	return "BRIDGE_RELEASE_ALLOWLIST.json", nil
}

func bridgeAllowlistField0199(platform string) string {
	switch platform {
	case "bungeecord":
		return "bungeeCordSha256"
	default:
		return platform + "Sha256"
	}
}

func extractBridgeVersion0199(file, platform string) string {
	prefix := "neverlauncher-" + platform + "-bridge-"
	return strings.TrimSuffix(strings.TrimPrefix(file, prefix), ".jar")
}

func compareSemver0199(a, b string) int {
	parse := func(v string) []int {
		base := strings.SplitN(v, "-", 2)[0]
		parts := strings.Split(base, ".")
		out := make([]int, 3)
		for i := 0; i < len(parts) && i < 3; i++ {
			fmt.Sscanf(parts[i], "%d", &out[i])
		}
		return out
	}
	aa, bb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if aa[i] > bb[i] {
			return 1
		}
		if aa[i] < bb[i] {
			return -1
		}
	}
	return strings.Compare(a, b)
}

func existingManagedBridgeArtifacts0199(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if strings.HasPrefix(name, "neverlauncher-") && strings.Contains(name, "-bridge-") && strings.HasSuffix(name, ".jar") {
			out = append(out, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(out)
	return out
}

func verifyBridgeArtifactShape0199(path, platform string) error {
	required := map[string][]string{
		"velocity":   {"velocity-plugin.json", "ru/neverlauncher/bridge/velocity/NeverLauncherVelocityBridge.class"},
		"bungeecord": {"bungee.yml", "ru/neverlauncher/bridge/bungeecord/NeverLauncherBungeeCordBridge.class"},
		"waterfall":  {"bungee.yml", "ru/neverlauncher/bridge/waterfall/NeverLauncherWaterfallBridge.class"},
		"bukkit":     {"plugin.yml", "ru/neverlauncher/bridge/bukkit/NeverLauncherBukkitBridge.class"},
		"spigot":     {"plugin.yml", "ru/neverlauncher/bridge/spigot/NeverLauncherSpigotBridge.class"},
		"paper":      {"plugin.yml", "ru/neverlauncher/bridge/paper/NeverLauncherPaperBridge.class"},
		"purpur":     {"plugin.yml", "ru/neverlauncher/bridge/purpur/NeverLauncherPurpurBridge.class"},
		"folia":      {"plugin.yml", "ru/neverlauncher/bridge/folia/NeverLauncherFoliaBridge.class"},
		"fabric":     {"fabric.mod.json", "ru/neverlauncher/bridge/fabric/NeverLauncherFabricBridge.class"},
		"quilt":      {"quilt.mod.json", "ru/neverlauncher/bridge/quilt/NeverLauncherQuiltBridge.class"},
		"forge":      {"META-INF/mods.toml", "ru/neverlauncher/bridge/forge/NeverLauncherForgeBridge.class"},
		"neoforge":   {"META-INF/neoforge.mods.toml", "ru/neverlauncher/bridge/neoforge/NeverLauncherNeoForgeBridge.class"},
		"sponge":     {"ru/neverlauncher/bridge/sponge/NeverLauncherSpongeBridge.class"},
		"vanilla":    {"META-INF/MANIFEST.MF", "ru/neverlauncher/bridge/vanilla/NeverLauncherVanillaBridge.class"},
	}
	r, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("недопустимый ServerBridge JAR %s: %w", path, err)
	}
	defer r.Close()
	entries := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		entries[f.Name] = f
	}
	for _, entry := range required[platform] {
		if entries[entry] == nil {
			return fmt.Errorf("%s артефакт является отсутствующий обязательный платформа запись %s", platform, entry)
		}
	}
	if platform == "folia" {
		text, err := readZipEntryText0199(path, "plugin.yml", 128*1024)
		if err != nil {
			return err
		}
		if !strings.Contains(text, "folia-supported: true") {
			return errors.New("Folia артефакт является не marked Folia-поддерживаемый")
		}
	}
	if platform == "vanilla" {
		text, err := readZipEntryText0199(path, "META-INF/MANIFEST.MF", 128*1024)
		if err != nil {
			return err
		}
		if !strings.Contains(text, "Main-Class: ru.neverlauncher.bridge.vanilla.NeverLauncherVanillaBridge") {
			return errors.New("Vanilla ServerBridge вспомогательный процесс Главный-Класс является отсутствующий")
		}
	}
	return nil
}

func readBridgeConfigValues0199(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	section := ""
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(rawLine) == len(strings.TrimLeft(rawLine, " \t")) && strings.HasSuffix(line, ":") {
			section = strings.TrimSpace(strings.TrimSuffix(line, ":"))
			continue
		}
		pos := strings.IndexByte(line, ':')
		if pos < 0 {
			pos = strings.IndexByte(line, '=')
		}
		if pos <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:pos])
		value := strings.TrimSpace(line[pos+1:])
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		if section != "" {
			key = section + "." + key
		}
		values[key] = value
	}
	return values, nil
}

func writeBridgeConfig0199(path, backend, serverID, projectID, profileID, channel string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body := fmt.Sprintf("# Managed by `nl server-bridge install` (NeverLauncher %s).\n# Only ServerBridge-owned files are changed; Minecraft/proxy core/authlib files are untouched.\nbackend:\n  url: %q\n  timeoutMs: 5000\n  retries: 2\n  heartbeatIntervalSeconds: 30\nserver:\n  id: %q\nidentity:\n  file: %q\nprofile:\n  projectId: %q\n  profileId: %q\n  channel: %q\nsecurity:\n  failMode: closed\n  requireLauncherSession: true\n  requireIntegrity: true\ntelemetry:\n  sampleIntervalSeconds: 10\n  samplingBudgetMs: 20\n", version, backend, serverID, "node-identity.properties", projectID, profileID, channel)
	return atomicWrite0199(path, []byte(body), 0o644)
}

func loadOrCreateNodeIdentity0199(path string) (bridgeIdentityMaterial0199, error) {
	if fileExists0199(path) {
		return loadNodeIdentityPublic0199(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return bridgeIdentityMaterial0199{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return bridgeIdentityMaterial0199{}, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return bridgeIdentityMaterial0199{}, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return bridgeIdentityMaterial0199{}, err
	}
	fingerprintBytes := sha256.Sum256(pub)
	fingerprint := hex.EncodeToString(fingerprintBytes[:])
	enc := base64.RawURLEncoding
	text := "# NeverLauncher ServerBridge node identity - PRIVATE KEY, do not share\n" +
		"formatVersion=1\nkeyAlgorithm=ed25519\n" +
		"publicKey=" + enc.EncodeToString(pub) + "\n" +
		"keyFingerprint=" + fingerprint + "\n" +
		"publicKeyX509=" + enc.EncodeToString(pubDER) + "\n" +
		"privateKeyPkcs8=" + enc.EncodeToString(privDER) + "\n"
	if err := atomicWrite0199(path, []byte(text), 0o600); err != nil {
		return bridgeIdentityMaterial0199{}, err
	}
	_ = os.Chmod(path, 0o600)
	return bridgeIdentityMaterial0199{PublicKey: enc.EncodeToString(pub), Fingerprint: fingerprint}, nil
}

func loadNodeIdentityPublic0199(path string) (bridgeIdentityMaterial0199, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return bridgeIdentityMaterial0199{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return bridgeIdentityMaterial0199{}, fmt.Errorf("узел идентичность должен быть regular non-символическая ссылка файл: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return bridgeIdentityMaterial0199{}, fmt.Errorf("узел идентичность разрешения должен быть закрытый (0600): %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return bridgeIdentityMaterial0199{}, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			values[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	if values["formatVersion"] != "1" || strings.ToLower(values["keyAlgorithm"]) != "ed25519" {
		return bridgeIdentityMaterial0199{}, errors.New("неподдерживаемый узел идентичность формат")
	}
	pub, err := base64.RawURLEncoding.DecodeString(values["publicKey"])
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return bridgeIdentityMaterial0199{}, errors.New("недопустимый узел идентичность publicKey")
	}
	sum := sha256.Sum256(pub)
	fp := hex.EncodeToString(sum[:])
	if !strings.EqualFold(fp, values["keyFingerprint"]) {
		return bridgeIdentityMaterial0199{}, errors.New("узел идентичность отпечаток несоответствие")
	}
	// Гарантировать Java среда выполнения будет быть able к parse закрытый ключ материал до предоставление учётной записи succeeds.
	privDER, err := base64.RawURLEncoding.DecodeString(values["privateKeyPkcs8"])
	if err != nil {
		return bridgeIdentityMaterial0199{}, errors.New("недопустимый узел идентичность privateKeyPkcs8")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return bridgeIdentityMaterial0199{}, errors.New("недопустимый узел идентичность PKCS#8 закрытый ключ")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || !privateKey.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(pub)) {
		return bridgeIdentityMaterial0199{}, errors.New("узел идентичность keypair несоответствие")
	}
	return bridgeIdentityMaterial0199{PublicKey: values["publicKey"], Fingerprint: fp}, nil
}

func enrollServerBridge0199(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	requestPath := flagValue(args, "--request", filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "enrollment-request.json"))
	raw, err := os.ReadFile(requestPath)
	if err != nil {
		return fmt.Errorf("чтение регистрация запрос: %w", err)
	}
	var req bridgeEnrollmentRequest0199
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("недопустимый регистрация запрос: %w", err)
	}
	if req.ID == "" || req.Kind == "" || req.PublicKey == "" || req.KeyFingerprint == "" {
		return errors.New("регистрация запрос является неполный")
	}
	backend := strings.TrimRight(firstNonEmpty0199(flagValue(args, "--backend", ""), req.BackendURL, os.Getenv("NEVERLAUNCHER_BACKEND_URL")), "/")
	token := backendToken(args)
	rotate := flagBool(args, "--rotate", false)
	dryRun := flagBool(args, "--dry-run", false)
	endpoint := "/api/v1/server-bridge/servers/register"
	body := map[string]any{"id": req.ID, "name": req.Name, "kind": req.Kind, "projectId": req.ProjectID, "profileId": req.ProfileID, "keyAlgorithm": "ed25519", "publicKey": req.PublicKey}
	if rotate {
		endpoint = "/api/v1/server-bridge/servers/" + req.ID + "/rotate-identity"
		body = map[string]any{"keyAlgorithm": "ed25519", "publicKey": req.PublicKey}
	}
	if dryRun {
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schemaVersion": "1.0", "dryRun": true, "backend": backend, "endpoint": endpoint, "request": body, "keyFingerprint": req.KeyFingerprint})
	}
	if backend == "" {
		return errors.New("регистрировать требует --серверная часть или backendUrl в регистрация-запрос.JSON")
	}
	if token == "" {
		return errors.New("регистрировать требует --токен или NEVERLAUNCHER_TOKEN")
	}
	payload, err := httpJSONWithAuth("POST", backend+endpoint, body, token)
	if err != nil && !rotate {
		// Регистрация является намеренно идемпотентный когда точный узел идентичность является уже present.
		listed, listErr := httpJSONWithAuth("GET", backend+"/api/v1/server-bridge/servers", nil, token)
		if listErr == nil {
			if node := findBackendBridgeNode0199(listed, req.ID); node != nil {
				if strings.EqualFold(fmt.Sprint(node["keyFingerprint"]), req.KeyFingerprint) && strings.EqualFold(fmt.Sprint(node["kind"]), req.Kind) {
					payload = map[string]any{"status": "already-enrolled", "server": node}
					err = nil
				}
			}
		}
	}
	if err != nil {
		return err
	}
	enrollmentState := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "enrollment.json")
	record := map[string]any{"schemaVersion": "1.0", "enrolledAt": time.Now().UTC().Format(time.RFC3339Nano), "backend": backend, "serverId": req.ID, "keyFingerprint": req.KeyFingerprint, "rotate": rotate, "response": payload}
	if err := writeJSONSecure0199(enrollmentState, record, 0o600); err != nil {
		return err
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), record)
}

func serverBridgeMigrateV30200(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	statePath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json")
	current, err := readBridgeProvisionState0199(statePath)
	if err != nil {
		return errors.New("сервер-мост migrate-v3 требует существующий управляемый ServerBridge установка; запуск `nl server-bridge install` первый")
	}
	if compareSemver0199(version, "0.20.0") < 0 {
		return fmt.Errorf("сервер-мост migrate-v3 требует nl >= 0.20.0; текущий CLI является %s", version)
	}
	targetVersion := strings.TrimSpace(flagValue(args, "--bridge-version", version))
	if compareSemver0199(targetVersion, "0.20.0") < 0 {
		return fmt.Errorf("ServerBridge 3 GA миграция цель должен быть >= 0.20.0, получил %s", targetVersion)
	}

	backend := strings.TrimRight(firstNonEmpty0199(flagValue(args, "--backend", ""), os.Getenv("NEVERLAUNCHER_BACKEND_URL")), "/")
	if backend == "" && current.ConfigPath != "" && fileExists0199(current.ConfigPath) {
		if values, readErr := readBridgeConfigValues0199(current.ConfigPath); readErr == nil {
			backend = strings.TrimRight(values["backend.url"], "/")
		}
	}
	if backend == "" {
		return errors.New("сервер-мост migrate-v3 требует Серверная часть URL к проверять Протокол v3 GA возможность до заменять артефакт")
	}
	capURL := backend + "/api/v1/server-bridge/capabilities?protocols=3&features=" + strings.Join([]string{
		"protocol.capability-negotiation", "protocol.feature-flags", "protocol.rolling-upgrade-v2",
		"security.ed25519-node-requests", "security.single-use-node-nonce", "integrity.sha256", "join.one-time", "handoff.one-time", "topology.runtime-learned",
		"runtime.node-discovery-v1", "security.runtime-identity-ed25519", "telemetry.server-v1", "events.ordered-stream-v1", "control.secure-channel-v1", "control.ha-channel-v2",
		"topology.routing-v2", "session.player-lifecycle-v3", "security.protocol-v3-signing-domain", "security.capability-downgrade-protection", "security.command-signatures-v3",
		"security.event-signatures-v3", "security.runtime-instance-binding-v3", "security.online-key-rotation-v1",
	}, ",")
	capabilities, err := httpJSONWithAuth("GET", capURL, nil, "")
	if err != nil {
		return fmt.Errorf("Протокол v3 GA Серверная часть предварительная проверка ошибка: %w", err)
	}
	data, _ := capabilities["data"].(map[string]any)
	if intFromJSON0200(data["negotiatedProtocolVersion"]) != 3 || data["protocolV3Frozen"] != true || fmt.Sprint(data["protocolV3Status"]) != "ga-frozen" || fmt.Sprint(data["protocolV3FeatureDigest"]) != "098bcd1e6f0f57044404edf994b32482ebc70e77054f4f91ff35e848c9d6fdbc" {
		return errors.New("Серверная часть делает не предоставлять зафиксированный ServerBridge 3 GA Протокол v3 возможность задать; миграция aborted до touching сервер файлы")
	}

	upgradeArgs := append([]string{}, args...)
	upgradeArgs[0] = "upgrade"
	if strings.TrimSpace(flagValue(upgradeArgs, "--bridge-version", "")) == "" {
		upgradeArgs = append(upgradeArgs, "--bridge-version", targetVersion)
	}
	if strings.TrimSpace(flagValue(upgradeArgs, "--backend", "")) == "" {
		upgradeArgs = append(upgradeArgs, "--backend", backend)
	}
	if flagBool(upgradeArgs, "--dry-run", false) {
		return provisionServerBridge0199(upgradeArgs, true)
	}
	fromVersion := current.Version
	if err := provisionServerBridge0199(upgradeArgs, true); err != nil {
		return err
	}
	updated, err := readBridgeProvisionState0199(statePath)
	if err != nil {
		return fmt.Errorf("чтение post-миграция ServerBridge состояние: %w", err)
	}
	if compareSemver0199(updated.Version, "0.20.0") < 0 {
		return fmt.Errorf("ServerBridge миграция committed unexpected версия %s", updated.Version)
	}
	record := map[string]any{
		"schemaVersion": "1.0", "toolVersion": version, "status": "artifact-migrated",
		"fromVersion": fromVersion, "toVersion": updated.Version, "protocolFrom": "v2/rolling", "protocolTo": "v3-ga-frozen",
		"backend": backend, "transactionId": updated.TransactionID, "migratedAt": time.Now().UTC().Format(time.RFC3339Nano),
		"restartRequired": true,
	}
	migrationPath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "protocol-v3-ga-migration.json")
	if err := writeJSONSecure0199(migrationPath, record, 0o644); err != nil {
		return fmt.Errorf("ServerBridge артефакт мигрировать но миграция запись может не быть сохранённый: %w", err)
	}
	return nil
}

func intFromJSON0200(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		i, _ := v.Int64()
		return int(i)
	default:
		return 0
	}
}

func serverBridgeProvisionStatus0199(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	detection, detectErr := detectServerBridgePlatform0199(root, flagValue(args, "--platform", ""))
	statePath := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json")
	state, stateErr := readBridgeProvisionState0199(statePath)
	result := map[string]any{"schemaVersion": "1.0", "toolVersion": version, "root": root}
	if detectErr != nil {
		result["detectionError"] = detectErr.Error()
	} else {
		result["detection"] = detection
	}
	if stateErr != nil {
		result["status"] = "not-installed"
		return writeOrPrintJSON(flagValue(args, "--output", ""), result)
	}
	result["status"] = "installed"
	result["state"] = state
	if hash, size, err := hashFile(state.ArtifactPath); err == nil {
		result["artifact"] = map[string]any{"exists": true, "sha256": hash, "bytes": size, "matchesManagedState": strings.EqualFold(hash, state.ArtifactSHA256)}
	} else {
		result["artifact"] = map[string]any{"exists": false, "error": err.Error()}
	}
	if identity, err := loadNodeIdentityPublic0199(state.IdentityPath); err == nil {
		result["nodeIdentity"] = map[string]any{"keyAlgorithm": "ed25519", "keyFingerprint": identity.Fingerprint, "publicKey": identity.PublicKey}
	} else {
		result["nodeIdentityError"] = err.Error()
	}

	backend := strings.TrimRight(firstNonEmpty0199(flagValue(args, "--backend", ""), os.Getenv("NEVERLAUNCHER_BACKEND_URL")), "/")
	token := backendToken(args)
	if backend != "" && token != "" {
		payload, err := httpJSONWithAuth("GET", backend+"/api/v1/server-bridge/servers", nil, token)
		if err != nil {
			result["backendError"] = err.Error()
		} else {
			reqPath := state.EnrollmentRequestPath
			raw, _ := os.ReadFile(reqPath)
			var req bridgeEnrollmentRequest0199
			_ = json.Unmarshal(raw, &req)
			node := findBackendBridgeNode0199(payload, req.ID)
			if node == nil {
				result["backendNode"] = map[string]any{"status": "not-enrolled", "serverId": req.ID}
			} else {
				result["backendNode"] = node
			}
		}
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), result)
}

func findBackendBridgeNode0199(payload map[string]any, id string) map[string]any {
	data, _ := payload["data"].(map[string]any)
	items, _ := data["items"].([]any)
	for _, item := range items {
		row, _ := item.(map[string]any)
		if row == nil {
			continue
		}
		if strings.TrimSpace(fmt.Sprint(row["id"])) == strings.TrimSpace(id) {
			return row
		}
	}
	return nil
}

func rollbackServerBridge0199(args []string) error {
	root, err := canonicalServerRoot0199(flagValue(args, "--server-root", "."))
	if err != nil {
		return err
	}
	txID := strings.TrimSpace(flagValue(args, "--transaction", ""))
	if txID == "" {
		state, err := readBridgeProvisionState0199(filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "current.json"))
		if err != nil {
			return errors.New("откат требует --транзакция или активный управляемый ServerBridge состояние")
		}
		txID = state.TransactionID
	}
	txPath := bridgeTransactionPath0199(root, txID)
	raw, err := os.ReadFile(txPath)
	if err != nil {
		return err
	}
	var tx bridgeProvisionTransaction0199
	if err := json.Unmarshal(raw, &tx); err != nil {
		return err
	}
	if tx.RolledBackAt != "" {
		return fmt.Errorf("транзакция %s является уже rolled back", tx.ID)
	}
	if flagBool(args, "--dry-run", false) {
		return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schemaVersion": "1.0", "dryRun": true, "transaction": tx})
	}
	if err := restoreBridgeTransaction0199(root, &tx, true); err != nil {
		return err
	}
	return writeOrPrintJSON(flagValue(args, "--output", ""), map[string]any{"schemaVersion": "1.0", "status": "rolled-back", "transactionId": tx.ID, "platform": tx.Platform})
}

func beginBridgeTransaction0199(root, operation, platform string) (bridgeProvisionTransaction0199, error) {
	nonce := make([]byte, 6)
	if _, err := rand.Read(nonce); err != nil {
		return bridgeProvisionTransaction0199{}, err
	}
	id := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(nonce)
	tx := bridgeProvisionTransaction0199{SchemaVersion: "1.0", ID: id, Operation: operation, Platform: platform, StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := os.MkdirAll(filepath.Dir(bridgeTransactionPath0199(root, id)), 0o700); err != nil {
		return tx, err
	}
	return tx, persistBridgeTransaction0199(root, tx)
}

func bridgeTransactionPath0199(root, id string) string {
	return filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "transactions", id+".json")
}

func persistBridgeTransaction0199(root string, tx bridgeProvisionTransaction0199) error {
	return writeJSONSecure0199(bridgeTransactionPath0199(root, tx.ID), tx, 0o600)
}

func txSnapshotPath0199(root string, tx *bridgeProvisionTransaction0199, path string) error {
	path = filepath.Clean(path)
	for _, c := range tx.Changes {
		if filepath.Clean(c.Path) == path {
			return nil
		}
	}
	change := bridgeProvisionChange0199{Path: path}
	if info, err := os.Lstat(path); err == nil {
		if info.IsDir() {
			return fmt.Errorf("транзакция цель является каталог, ожидаемый файл: %s", path)
		}
		change.Existed = true
		relHash := sha256.Sum256([]byte(path))
		backup := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "backups", tx.ID, hex.EncodeToString(relHash[:8])+"-"+filepath.Base(path))
		if err := atomicCopyFile0199(path, backup, info.Mode().Perm()); err != nil {
			return err
		}
		change.BackupPath = backup
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tx.Changes = append(tx.Changes, change)
	return persistBridgeTransaction0199(root, *tx)
}

func txSnapshotAndRemove0199(root string, tx *bridgeProvisionTransaction0199, path string) error {
	if err := txSnapshotPath0199(root, tx, path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func restoreBridgeTransaction0199(root string, tx *bridgeProvisionTransaction0199, persist bool) error {
	for i := len(tx.Changes) - 1; i >= 0; i-- {
		change := tx.Changes[i]
		if change.Existed {
			if change.BackupPath == "" {
				return fmt.Errorf("транзакция %s отсутствующий резервное копирование для %s", tx.ID, change.Path)
			}
			info, err := os.Stat(change.BackupPath)
			if err != nil {
				return err
			}
			if err := atomicCopyFile0199(change.BackupPath, change.Path, info.Mode().Perm()); err != nil {
				return err
			}
		} else {
			if err := os.Remove(change.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	if persist {
		tx.RolledBackAt = time.Now().UTC().Format(time.RFC3339Nano)
		return persistBridgeTransaction0199(root, *tx)
	}
	return nil
}

func installVanillaSidecarLaunchers0199(root, artifactFile string, tx *bridgeProvisionTransaction0199) error {
	dir := filepath.Join(root, filepath.FromSlash(serverBridgeProvisionStateDir0199), "vanilla")
	sh := filepath.Join(dir, "run-server-bridge.sh")
	cmd := filepath.Join(dir, "run-server-bridge.cmd")
	if err := txSnapshotPath0199(root, tx, sh); err != nil {
		return err
	}
	if err := txSnapshotPath0199(root, tx, cmd); err != nil {
		return err
	}
	shell := "#!/usr/bin/env sh\nset -eu\nDIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\nexec java -jar \"$DIR/" + artifactFile + "\" --server-dir \"" + escapeShellDouble0199(root) + "\" \"$@\"\n"
	windows := "@echo off\r\nsetlocal\r\njava -jar \"%~dp0" + artifactFile + "\" --server-dir \"" + root + "\" %*\r\n"
	if err := atomicWrite0199(sh, []byte(shell), 0o755); err != nil {
		return err
	}
	if err := atomicWrite0199(cmd, []byte(windows), 0o644); err != nil {
		return err
	}
	return nil
}

func atomicCopyFile0199(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(dst), ".nl-bridge-copy-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	ok := false
	defer func() {
		temp.Close()
		if !ok {
			_ = os.Remove(tempName)
		}
	}()
	if _, err := io.Copy(temp, in); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := replaceFile0199(tempName, dst); err != nil {
		return err
	}
	ok = true
	return nil
}

func atomicWrite0199(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".nl-bridge-write-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	ok := false
	defer func() {
		temp.Close()
		if !ok {
			_ = os.Remove(tempName)
		}
	}()
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := replaceFile0199(tempName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// replaceFile0199 сохраняет одинаковый-каталог temp-файл запись атомарный на платформы
// где переименование-над-существующий является поддерживаемый. Windows делает не guarantee тот
// behaviour, так fall back к удалять+переименование; предоставление учётной записи транзакция имеет
// уже snapshotted управляемый назначение до этот вспомогательный модуль является используется.
func replaceFile0199(tempName, dst string) error {
	err := os.Rename(tempName, dst)
	if err == nil {
		return nil
	}
	if runtime.GOOS != "windows" {
		return err
	}
	if removeErr := os.Remove(dst); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return fmt.Errorf("заменять %s: переименование ошибка: %v; удалять назначение ошибка: %w", dst, err, removeErr)
	}
	if retryErr := os.Rename(tempName, dst); retryErr != nil {
		return fmt.Errorf("заменять %s: переименование ошибка: %v; повторить ошибка: %w", dst, err, retryErr)
	}
	return nil
}

func writeJSONSecure0199(path string, payload any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return atomicWrite0199(path, raw, mode)
}

func readBridgeProvisionState0199(path string) (bridgeProvisionState0199, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return bridgeProvisionState0199{}, err
	}
	var state bridgeProvisionState0199
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, err
	}
	if state.SchemaVersion != "1.0" || state.Platform == "" || state.ArtifactPath == "" {
		return state, errors.New("недопустимый управляемый ServerBridge состояние")
	}
	return state, nil
}

func defaultBridgeProfile0199(platform string) string {
	switch platform {
	case "fabric", "quilt", "forge", "neoforge":
		return platform
	default:
		return "vanilla"
	}
}

func firstNonEmpty0199(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func appendUnique0199(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func relativeOrBase0199(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return filepath.Base(path)
}

func fileExists0199(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
func escapeShellDouble0199(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "\"", "\\\"")
}
