package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestForgeAndNeoForgeProcessorMaterializers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Тестовый исполняемый файл Java использует POSIX shell; рабочая реализация поддерживает разные платформы")
	}
	for _, loader := range []string{"forge", "neoforge"} {
		t.Run(loader, func(t *testing.T) {
			minecraftVersion := "1.21.1"
			loaderVersion := "52.0.1"
			if loader == "neoforge" {
				loaderVersion = "21.1.105"
			}
			clientJar := []byte("minecraft-client")
			asset := []byte("minecraft-asset")
			assetHash := sha1HexLocal(asset)
			generated := []byte("generated-runtime-jar")
			processorJar := testProcessorJar(t)

			mux := http.NewServeMux()
			server := httptest.NewServer(mux)
			defer server.Close()
			base := server.URL

			assetIndex := map[string]any{"objects": map[string]any{"test.txt": map[string]any{"hash": assetHash, "size": len(asset)}}}
			assetIndexBytes, _ := json.Marshal(assetIndex)
			vanillaVersion := map[string]any{
				"id": minecraftVersion, "type": "release", "mainClass": "net.minecraft.client.main.Main", "assets": "test-assets",
				"assetIndex":  map[string]any{"id": "test-assets", "url": base + "/asset-index.json", "sha1": sha1HexLocal(assetIndexBytes), "size": len(assetIndexBytes)},
				"downloads":   map[string]any{"client": map[string]any{"url": base + "/client.jar", "sha1": sha1HexLocal(clientJar), "size": len(clientJar)}},
				"javaVersion": map[string]any{"majorVersion": 21},
				"arguments": map[string]any{
					"jvm":  []any{"-Djava.library.path=${natives_directory}", "-cp", "${classpath}"},
					"game": []any{"--username", "${auth_player_name}", "--version", "${version_name}"},
				},
				"libraries": []any{},
			}
			vanillaVersionBytes, _ := json.Marshal(vanillaVersion)
			manifest := MojangVersionManifest{Latest: map[string]string{"release": minecraftVersion}, Versions: []MojangManifestVersion{{ID: minecraftVersion, Type: "release", URL: base + "/version.json", SHA1: sha1HexLocal(vanillaVersionBytes)}}}
			manifestBytes, _ := json.Marshal(manifest)

			installer := testForgeInstaller(t, loader, minecraftVersion, loaderVersion, generated, processorJar)
			installerSHA1 := sha1HexLocal(installer)
			var installerUp atomic.Bool
			installerUp.Store(true)
			mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(manifestBytes) })
			mux.HandleFunc("/version.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(vanillaVersionBytes) })
			mux.HandleFunc("/client.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientJar) })
			mux.HandleFunc("/asset-index.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(assetIndexBytes) })
			mux.HandleFunc("/assets/"+assetHash[:2]+"/"+assetHash, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(asset) })
			mux.HandleFunc("/installer.jar", func(w http.ResponseWriter, r *http.Request) {
				if !installerUp.Load() {
					http.Error(w, "installer upstream unavailable", http.StatusServiceUnavailable)
					return
				}
				_, _ = w.Write(installer)
			})
			mux.HandleFunc("/installer.jar.sha1", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprintln(w, installerSHA1) })

			javaPath := testFakeJava(t, generated)
			dir := t.TempDir()
			result, err := installForgeLike(context.Background(), forgeMaterializeOptions{
				Loader: loader, MinecraftVersion: "latest-release", LoaderVersion: loaderVersion, ClientDir: dir,
				JavaExecutable: javaPath, InstallerURL: base + "/installer.jar", VersionManifest: base + "/manifest.json",
				AssetBaseURL: base + "/assets", LibraryBaseURL: base + "/libraries", Targets: []vanillaTarget{currentVanillaTarget()},
				Workers: 3, StrictUpstream: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "installed-and-verified" || result.Loader != loader || result.ProcessorRan != 1 || result.ProcessorSkipped != 0 {
				t.Fatalf("Неожиданный результат: %+v", result)
			}
			generatedRel, err := mavenCoordinatePath("com.example:generated:1.0")
			if err != nil {
				t.Fatal(err)
			}
			for _, rel := range []string{
				"versions/" + minecraftVersion + "/" + minecraftVersion + ".jar",
				result.ProfilePath,
				"libraries/com/example/processor/1.0/processor-1.0.jar",
				"libraries/" + generatedRel,
			} {
				if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
					t.Fatalf("Не найден файл или компонент %s: %v", rel, err)
				}
			}
			gotGenerated, err := os.ReadFile(filepath.Join(dir, "libraries", filepath.FromSlash(generatedRel)))
			if err != nil || !bytes.Equal(gotGenerated, generated) {
				t.Fatalf("Несовпадение вывода обработчика: %q %v", gotGenerated, err)
			}

			// Идемпотентность: при проверенном результате процессора следующий запуск должен пропустить дорогостоящую обработку.
			second, err := installForgeLike(context.Background(), forgeMaterializeOptions{
				Loader: loader, MinecraftVersion: minecraftVersion, LoaderVersion: loaderVersion, ClientDir: dir,
				JavaExecutable: javaPath, InstallerURL: base + "/installer.jar", InstallerSHA1: installerSHA1,
				VersionManifest: base + "/manifest.json", AssetBaseURL: base + "/assets", LibraryBaseURL: base + "/libraries",
				Targets: []vanillaTarget{currentVanillaTarget()}, Workers: 2, StrictUpstream: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if second.ProcessorSkipped != 1 || second.ProcessorRan != 0 || !compatibilitySHA256RE.MatchString(second.ProcessorJournalSHA256) {
				t.Fatalf("Ожидалось попадание в кеш журнала обработчика: %+v", second)
			}

			// Имитируйте сбой после создания проверенного результата процессора, но до
			// фиксации надёжного журнала. Следующая материализация только из кеша должна
			// восстановить выполнявшуюся запись без повторного запуска процессора.
			journalRaw, err := os.ReadFile(filepath.FromSlash(second.ProcessorJournalPath))
			if err != nil {
				t.Fatalf("Чтение журнала обработчика: %v", err)
			}
			var journal forgeProcessorJournal
			if err := json.Unmarshal(journalRaw, &journal); err != nil {
				t.Fatalf("Разбор журнала обработчика: %v", err)
			}
			entry := journal.Entries["0"]
			entry.State = "running"
			entry.Recovered = false
			journal.Entries["0"] = entry
			journalRaw, _ = json.MarshalIndent(journal, "", "  ")
			if err := writeAtomicBytes(filepath.FromSlash(second.ProcessorJournalPath), append(journalRaw, '\n'), 0o600); err != nil {
				t.Fatalf("Ошибка записи журнала имитации аварийного завершения: %v", err)
			}
			installerPath := filepath.Join(dir, ".launcher", "installers", loader, sanitizeVersionToken(second.ArtifactVersion), "installer.jar")
			if err := os.Remove(installerPath); err != nil {
				t.Fatalf("Удаление локального установщика перед восстановлением из кеша: %v", err)
			}
			installerUp.Store(false)
			third, err := installForgeLike(context.Background(), forgeMaterializeOptions{
				Loader: loader, MinecraftVersion: minecraftVersion, LoaderVersion: loaderVersion, ClientDir: dir,
				JavaExecutable: javaPath, InstallerURL: base + "/installer.jar",
				VersionManifest: base + "/manifest.json", AssetBaseURL: base + "/assets", LibraryBaseURL: base + "/libraries",
				Targets: []vanillaTarget{currentVanillaTarget()}, Workers: 2, StrictUpstream: true, LoaderCacheOnly: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatalf("Не удалось восстановить установщик или обработчик из кеша: %v", err)
			}
			if !third.ResolutionPinned || !third.LoaderCacheOnly || !third.InstallerCacheHit || !third.UpstreamRecoveryUsed || third.ProcessorRan != 0 || third.ProcessorSkipped != 1 || third.ProcessorRecovered != 1 || !compatibilitySHA256RE.MatchString(third.ProcessorJournalSHA256) {
				t.Fatalf("Некорректные доказательства восстановления установщика или обработчика: %+v", third)
			}

			// Восстановление также должно учитывать прерванный процессор, результат которого нельзя
			// принять, если его удалось успешно перезапустить с закреплёнными локальными входами.
			journalRaw, err = os.ReadFile(filepath.FromSlash(third.ProcessorJournalPath))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(journalRaw, &journal); err != nil {
				t.Fatal(err)
			}
			entry = journal.Entries["0"]
			entry.State = "failed"
			entry.Recovered = false
			journal.Entries["0"] = entry
			journalRaw, _ = json.MarshalIndent(journal, "", "  ")
			if err := writeAtomicBytes(filepath.FromSlash(third.ProcessorJournalPath), append(journalRaw, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, "libraries", filepath.FromSlash(generatedRel))); err != nil {
				t.Fatal(err)
			}
			fourth, err := installForgeLike(context.Background(), forgeMaterializeOptions{
				Loader: loader, MinecraftVersion: minecraftVersion, LoaderVersion: loaderVersion, ClientDir: dir,
				JavaExecutable: javaPath, InstallerURL: base + "/installer.jar", VersionManifest: base + "/manifest.json",
				AssetBaseURL: base + "/assets", LibraryBaseURL: base + "/libraries",
				Targets: []vanillaTarget{currentVanillaTarget()}, Workers: 2, StrictUpstream: true,
				LoaderCacheOnly: true, HTTPClient: server.Client(),
			})
			if err != nil {
				t.Fatalf("Повторный запуск прерванного обработчика завершился ошибкой: %v", err)
			}
			if fourth.ProcessorRecovered != 1 || fourth.ProcessorRan != 1 || fourth.ProcessorSkipped != 0 {
				t.Fatalf("Повторный запуск прерванного обработчика должен выполнять настоящее восстановление: %+v", fourth)
			}

			packagePath := filepath.Join(t.TempDir(), "package.json")
			args := []string{
				"--minecraft", minecraftVersion, "--loader-version", loaderVersion, "--client-dir", dir, "--java", javaPath,
				"--installer-url", base + "/installer.jar", "--installer-sha1", installerSHA1,
				"--version-manifest", base + "/manifest.json", "--asset-base-url", base + "/assets", "--library-base-url", base + "/libraries",
				"--target", currentVanillaTarget().OS + "/" + currentVanillaTarget().Arch,
				"--project", "test-project", "--profile", loader, "--channel", "stable", "--version", "1.0.0", "--output", packagePath,
			}
			if err := handleRuntimeForgeLikePackage(loader, args); err != nil {
				t.Fatalf("Ошибка пакета %s: %v", loader, err)
			}
			pkg, err := readClientPackageManifest(packagePath)
			if err != nil {
				t.Fatal(err)
			}
			seenProfile, seenGenerated := false, false
			for _, file := range pkg.Files {
				if strings.HasPrefix(file.Path, ".launcher/") {
					t.Fatalf("Состояние локального установщика попало в пакет: %s", file.Path)
				}
				seenProfile = seenProfile || file.Path == result.ProfilePath
				seenGenerated = seenGenerated || file.Path == "libraries/"+generatedRel
			}
			if !seenProfile || !seenGenerated {
				t.Fatalf("В пакете отсутствуют артефакты Forge/NeoForge: профиль=%v сгенерировано=%v", seenProfile, seenGenerated)
			}
		})
	}
}

func TestForgeNeoForgeMavenVersionSelection(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	forgeMetadata := `<metadata><versioning><versions><version>1.20.1-47.3.0</version><version>1.20.1-47.4.0</version><version>1.21.1-52.0.1</version></versions></versioning></metadata>`
	neoLegacyMetadata := `<metadata><versioning><versions><version>1.20.1-47.1.76</version><version>1.20.1-47.1.79</version><version>1.20.2-48.0.0</version></versions></versioning></metadata>`
	neoMetadata := `<metadata><versioning><versions><version>21.1.100-beta</version><version>21.1.105</version><version>21.4.20</version><version>26.2.0.74</version><version>26.2.0.75</version></versions></versioning></metadata>`
	mux.HandleFunc("/forge.xml", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, forgeMetadata) })
	mux.HandleFunc("/neo-legacy.xml", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, neoLegacyMetadata) })
	mux.HandleFunc("/neo.xml", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, neoMetadata) })

	loaderVersion, artifactVersion, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "forge", "1.20.1", "latest-stable", server.URL+"/forge.xml")
	if err != nil || loaderVersion != "47.4.0" || artifactVersion != "1.20.1-47.4.0" {
		t.Fatalf("Выбор Forge: %q %q %v", loaderVersion, artifactVersion, err)
	}
	loaderVersion, artifactVersion, _, err = resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.20.1", "latest-stable", server.URL+"/neo-legacy.xml")
	if err != nil || loaderVersion != "1.20.1-47.1.79" || artifactVersion != "1.20.1-47.1.79" {
		t.Fatalf("Выбор NeoForge 1.20.1: %q %q %v", loaderVersion, artifactVersion, err)
	}
	loaderVersion, artifactVersion, _, err = resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.21.1", "latest-stable", server.URL+"/neo.xml")
	if err != nil || loaderVersion != "21.1.105" || artifactVersion != "21.1.105" {
		t.Fatalf("Выбор NeoForge: %q %q %v", loaderVersion, artifactVersion, err)
	}
	loaderVersion, artifactVersion, _, err = resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "26.2", "latest-stable", server.URL+"/neo.xml")
	if err != nil || loaderVersion != "26.2.0.75" || artifactVersion != "26.2.0.75" {
		t.Fatalf("Выбор NeoForge 26.2: %q %q %v", loaderVersion, artifactVersion, err)
	}
	if _, _, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.21.1", "21.4.20", server.URL+"/neo.xml"); err == nil {
		t.Fatal("Принята явно указанная несовместимая версия NeoForge/Minecraft")
	}
	if got := forgeInstallerURL("neoforge", "1.20.1", "1.20.1-47.1.79"); !strings.Contains(got, "/net/neoforged/forge/1.20.1-47.1.79/forge-1.20.1-47.1.79-installer.jar") {
		t.Fatalf("Неожиданный URL установщика NeoForge 1.20.1: %s", got)
	}
	if got := forgeInstallerURL("neoforge", "26.2", "26.2.0.75"); !strings.Contains(got, "/net/neoforged/neoforge/26.2.0.75/neoforge-26.2.0.75-installer.jar") {
		t.Fatalf("Неожиданный URL современного установщика NeoForge: %s", got)
	}
}

func TestNeoForgeMavenMetadataRetriesTransientNotFound(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) <= 2 {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, `<metadata><versioning><versions><version>21.1.252</version></versions></versioning></metadata>`)
	}))
	defer server.Close()

	loaderVersion, artifactVersion, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.21.1", "latest-stable", server.URL)
	if err != nil {
		t.Fatalf("Временная ошибка метаданных 404 не вызвала повтор запроса: %v", err)
	}
	if loaderVersion != "21.1.252" || artifactVersion != "21.1.252" {
		t.Fatalf("Неожиданная версия NeoForge после повторного запроса метаданных: %q %q", loaderVersion, artifactVersion)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("Количество запросов метаданных: %d, ожидалось 3", got)
	}
}

func TestNeoForgeMavenMetadataRetriesSemanticallyIncompleteSnapshot(t *testing.T) {
	var requests atomic.Int32
	var refreshed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := requests.Add(1)
		if request > 1 && r.URL.Query().Get("_launcher_refresh") != "" {
			refreshed.Add(1)
		}
		if request == 1 {
			_, _ = fmt.Fprint(w, `<metadata><versioning><versions><version>21.4.20</version></versions></versioning></metadata>`)
			return
		}
		_, _ = fmt.Fprint(w, `<metadata><versioning><versions><version>21.4.20</version><version>21.1.252</version></versions></versioning></metadata>`)
	}))
	defer server.Close()

	loaderVersion, artifactVersion, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.21.1", "latest-stable", server.URL+"/maven-metadata.xml")
	if err != nil {
		t.Fatalf("Повторный запрос неполных метаданных NeoForge не выполнен: %v", err)
	}
	if loaderVersion != "21.1.252" || artifactVersion != "21.1.252" {
		t.Fatalf("Неожиданная версия NeoForge после повторного запроса неполных метаданных: %q %q", loaderVersion, artifactVersion)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("Количество запросов метаданных: %d, ожидалось 2", got)
	}
	if got := refreshed.Load(); got != 1 {
		t.Fatalf("Повторный запрос не обошёл изменяемый кеш метаданных: запросов обновления — %d", got)
	}
}

func TestNeoForgeMavenMetadataPersistentSemanticMismatchFailsClosed(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprint(w, `<metadata><versioning><versions><version>21.4.20</version><version>21.2.10-beta</version></versions></versioning></metadata>`)
	}))
	defer server.Close()

	_, _, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.21.1", "latest-stable", server.URL+"/maven-metadata.xml")
	if err == nil || !strings.Contains(err.Error(), "не имеет latest-stable версии") {
		t.Fatalf("Несовместимые сохранённые метаданные должны приводить к отказу: %v", err)
	}
	if got := requests.Load(); got != compatibilityHTTPAttempts {
		t.Fatalf("Число запросов семантических метаданных=%d, ожидается %d", got, compatibilityHTTPAttempts)
	}
}

func TestNeoForgeMavenMetadataPersistentNotFoundFailsClosed(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	_, _, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.21.1", "latest-stable", server.URL)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("Ошибка 404 при запросе сохранённых метаданных должна приводить к отказу: %v", err)
	}
	if got := requests.Load(); got != compatibilityHTTPAttempts {
		t.Fatalf("Число запросов метаданных=%d, ожидается %d", got, compatibilityHTTPAttempts)
	}
}

func TestForgeLibraryMaterializationDeduplicatesSameDestinationBeforeWorkers(t *testing.T) {
	payload := []byte("same-forge-library")
	sha1sum := sha1HexLocal(payload)
	var requests atomic.Int32
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/unsafe.jar", func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write(payload)
	})
	libraries := []MojangLibrary{
		{Name: "net.minecraftforge:unsafe:0.9.2", Downloads: MojangLibraryDownloads{Artifact: MojangDownload{Path: "net/minecraftforge/unsafe/0.9.2/unsafe-0.9.2.jar", URL: server.URL + "/unsafe.jar", SHA1: sha1sum, Size: int64(len(payload))}}},
		{Name: "net.minecraftforge:unsafe:0.9.2", Downloads: MojangLibraryDownloads{Artifact: MojangDownload{Path: "net/minecraftforge/unsafe/0.9.2/unsafe-0.9.2.jar", URL: server.URL + "/unsafe.jar", SHA1: sha1sum, Size: int64(len(payload))}}},
	}
	downloaded, err := materializeForgeLibraries(context.Background(), server.Client(), t.TempDir(), &libraries, "forge", 8, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("Повторяющийся целевой файл загружен %d раз, ожидается 1", got)
	}
	if len(downloaded) != 1 || downloaded[0].Path != "libraries/net/minecraftforge/unsafe/0.9.2/unsafe-0.9.2.jar" {
		t.Fatalf("Неожиданный результат удаления дубликатов: %+v", downloaded)
	}
}

func TestForgeInstallV1ProcessorTokens(t *testing.T) {
	clientDir := t.TempDir()
	dataDir := filepath.Join(clientDir, ".launcher", "installer-data")
	if err := os.MkdirAll(filepath.Join(dataDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	patchPath := filepath.Join(dataDir, "data", "client.lzma")
	if err := os.WriteFile(patchPath, []byte("patch"), 0o644); err != nil {
		t.Fatal(err)
	}
	pc := forgeProcessorContext{
		MinecraftVersion: "1.20.1", ClientDir: clientDir, InstallerPath: filepath.Join(clientDir, "installer.jar"), InstallerDataDir: dataDir,
		Profile: &forgeInstallerProfile{Data: map[string]forgeDataValue{
			"BINPATCH": {Client: "/data/client.lzma"},
			"PATCHED":  {Client: "[net.minecraftforge:forge:1.20.1-47.4.23:client]"},
			"HASH":     {Client: "'0123456789abcdef0123456789abcdef01234567'"},
		}},
	}
	resolved, err := resolveProcessorToken(pc, "--mc={MINECRAFT_VERSION};side={SIDE};patch={BINPATCH};hash={HASH}")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resolved, "--mc=1.20.1;side=client;patch=") || !strings.Contains(resolved, patchPath) || !strings.HasSuffix(resolved, "hash=0123456789abcdef0123456789abcdef01234567") {
		t.Fatalf("Несовпадение подстановки токенов InstallV1: %q", resolved)
	}
	artifact, err := resolveProcessorToken(pc, "{PATCHED}")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(artifact), "libraries/net/minecraftforge/forge/1.20.1-47.4.23/forge-1.20.1-47.4.23-client.jar") {
		t.Fatalf("Несовпадение токена артефакта InstallV1: %q", artifact)
	}
	if _, err := resolveProcessorToken(pc, "{UNKNOWN}"); err == nil {
		t.Fatal("Принят неизвестный токен обработчика")
	}
}

func TestForgeLegacy1122V1UniversalInstaller(t *testing.T) {
	universal := []byte("forge-1.12.2-universal-fixture")
	universalSHA1 := sha1HexLocal(universal)
	clientOnly := []byte("legacy-client-library")
	clientSHA1 := sha1HexLocal(clientOnly)
	serverOnlyRequested := atomic.Bool{}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/repo/com/example/clientlib/1.0/clientlib-1.0.jar", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(clientOnly) })
	mux.HandleFunc("/repo/com/example/clientlib/1.0/clientlib-1.0.jar.sha1", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, clientSHA1) })
	mux.HandleFunc("/repo/com/example/serverlib/1.0/serverlib-1.0.jar", func(w http.ResponseWriter, r *http.Request) {
		serverOnlyRequested.Store(true)
		http.Error(w, "server-only library must not be requested by client materialization", http.StatusTeapot)
	})

	profileID := "1.12.2-forge-14.23.5.2859"
	universalCoord := "net.minecraftforge:forge:1.12.2-14.23.5.2859"
	universalEntry := "forge-1.12.2-14.23.5.2859-universal.jar"
	versionInfo := map[string]any{
		"id": profileID, "inheritsFrom": "1.12.2", "type": "release",
		"mainClass":          "net.minecraft.launchwrapper.Launch",
		"minecraftArguments": "--username ${auth_player_name} --tweakClass net.minecraftforge.fml.common.launcher.FMLTweaker",
		"libraries": []any{
			map[string]any{"name": universalCoord, "checksums": []any{universalSHA1}, "clientreq": true, "serverreq": true},
			map[string]any{"name": "com.example:clientlib:1.0", "url": server.URL + "/repo/", "checksums": []any{clientSHA1}, "clientreq": true, "serverreq": true},
			map[string]any{"name": "com.example:serverlib:1.0", "url": server.URL + "/repo/", "checksums": []any{sha1HexLocal([]byte("unused"))}, "clientreq": false, "serverreq": true},
		},
	}
	installProfile := map[string]any{
		"install": map[string]any{
			"profileName": "Forge", "target": profileID, "path": universalCoord,
			"version": "14.23.5.2859", "filePath": universalEntry, "minecraft": "1.12.2",
		},
		"versionInfo": versionInfo,
	}
	profileBytes, _ := json.Marshal(installProfile)
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, payload := range map[string][]byte{"install_profile.json": profileBytes, universalEntry: universal} {
		entry, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = entry.Write(payload)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	installerPath := filepath.Join(t.TempDir(), "forge-installer.jar")
	if err := os.WriteFile(installerPath, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	bundle, err := inspectForgeInstaller(installerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.Legacy || bundle.LegacyMode != "legacy-v1-universal" || bundle.Version.ID != profileID {
		t.Fatalf("Несоответствие при определении устаревшего установщика V1: %+v", bundle)
	}

	clientDir := t.TempDir()
	result, err := installForgeLegacy(context.Background(), forgeMaterializeOptions{
		Loader: "forge", MinecraftVersion: "1.12.2", ClientDir: clientDir,
		Workers: 2, StrictUpstream: true, HTTPClient: server.Client(),
	}, vanillaInstallResult{MinecraftVersion: "1.12.2", JavaMajorVersion: 8, ClientDir: clientDir, Status: "installed-and-verified"},
		"14.23.5.2859", "1.12.2-14.23.5.2859", "fixture-metadata", server.URL+"/installer.jar", sha1HexLocal(archive.Bytes()),
		vanillaDownloadedFile{Path: ".launcher/installers/forge.jar", SHA1: sha1HexLocal(archive.Bytes()), SHA256: strings.Repeat("b", 64)},
		installerPath, bundle,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.InstallMode != "legacy-v1-universal" || result.MainClass != "net.minecraft.launchwrapper.Launch" || result.ProcessorCount != 0 {
		t.Fatalf("Неожиданный результат установки устаревшей версии: %+v", result)
	}
	if result.LegacyUniversalSHA1 != universalSHA1 || result.LegacyUniversalSHA256 == "" {
		t.Fatalf("Несоответствие подтверждений универсального пакета устаревшей версии: %+v", result)
	}
	if serverOnlyRequested.Load() {
		t.Fatal("Запрошена устаревшая библиотека с clientreq=false")
	}
	for _, rel := range []string{
		result.LegacyUniversalPath,
		"libraries/com/example/clientlib/1.0/clientlib-1.0.jar",
		result.ProfilePath,
		".launcher/forge-install.json",
	} {
		if _, err := os.Stat(filepath.Join(clientDir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("Отсутствует артефакт старой версии Forge %s: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(clientDir, "libraries/com/example/serverlib/1.0/serverlib-1.0.jar")); !os.IsNotExist(err) {
		t.Fatalf("Материализована устаревшая библиотека только для сервера: %v", err)
	}
	profileOnDisk, err := os.ReadFile(filepath.Join(clientDir, filepath.FromSlash(result.ProfilePath)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(profileOnDisk, []byte(`"clientreq":false`)) || !bytes.Contains(profileOnDisk, []byte("FMLTweaker")) {
		t.Fatalf("Исходное поле versionInfo устаревшей версии не сохранено: %s", profileOnDisk)
	}
}

func TestForgeLegacy1710V1LaunchWrapperInstaller(t *testing.T) {
	universal := []byte("forge-1.7.10-universal-fixture")
	universalSHA1 := sha1HexLocal(universal)
	profileID := "1.7.10-Forge10.13.4.1614-1.7.10"
	universalCoord := "net.minecraftforge:forge:1.7.10-10.13.4.1614-1.7.10"
	universalEntry := "forge-1.7.10-10.13.4.1614-1.7.10-universal.jar"
	versionInfo := map[string]any{
		"id": profileID, "type": "release",
		"mainClass":          "net.minecraft.launchwrapper.Launch",
		"minecraftArguments": "--username ${auth_player_name} --tweakClass cpw.mods.fml.common.launcher.FMLTweaker",
		"libraries": []any{
			map[string]any{"name": universalCoord, "checksums": []any{universalSHA1}, "clientreq": true, "serverreq": true},
		},
	}
	installProfile := map[string]any{
		"install": map[string]any{
			"profileName": "Forge", "target": profileID, "path": universalCoord,
			"version": "10.13.4.1614-1.7.10", "filePath": universalEntry, "minecraft": "1.7.10",
		},
		"versionInfo": versionInfo,
	}
	profileBytes, _ := json.Marshal(installProfile)
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, payload := range map[string][]byte{"install_profile.json": profileBytes, universalEntry: universal} {
		entry, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = entry.Write(payload)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	installerPath := filepath.Join(t.TempDir(), "forge-1.7.10-installer.jar")
	if err := os.WriteFile(installerPath, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	bundle, err := inspectForgeInstaller(installerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.Legacy || bundle.LegacyMode != "legacy-v1-universal" || bundle.Version.InheritsFrom != "" {
		t.Fatalf("Несовпадение определения установщика V1 для 1.7.10: %+v", bundle)
	}
	clientDir := t.TempDir()
	result, err := installForgeLegacy(context.Background(), forgeMaterializeOptions{
		Loader: "forge", MinecraftVersion: "1.7.10", ClientDir: clientDir,
		Workers: 1, StrictUpstream: true, HTTPClient: http.DefaultClient,
	}, vanillaInstallResult{MinecraftVersion: "1.7.10", JavaMajorVersion: 8, ClientDir: clientDir, Status: "installed-and-verified"},
		"10.13.4.1614-1.7.10", "1.7.10-10.13.4.1614-1.7.10", "fixture-metadata", "https://example.invalid/installer.jar", sha1HexLocal(archive.Bytes()),
		vanillaDownloadedFile{Path: ".launcher/installers/forge.jar", SHA1: sha1HexLocal(archive.Bytes()), SHA256: strings.Repeat("c", 64)},
		installerPath, bundle,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.InstallMode != "legacy-v1-universal" || result.MainClass != "net.minecraft.launchwrapper.Launch" {
		t.Fatalf("Неожиданный результат для Forge 1.7.10: %+v", result)
	}
	if result.LegacyTweaker != "cpw.mods.fml.common.launcher.FMLTweaker" || result.LegacyBaseVersion != "1.7.10" || !result.LegacyProfileNormalized {
		t.Fatalf("Несоответствие исторических доказательств для Forge 1.7.10: %+v", result)
	}
	profileOnDisk, err := os.ReadFile(filepath.Join(clientDir, filepath.FromSlash(result.ProfilePath)))
	if err != nil {
		t.Fatal(err)
	}
	var normalized map[string]any
	if err := json.Unmarshal(profileOnDisk, &normalized); err != nil {
		t.Fatal(err)
	}
	if normalized["inheritsFrom"] != "1.7.10" || !strings.Contains(string(profileOnDisk), "cpw.mods.fml.common.launcher.FMLTweaker") {
		t.Fatalf("Профиль Forge 1.7.10 нормализован неправильно: %s", profileOnDisk)
	}
}

func TestCanonicalLegacyForgeRepositoryURL(t *testing.T) {
	for input, expected := range map[string]string{
		"http://files.minecraftforge.net/maven/": "https://maven.minecraftforge.net",
		"http://maven.minecraftforge.net/":       "https://maven.minecraftforge.net",
		"https://maven.minecraftforge.net/":      "https://maven.minecraftforge.net/",
		"http://127.0.0.1:8080/repo/":            "http://127.0.0.1:8080/repo/",
	} {
		if actual := canonicalLegacyForgeURL(input); actual != expected {
			t.Fatalf("canonicalLegacyForgeURL(%q)=%q, ожидалось %q", input, actual, expected)
		}
	}
}

func TestForgeLegacy1122RepackedEmptyProcessorInstaller(t *testing.T) {
	universal := []byte("forge-1.12.2-repacked-universal")
	coord := "net.minecraftforge:forge:1.12.2-14.23.5.2864"
	rel, err := mavenCoordinatePath(coord)
	if err != nil {
		t.Fatal(err)
	}
	profile := map[string]any{
		"spec": 1, "profile": "Forge", "version": "1.12.2-forge-14.23.5.2864", "json": "/version.json",
		"path": coord, "minecraft": "1.12.2", "data": map[string]any{}, "processors": []any{},
		"libraries": []any{map[string]any{"name": coord, "downloads": map[string]any{"artifact": map[string]any{"path": rel, "sha1": sha1HexLocal(universal), "size": len(universal)}}}},
	}
	versionInfo := map[string]any{
		"id": "1.12.2-forge-14.23.5.2864", "inheritsFrom": "1.12.2", "type": "release",
		"mainClass":          "net.minecraft.launchwrapper.Launch",
		"minecraftArguments": "--tweakClass net.minecraftforge.fml.common.launcher.FMLTweaker", "libraries": []any{},
	}
	profileBytes, _ := json.Marshal(profile)
	versionBytes, _ := json.Marshal(versionInfo)
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, payload := range map[string][]byte{
		"install_profile.json": profileBytes,
		"version.json":         versionBytes,
		"maven/" + rel:         universal,
	} {
		entry, createErr := zw.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		_, _ = entry.Write(payload)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	installerPath := filepath.Join(t.TempDir(), "forge-installer.jar")
	if err := os.WriteFile(installerPath, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	bundle, err := inspectForgeInstaller(installerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.Legacy || bundle.LegacyMode != "legacy-v2-empty-processors" || bundle.Profile.Path != coord {
		t.Fatalf("Несоответствие при определении переупакованного устаревшего установщика 1.12.2: %+v", bundle)
	}
}

func TestInstallerArchiveSecurityAndCoordinateParsing(t *testing.T) {
	if got, err := mavenCoordinatePath("net.minecraftforge:installertools:1.4.1:fatjar@jar"); err != nil || got != "net/minecraftforge/installertools/1.4.1/installertools-1.4.1-fatjar.jar" {
		t.Fatalf("Неожиданный путь Maven: %q %v", got, err)
	}
	if got, err := mavenCoordinatePath("de.oceanlabs.mcp:mcp_config:1.20.1:mappings@txt"); err != nil || !strings.HasSuffix(got, "mcp_config-1.20.1-mappings.txt") {
		t.Fatalf("Неожиданный расширенный путь Maven: %q %v", got, err)
	}
	if _, err := safeArchiveRelative("../escape"); err == nil {
		t.Fatal("Допущен выход за пределы каталога при обработке архива установщика")
	}
	if !neoForgeVersionMatchesMinecraft("21.1.105", "1.21.1") ||
		!neoForgeVersionMatchesMinecraft("26.2.0.75", "26.2") ||
		!neoForgeVersionMatchesMinecraft("26.1.1.12", "26.1.1") ||
		neoForgeVersionMatchesMinecraft("21.4.20", "1.21.1") ||
		neoForgeVersionMatchesMinecraft("26.2.0.75", "26.1") {
		t.Fatal("Неверное сопоставление совместимости NeoForge и Minecraft")
	}
}

func testProcessorJar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	manifest, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = manifest.Write([]byte("Manifest-Version: 1.0\nMain-Class: com.example.Processor\n\n"))
	payload, err := zw.Create("com/example/Processor.class")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = payload.Write([]byte("fixture-bytecode-placeholder"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testForgeInstaller(t *testing.T, loader, minecraftVersion, loaderVersion string, generated, processorJar []byte) []byte {
	t.Helper()
	profileID := minecraftVersion + "-" + loader + "-" + loaderVersion
	profile := map[string]any{
		"spec": 1, "profile": "com.example:" + loader + ":" + loaderVersion, "version": profileID, "json": "/version.json", "minecraft": minecraftVersion,
		"data": map[string]any{
			"OUT":      map[string]any{"client": "[com.example:generated:1.0]", "server": ""},
			"OUT_SHA":  map[string]any{"client": "'" + sha1HexLocal(generated) + "'", "server": ""},
			"BINPATCH": map[string]any{"client": "/data/client.lzma", "server": "/data/server.lzma"},
		},
		"processors": []any{map[string]any{
			"sides": []any{"client"}, "jar": "com.example:processor:1.0", "classpath": []any{},
			"args": []any{"--patch", "{BINPATCH}", "--minecraft={MINECRAFT_VERSION}", "--side={SIDE}", "--out", "{OUT}"}, "outputs": map[string]any{"{OUT}": "{OUT_SHA}"},
		}},
		"libraries": []any{map[string]any{"name": "com.example:processor:1.0"}},
	}
	versionProfile := map[string]any{
		"id": profileID, "inheritsFrom": minecraftVersion, "type": "release", "mainClass": "cpw.mods.bootstraplauncher.BootstrapLauncher",
		"arguments": map[string]any{"game": []any{"--launchTarget", "forgeclient"}, "jvm": []any{"-D" + loader + ".fixture=true"}},
		"libraries": []any{map[string]any{"name": "com.example:generated:1.0"}},
	}
	profileBytes, _ := json.Marshal(profile)
	versionBytes, _ := json.Marshal(versionProfile)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{
		"install_profile.json": profileBytes,
		"version.json":         versionBytes,
		"maven/com/example/processor/1.0/processor-1.0.jar": processorJar,
		"data/client.lzma": []byte("binary-patch-fixture"),
	} {
		entry, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = entry.Write(data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testFakeJava(t *testing.T, output []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "java-fixture")
	script := `#!/bin/sh
if [ "$1" = "-version" ]; then
  echo 'openjdk version "21.0.11" 2026-04-21' >&2
  exit 0
fi
previous=""
for argument in "$@"; do
  if [ "$previous" = "--out" ]; then
    mkdir -p "$(dirname "$argument")"
    printf '%s' 'OUTPUT_PLACEHOLDER' > "$argument"
    exit 0
  fi
  previous="$argument"
done
echo "missing --out" >&2
exit 17
`
	script = strings.Replace(script, "OUTPUT_PLACEHOLDER", string(output), 1)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLegacyNativeClassifierContainerHasNoInventedBaseJar(t *testing.T) {
	for _, coordinate := range []string{"org.lwjgl.lwjgl:lwjgl-platform:2.9.1", "net.java.jinput:jinput-platform:2.0.5", "tv.twitch:twitch-platform:5.16", "tv.twitch:twitch-external-platform:4.5"} {
		lib := MojangLibrary{Name: coordinate, Natives: map[string]string{"windows": "natives-windows", "linux": "natives-linux"}}
		if !isLegacyNativeClassifierContainer(lib) {
			t.Fatalf("Нельзя загружать отсутствующий базовый JAR, используемый только классификатором: %s", coordinate)
		}
		lib.Downloads.Artifact = MojangDownload{URL: "https://example.com/lib.jar", SHA1: "0123456789abcdef0123456789abcdef01234567"}
		if isLegacyNativeClassifierContainer(lib) {
			t.Fatalf("Нельзя пропускать проверенный базовый JAR: %s", coordinate)
		}
	}
	if isLegacyNativeClassifierContainer(MojangLibrary{Name: "org.lwjgl.lwjgl:lwjgl:2.9.1", Natives: map[string]string{"windows": "natives-windows"}}) {
		t.Fatal("Основная библиотека LWJGL в пути классов не должна пропускаться")
	}
}

func TestForgeLatestStableChoosesNumericMaximumIndependentOfMetadataOrder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `<metadata><versioning><versions>
			<version>1.18-38.0.17</version><version>1.18-38.0.9</version><version>1.18-38.0.0</version>
			<version>1.16.5-36.2.42</version><version>1.16.5-36.0.0</version>
			<version>1.18-38.1.0-beta</version>
		</versions></versioning></metadata>`)
	}))
	defer server.Close()
	for _, tc := range []struct{ minecraft, want string }{{"1.18", "38.0.17"}, {"1.16.5", "36.2.42"}} {
		got, _, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "forge", tc.minecraft, "latest-stable", server.URL)
		if err != nil || got != tc.want {
			t.Fatalf("Forge %s: получено %s, ожидалось %s, ошибка=%v", tc.minecraft, got, tc.want, err)
		}
	}
}

func TestForgeLegacyProfileAlreadyInheritedReportsNormalized(t *testing.T) {
	raw := []byte(`{"id":"1.7.10-forge-test","inheritsFrom":"1.7.10","mainClass":"net.minecraft.launchwrapper.Launch"}`)
	profile, normalized, err := normalizeForgeLegacyRuntimeProfile(raw, loaderVersionProfile{}, "1.7.10")
	if err != nil {
		t.Fatal(err)
	}
	if !normalized {
		t.Fatal("Профиль с наследованием Vanilla должен соответствовать проверке legacyProfileNormalized")
	}
	if string(profile) != string(raw) {
		t.Fatalf("Уже нормализованный профиль был без необходимости перезаписан: %s", profile)
	}
}

func TestNeoForgePrereleaseOnlyMetadataDoesNotPassAsStable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `<metadata><versioning><versions><version>20.5.0-beta</version><version>20.5.17-beta</version><version>20.4.250</version></versions></versioning></metadata>`)
	}))
	defer server.Close()
	_, _, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.20.5", "latest-stable", server.URL)
	if err == nil || !strings.Contains(err.Error(), "latest-stable") || !strings.Contains(err.Error(), "20.5.17-beta") || !strings.Contains(err.Error(), "prerelease") {
		t.Fatalf("Источник только с предварительными версиями должен оставаться недоступным с объяснением причины: %v", err)
	}
	got, _, _, err := resolveForgeLikeVersion(context.Background(), server.Client(), "neoforge", "1.20.5", "latest", server.URL)
	if err != nil || got != "20.5.17-beta" {
		t.Fatalf("Явно указанный latest должен допускать предварительные версии: %q %v", got, err)
	}
}

// Прерванные передачи Forge CDN повторяются в рамках одной материализации.
// Восстановленный файл всё равно должен соответствовать точному SHA-1 издателя.
func TestForgeInstallerTransportRecovery(t *testing.T) {
	payload := bytes.Repeat([]byte("forge-installer-content"), 4096)
	digest := sha1HexLocal(payload)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		if n == 1 {
			// Преждевременный EOF после корректного HTTP 200 ни в коем случае нельзя фиксировать.
			_, _ = w.Write(payload[:1024])
			return
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	root := t.TempDir()
	task := vanillaDownloadTask{Path: "installers/forge.jar", URL: server.URL + "/installer.jar", SHA1: digest, Kind: "forge-installer"}
	result, err := downloadForgeInstallerRecoveringTransport(context.Background(), server.Client(), task, root)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || result.SHA1 != digest || result.Size != int64(len(payload)) {
		t.Fatalf("Восстановление должно выполнить ровно две полные проверенные попытки: запросов=%d результат=%+v", requests.Load(), result)
	}
	final, err := os.ReadFile(filepath.Join(root, "installers", "forge.jar"))
	if err != nil || !bytes.Equal(final, payload) {
		t.Fatalf("Восстановленный файл не был записан атомарно: %v", err)
	}
}

func TestForgeInstallerTransportRecoveryDoesNotRetryIntegrityOrHTTPFailures(t *testing.T) {
	for _, scenario := range []string{"checksum", "http404", "unverified"} {
		t.Run(scenario, func(t *testing.T) {
			var requests atomic.Int32
			payload := []byte("rejected installer")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if scenario == "http404" {
					http.NotFound(w, r)
					return
				}
				if scenario == "unverified" {
					w.Header().Set("Content-Length", fmt.Sprint(len(payload)*2))
				}
				_, _ = w.Write(payload)
			}))
			defer server.Close()
			digest := sha1HexLocal([]byte("other bytes"))
			if scenario == "unverified" {
				digest = ""
			}
			_, err := downloadForgeInstallerRecoveringTransport(context.Background(), server.Client(), vanillaDownloadTask{Path: "forge.jar", URL: server.URL + "/installer.jar", SHA1: digest}, t.TempDir())
			if err == nil || requests.Load() != 1 {
				t.Fatalf("Для %s должен происходить один отказ без повтора: запросов=%d ошибка=%v", scenario, requests.Load(), err)
			}
		})
	}
}
