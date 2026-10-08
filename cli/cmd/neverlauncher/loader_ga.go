package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

type loaderGASupportEntry0180 struct {
	Loader           string `json:"loader"`
	MinecraftVersion string `json:"minecraftVersion"`
	JavaMajor        int    `json:"javaMajor"`
	InstallMode      string `json:"installMode"`
	Legacy           bool   `json:"legacy"`
}

func compatibilityLoaderGA0180Required(ver string) bool {
	return compatibilityVersionAtLeast(ver, 0, 18, 0)
}

func loaderGASupport0180(loader, minecraft string) (loaderGASupportEntry0180, bool) {
	loader = strings.ToLower(strings.TrimSpace(loader))
	minecraft = strings.TrimSpace(minecraft)
	entry := loaderGASupportEntry0180{Loader: loader, MinecraftVersion: minecraft}
	switch loader {
	case "fabric":
		javaMajor, ok := fabricCompatibilityII0171[minecraft]
		if !ok {
			return loaderGASupportEntry0180{}, false
		}
		entry.JavaMajor, entry.InstallMode = javaMajor, "fabric-meta-profile"
		return entry, true
	case "quilt":
		javaMajor, ok := quiltCompatibilityII0172[minecraft]
		if !ok {
			return loaderGASupportEntry0180{}, false
		}
		entry.JavaMajor, entry.InstallMode = javaMajor, "quilt-meta-profile"
		return entry, true
	case "forge":
		if javaMajor, ok := forgeLegacy1710_0175[minecraft]; ok {
			entry.JavaMajor, entry.InstallMode, entry.Legacy = javaMajor, "forge-v1-universal-launchwrapper-fml", true
			return entry, true
		}
		if javaMajor, ok := forgeLegacy1122_0174[minecraft]; ok {
			entry.JavaMajor, entry.InstallMode, entry.Legacy = javaMajor, "forge-v1-universal-fml", true
			return entry, true
		}
		javaMajor, ok := forgeModern0173[minecraft]
		if !ok {
			return loaderGASupportEntry0180{}, false
		}
		entry.JavaMajor, entry.InstallMode = javaMajor, "forge-processor-installer"
		return entry, true
	case "neoforge":
		javaMajor, ok := neoForgeCompatibilityII0176[minecraft]
		if !ok {
			return loaderGASupportEntry0180{}, false
		}
		entry.JavaMajor, entry.InstallMode = javaMajor, "neoforge-processor-installer"
		return entry, true
	default:
		return loaderGASupportEntry0180{}, false
	}
}

func enforceLoaderGASupport0180(loader, minecraft string, detectedJavaMajor int) (loaderGASupportEntry0180, error) {
	entry, ok := loaderGASupport0180(loader, minecraft)
	if !ok {
		return loaderGASupportEntry0180{}, fmt.Errorf("Загрузчик Совместимость GA 0.18.0: %s Minecraft %s является вне сертифицированный GA поддержка поверхность", strings.ToLower(strings.TrimSpace(loader)), strings.TrimSpace(minecraft))
	}
	if detectedJavaMajor > 0 && detectedJavaMajor != entry.JavaMajor {
		return loaderGASupportEntry0180{}, fmt.Errorf("Загрузчик Совместимость GA 0.18.0: %s Minecraft %s требует Java %d, материализовать Vanilla профиль требует Java %d", entry.Loader, entry.MinecraftVersion, entry.JavaMajor, detectedJavaMajor)
	}
	return entry, nil
}

func loaderGASupportEntries0180() []loaderGASupportEntry0180 {
	entries := make([]loaderGASupportEntry0180, 0, len(fabricCompatibilityII0171)+len(quiltCompatibilityII0172)+len(forgeModern0173)+len(forgeLegacy1122_0174)+len(forgeLegacy1710_0175)+len(neoForgeCompatibilityII0176))
	for _, loader := range []string{"fabric", "quilt", "forge", "neoforge"} {
		var versions []string
		switch loader {
		case "fabric":
			for minecraft := range fabricCompatibilityII0171 {
				versions = append(versions, minecraft)
			}
		case "quilt":
			for minecraft := range quiltCompatibilityII0172 {
				versions = append(versions, minecraft)
			}
		case "forge":
			for minecraft := range forgeLegacy1710_0175 {
				versions = append(versions, minecraft)
			}
			for minecraft := range forgeLegacy1122_0174 {
				versions = append(versions, minecraft)
			}
			for minecraft := range forgeModern0173 {
				versions = append(versions, minecraft)
			}
		case "neoforge":
			for minecraft := range neoForgeCompatibilityII0176 {
				versions = append(versions, minecraft)
			}
		}
		sort.Strings(versions)
		for _, minecraft := range versions {
			entry, ok := loaderGASupport0180(loader, minecraft)
			if !ok {
				panic("invalid GA support entry " + loader + "/" + minecraft)
			}
			entries = append(entries, entry)
		}
	}
	return entries
}

func loaderGASupportSHA2560180() string {
	digest := sha256.New()
	for _, entry := range loaderGASupportEntries0180() {
		fmt.Fprintf(digest, "%s\x00%s\x00%d\x00%s\x00%t\n", entry.Loader, entry.MinecraftVersion, entry.JavaMajor, entry.InstallMode, entry.Legacy)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func loaderGAVersions0180(loader string) []string {
	versions := []string{}
	for _, entry := range loaderGASupportEntries0180() {
		if entry.Loader == loader {
			versions = append(versions, entry.MinecraftVersion)
		}
	}
	return versions
}

func validateLoaderGASupportPolicy0180() error {
	entries := loaderGASupportEntries0180()
	wantCounts := map[string]int{"fabric": 48, "quilt": 48, "forge": 45, "neoforge": 22}
	counts := map[string]int{}
	legacy := map[string]bool{}
	seen := map[string]bool{}
	for _, entry := range entries {
		key := entry.Loader + "\x00" + entry.MinecraftVersion
		if seen[key] {
			return fmt.Errorf("Загрузчик Совместимость GA дубликат поддержка запись %s/%s", entry.Loader, entry.MinecraftVersion)
		}
		seen[key] = true
		counts[entry.Loader]++
		if entry.Loader == "forge" && entry.Legacy {
			legacy[entry.MinecraftVersion] = true
		}
		if entry.JavaMajor != 8 && entry.JavaMajor != 16 && entry.JavaMajor != 17 && entry.JavaMajor != 21 && entry.JavaMajor != 25 {
			return fmt.Errorf("Загрузчик Совместимость GA недопустимый Java крупный %d для %s/%s", entry.JavaMajor, entry.Loader, entry.MinecraftVersion)
		}
	}
	for loader, want := range wantCounts {
		if counts[loader] != want {
			return fmt.Errorf("Загрузчик Совместимость GA %s поддержка счётчик=%d want=%d", loader, counts[loader], want)
		}
	}
	if !legacy["1.7.10"] || !legacy["1.12.2"] || len(legacy) != 2 {
		return fmt.Errorf("Загрузчик Совместимость GA устаревший Forge поверхность несоответствие: %v", legacy)
	}
	if len(loaderGASupportSHA2560180()) != 64 {
		return fmt.Errorf("Загрузчик Совместимость GA поддержка хеш недопустимый")
	}
	return nil
}
