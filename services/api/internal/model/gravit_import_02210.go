package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Gravit conversion never downloads files, executes actions or trusts a foreign
// classloader. Output settings are intended for a NEW Never build workspace;
// the normal stage/validate/sign/publish pipeline remains mandatory.
var gravitJavaClass02210 = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+$`)

type GravitFieldResult02210 struct {
	Field  string `json:"field"`
	Status string `json:"status"` // mapped, transformed, manual, blocked
	Target string `json:"target,omitempty"`
	Reason string `json:"reason"`
}
type GravitServer02210 struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Default bool   `json:"default"`
}
type GravitBuildSettings02210 struct {
	Minecraft    MinecraftInfo     `json:"minecraft"`
	Runtime      RuntimeInfo       `json:"runtime"`
	Directories  Directories       `json:"directories"`
	FileRules    []FileRule        `json:"fileRules"`
	ToolVersions map[string]string `json:"toolVersions"`
}
type GravitImportResult02210 struct {
	Format       string                   `json:"format"`
	SourceSHA256 string                   `json:"sourceSha256"`
	Ready        bool                     `json:"ready"`
	Profile      Profile                  `json:"profile"`
	Settings     GravitBuildSettings02210 `json:"settings"`
	Servers      []GravitServer02210      `json:"servers"`
	Fields       []GravitFieldResult02210 `json:"fields"`
	Summary      map[string]int           `json:"summary"`
}

// ConvertGravitProfile02210 consumes a single JSON ClientProfile. JSONC must
// first be converted to valid JSON by the operator: stripping comments inside
// string literals without a parser would be unsafe. Empty/unknown fields never
// disappear silently. SourceSHA256 identifies the exact input bytes analyzed.
func ConvertGravitProfile02210(source []byte, projectID, profileID, profileName, loaderHint string) (GravitImportResult02210, error) {
	if len(source) == 0 || len(source) > 1<<20 {
		return GravitImportResult02210{}, errors.New("Gravit ClientProfile must be 1 byte to 1 MiB")
	}
	root, err := gravitObject02210(source)
	if err != nil {
		return GravitImportResult02210{}, err
	}
	if len(root) == 0 {
		return GravitImportResult02210{}, errors.New("empty Gravit ClientProfile")
	}
	sum := sha256.Sum256(source)
	out := GravitImportResult02210{Format: "neverlauncher.gravit-import-report.v1", SourceSHA256: hex.EncodeToString(sum[:]), Servers: []GravitServer02210{}, Fields: []GravitFieldResult02210{}, Summary: map[string]int{"mapped": 0, "transformed": 0, "manual": 0, "blocked": 0}}
	report := func(field, status, target, reason string) {
		out.Fields = append(out.Fields, GravitFieldResult02210{field, status, target, reason})
		out.Summary[status]++
	}
	stringField := func(field string) (string, bool) {
		raw, ok := root[field]
		if !ok {
			return "", false
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			report(field, "blocked", "", "expected a string")
			return "", false
		}
		return s, true
	}
	integerField := func(field string) (int, bool) {
		raw, ok := root[field]
		if !ok {
			return 0, false
		}
		var n int
		if err := json.Unmarshal(raw, &n); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			report(field, "blocked", "", "expected an integer")
			return 0, false
		}
		return n, true
	}
	listField := func(field string) ([]string, bool) {
		raw, ok := root[field]
		if !ok {
			return nil, false
		}
		var v []string
		if err := json.Unmarshal(raw, &v); err != nil || v == nil {
			report(field, "blocked", "", "expected an array of strings")
			return nil, false
		}
		if len(v) > 4096 {
			report(field, "blocked", "", "too many entries")
			return nil, false
		}
		return v, true
	}
	title, ok := stringField("title")
	if ok {
		report("title", "mapped", "profile.name", "display title")
	}
	if title == "" {
		report("title", "blocked", "profile.name", "nonempty title required")
	}
	desc, ok := stringField("info")
	if ok {
		report("info", "mapped", "profile.description", "display description")
	}
	if profileName == "" {
		profileName = title
	}
	if len(profileName) > 120 || len(desc) > 4096 {
		return GravitImportResult02210{}, errors.New("profile title or description too long")
	}
	if projectID == "" || !profileID0225.MatchString(profileID) || profileID == "." || profileID == ".." {
		return GravitImportResult02210{}, errors.New("destination project ID and safe new profile ID required")
	}
	version, ok := stringField("version")
	if ok {
		report("version", "mapped", "settings.minecraft.version", "Minecraft version")
	}
	if version == "" {
		report("version", "blocked", "settings.minecraft.version", "Minecraft version required")
	}
	out.Settings.Minecraft.Version = version
	mainClass, ok := stringField("mainClass")
	if ok {
		out.Settings.Runtime.Launch.MainClass = mainClass
		report("mainClass", "mapped", "settings.runtime.launch.mainClass", "Java entrypoint")
	}
	if !gravitJavaClass02210.MatchString(mainClass) {
		report("mainClass", "blocked", "settings.runtime.launch.mainClass", "valid fully qualified Java main class required")
	}
	out.Settings.Runtime.Launch.ClasspathStrategy = "manifest"
	out.Settings.Runtime.Java.Distribution = "temurin"
	if loaderHint == "" {
		loaderHint = "vanilla"
		report("loaderHint", "manual", "profile.loader", "confirm loader (Gravit ClientProfile does not specify loader identity)")
	}
	switch loaderHint {
	case "vanilla", "fabric", "quilt", "forge", "neoforge":
	default:
		report("loaderHint", "blocked", "profile.loader", "unsupported loader hint")
	}
	out.Settings.Minecraft.Loader = loaderHint
	out.Profile = Profile{ID: profileID, ProjectID: projectID, Name: profileName, Description: desc, Loader: loaderHint, Preset: "custom"}
	if p, e := NormalizeProfileV2(out.Profile); e == nil {
		out.Profile = p
	} else {
		report("destination", "blocked", "profile", e.Error())
	}
	if v, ok := stringField("uuid"); ok {
		if len(v) < 8 || len(v) > 64 {
			report("uuid", "blocked", "", "invalid source UUID")
		} else {
			report("uuid", "transformed", "sourceSha256", "source UUID is not reused as Never profile identity")
		}
	}
	if v, ok := stringField("dir"); ok {
		if !gravitSafePath02210(v) {
			report("dir", "blocked", "", "unsafe source installation directory")
		} else {
			report("dir", "manual", "", "source directory is selected during workspace import, not a client file path")
		}
	}
	if v, ok := stringField("assetDir"); ok {
		if !gravitSafePath02210(v) {
			report("assetDir", "blocked", "", "unsafe assets directory")
		} else {
			out.Settings.Directories.Assets = v
			report("assetDir", "mapped", "settings.directories.assets", "asset directory")
		}
	}
	if v, ok := stringField("assetIndex"); ok {
		if v == "" {
			report("assetIndex", "blocked", "", "empty asset index")
		} else {
			report("assetIndex", "manual", "", "asset index metadata must be supplied during Minecraft assets preparation")
		}
	}
	if v, ok := integerField("sortIndex"); ok {
		if v == 0 {
			report("sortIndex", "mapped", "", "default sort position")
		} else {
			report("sortIndex", "manual", "", "Never Profile v2 has no persistent sort index")
		}
	}
	for _, key := range []string{"minJavaVersion", "recommendJavaVersion", "maxJavaVersion"} {
		if v, ok := integerField(key); ok {
			if v < 0 || (v > 255 && !(key == "maxJavaVersion" && v == 999)) {
				report(key, "blocked", "", "Java major version outside supported range")
				continue
			}
			target := "settings.runtime.java."
			status := "mapped"
			reason := "Java version bound"
			switch key {
			case "minJavaVersion":
				out.Settings.Runtime.Java.MinimumMajorVersion = v
				target += "minimumMajorVersion"
			case "recommendJavaVersion":
				out.Settings.Runtime.Java.RecommendedMajorVersion = v
				out.Settings.Runtime.Java.MajorVersion = v
				target += "recommendedMajorVersion"
			case "maxJavaVersion":
				target += "maximumMajorVersion"
				if v == 999 {
					status = "transformed"
					reason = "Gravit unbounded sentinel 999 mapped to Never maximum 0"
				} else {
					out.Settings.Runtime.Java.MaximumMajorVersion = v
				}
			}
			report(key, status, target, reason)
		}
	}
	java := &out.Settings.Runtime.Java
	if java.MajorVersion == 0 {
		java.MajorVersion = java.MinimumMajorVersion
	}
	if java.MajorVersion == 0 {
		report("recommendJavaVersion", "blocked", "settings.runtime.java.majorVersion", "explicit Java major required")
	}
	if v, ok := root["warnMissJavaVersion"]; ok {
		var b bool
		if json.Unmarshal(v, &b) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			report("warnMissJavaVersion", "blocked", "", "expected boolean")
		} else if b {
			report("warnMissJavaVersion", "manual", "", "Never enforces Java constraints rather than warning and continuing")
		} else {
			report("warnMissJavaVersion", "transformed", "settings.runtime.java", "Never enforces Java constraints")
		}
	}
	for _, key := range []string{"jvmArgs", "clientArgs"} {
		if values, ok := listField(key); ok {
			if key == "jvmArgs" {
				check := Manifest{Runtime: RuntimeInfo{Java: JavaInfo{MajorVersion: 17, Distribution: "temurin"}, JVMArgs: values}}
				if e := ValidateRuntimeConstraints0223(check); e != nil {
					report(key, "blocked", "settings.runtime.jvmArgs", e.Error())
					continue
				}
				out.Settings.Runtime.JVMArgs = values
				report(key, "mapped", "settings.runtime.jvmArgs", "preserved ordered JVM argument array; project publisher must approve custom arguments")
			} else {
				unsafe := ""
				protected := map[string]bool{"--accesstoken": true, "--uuid": true, "--username": true, "--usertype": true, "--xuid": true, "--clientid": true, "--gamedir": true, "--assetsdir": true}
				for _, arg := range values {
					lower := strings.ToLower(arg)
					if strings.ContainsAny(arg, "\x00\r\n") || protected[strings.SplitN(lower, "=", 2)[0]] {
						unsafe = arg
						break
					}
				}
				if unsafe != "" {
					report(key, "blocked", "settings.minecraft.gameArgs", "reserved or unsafe Minecraft launch argument "+unsafe)
					continue
				}
				out.Settings.Minecraft.GameArgs = values
				report(key, "mapped", "settings.minecraft.gameArgs", "preserved ordered client arguments; auth/session arguments remain runtime-owned")
			}
		}
	}
	for _, key := range []string{"classPath", "altClassPath"} {
		if v, ok := listField(key); ok {
			if key == "altClassPath" && len(v) > 0 {
				report(key, "blocked", "", "Gravit alternate system classpath is not equivalent to Never signed classpath")
				continue
			}
			if key == "altClassPath" {
				report(key, "mapped", "", "empty alternate classpath")
				continue
			}
			good := true
			seenPaths := map[string]bool{}
			for _, entry := range v {
				normalized := strings.ToLower(entry)
				if seenPaths[normalized] {
					report(key, "blocked", "", "duplicate classpath entry: "+entry)
					good = false
					break
				}
				seenPaths[normalized] = true
				if !gravitSafePath02210(entry) || gravitProtected02210(entry) {
					report(key, "blocked", "", "unsafe classpath entry: "+entry)
					good = false
					break
				}
				if !strings.HasSuffix(strings.ToLower(entry), ".jar") {
					report(key, "blocked", "", "directory/non-JAR classpath requires enumerating signed JAR files: "+entry)
					good = false
					break
				}
			}
			if good {
				out.Settings.Runtime.Launch.ClasspathEntries = v
				report(key, "transformed", "settings.runtime.launch.classpathEntries", "ordered JAR list; each JAR must be staged with SHA-256 before publication")
			}
		}
	}
	if _, ok := root["classLoaderConfig"]; !ok {
		report("classLoaderConfig", "blocked", "", "classloader must be explicit; Gravit default cannot be assumed equivalent to Never")
	}
	if raw, ok := root["classLoaderConfig"]; ok {
		var v string
		if json.Unmarshal(raw, &v) != nil {
			report("classLoaderConfig", "blocked", "", "expected string")
		} else if v == "SYSTEM_ARGS" {
			report("classLoaderConfig", "transformed", "settings.runtime.launch", "native JVM process launch; confirm equivalent main class and bootstrap")
		} else {
			report("classLoaderConfig", "blocked", "", "unsupported Gravit classloader "+v+"; Never will not execute foreign launcher bootstrap")
		}
	}
	for _, key := range []string{"compatClasses", "updateOptional"} {
		if raw, ok := root[key]; ok {
			var list []json.RawMessage
			if json.Unmarshal(raw, &list) != nil || list == nil {
				report(key, "blocked", "", "expected array")
			} else if len(list) > 0 {
				for i, item := range list {
					field := fmt.Sprintf("%s[%d]", key, i)
					if key == "updateOptional" {
						var option map[string]json.RawMessage
						if json.Unmarshal(item, &option) == nil {
							if actions, found := option["actions"]; found {
								var values []json.RawMessage
								if json.Unmarshal(actions, &values) == nil {
									for j, a := range values {
										var action map[string]json.RawMessage
										if json.Unmarshal(a, &action) == nil {
											var kind string
											_ = json.Unmarshal(action["type"], &kind)
											report(fmt.Sprintf("%s.actions[%d]", field, j), "blocked", "", "unsupported optional action "+kind+"; manual port with dependency/conflict semantics required")
										}
									}
								}
							}
						}
					}
					report(field, "blocked", "", "optional actions or compatibility bootstrap cannot be reproduced safely")
				}
			} else {
				report(key, "mapped", "", "empty array")
			}
		}
	}
	// File policy conversion is conservative: verify never authorizes removal of
	// files absent from the manifest, even for Gravit `update` directories.
	policy := map[string]FileRule{}
	for _, key := range []string{"update", "updateVerify", "updateExclusions"} {
		v, ok := listField(key)
		if !ok {
			continue
		}
		valid := true
		for _, raw := range v {
			pattern, good := gravitFilePattern02210(raw)
			if !good {
				report(key, "blocked", "", "unsafe file rule: "+raw)
				valid = false
				continue
			}
			if key != "updateExclusions" && gravitProtected02210(raw) {
				report(key, "blocked", "", "Gravit attempts to update user-owned path: "+raw)
				valid = false
				continue
			}
			rule := FileRule{Pattern: pattern, Action: "verify", Ownership: "required"}
			if key == "updateExclusions" {
				rule = FileRule{Pattern: pattern, Action: "exclude", Ownership: "user-owned"}
			}
			if prior, exists := policy[pattern]; exists && prior.Action != rule.Action {
				report(key, "blocked", "", "contradictory ownership at "+pattern)
				valid = false
				continue
			}
			policy[pattern] = rule
		}
		if valid {
			status := "transformed"
			target := "settings.fileRules"
			reason := "managed Gravit update converted to non-destructive Never verify rules; actual hashes required"
			if key == "updateExclusions" {
				reason = "exclusions translated to user-owned protection"
			}
			if len(v) == 0 {
				status = "mapped"
				reason = "empty file rule list"
			}
			report(key, status, target, reason)
		}
	}
	keys := make([]string, 0, len(policy))
	for k := range policy {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Settings.FileRules = append(out.Settings.FileRules, policy[k])
	}
	if len(out.Settings.FileRules) > 0 {
		probe := Manifest{SchemaVersion: ManifestSchemaV2, FileRules: out.Settings.FileRules}
		if err := ValidateFileOwnership0224(probe); err != nil {
			report("fileRules", "blocked", "settings.fileRules", err.Error())
		}
	}
	if raw, ok := root["settings"]; ok {
		fields, e := gravitObject02210(raw)
		if e != nil {
			report("settings", "blocked", "", "expected settings object")
		} else {
			for k, v := range fields {
				switch k {
				case "ram":
					var n int
					if json.Unmarshal(v, &n) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) || n < 0 || n > 1048576 {
						report("settings.ram", "blocked", "", "RAM must be nonnegative integer")
					} else {
						out.Settings.Runtime.Memory.RecommendedMb = n
						report("settings.ram", "transformed", "settings.runtime.memory.recommendedMb", "zero means automatic")
					}
				case "autoEnter", "fullScreen":
					var b bool
					if json.Unmarshal(v, &b) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
						report("settings."+k, "blocked", "", "expected boolean")
					} else if b {
						report("settings."+k, "manual", "", "Desktop user preference cannot be enforced by Build Workspace settings")
					} else {
						report("settings."+k, "mapped", "", "disabled by default; no workspace override required")
					}
				default:
					report("settings."+k, "blocked", "", "unknown settings key")
				}
			}
		}
	}
	if raw, ok := root["servers"]; ok {
		var servers []map[string]json.RawMessage
		if json.Unmarshal(raw, &servers) != nil || servers == nil {
			report("servers", "blocked", "", "expected server array")
		} else {
			if len(servers) > 128 {
				report("servers", "blocked", "", "too many servers")
			} else if len(servers) == 0 {
				report("servers", "mapped", "", "empty list")
			} else {
				defaults := 0
				for i, s := range servers {
					label := fmt.Sprintf("servers[%d]", i)
					var name, address string
					var port int
					var d bool
					if json.Unmarshal(s["name"], &name) != nil || json.Unmarshal(s["serverAddress"], &address) != nil || json.Unmarshal(s["serverPort"], &port) != nil || name == "" || address == "" || port < 1 || port > 65535 {
						report(label, "blocked", "", "server name, address and valid TCP port required")
						continue
					}
					if v, has := s["isDefault"]; has && json.Unmarshal(v, &d) != nil {
						report(label, "blocked", "", "isDefault must be boolean")
						continue
					}
					if d {
						defaults++
					}
					for k := range s {
						switch k {
						case "name", "serverAddress", "serverPort", "isDefault", "protocol", "socketPing":
						default:
							report(label+"."+k, "blocked", "", "unrecognized server behavior")
						}
					}
					out.Servers = append(out.Servers, GravitServer02210{Name: name, Address: address, Port: port, Default: d})
					report(label, "manual", "serverBrowser", "create project/profile-scoped Never ServerBridge server; direct Gravit server entries are not imported into registry")
				}
				if defaults > 1 {
					report("servers", "blocked", "", "multiple default servers")
				}
			}
		}
	}
	if raw, ok := root["limited"]; ok {
		var limited bool
		if json.Unmarshal(raw, &limited) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			report("limited", "blocked", "", "expected boolean")
		} else if limited {
			report("limited", "blocked", "", "Gravit permission restriction needs explicit Never ACL; cannot grant access by importing")
		} else {
			report("limited", "mapped", "", "unrestricted source profile")
		}
	}
	if raw, ok := root["properties"]; ok {
		var p map[string]json.RawMessage
		if json.Unmarshal(raw, &p) != nil || p == nil {
			report("properties", "blocked", "", "expected object")
		} else if len(p) > 0 {
			report("properties", "manual", "", "custom properties require explicit audit for launch/auth semantics")
		} else {
			report("properties", "mapped", "", "no custom properties")
		}
	}
	known := map[string]bool{}
	for _, k := range []string{"title", "uuid", "version", "info", "dir", "sortIndex", "assetIndex", "assetDir", "update", "updateExclusions", "updateVerify", "updateOptional", "jvmArgs", "classPath", "altClassPath", "clientArgs", "compatClasses", "properties", "servers", "classLoaderConfig", "recommendJavaVersion", "minJavaVersion", "maxJavaVersion", "warnMissJavaVersion", "settings", "limited", "mainClass"} {
		known[k] = true
	}
	for k := range root {
		if !known[k] {
			report(k, "blocked", "", "unknown Gravit field: no silent omission of potential launch/security behavior")
		}
	}
	// A preview may contain classpath paths not yet present in its file list.
	// Validate the rest with the same production validator used by publication.
	runtimeProbe := out.Settings.Runtime
	runtimeProbe.Launch.ClasspathEntries = nil
	check := Manifest{SchemaVersion: ManifestSchemaV2, Runtime: runtimeProbe, Minecraft: out.Settings.Minecraft}
	if err := ValidateRuntimeConstraints0223(check); err != nil {
		report("runtime", "blocked", "settings.runtime", err.Error())
	}
	sort.Slice(out.Fields, func(i, j int) bool {
		if out.Fields[i].Field == out.Fields[j].Field {
			return out.Fields[i].Status < out.Fields[j].Status
		}
		return out.Fields[i].Field < out.Fields[j].Field
	})
	out.Ready = out.Summary["blocked"] == 0 && out.Summary["manual"] == 0
	return out, nil
}

func gravitObject02210(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return nil, errors.New("Gravit ClientProfile must be a JSON object")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		tok, e = d.Token()
		if e != nil {
			return nil, e
		}
		k, ok := tok.(string)
		if !ok {
			return nil, errors.New("invalid object key")
		}
		if _, exists := out[k]; exists {
			return nil, fmt.Errorf("duplicate JSON field %q", k)
		}
		var v json.RawMessage
		if e = d.Decode(&v); e != nil {
			return nil, e
		}
		out[k] = v
	}
	if _, e = d.Token(); e != nil {
		return nil, e
	}
	var tail json.RawMessage
	if e = d.Decode(&tail); e != nil && e != io.EOF {
		return nil, errors.New("unexpected trailing JSON input")
	}
	if len(tail) != 0 {
		return nil, errors.New("unexpected trailing JSON value")
	}
	return out, nil
}
func gravitSafePath02210(s string) bool {
	if s == "" || len(s) > 512 || strings.ContainsAny(s, "\\:\x00\r\n*?[]") || strings.HasPrefix(s, "/") || path.Clean(s) != s || s == "." || s == ".." || strings.HasPrefix(s, "../") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func gravitFilePattern02210(s string) (string, bool) {
	if !gravitSafePath02210(s) {
		return "", false
	}
	if strings.HasSuffix(strings.ToLower(s), ".jar") || strings.Contains(path.Base(s), ".") {
		return s, true
	}
	return s + "/**", true
}

func gravitProtected02210(s string) bool { return protectedFilePath0224(s) }
