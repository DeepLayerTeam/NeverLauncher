// Package gravitdetector analyzes an untrusted Gravit installation ZIP without
// extracting to disk, interpreting class files, executing JARs or emitting secrets.
package gravitdetector

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const MaxArchiveBytes = 64 << 20
const maxEntries = 5000
const maxExpandedBytes = 128 << 20
const maxConfigBytes = 2 << 20
const maxJarBytes = 32 << 20

var versionPattern = regexp.MustCompile(`(?:^|[^0-9])(?:v)?(5\.[0-9]{1,2}\.[0-9]{1,3})(?:[^0-9]|$)`)

type Finding struct {
	Code      string `json:"code"`
	Severity  string `json:"severity"` // info | manual | blocked
	Component string `json:"component"`
	Path      string `json:"path,omitempty"`
	Message   string `json:"message"`
}
type Component struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Status string `json:"status"` // recognized | manual | blocked
	Type   string `json:"type,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}
type Report struct {
	Format          string         `json:"format"`
	SourceSHA256    string         `json:"sourceSha256"`
	SourceEntries   int            `json:"sourceEntries"`
	ClaimedVersion  string         `json:"claimedVersion,omitempty"`
	DetectedVersion string         `json:"detectedVersion,omitempty"`
	VersionEvidence string         `json:"versionEvidence"` // signed upstream provenance is outside the scope
	VersionStatus   string         `json:"versionStatus"`   // recognized | unverified | unsupported | conflict
	Status          string         `json:"status"`          // manual | blocked, never production compatible by inference
	CutoverAllowed  bool           `json:"cutoverAllowed"`
	Components      []Component    `json:"components"`
	Findings        []Finding      `json:"findings"`
	Summary         map[string]int `json:"summary"`
}

func (r *Report) finding(code, severity, kind, file, message string) {
	r.Findings = append(r.Findings, Finding{code, severity, kind, file, message})
}
func recognizedVersion(v string) bool {
	m := versionPattern.FindStringSubmatch(v)
	if len(m) != 2 || strings.TrimPrefix(v, "v") != m[1] {
		return false
	}
	p := strings.Split(m[1], ".")
	patch, e := strconv.Atoi(p[2])
	return e == nil && p[0] == "5" && p[1] == "7" && patch <= 12
}

// Assess validates the entire bounded archive before parsing any configuration.
// The report contains classifications and digests, never source JSON or secrets.
func Assess(source []byte, claimedVersion string) (Report, error) {
	if len(source) == 0 || len(source) > MaxArchiveBytes {
		return Report{}, errors.New("source ZIP must be 1..64 MiB")
	}
	if len(claimedVersion) > 40 || strings.ContainsAny(claimedVersion, "\n\r\t") {
		return Report{}, errors.New("invalid claimed Gravit version")
	}
	h := sha256.Sum256(source)
	r := Report{Format: "neverlauncher.gravit-compatibility.v1", SourceSHA256: hex.EncodeToString(h[:]), ClaimedVersion: strings.TrimSpace(claimedVersion), VersionEvidence: "absent", VersionStatus: "unverified", Status: "manual", Components: []Component{}, Findings: []Finding{}, Summary: map[string]int{}}
	z, err := zip.NewReader(bytes.NewReader(source), int64(len(source)))
	if err != nil {
		return Report{}, fmt.Errorf("invalid Gravit ZIP: %w", err)
	}
	if len(z.File) == 0 || len(z.File) > maxEntries {
		return Report{}, errors.New("ZIP entry count outside safe limit")
	}
	seen := map[string]bool{}
	files := make([]*zip.File, 0, len(z.File))
	var expanded uint64
	for _, f := range z.File {
		n := strings.ReplaceAll(f.Name, "\\", "/")
		clean := path.Clean(n)
		if n == "" || strings.HasPrefix(n, "/") || clean == ".." || strings.HasPrefix(clean, "../") || strings.ContainsRune(n, '\x00') || strings.Contains(n, ":") || clean != strings.TrimSuffix(n, "/") || f.Mode()&os.ModeSymlink != 0 {
			return Report{}, fmt.Errorf("unsafe ZIP member path or type: %q", f.Name)
		}
		normalized := strings.ToLower(clean)
		if seen[normalized] {
			return Report{}, fmt.Errorf("duplicate ZIP member: %q", f.Name)
		}
		seen[normalized] = true
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Flags&1 != 0 {
			return Report{}, errors.New("encrypted ZIP entries are not supported")
		}
		if f.Method != zip.Deflate && f.Method != zip.Store {
			return Report{}, errors.New("unsupported ZIP compression")
		}
		expanded += f.UncompressedSize64
		if expanded > maxExpandedBytes {
			return Report{}, errors.New("ZIP expanded data exceeds 128 MiB")
		}
		if f.UncompressedSize64 > 0 && f.CompressedSize64 == 0 {
			return Report{}, errors.New("ZIP compression size invalid")
		}
		if f.UncompressedSize64 > f.CompressedSize64*400+4096 {
			return Report{}, errors.New("ZIP compression expansion ratio exceeds limit")
		}
		files = append(files, f)
	}
	r.SourceEntries = len(files)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	foundLaunch := false
	launchConfigs := 0
	runtimeConfigs := 0
	profileCount := 0
	foundRuntime := false
	var manifestVersions []string
	for _, f := range files {
		n := strings.ReplaceAll(f.Name, "\\", "/")
		lower := strings.ToLower(n)
		base := strings.ToLower(path.Base(n))
		switch {
		case base == "launchserver.json":
			foundLaunch = true
			launchConfigs++
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("launchserver", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "launchserver", Path: n, Status: "recognized", Type: "json"})
			r.inspectLaunch(n, obj)
		case strings.HasSuffix(lower, "/profiles/") || (strings.Contains(lower, "/profiles/") && strings.HasSuffix(lower, ".json")) || strings.HasPrefix(lower, "profiles/") && strings.HasSuffix(lower, ".json"):
			profileCount++
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("client_profile", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "client_profile", Path: n, Status: "recognized", Type: "json"})
			r.inspectProfile(n, obj)
		case base == "launchserverruntime.json" || base == "launchserverruntimeconfig.json":
			foundRuntime = true
			runtimeConfigs++
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("runtime", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "runtime", Path: n, Status: "recognized", Type: "json"})
			r.inspectRuntime(n, obj)
		case (strings.Contains(lower, "/runtime/") || strings.HasPrefix(lower, "runtime/")) && strings.HasSuffix(lower, ".json"):
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("runtime_settings", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "runtime_settings", Path: n, Status: "manual", Type: "json"})
			r.inspectRuntime(n, obj)
		case strings.Contains(lower, "/modules/") && strings.HasSuffix(lower, ".jar") || strings.HasPrefix(lower, "modules/") && strings.HasSuffix(lower, ".jar"):
			r.Components = append(r.Components, Component{Kind: "module", Path: n, Status: "manual", Type: "jar"})
			r.finding("MODULE_REVIEW_REQUIRED", "manual", "module", n, "custom module requires semantic analysis; JAR is never executed")
		case (base == ".env" || strings.HasSuffix(lower, "/serverwrapper.env")) && f.UncompressedSize64 <= maxConfigBytes:
			data, e := readBounded(f, maxConfigBytes)
			if e != nil {
				r.finding("WRAPPER_ENV_UNREADABLE", "blocked", "server_wrapper", n, "unable to read wrapper environment")
				continue
			}
			if bytes.Contains(data, []byte("SERVERWRAPPER_ADDRESS=")) || bytes.Contains(data, []byte("SERVERWRAPPER_CHECK_SERVER_TOKEN=")) {
				r.Components = append(r.Components, Component{Kind: "server_wrapper", Path: n, Status: "manual", Type: "environment"})
				r.finding("WRAPPER_REENROLL", "manual", "server_wrapper", n, "ServerWrapper environment contains legacy integration settings; secrets and keys are not imported")
			}
		case strings.Contains(lower, "serverwrapper/") && base == "config.json":
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("server_wrapper", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "server_wrapper", Path: n, Status: "manual", Type: "json"})
			r.inspectWrapper(n, obj)
		case base == "serverwrapper.json" || base == "serverwrapperconfig.json":
			obj, e := readObject(f)
			if e != nil {
				r.addInvalid("server_wrapper", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "server_wrapper", Path: n, Status: "manual", Type: "json"})
			r.inspectWrapper(n, obj)
		case base == "launchserver.jar":
			if f.UncompressedSize64 > maxJarBytes {
				r.finding("SERVER_JAR_TOO_LARGE", "blocked", "version", n, "server JAR exceeds manifest inspection limit")
				continue
			}
			buf, e := readBounded(f, maxJarBytes)
			if e != nil {
				r.addInvalid("version", n, e)
				continue
			}
			if v, ok := jarManifestVersion(buf); ok {
				manifestVersions = append(manifestVersions, v)
			} else {
				r.finding("SERVER_VERSION_UNREADABLE", "manual", "version", n, "cannot establish Gravit release from server JAR manifest")
			}
		case strings.HasSuffix(lower, ".json") && (strings.Contains(lower, "/modules/") || strings.HasPrefix(lower, "modules/")):
			if _, e := readObject(f); e != nil {
				r.addInvalid("module_config", n, e)
				continue
			}
			r.Components = append(r.Components, Component{Kind: "module_config", Path: n, Status: "manual", Type: "json"})
			r.finding("MODULE_CONFIG_REVIEW", "manual", "module_config", n, "module-specific settings require manual compatibility review")
		}
	}
	if launchConfigs > 1 {
		r.finding("MULTIPLE_LAUNCHSERVERS", "blocked", "launchserver", "", "multiple LaunchServer.json configs make source identity ambiguous")
	}
	if runtimeConfigs > 1 {
		r.finding("MULTIPLE_RUNTIMES", "blocked", "runtime", "", "multiple runtime configs make source identity ambiguous")
	}
	if !foundLaunch {
		r.finding("LAUNCHSERVER_MISSING", "blocked", "launchserver", "", "LaunchServer.json is required")
	}
	if profileCount == 0 {
		r.finding("PROFILES_MISSING", "manual", "client_profile", "", "no ClientProfile JSON found in profiles/")
	}
	if !foundRuntime {
		r.finding("RUNTIME_MISSING", "manual", "runtime", "", "no LaunchServerRuntime.json found; inspect runtime settings separately")
	}
	if len(manifestVersions) > 0 {
		v := manifestVersions[0]
		consistent := true
		for _, next := range manifestVersions {
			if next != v {
				consistent = false
			}
		}
		r.DetectedVersion = v
		r.VersionEvidence = "jar-manifest"
		if !consistent || (r.ClaimedVersion != "" && strings.TrimPrefix(r.ClaimedVersion, "v") != v) {
			r.VersionStatus = "conflict"
			r.finding("VERSION_CONFLICT", "blocked", "version", "", "conflicting source and declared Gravit versions")
		} else if recognizedVersion(v) {
			r.VersionStatus = "recognized"
		} else {
			r.VersionStatus = "unsupported"
			r.finding("VERSION_UNSUPPORTED", "blocked", "version", "", "detected server version is outside recognized 5.7.0..5.7.12 range")
		}
	} else if r.ClaimedVersion != "" {
		r.VersionEvidence = "operator-claim"
		r.finding("VERSION_NOT_VERIFIED", "manual", "version", "", "operator-supplied version is not proof of source binary identity")
		if !recognizedVersion(strings.TrimPrefix(r.ClaimedVersion, "v")) {
			r.VersionStatus = "unsupported"
			r.finding("VERSION_UNSUPPORTED", "blocked", "version", "", "claimed version is outside recognized 5.7.0..5.7.12 range")
		}
	} else {
		r.finding("VERSION_NOT_VERIFIED", "manual", "version", "", "no verifiable server version; supply LaunchServer.jar from the same installation")
	}
	r.Summary = map[string]int{"recognized": 0, "manual": 0, "blocked": 0}
	for _, c := range r.Components {
		r.Summary[c.Status]++
	}
	for _, f := range r.Findings {
		r.Summary[f.Severity]++
		if f.Severity == "blocked" {
			r.Status = "blocked"
		}
	}
	// This scanner NEVER issues permission to cut over: identity, world and module
	// parity are certified by separate migration stages in later releases.
	r.CutoverAllowed = false
	return r, nil
}
func (r *Report) addInvalid(kind, p string, e error) {
	r.Components = append(r.Components, Component{Kind: kind, Path: p, Status: "blocked"})
	r.finding("INVALID_JSON", "blocked", kind, p, e.Error())
}
func readBounded(f *zip.File, limit uint64) ([]byte, error) {
	if f.UncompressedSize64 > limit {
		return nil, errors.New("file exceeds inspection size limit")
	}
	rd, e := f.Open()
	if e != nil {
		return nil, e
	}
	defer rd.Close()
	b, e := io.ReadAll(io.LimitReader(rd, int64(limit)+1))
	if e != nil {
		return nil, e
	}
	if uint64(len(b)) != f.UncompressedSize64 || uint64(len(b)) > limit {
		return nil, errors.New("truncated or oversized ZIP entry")
	}
	return b, nil
}
func readObject(f *zip.File) (map[string]json.RawMessage, error) {
	b, e := readBounded(f, maxConfigBytes)
	if e == nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		if err := rejectDuplicateJSON0332(dec); err != nil {
			return nil, err
		}
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			return nil, errors.New("multiple JSON values")
		}
	}
	if e != nil {
		return nil, e
	}
	var v map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(b))
	if e = dec.Decode(&v); e != nil {
		return nil, errors.New("invalid JSON object")
	}
	if v == nil {
		return nil, errors.New("JSON root must be an object")
	}
	var trailing any
	if e = dec.Decode(&trailing); e != io.EOF {
		return nil, errors.New("multiple JSON values")
	}
	return v, nil
}
func rawObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var v map[string]json.RawMessage
	return v, json.Unmarshal(raw, &v) == nil && v != nil
}
func readType(obj map[string]json.RawMessage) string {
	var s string
	_ = json.Unmarshal(obj["type"], &s)
	return strings.ToLower(strings.TrimSpace(s))
}
func (r *Report) inspectLaunch(p string, obj map[string]json.RawMessage) {
	auth, ok := rawObject(obj["auth"])
	if !ok || len(auth) == 0 {
		r.finding("AUTH_INVALID", "blocked", "launchserver", p, "auth providers absent or not a provider map")
	} else {
		keys := make([]string, 0, len(auth))
		for k := range auth {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		defaults := 0
		for _, name := range keys {
			pair, valid := rawObject(auth[name])
			if !valid {
				r.finding("AUTH_ENTRY_INVALID", "blocked", "auth", p, "auth provider record must be an object")
				continue
			}
			var isDefault bool
			_ = json.Unmarshal(pair["isDefault"], &isDefault)
			if isDefault {
				defaults++
			}
			core, valid := rawObject(pair["core"])
			if !valid {
				r.finding("AUTH_CORE_MISSING", "blocked", "auth", p, "auth provider core is missing")
				continue
			}
			typ := readType(core)
			switch typ {
			case "sql", "mysql", "postgresql", "postgres", "file", "fileauthsystem", "memory", "reject", "null", "merge", "minecraft", "microsoft":
				r.finding("AUTH_REQUIRES_MAPPING", "manual", "auth", p, "auth core "+typ+" requires a dedicated credential and UUID migration review")
			case "":
				r.finding("AUTH_TYPE_MISSING", "blocked", "auth", p, "auth core type is required")
			default:
				r.finding("UNKNOWN_AUTH_PROVIDER", "blocked", "auth", p, "unknown auth core type (name and secret values are never recorded)")
			}
			if t, exists := pair["textureProvider"]; exists {
				provider, valid := rawObject(t)
				if !valid {
					r.finding("TEXTURE_INVALID", "blocked", "texture", p, "texture provider must be an object")
				} else if kind := readType(provider); kind == "" {
					r.finding("TEXTURE_TYPE_MISSING", "blocked", "texture", p, "texture provider type missing")
				} else if kind != "void" && kind != "request" && kind != "json" && kind != "database" && kind != "local" && kind != "none" && kind != "mojang" {
					r.finding("TEXTURE_UNKNOWN", "manual", "texture", p, "texture provider requires a compatibility adapter")
				}
			}
		}
		if defaults != 1 {
			r.finding("AUTH_DEFAULT_AMBIGUOUS", "blocked", "auth", p, "exactly one default authentication provider is required")
		}
	}
	for _, key := range []string{"protectHandler", "permissionsHandler", "hwidHandler", "components", "netty"} {
		if raw, ok := obj[key]; ok {
			if m, valid := rawObject(raw); !valid {
				r.finding("LAUNCHSERVER_OBJECT_INVALID", "blocked", "launchserver", p, key+" must be an object")
			} else if key == "protectHandler" || key == "permissionsHandler" || key == "hwidHandler" {
				if typ := readType(m); typ != "" && typ != "none" && typ != "void" {
					r.finding("SECURITY_REVIEW", "manual", "launchserver", p, key+" handler requires manual security review")
				}
			}
		}
	}
	for _, key := range []string{"authProvider", "authHandler", "textureProvider"} {
		if _, ok := obj[key]; ok {
			r.finding("LEGACY_AUTH_SCHEMA", "blocked", "launchserver", p, "legacy auth schema detected: "+key)
		}
	}
}
func (r *Report) inspectProfile(p string, obj map[string]json.RawMessage) {
	for _, k := range []string{"title", "version", "mainClass"} {
		var s string
		if e := json.Unmarshal(obj[k], &s); e != nil || s == "" {
			r.finding("PROFILE_FIELD_INVALID", "blocked", "client_profile", p, "missing/invalid profile field: "+k)
		}
	}
	for _, k := range []string{"classPath", "jvmArgs", "clientArgs", "update", "updateVerify", "updateExclusions"} {
		if v, exists := obj[k]; exists {
			if len(v) > maxConfigBytes {
				r.finding("PROFILE_FIELD_TOO_LARGE", "blocked", "client_profile", p, k+" exceeds inspection limit")
			}
		}
	}
	for _, key := range []string{"updateOptional", "optional", "optionals", "optionalFiles", "optionalActions"} {
		if raw, ok := obj[key]; ok && string(raw) != "null" {
			r.inspectOptional(p, key, raw)
		}
	}
	if _, ok := obj["servers"]; ok {
		r.finding("PROFILE_SERVERS_REVIEW", "manual", "client_profile", p, "server entries require target connectivity verification")
	}
}
func (r *Report) inspectRuntime(p string, obj map[string]json.RawMessage) {
	if len(obj) == 0 {
		r.finding("EMPTY_RUNTIME", "manual", "runtime", p, "runtime config is empty")
	}
	for _, k := range []string{"secretKey", "accessToken", "refreshToken", "privateKey"} {
		if _, found := obj[k]; found {
			r.finding("RUNTIME_CREDENTIALS", "manual", "runtime", p, "runtime trust material is never imported")
		}
	}
}
func (r *Report) inspectWrapper(p string, obj map[string]json.RawMessage) {
	if len(obj) == 0 {
		r.finding("WRAPPER_EMPTY", "manual", "server_wrapper", p, "empty wrapper config")
	}
	r.finding("WRAPPER_REENROLL", "manual", "server_wrapper", p, "ServerWrapper credentials and trust anchors must be replaced by Never ServerBridge")
}
func jarManifestVersion(source []byte) (string, bool) {
	z, e := zip.NewReader(bytes.NewReader(source), int64(len(source)))
	if e != nil || len(z.File) > 20000 {
		return "", false
	}
	for _, f := range z.File {
		if strings.EqualFold(f.Name, "META-INF/MANIFEST.MF") {
			b, e := readBounded(f, 64<<10)
			if e != nil {
				return "", false
			}
			t := strings.ReplaceAll(string(b), "\r\n", "\n")
			lines := strings.Split(t, "\n")
			var product, version string
			for _, line := range lines {
				if i := strings.IndexByte(line, ':'); i > 0 {
					key := strings.ToLower(strings.TrimSpace(line[:i]))
					v := strings.TrimSpace(line[i+1:])
					switch key {
					case "implementation-title", "bundle-name", "implementation-vendor":
						product += " " + strings.ToLower(v)
					case "implementation-version", "bundle-version":
						if version == "" {
							version = v
						}
					}
				}
			}
			// Do not confuse an arbitrary JAR's implementation version with Gravit.
			if !strings.Contains(product, "gravit") && !strings.Contains(product, "launchserver") {
				return "", false
			}
			m := versionPattern.FindStringSubmatch(version)
			if len(m) != 2 {
				return "", false
			}
			return m[1], true
		}
	}
	return "", false
}

// inspectOptional recognizes known actions but does not assume that the referenced
// assets exist in Never. Unknown actions are hard blockers, not warnings.
func (r *Report) inspectOptional(p, key string, raw json.RawMessage) {
	var options []json.RawMessage
	if err := json.Unmarshal(raw, &options); err != nil || options == nil {
		r.finding("OPTIONALS_INVALID", "blocked", "client_profile", p, "optional tree must be an array")
		return
	}
	if len(options) > 4096 {
		r.finding("OPTIONALS_EXCESS", "blocked", "client_profile", p, "too many optional elements")
		return
	}
	for _, entry := range options {
		option, ok := rawObject(entry)
		if !ok {
			r.finding("OPTIONAL_INVALID", "blocked", "client_profile", p, "optional element must be an object")
			continue
		}
		actions, ok := option["actions"]
		if !ok {
			continue
		}
		var list []json.RawMessage
		if err := json.Unmarshal(actions, &list); err != nil || list == nil || len(list) > 64 {
			r.finding("OPTIONAL_ACTIONS_INVALID", "blocked", "client_profile", p, "optional actions must be an array of up to 64 elements")
			continue
		}
		for _, entry := range list {
			act, ok := rawObject(entry)
			if !ok {
				r.finding("OPTIONAL_ACTION_INVALID", "blocked", "client_profile", p, "invalid optional action object")
				continue
			}
			switch readType(act) {
			case "file", "classpath", "jvmargs", "clientargs":
				r.finding("OPTIONAL_ACTION_REVIEW", "manual", "client_profile", p, "recognized optional action requires signed-file conversion")
			default:
				r.finding("UNKNOWN_OPTIONAL_ACTION", "blocked", "client_profile", p, "unsupported or missing optional action type")
			}
		}
	}
}

// rejectDuplicateJSON0332 traverses nested objects before decoding them into
// maps, since encoding/json ordinarily accepts duplicate keys (last wins).
func rejectDuplicateJSON0332(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return errors.New("invalid JSON syntax")
	}
	open, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch open {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			keyToken, e := d.Token()
			if e != nil {
				return errors.New("invalid JSON object")
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON key")
			}
			if seen[key] {
				return errors.New("duplicate JSON key")
			}
			seen[key] = true
			if len(seen) > 65536 {
				return errors.New("too many JSON object keys")
			}
			if e = rejectDuplicateJSON0332(d); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return errors.New("JSON object not closed")
		}
	case '[':
		i := 0
		for d.More() {
			if i > 100000 {
				return errors.New("too many array elements")
			}
			if err := rejectDuplicateJSON0332(d); err != nil {
				return err
			}
			i++
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return errors.New("JSON array not closed")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
