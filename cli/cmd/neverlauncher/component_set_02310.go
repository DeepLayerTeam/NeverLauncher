package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Set at build time by a trusted release pipeline: -ldflags
// '-X main.componentSetTrustedKey02310=<64-hex-character-Ed25519-public-key>'.
// Never obtain this value from the downloaded component package.
var componentSetTrustedKey02310 string

// A separate offline root is provisioned at release build; it never comes from the package.
var componentSetRootKey02312 string

const componentPolicyFile02312 = "COMPONENT_TRUST_POLICY.json"
const componentSignatureFile02312 = "COMPONENT_SET_SIGNATURE_V2.json"

type componentSignature02312 struct {
	SchemaVersion  string `json:"schemaVersion"`
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"keyId"`
	TrustEpoch     uint64 `json:"trustEpoch"`
	PolicySHA256   string `json:"policySha256"`
	ManifestSHA256 string `json:"manifestSha256"`
	SignedAt       string `json:"signedAt"`
	Signature      string `json:"signature"`
}

const componentSetSignatureFile02310 = "COMPONENT_SET_SIGNATURE.json"

type componentSetSignature02310 struct {
	SchemaVersion  string `json:"schemaVersion"`
	Algorithm      string `json:"algorithm"`
	Signature      string `json:"signature"`
	ManifestSHA256 string `json:"manifestSha256"`
}
type componentProtocolRequirement02310 struct {
	Component string `json:"component"`
	Protocol  string `json:"protocol"`
	Minimum   uint32 `json:"minimum"`
}
type componentProtocol02310 struct {
	Component string                              `json:"component"`
	Provides  map[string]uint32                   `json:"provides"`
	Requires  []componentProtocolRequirement02310 `json:"requires,omitempty"`
}
type componentSet02310 struct {
	SchemaVersion string                   `json:"schemaVersion"`
	Protocols     []componentProtocol02310 `json:"protocols"`
}

func componentCoordinationRequired02310(ver string) bool {
	major, minor, patch, ok := parseCoreVersion(ver)
	return ok && (major > 0 || (minor > 23 || (minor == 23 && patch >= 10)))
}

// The signature authenticates the *exact* manifest bytes, including every file,
// protocol edge and target. The package hash is checked independently upstream.
func verifySignedComponentSet02310(manifestPath string, manifest componentUpdateManifest0157, allowDevelopment bool) error {
	if !componentCoordinationRequired02310(manifest.ProductVersion) {
		return nil
	}
	if err := validateComponentProtocols02310(manifest); err != nil {
		return err
	}
	if allowDevelopment && (manifest.TrustMode == "development-self-test" || manifest.TrustMode == "unsigned-development" || manifest.TrustMode == "adhoc-development") {
		return nil
	}
	if componentTrustRequired02312(manifest.ProductVersion) {
		return verifyComponentTrust02312(manifestPath)
	}
	key, err := hex.DecodeString(strings.TrimSpace(componentSetTrustedKey02310))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("component-set trust root is not built into updater; production update refused")
	}
	signaturePath := filepath.Join(filepath.Dir(manifestPath), componentSetSignatureFile02310)
	info, err := os.Lstat(signaturePath)
	if err != nil {
		return fmt.Errorf("component-set signature missing: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 2048 {
		return errors.New("unsafe component-set signature file")
	}
	sigRaw, err := os.ReadFile(signaturePath)
	if err != nil {
		return err
	}
	var envelope componentSetSignature02310
	if err := json.Unmarshal(sigRaw, &envelope); err != nil {
		return err
	}
	if envelope.SchemaVersion != "1.0" || envelope.Algorithm != "ed25519" {
		return errors.New("unsupported component-set signature")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	if envelope.ManifestSHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("component-set manifest digest mismatch")
	}
	signature, err := hex.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), raw, signature) {
		return errors.New("component-set Ed25519 signature invalid")
	}
	return nil
}

// Fail closed on protocol mismatches *before* the first live file is touched.
// The minimum verified protocol requirements are derived from the actual
// Guard v4, sensor v3 and updater v2 wire implementations.
func validateComponentProtocols02310(manifest componentUpdateManifest0157) error {
	if manifest.ComponentSet == nil || manifest.ComponentSet.SchemaVersion != "1.0" {
		return errors.New("component-set protocol matrix missing")
	}
	required := map[string]map[string]uint32{
		"desktop": {"guard-ipc": 4},
		"guard":   {"guard-ipc": 4},
		"runtime": {"guard-ipc": 4},
		"updater": {"component-update": 2},
	}
	if manifest.Platform == "windows" {
		required["sensor"] = map[string]uint32{"sensor-ipc": 3}
	}
	if len(manifest.ComponentSet.Protocols) != len(required) {
		return errors.New("component-set does not cover all required roles")
	}
	roles := map[string]bool{}
	for _, item := range manifest.Components {
		roles[item.Component] = true
	}
	updaterCount := 0
	for _, item := range manifest.SupportFiles {
		if item.Component == "updater" {
			updaterCount++
			if !item.Executable {
				return errors.New("updater helper must be executable")
			}
		}
	}
	if updaterCount != 1 {
		return errors.New("component-set requires exactly one updater helper in supportFiles")
	}
	roles["updater"] = true
	byRole := map[string]componentProtocol02310{}
	for _, item := range manifest.ComponentSet.Protocols {
		expected, ok := required[item.Component]
		if !ok || !roles[item.Component] {
			return fmt.Errorf("unexpected component protocol role %q", item.Component)
		}
		if _, duplicate := byRole[item.Component]; duplicate {
			return fmt.Errorf("duplicate component protocol role %q", item.Component)
		}
		if len(item.Provides) != len(expected) {
			return fmt.Errorf("unexpected protocol declarations for %s", item.Component)
		}
		for proto, n := range expected {
			if item.Provides[proto] != n {
				return fmt.Errorf("unsupported %s %s: got %d expected %d", item.Component, proto, item.Provides[proto], n)
			}
		}
		byRole[item.Component] = item
	}
	for name := range required {
		if _, ok := byRole[name]; !ok {
			return fmt.Errorf("missing protocol role %s", name)
		}
	}
	// These edges are mandatory even when a manifest tries to omit them.
	edges := map[string][]componentProtocolRequirement02310{
		"desktop": {{"guard", "guard-ipc", 4}, {"runtime", "guard-ipc", 4}, {"updater", "component-update", 2}},
		"guard":   {{"runtime", "guard-ipc", 4}},
		"runtime": {{"guard", "guard-ipc", 4}},
		"updater": {{"desktop", "guard-ipc", 4}},
	}
	if manifest.Platform == "windows" {
		edges["guard"] = append(edges["guard"], componentProtocolRequirement02310{"sensor", "sensor-ipc", 3})
	}
	for name, item := range byRole {
		mandatory := edges[name]
		if len(item.Requires) != len(mandatory) {
			return fmt.Errorf("%s protocol requirements do not match compiled compatibility policy", name)
		}
		found := map[string]bool{}
		for _, req := range item.Requires {
			key := req.Component + "/" + req.Protocol
			if found[key] {
				return fmt.Errorf("duplicate protocol dependency %s", key)
			}
			found[key] = true
			target, ok := byRole[req.Component]
			if !ok || req.Minimum == 0 || target.Provides[req.Protocol] < req.Minimum {
				return fmt.Errorf("%s requires unavailable %s >= %d", name, key, req.Minimum)
			}
			valid := false
			for _, need := range mandatory {
				if req == need {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("%s has unexpected protocol dependency %s", name, key)
			}
		}
	}
	return nil
}

func containsCoreComponent02310(value string) bool {
	return value == "desktop" || value == "guard" || value == "runtime" || value == "sensor"
}

// Fixed compatibility matrix is also exercised by the real updater self-test.
func builtInComponentProtocolSet02310(platform string) *componentSet02310 {
	rows := []componentProtocol02310{
		{Component: "desktop", Provides: map[string]uint32{"guard-ipc": 4}, Requires: []componentProtocolRequirement02310{{"guard", "guard-ipc", 4}, {"runtime", "guard-ipc", 4}, {"updater", "component-update", 2}}},
		{Component: "guard", Provides: map[string]uint32{"guard-ipc": 4}, Requires: []componentProtocolRequirement02310{{"runtime", "guard-ipc", 4}}},
		{Component: "runtime", Provides: map[string]uint32{"guard-ipc": 4}, Requires: []componentProtocolRequirement02310{{"guard", "guard-ipc", 4}}},
		{Component: "updater", Provides: map[string]uint32{"component-update": 2}, Requires: []componentProtocolRequirement02310{{"desktop", "guard-ipc", 4}}},
	}
	if platform == "windows" {
		rows[1].Requires = append(rows[1].Requires, componentProtocolRequirement02310{"sensor", "sensor-ipc", 3})
		rows = append(rows, componentProtocol02310{Component: "sensor", Provides: map[string]uint32{"sensor-ipc": 3}})
	}
	return &componentSet02310{SchemaVersion: "1.0", Protocols: rows}
}

// Recovery must not restart the launcher merely because journal replay returned
// without an error: verify all recorded active components, including the
// updater that participates in the coordinated set.
func verifyRestartedComponentSet02310(root, desktopPath string) error {
	statePath := filepath.Join(root, filepath.FromSlash(componentUpdateStateFile0157))
	state, present, err := readComponentUpdateStateOptional01510(statePath)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("recovery cannot prove installed component state; refusing automatic restart")
	}
	if err := reconcileInstalledComponentGeneration02311(root); err != nil {
		return err
	}
	appRoot := ""
	if strings.EqualFold(state.Platform, "macos") {
		appRoot = filepath.Dir(filepath.Dir(filepath.Dir(desktopPath)))
	}
	verifyState := func() error {
		for _, item := range append(append([]componentUpdateArtifact0157{}, state.Components...), state.SupportFiles...) {
			path := filepath.Join(root, filepath.FromSlash(item.TargetPath))
			if appRoot != "" {
				path = filepath.Join(appRoot, filepath.FromSlash(item.TargetPath))
			}
			if err := verifyUpdaterFile0156(path, item.Size, item.SHA256); err != nil {
				return fmt.Errorf("recovery active %s: %w", item.Component, err)
			}
		}
		return nil
	}
	if err := verifyState(); err == nil {
		return nil
	} else if appRoot == "" {
		return err
	}
	// On macOS an intact, signed .app may have been committed just before
	// power loss, with the external state write not yet durable. Derive state
	// only from the still-trusted signature inside the sealed new application.
	manifestPath := filepath.Join(appRoot, "Contents", "Resources", componentUpdateManifestFile0157)
	manifest, err := readComponentUpdateManifest0157(manifestPath)
	if err != nil {
		return err
	}
	if err := validateComponentUpdateManifest0157(manifest, filepath.Dir(manifestPath), false); err != nil {
		return err
	}
	if err := verifySignedComponentSet02310(manifestPath, manifest, false); err != nil {
		return err
	}
	if err := verifyMacOSInstalledBundle0157(manifest, appRoot, false); err != nil {
		return err
	}
	body, err := componentStateBytes0157(manifest)
	if err != nil {
		return err
	}
	if err := writeUpdaterBytes0156(statePath+".recovered", body, 0o600); err != nil {
		return err
	}
	if err := replaceFileAtomicPortable(statePath+".recovered", statePath); err != nil {
		return err
	}
	return nil
}
