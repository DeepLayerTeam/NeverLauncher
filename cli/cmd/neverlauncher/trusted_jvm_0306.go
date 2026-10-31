package main

// Trusted JVM plugins have unrestricted access to the Minecraft process.
// They are not Extensions sandbox workers. No unverified JAR is ever
// forwarded to Java, and the trust anchor must live outside the client tree.
import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const trustedRoot0306 = ".launcher/trusted-jvm"
const trustedActive0306 = trustedRoot0306 + "/active.json"
const trustedSchema0306 = "launcher.trusted-jvm.v1"
const trustedPublicKeyEnv0306 = "NEVERLAUNCHER_TRUSTED_JVM_PUBLIC_KEY_FILE"

type trustedRecord0306 struct {
	Schema         string              `json:"schemaVersion"`
	PackageID      string              `json:"packageIdentity"`
	PackageSHA256  string              `json:"packageSha256"`
	Publisher      string              `json:"publisher"`
	ExtensionID    string              `json:"extensionId"`
	Version        string              `json:"version"`
	AgentSHA256    string              `json:"agentSha256"`
	Plugins        []trustedPlugin0306 `json:"plugins"`
	ApprovedAccess string              `json:"approvedAccess"`
}
type trustedPlugin0306 struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

func trustedPath0306(root, rel string) (string, error) { return secureClientDestination(root, rel) }
func trustedBytes0306(z *zip.File, capBytes int64) ([]byte, error) {
	if z.UncompressedSize64 > uint64(capBytes) || !z.Mode().IsRegular() {
		return nil, errors.New("trusted package entry exceeds size or is not regular")
	}
	r, err := z.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, capBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > capBytes {
		return nil, errors.New("trusted entry too large")
	}
	return b, nil
}
func trustedDigest0306(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

// Never trust a publisher key shipped in the same client installation.
func trustedAnchor0306(root, key string) error {
	if key == "" {
		return fmt.Errorf("external %s trust anchor required", trustedPublicKeyEnv0306)
	}
	if err := trustedRegular0306(key); err != nil {
		return err
	}
	absoluteKey, err := filepath.EvalSymlinks(key)
	if err != nil {
		return err
	}
	absoluteKey, err = filepath.Abs(absoluteKey)
	if err != nil {
		return err
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absoluteRoot, absoluteKey)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
		return errors.New("trusted JVM public key must be outside the Minecraft client root")
	}
	return nil
}
func trustedAtomic0306(target string, contents []byte) error {
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(target), ".signed-jvm-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(contents)
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return replaceFileAtomicPortable(name, target)
}

func trustedRegular0306(p string) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("not a regular trusted file: %s", p)
	}
	return nil
}
func trustedAnalyze0306(archive, key string) (trustedRecord0306, map[string][]byte, error) {
	var record trustedRecord0306
	if err := trustedRegular0306(archive); err != nil {
		return record, nil, err
	}
	result, err := verifyExtensionPackage0202(archive, key, false)
	if err != nil {
		return record, nil, err
	}
	if result["signed"] != true {
		return record, nil, errors.New("trusted JVM requires signed .nlext")
	}
	analysis, err := analyzeExtensionPackage0202(archive)
	if err != nil {
		return record, nil, err
	}
	defer analysis.Close()
	prefix := extensionPackagePayloadPrefix0202 + "trusted/"
	allowed := map[string][]byte{}
	plugins := []trustedPlugin0306{}
	count := 0
	var totalBytes int64
	for name, entry := range analysis.Entries {
		if !strings.HasPrefix(name, prefix) || strings.HasSuffix(name, "/") {
			continue
		}
		rel := strings.TrimPrefix(name, prefix)
		if rel != "agent.jar" && !(strings.HasPrefix(rel, "plugins/") && strings.HasSuffix(rel, ".jar") && len(strings.Split(rel, "/")) == 2) {
			return record, nil, fmt.Errorf("unsupported trusted payload: %q", name)
		}
		if count++; count > 17 {
			return record, nil, errors.New("too many trusted JARs")
		}
		b, err := trustedBytes0306(entry, 32<<20)
		if err != nil {
			return record, nil, err
		}
		if _, err = zip.NewReader(bytes.NewReader(b), int64(len(b))); err != nil {
			return record, nil, fmt.Errorf("invalid trusted JAR %s: %w", rel, err)
		}
		// Structural validation prevents malformed archives from reaching the JVM.
		temp, err := os.CreateTemp("", "nl-trusted-*.jar")
		if err != nil {
			return record, nil, err
		}
		tmp := temp.Name()
		_, wr := temp.Write(b)
		cl := temp.Close()
		if wr != nil {
			err = wr
		} else if cl != nil {
			err = cl
		} else {
			err = verifyCompatibilityJar0279(tmp, rel == "agent.jar")
		}
		_ = os.Remove(tmp)
		if err != nil {
			return record, nil, fmt.Errorf("trusted JAR %s: %w", rel, err)
		}
		totalBytes += int64(len(b))
		if totalBytes > 128<<20 {
			return record, nil, errors.New("trusted JVM package exceeds 128 MiB expanded JAR limit")
		}
		allowed[rel] = b
		if rel == "agent.jar" {
			// Reject arbitrary agents: bootstrap is our audited implementation,
			// while third-party trusted hooks are packaged under plugins/.
			zr, _ := zip.NewReader(bytes.NewReader(b), int64(len(b)))
			var found bool
			for _, f := range zr.File {
				if f.Name == "META-INF/MANIFEST.MF" {
					m, _ := trustedBytes0306(f, 65536)
					found = strings.Contains(string(m), "Premain-Class: ru.launcher.trusted.Agent")
				}
			}
			if !found {
				return record, nil, errors.New("trusted agent must use Launcher premain")
			}
			record.AgentSHA256 = trustedDigest0306(b)
		} else {
			plugins = append(plugins, trustedPlugin0306{Name: strings.TrimPrefix(rel, "plugins/"), SHA256: trustedDigest0306(b)})
		}
	}
	if len(allowed) == 0 || len(record.AgentSHA256) == 0 {
		return record, nil, errors.New("signed package missing trusted/agent.jar")
	}
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].Name < plugins[j].Name })
	record.Schema = trustedSchema0306
	record.PackageID = analysis.Descriptor.PackageIdentity
	record.Publisher = analysis.Manifest.Publisher
	record.ExtensionID = analysis.Manifest.ID
	record.Version = analysis.Manifest.Version
	record.Plugins = plugins
	record.ApprovedAccess = "full-minecraft-jvm"
	data, err := os.ReadFile(archive)
	if err != nil {
		return record, nil, err
	}
	record.PackageSHA256 = trustedDigest0306(data)
	return record, allowed, nil
}
func trustedInstall0306(root, archive, key string) (trustedRecord0306, error) {
	if err := trustedAnchor0306(root, key); err != nil {
		return trustedRecord0306{}, err
	}
	rec, blobs, err := trustedAnalyze0306(archive, key)
	if err != nil {
		return rec, err
	}
	// Immutable release directories, switched with atomic active record.
	release := trustedRoot0306 + "/releases/" + rec.PackageSHA256
	for name, b := range blobs {
		target, err := trustedPath0306(root, release+"/"+name)
		if err != nil {
			return rec, err
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return rec, err
		}
		if err = trustedAtomic0306(target, b); err != nil {
			return rec, err
		}
	}
	src, err := os.ReadFile(archive)
	if err != nil {
		return rec, err
	}
	pkg, err := trustedPath0306(root, release+"/signed.nlext")
	if err != nil {
		return rec, err
	}
	if err = trustedAtomic0306(pkg, src); err != nil {
		return rec, err
	}
	active, err := trustedPath0306(root, trustedActive0306)
	if err != nil {
		return rec, err
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return rec, err
	}
	if err = trustedAtomic0306(active, append(raw, '\n')); err != nil {
		return rec, err
	}
	return rec, nil
}
func trustedLoad0306(root, key string) (*trustedRecord0306, string, error) {
	active, err := trustedPath0306(root, trustedActive0306)
	if err != nil {
		return nil, "", err
	}
	st, err := os.Lstat(active)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if !st.Mode().IsRegular() || st.Size() > 8192 {
		return nil, "", errors.New("invalid trusted active record")
	}
	raw, err := os.ReadFile(active)
	if err != nil {
		return nil, "", err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var rec trustedRecord0306
	if err = d.Decode(&rec); err != nil {
		return nil, "", err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return nil, "", errors.New("extra trusted record data")
	}
	if rec.Schema != trustedSchema0306 || rec.ApprovedAccess != "full-minecraft-jvm" || !isSHA256Hex0271(rec.PackageSHA256) {
		return nil, "", errors.New("invalid trusted record")
	}
	if err := trustedAnchor0306(root, key); err != nil {
		return nil, "", err
	}
	release := trustedRoot0306 + "/releases/" + rec.PackageSHA256
	pkg, err := trustedPath0306(root, release+"/signed.nlext")
	if err != nil {
		return nil, "", err
	}
	if err = trustedRegular0306(pkg); err != nil {
		return nil, "", err
	}
	expected, blobs, err := trustedAnalyze0306(pkg, key)
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(mustJSON0306(rec), mustJSON0306(expected)) {
		return nil, "", errors.New("trusted record differs from signed package")
	}
	for name, b := range blobs {
		p, err := trustedPath0306(root, release+"/"+name)
		if err != nil {
			return nil, "", err
		}
		if err = trustedRegular0306(p); err != nil {
			return nil, "", err
		}
		actual, err := os.ReadFile(p)
		if err != nil {
			return nil, "", err
		}
		if trustedDigest0306(actual) != trustedDigest0306(b) {
			return nil, "", fmt.Errorf("trusted JAR changed: %s", name)
		}
	}
	return &rec, release, nil
}
func mustJSON0306(x any) []byte { b, _ := json.Marshal(x); return b }

// trustedPrepare returns JVM parameters and a wrapper main class. Caller MUST
// call cleanup after the child exits; the config contains absolute plugin paths.
func trustedPrepare0306(root, originalMain string) ([]string, string, func(), error) {
	key := strings.TrimSpace(os.Getenv(trustedPublicKeyEnv0306))
	rec, release, err := trustedLoad0306(root, key)
	if err != nil {
		return nil, "", nil, err
	}
	if rec == nil {
		return nil, originalMain, func() {}, nil
	}
	agent, err := trustedPath0306(root, release+"/agent.jar")
	if err != nil {
		return nil, "", nil, err
	}
	if originalMain == "" || strings.ContainsAny(originalMain, "\r\n\x00") {
		return nil, "", nil, errors.New("invalid Minecraft main class")
	}
	var config strings.Builder
	fmt.Fprintf(&config, "main=%s\n", base64.StdEncoding.EncodeToString([]byte(originalMain)))
	fmt.Fprintf(&config, "count=%d\n", len(rec.Plugins))
	for i, p := range rec.Plugins {
		file, err := trustedPath0306(root, release+"/plugins/"+p.Name)
		if err != nil {
			return nil, "", nil, err
		}
		fmt.Fprintf(&config, "plugin.%d=%s\nplugin.%d.sha256=%s\n", i, base64.StdEncoding.EncodeToString([]byte(file)), i, p.SHA256)
	}
	parent, err := trustedPath0306(root, trustedRoot0306)
	if err != nil {
		return nil, "", nil, err
	}
	f, err := os.CreateTemp(parent, ".launch-*.properties")
	if err != nil {
		return nil, "", nil, err
	}
	err = f.Chmod(0600)
	if err == nil {
		_, err = f.WriteString(config.String())
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return nil, "", nil, err
	}
	cleanup := func() { _ = os.Remove(f.Name()) }
	return []string{"-javaagent:" + agent + "=" + f.Name()}, "ru.launcher.trusted.MinecraftMain", cleanup, nil
}
func handleTrustedJVM0306(args []string) error {
	if len(args) == 0 {
		return errors.New("trusted JVM: trusted-install|trusted-verify|trusted-inspect|trusted-remove")
	}
	root := flagValue(args[1:], "--client-dir", "")
	if root == "" {
		return errors.New("--client-dir required")
	}
	key := flagValue(args[1:], "--public-key", os.Getenv(trustedPublicKeyEnv0306))
	switch args[0] {
	case "trusted-install":
		if flagValue(args[1:], "--approve-full-jvm-access", "") != "true" {
			return errors.New("explicit --approve-full-jvm-access true required: agents have unrestricted access to Minecraft JVM")
		}
		archive := flagValue(args[1:], "--package", "")
		if archive == "" || key == "" {
			return errors.New("signed --package and external --public-key required")
		}
		rec, err := trustedInstall0306(root, archive, key)
		if err != nil {
			return err
		}
		printJSON(map[string]any{"installed": true, "access": "full-minecraft-jvm", "extensionId": rec.ExtensionID, "version": rec.Version, "packageSha256": rec.PackageSHA256})
		return nil
	case "trusted-verify", "trusted-inspect":
		rec, _, err := trustedLoad0306(root, key)
		if err != nil {
			return err
		}
		if rec == nil {
			return errors.New("no trusted JVM agent installed")
		}
		printJSON(rec)
		return nil
	case "trusted-remove":
		active, err := trustedPath0306(root, trustedActive0306)
		if err != nil {
			return err
		}
		if err = os.Remove(active); err != nil {
			return err
		}
		printJSON(map[string]any{"disabled": true})
		return nil
	default:
		return fmt.Errorf("unknown trusted JVM command %q", args[0])
	}
}
