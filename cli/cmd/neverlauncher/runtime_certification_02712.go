package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Runtime certification is bound to the *verified* Client Factory lock, not
// to a mutable version selector or an assertion made by the caller. The probe
// runs NeverRuntime against a disposable copy, leaving locked outputs intact.
const factoryCertSchema02712 = "neverlauncher.factory.runtime-certificate.v1"

type factoryProbe02712 struct {
	Status            string `json:"status"`
	MinecraftVersion  string `json:"minecraftVersion"`
	MainClass         string `json:"mainClass"`
	RequiredJavaMajor int    `json:"requiredJavaMajor"`
	DetectedJavaMajor int    `json:"detectedJavaMajor"`
	ClasspathEntries  int    `json:"classpathEntries"`
	TimedOut          bool   `json:"timedOut"`
	Success           bool   `json:"success"`
	LogPath           string `json:"logPath"`
	RuntimeSeconds    int64  `json:"runtimeSeconds"`
}
type factoryRuntimeCertificate02712 struct {
	Schema           string        `json:"schema"`
	Status           string        `json:"status"`
	CreatedAt        string        `json:"createdAt"`
	MinecraftVersion string        `json:"minecraftVersion"`
	Loader           string        `json:"loader"`
	LoaderVersion    string        `json:"loaderVersion,omitempty"`
	ProfileID        string        `json:"profileId"`
	Target           vanillaTarget `json:"target"`
	JavaMajor        int           `json:"javaMajor"`
	PlanSHA256       string        `json:"planSha256"`
	JavaSHA256       string        `json:"javaSha256"`
	RuntimeSHA256    string        `json:"runtimeSha256"`
	LogSHA256        string        `json:"logSha256"`
	LogFile          string        `json:"logFile"`
	ProbeSHA256      string        `json:"probeSha256"`
	ProbeFile        string        `json:"probeFile"`
	RuntimeSeconds   int64         `json:"runtimeSeconds"`
	PublicKey        string        `json:"publicKey"`
	Signature        string        `json:"signature"`
}

func certDigest02712(p factoryRuntimeCertificate02712) ([]byte, error) {
	p.Signature = ""
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	return digest[:], nil
}
func certHashFile02712(path string) (string, error) {
	sum, _, err := hashFile(path)
	return sum, err
}
func certResolveExecutable02712(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("executable is required")
	}
	full, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	full, err = filepath.Abs(full)
	if err != nil {
		return "", err
	}
	st, err := os.Lstat(full)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("executable must be a regular file (no symlink)")
	}
	return full, nil
}
func certPrivateKey02712(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return ed25519.PrivateKey(key), nil
}
func certReadPublic02712(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(pub), nil
}
func factoryCertKeygen02712(privatePath, publicPath string) error {
	if privatePath == "" || publicPath == "" || privatePath == publicPath {
		return errors.New("--private-key and --public-key require separate paths")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// O_EXCL forbids replacement of previously established trust roots.
	for i, item := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{privatePath, priv, 0600}, {publicPath, pub, 0644}} {
		if err = os.MkdirAll(filepath.Dir(item.path), 0700); err != nil {
			return err
		}
		f, e := os.OpenFile(item.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, item.mode)
		if e != nil {
			if i == 1 {
				_ = os.Remove(privatePath)
			}
			return e
		}
		_, e = f.Write([]byte(base64.StdEncoding.EncodeToString(item.data) + "\n"))
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			_ = os.Remove(item.path)
			if i == 1 {
				_ = os.Remove(privatePath)
			}
			return e
		}
	}
	return nil
}
func certProfileID02712(plan factoryPlan0271) (string, error) {
	profile := filepath.ToSlash(plan.Launch.ProfilePath)
	if err := validateVanillaRelativePath(profile); err != nil {
		return "", err
	}
	if !strings.HasPrefix(profile, "versions/") || !strings.HasSuffix(profile, ".json") {
		return "", errors.New("invalid profile path")
	}
	id := strings.TrimSuffix(filepath.Base(profile), ".json")
	if filepath.ToSlash(filepath.Join("versions", id, id+".json")) != profile {
		return "", errors.New("unexpected profile path")
	}
	return id, nil
}

var certRuntimeMarker02712 = regexp.MustCompile(`(?i)(?:LWJGL|Setting user|Loading Minecraft|OpenGL|Backend library|Launching wrapped minecraft|MinecraftForge|FabricLoader|QuiltLoader|Minecraft client initialized)`)

func certValidateProbe02712(plan factoryPlan0271, profile string, probe factoryProbe02712, log []byte, maxSeconds int) error {
	if probe.Status != "passed" || probe.MinecraftVersion != profile || probe.MainClass != plan.Launch.MainClass || probe.RequiredJavaMajor != plan.Java.Major || probe.DetectedJavaMajor != plan.Java.Major || probe.ClasspathEntries < 1 {
		return errors.New("runtime probe does not match pinned profile, Java or classpath")
	}
	if !probe.Success && !probe.TimedOut {
		return errors.New("runtime process failed")
	}
	if probe.RuntimeSeconds < 0 || probe.RuntimeSeconds > int64(maxSeconds+20) {
		return errors.New("runtime duration is implausible")
	}
	if probe.TimedOut && probe.RuntimeSeconds < 10 {
		return errors.New("runtime exited/stalled before minimum launch observation")
	}
	index := bytes.Index(log, []byte("--- process output ---"))
	if index < 0 || !certRuntimeMarker02712.Match(log[index+len("--- process output ---"):]) {
		return errors.New("real Minecraft startup marker absent from process output")
	}
	return nil
}
func certHostTarget02712(target vanillaTarget) error {
	actual := currentVanillaTarget()
	if actual.OS != target.OS || actual.Arch != target.Arch {
		return fmt.Errorf("runtime certification requires native runner %s/%s, got %s/%s", target.OS, target.Arch, actual.OS, actual.Arch)
	}
	return nil
}
func certFiles02712(dir string, cert factoryRuntimeCertificate02712) error {
	for _, item := range []struct{ name, hash string }{{cert.ProbeFile, cert.ProbeSHA256}, {cert.LogFile, cert.LogSHA256}} {
		if item.name == "" || filepath.Base(item.name) != item.name || !isSHA256Hex0271(item.hash) {
			return errors.New("invalid evidence file reference")
		}
		file := filepath.Join(dir, item.name)
		st, err := os.Lstat(file)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return errors.New("evidence must be a regular file")
		}
		sum, err := certHashFile02712(file)
		if err != nil {
			return err
		}
		if sum != item.hash {
			return fmt.Errorf("evidence digest mismatch: %s", item.name)
		}
	}
	return nil
}
func certVerify02712(clientDir, certificateFile, publicKeyPath string) (factoryRuntimeCertificate02712, error) {
	var cert factoryRuntimeCertificate02712
	raw, err := os.ReadFile(certificateFile)
	if err != nil {
		return cert, err
	}
	if err = json.Unmarshal(raw, &cert); err != nil {
		return cert, err
	}
	if cert.Schema != factoryCertSchema02712 || cert.Status != "certified" || !isSHA256Hex0271(cert.PlanSHA256) || !isSHA256Hex0271(cert.JavaSHA256) || !isSHA256Hex0271(cert.RuntimeSHA256) {
		return cert, errors.New("invalid runtime certificate")
	}
	pub, err := certReadPublic02712(publicKeyPath)
	if err != nil {
		return cert, err
	}
	if cert.PublicKey != base64.StdEncoding.EncodeToString(pub) {
		return cert, errors.New("certificate signed by a different trust root")
	}
	signature, err := base64.StdEncoding.DecodeString(cert.Signature)
	if err != nil {
		return cert, err
	}
	digest, err := certDigest02712(cert)
	if err != nil {
		return cert, err
	}
	if !ed25519.Verify(pub, digest, signature) {
		return cert, errors.New("invalid runtime certification signature")
	}
	if err = certFiles02712(filepath.Dir(certificateFile), cert); err != nil {
		return cert, err
	}
	plan, err := readFactoryPlan0271(clientDir)
	if err != nil {
		return cert, err
	}
	if err = verifyFactoryPlan0271(clientDir, plan); err != nil {
		return cert, err
	}
	if err = requireCurrentFactoryAdapters02711(plan); err != nil {
		return cert, err
	}
	if cert.PlanSHA256 != plan.ReproducibilitySHA256 || cert.Loader != plan.Loader || cert.LoaderVersion != plan.LoaderVersion || cert.MinecraftVersion != plan.MinecraftVersion || cert.JavaMajor != plan.Java.Major {
		return cert, errors.New("certificate does not match current InstallPlan")
	}
	profile, err := certProfileID02712(plan)
	if err != nil {
		return cert, err
	}
	if cert.ProfileID != profile {
		return cert, errors.New("certified profile differs from plan")
	}
	found := false
	for _, t := range plan.Targets {
		if t == cert.Target {
			found = true
			break
		}
	}
	if !found {
		return cert, errors.New("certified target was not in InstallPlan")
	}
	var probe factoryProbe02712
	pr, err := os.ReadFile(filepath.Join(filepath.Dir(certificateFile), cert.ProbeFile))
	if err != nil {
		return cert, err
	}
	if err = json.Unmarshal(pr, &probe); err != nil {
		return cert, err
	}
	lg, err := os.ReadFile(filepath.Join(filepath.Dir(certificateFile), cert.LogFile))
	if err != nil {
		return cert, err
	}
	if err = certValidateProbe02712(plan, profile, probe, lg, 3600); err != nil {
		return cert, err
	}
	if cert.RuntimeSeconds != probe.RuntimeSeconds {
		return cert, errors.New("runtime duration changed")
	}
	return cert, nil
}
func certRun02712(ctx context.Context, clientDir, runtimeName, javaName, expectedRuntimeSHA, privateKeyPath, out string, maxSeconds int) (factoryRuntimeCertificate02712, error) {
	cert := factoryRuntimeCertificate02712{}
	if out == "" || out == "-" {
		return cert, errors.New("--output must name a certificate file outside client root")
	}
	if maxSeconds < 15 || maxSeconds > 3600 {
		return cert, errors.New("--max-runtime-seconds must be 15..3600")
	}
	if err := rejectFactoryOutputPath0271(clientDir, out); err != nil {
		return cert, err
	}
	if err := rejectFactoryOutputPath0271(clientDir, privateKeyPath); err != nil {
		return cert, fmt.Errorf("signing key must be outside client: %w", err)
	}
	plan, err := readFactoryPlan0271(clientDir)
	if err != nil {
		return cert, err
	}
	if err = verifyFactoryPlan0271(clientDir, plan); err != nil {
		return cert, err
	}
	if err = requireCurrentFactoryAdapters02711(plan); err != nil {
		return cert, err
	}
	if len(plan.Targets) != 1 {
		return cert, errors.New("certification requires a single OS/arch target; certify each target separately")
	}
	target := plan.Targets[0]
	if err = certHostTarget02712(target); err != nil {
		return cert, err
	}
	profile, err := certProfileID02712(plan)
	if err != nil {
		return cert, err
	}
	rt, err := certResolveExecutable02712(runtimeName)
	if err != nil {
		return cert, err
	}
	java, err := certResolveExecutable02712(javaName)
	if err != nil {
		return cert, err
	}
	rtSHA, err := certHashFile02712(rt)
	if err != nil {
		return cert, err
	}
	if !isSHA256Hex0271(expectedRuntimeSHA) || rtSHA != expectedRuntimeSHA {
		return cert, errors.New("NeverRuntime executable does not match --runtime-sha256")
	}
	javaSHA, err := certHashFile02712(java)
	if err != nil {
		return cert, err
	}
	key, err := certPrivateKey02712(privateKeyPath)
	if err != nil {
		return cert, err
	}
	// Copy verified immutable inputs: the game may write logs, options and caches.
	staging, err := os.MkdirTemp("", "neverlauncher-cert-02712-")
	if err != nil {
		return cert, err
	}
	defer os.RemoveAll(staging)
	copyRoot := filepath.Join(staging, "client")
	if err = os.MkdirAll(copyRoot, 0700); err != nil {
		return cert, err
	}
	if err = copyFactoryExisting0271(clientDir, copyRoot); err != nil {
		return cert, err
	}
	if err = verifyFactoryPlan0271(copyRoot, plan); err != nil {
		return cert, err
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(maxSeconds+45)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, rt, "certify-vanilla", "--root", copyRoot, "--version", profile, "--java", java, "--required-java-major", strconv.Itoa(plan.Java.Major), "--max-runtime-seconds", strconv.Itoa(maxSeconds))
	cmd.Dir = staging
	// Avoid passing credentials / auth tokens to the subprocess.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + staging, "TMPDIR=" + staging}
	for _, key := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "LIBGL_ALWAYS_SOFTWARE", "DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH", "SystemRoot", "WINDIR", "APPDATA", "LOCALAPPDATA"} {
		if v, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+v)
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &boundedWriter02712{w: &stdout, max: 2 << 20}
	cmd.Stderr = &boundedWriter02712{w: &stderr, max: 2 << 20}
	if err = cmd.Run(); err != nil {
		return cert, fmt.Errorf("NeverRuntime probe failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var probe factoryProbe02712
	if err = json.Unmarshal(stdout.Bytes(), &probe); err != nil {
		return cert, fmt.Errorf("NeverRuntime returned invalid JSON: %w", err)
	}
	// Never trust a supplied log path: it must be a real regular file underneath the disposable root.
	absLog, err := filepath.Abs(probe.LogPath)
	if err != nil {
		return cert, err
	}
	rel, err := filepath.Rel(copyRoot, absLog)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return cert, errors.New("runtime log escaped isolated client root")
	}
	// Reject parent-directory symlinks created by the tested JVM. A syntactically
	// in-root path is insufficient if logs/ points outside the disposable tree.
	if _, err := secureClientDestination(copyRoot, filepath.ToSlash(rel)); err != nil {
		return cert, fmt.Errorf("unsafe runtime log path: %w", err)
	}
	st, err := os.Lstat(absLog)
	if err != nil {
		return cert, err
	}
	if !st.Mode().IsRegular() || st.Size() > 32<<20 {
		return cert, errors.New("runtime log is not regular or too large")
	}
	log, err := os.ReadFile(absLog)
	if err != nil {
		return cert, err
	}
	if err = certValidateProbe02712(plan, profile, probe, log, maxSeconds); err != nil {
		return cert, err
	}
	if after, e := certHashFile02712(rt); e != nil || after != rtSHA {
		return cert, errors.New("NeverRuntime executable changed during probe")
	}
	if after, e := certHashFile02712(java); e != nil || after != javaSHA {
		return cert, errors.New("Java executable changed during probe")
	}
	if err = verifyFactoryPlan0271(clientDir, plan); err != nil {
		return cert, fmt.Errorf("installed client mutated during certification: %w", err)
	}
	absOut, err := filepath.Abs(out)
	if err != nil {
		return cert, err
	}
	if err = os.MkdirAll(filepath.Dir(absOut), 0700); err != nil {
		return cert, err
	}
	prefix := strings.TrimSuffix(filepath.Base(absOut), filepath.Ext(absOut))
	if prefix == "" || prefix == "." {
		return cert, errors.New("invalid certificate name")
	}
	probeFile := prefix + ".probe.json"
	logFile := prefix + ".runtime.log"
	probeJSON, err := json.MarshalIndent(probe, "", "  ")
	if err != nil {
		return cert, err
	}
	// Do not leave partial evidence on failed write.
	probePath := filepath.Join(filepath.Dir(absOut), probeFile)
	logPath := filepath.Join(filepath.Dir(absOut), logFile)
	if err = writeAtomicBytes(probePath, append(probeJSON, '\n'), 0600); err != nil {
		return cert, err
	}
	if err = writeAtomicBytes(logPath, log, 0600); err != nil {
		_ = os.Remove(probePath)
		return cert, err
	}
	rawProbeHash, err := certHashFile02712(probePath)
	if err != nil {
		return cert, err
	}
	rawLogHash, err := certHashFile02712(logPath)
	if err != nil {
		return cert, err
	}
	cert = factoryRuntimeCertificate02712{Schema: factoryCertSchema02712, Status: "certified", CreatedAt: time.Now().UTC().Format(time.RFC3339), MinecraftVersion: plan.MinecraftVersion, Loader: plan.Loader, LoaderVersion: plan.LoaderVersion, ProfileID: profile, Target: target, JavaMajor: plan.Java.Major, PlanSHA256: plan.ReproducibilitySHA256, JavaSHA256: javaSHA, RuntimeSHA256: rtSHA, ProbeSHA256: rawProbeHash, LogSHA256: rawLogHash, ProbeFile: probeFile, LogFile: logFile, RuntimeSeconds: probe.RuntimeSeconds, PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	digest, err := certDigest02712(cert)
	if err != nil {
		return cert, err
	}
	cert.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, digest))
	raw, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return cert, err
	}
	if err = writeAtomicBytes(absOut, append(raw, '\n'), 0600); err != nil {
		return cert, err
	}
	return cert, nil
}

type boundedWriter02712 struct {
	w   *bytes.Buffer
	max int
}

func (b *boundedWriter02712) Write(p []byte) (int, error) {
	if b.w.Len()+len(p) > b.max {
		return 0, errors.New("probe output exceeded limit")
	}
	return b.w.Write(p)
}
func handleRuntimeCertification02712(args []string) error {
	if len(args) == 0 {
		return errors.New("certification requires certify-keygen|certify-run|certify-verify")
	}
	tail := args[1:]
	switch args[0] {
	case "certify-keygen":
		return factoryCertKeygen02712(flagValue(tail, "--private-key", ""), flagValue(tail, "--public-key", ""))
	case "certify-run":
		seconds, err := strconv.Atoi(flagValue(tail, "--max-runtime-seconds", "45"))
		if err != nil {
			return err
		}
		client := flagValue(tail, "--client-dir", "")
		if client == "" {
			return errors.New("--client-dir required")
		}
		cert, err := certRun02712(context.Background(), client, flagValue(tail, "--runtime", ""), flagValue(tail, "--java", ""), flagValue(tail, "--runtime-sha256", ""), flagValue(tail, "--private-key", ""), flagValue(tail, "--output", ""), seconds)
		if err != nil {
			return err
		}
		return writeOrPrintJSON("-", cert)
	case "certify-matrix":
		report, err := certifyMatrix02712(flagValue(tail, "--matrix", ""), flagValue(tail, "--public-key", ""), flagValue(tail, "--output", ""), flagBool(tail, "--require-all-loaders", true))
		if err != nil {
			return err
		}
		if flagValue(tail, "--output", "") == "" || flagValue(tail, "--output", "") == "-" {
			return writeOrPrintJSON("-", report)
		}
		return nil
	case "certify-verify":
		client := flagValue(tail, "--client-dir", "")
		if client == "" {
			return errors.New("--client-dir required")
		}
		cert, err := certVerify02712(client, flagValue(tail, "--certificate", ""), flagValue(tail, "--public-key", ""))
		if err != nil {
			return err
		}
		for _, binary := range []struct{ name, hash string }{{flagValue(tail, "--runtime", ""), cert.RuntimeSHA256}, {flagValue(tail, "--java", ""), cert.JavaSHA256}} {
			if binary.name == "" {
				continue
			}
			path, e := certResolveExecutable02712(binary.name)
			if e != nil {
				return e
			}
			sum, e := certHashFile02712(path)
			if e != nil {
				return e
			}
			if sum != binary.hash {
				return errors.New("certification binary identity changed: " + binary.name)
			}
		}
		return writeOrPrintJSON(flagValue(tail, "--output", "-"), cert)
	default:
		return fmt.Errorf("unknown certification command %q", args[0])
	}
}

// Used by automated checks and certificate verifier; changing implementation
// does not alter signed InstallPlan bytes for existing deployments.
