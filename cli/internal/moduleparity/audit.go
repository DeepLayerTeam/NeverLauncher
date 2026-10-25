// Package moduleparity provides an executable, fail-closed inventory of Gravit
// module equivalents. It deliberately separates source inspection, executed
// regression tests, and full functional parity certification.
package moduleparity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const MatrixPath = "compatibility/gravit/module-parity-0301.json"
const JavaContractPath = "sdk/api/java-extension-api-0301.json"
const HistoricalPath = "compatibility/gravit/authorization-coverage-0211.json"

type Module struct {
	ID             string   `json:"id"`
	UpstreamModule string   `json:"upstreamModule"`
	Status         string   `json:"status"`
	Equivalent     string   `json:"equivalent"`
	SourceRefs     []string `json:"sourceRefs"`
	TestRefs       []string `json:"testRefs"`
	Limitations    string   `json:"limitations"`
}
type Matrix struct {
	SchemaVersion  string `json:"schemaVersion"`
	ProductVersion string `json:"productVersion"`
	AuditBaseline  string `json:"auditBaseline"`
	Upstream       struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
	} `json:"upstream"`
	Policy  json.RawMessage `json:"policy"`
	Modules []Module        `json:"modules"`
}
type TestOutcome struct {
	Status  string `json:"status"`
	Passed  int    `json:"passed"`
	Skipped int    `json:"skipped,omitempty"`
	Detail  string `json:"detail,omitempty"`
}
type Result struct {
	ModuleID        string            `json:"moduleId"`
	UpstreamModule  string            `json:"upstreamModule"`
	Status          string            `json:"status"`
	SourceValidated bool              `json:"sourceValidated"`
	SourceDigests   map[string]string `json:"sourceSha256,omitempty"`
	Test            TestOutcome       `json:"test"`
	Limitations     string            `json:"limitations"`
}
type Report struct {
	SchemaVersion  string   `json:"schemaVersion"`
	ProductVersion string   `json:"productVersion"`
	UpstreamCommit string   `json:"upstreamCommit"`
	AuditStatus    string   `json:"auditStatus"`
	FullyCertified bool     `json:"fullyCertified"`
	Results        []Result `json:"results"`
}
type Options struct {
	RunTests bool
	Timeout  time.Duration
	Selected map[string]bool
}

var goTestFunc = regexp.MustCompile(`(?m)^func\s+(Test[A-Za-z0-9_]+)\s*\(\s*[^)]*\*testing\.T\s*\)`)
var validCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

func readJSON(file string, out any) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	var extra any
	if err = d.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: invalid trailing data: %v", file, err)
	}
	return nil
}

// SafeRepoFile refuses symlinks (including symlink parent directories), paths
// outside the checkout and non-regular files. Audits must never read arbitrary
// filesystem paths from a modified evidence registry.
func SafeRepoFile(root, relative string) (string, error) {
	if relative == "" || strings.Contains(relative, "\\") || strings.Contains(relative, "\x00") || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", fmt.Errorf("invalid evidence path %q", relative)
	}
	p := root
	for _, part := range strings.Split(relative, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("invalid evidence path %q", relative)
		}
		p = filepath.Join(p, part)
		info, err := os.Lstat(p)
		if err != nil {
			return "", fmt.Errorf("evidence path missing %q: %w", relative, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink evidence forbidden: %q", relative)
		}
	}
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("evidence path is not a regular file: %q", relative)
	}
	return p, nil
}

func digest(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

func validateJavaContract(root string) error {
	var spec struct {
		SchemaVersion         string                       `json:"schemaVersion"`
		Phase                 string                       `json:"phase"`
		HostProtocolVersion   string                       `json:"hostProtocolVersion"`
		ExtensionAPIVersion   string                       `json:"extensionApiVersion"`
		ManifestSchemaVersion string                       `json:"manifestSchemaVersion"`
		MinimumJava           int                          `json:"minimumJava"`
		TypeBindings          map[string]map[string]string `json:"typeBindings"`
		RequiredHostRoutes    []string                     `json:"requiredHostRoutes"`
		Rules                 []string                     `json:"rules"`
	}
	if err := readJSON(filepath.Join(root, JavaContractPath), &spec); err != nil {
		return err
	}
	if spec.SchemaVersion != "1.0" || spec.Phase != "design-not-a-shipping-sdk" || spec.MinimumJava != 17 || len(spec.Rules) < 3 {
		return errors.New("unsafe/unversioned Java API design")
	}
	var host struct {
		SchemaVersion       string                       `json:"schemaVersion"`
		HostProtocolVersion string                       `json:"hostProtocolVersion"`
		ExtensionAPIVersion string                       `json:"extensionApiVersion"`
		Types               map[string]map[string]string `json:"types"`
	}
	hostBytes, err := os.ReadFile(filepath.Join(root, "sdk/api/extension-host-protocol.json"))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(hostBytes, &host); err != nil {
		return err
	}
	if host.SchemaVersion != "1.0" || host.HostProtocolVersion != spec.HostProtocolVersion || host.ExtensionAPIVersion != spec.ExtensionAPIVersion {
		return errors.New("Java API design drifts from shipping host protocol")
	}
	astFile, e := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "services/api/internal/extensioncontract/contract_0210.go"), nil, 0)
	if e != nil {
		return e
	}
	constants := map[string]string{}
	ast.Inspect(astFile, func(n ast.Node) bool {
		v, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range v.Names {
			if i < len(v.Values) {
				if lit, ok := v.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					constants[name.Name] = strings.Trim(lit.Value, "\"")
				}
			}
		}
		return true
	})
	if constants["HostProtocolVersion"] != spec.HostProtocolVersion || constants["ExtensionAPIVersion"] != spec.ExtensionAPIVersion || constants["ManifestSchemaVersion"] != spec.ManifestSchemaVersion {
		return errors.New("Java API design drifts from frozen Go extension contract")
	}
	for typeName, fields := range spec.TypeBindings {
		shipping, ok := host.Types[typeName]
		if !ok || len(shipping) != len(fields) {
			return fmt.Errorf("Java type %s mismatches host protocol", typeName)
		}
		for key, val := range fields {
			if shipping[key] != val {
				return fmt.Errorf("Java type %s.%s mismatch", typeName, key)
			}
		}
	}
	if len(spec.TypeBindings) != len(host.Types) {
		return errors.New("Java type bindings do not cover existing host types")
	}
	hostSource, err := os.ReadFile(filepath.Join(root, "services/api/internal/extensionhost/host_0205.go"))
	if err != nil {
		return err
	}
	for _, route := range spec.RequiredHostRoutes {
		if !strings.HasPrefix(route, "POST /v1/") && !strings.HasPrefix(route, "GET /v1/") && !strings.HasPrefix(route, "DELETE /v1/") {
			return fmt.Errorf("unscoped Java route: %s", route)
		}
		if !bytes.Contains(hostSource, []byte("\""+route+"\"")) {
			return fmt.Errorf("host no longer supports Java-design route %q", route)
		}
	}
	return nil
}

// Inspect validates current source/test existence and protocol contract without
// invoking builds. A PASS here means evidence integrity, never Gravit parity.
func Inspect(root string) (Report, error) {
	var out Report
	root, err := filepath.Abs(root)
	if err != nil {
		return out, err
	}
	var m Matrix
	if err = readJSON(filepath.Join(root, MatrixPath), &m); err != nil {
		return out, err
	}
	versionBytes, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return out, err
	}
	version := strings.TrimSpace(string(versionBytes))
	if m.SchemaVersion != "1.0" || m.ProductVersion != version || m.AuditBaseline != "0.30.0" || version != "0.30.1" {
		return out, fmt.Errorf("registry/version mismatch: registry=%s repo=%s", m.ProductVersion, version)
	}
	if m.Upstream.Repository != "GravitLauncher/LauncherModules" || !validCommit.MatchString(m.Upstream.Commit) {
		return out, errors.New("invalid pinned upstream revision")
	}
	var frozen struct {
		Upstream struct {
			Components map[string]struct {
				Commit string `json:"commit"`
			} `json:"components"`
		} `json:"upstream"`
		Requirements []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"requirements"`
	}
	if err = readHistorical(filepath.Join(root, HistoricalPath), &frozen); err != nil {
		return out, err
	}
	if frozen.Upstream.Components["launcher-modules"].Commit != m.Upstream.Commit {
		return out, errors.New("current parity matrix silently changes frozen upstream revision")
	}
	if len(m.Modules) != 19 {
		return out, fmt.Errorf("expected exactly 19 modules; got %d", len(m.Modules))
	}
	upstreamNames := map[string]string{}
	for _, r := range frozen.Requirements {
		upstreamNames[r.ID] = r.Name
	}
	out = Report{SchemaVersion: "1.0", ProductVersion: version, UpstreamCommit: m.Upstream.Commit, AuditStatus: "source-validated-not-certified", FullyCertified: false, Results: make([]Result, 0, 19)}
	for i, mod := range m.Modules {
		id := fmt.Sprintf("M%02d", i+1)
		if mod.ID != id || mod.UpstreamModule != upstreamNames[id] || strings.TrimSpace(mod.Equivalent) == "" || strings.TrimSpace(mod.Limitations) == "" {
			return Report{}, fmt.Errorf("%s: invalid id, upstream name, equivalent, or limitations", id)
		}
		if mod.Status != "partial" && mod.Status != "planned" && mod.Status != "blocked" {
			return Report{}, fmt.Errorf("%s: unsupported status %q; full certification requires a separate release gate", id, mod.Status)
		}
		if mod.Status == "partial" && (len(mod.SourceRefs) == 0 || len(mod.TestRefs) == 0) {
			return Report{}, fmt.Errorf("%s: partial implementation without source and tests", id)
		}
		digests := map[string]string{}
		seen := map[string]bool{}
		for _, ref := range append(append([]string{}, mod.SourceRefs...), mod.TestRefs...) {
			if seen[ref] {
				return Report{}, fmt.Errorf("%s duplicate evidence: %s", id, ref)
			}
			seen[ref] = true
			p, e := SafeRepoFile(root, ref)
			if e != nil {
				return Report{}, fmt.Errorf("%s: %w", id, e)
			}
			hash, e := digest(p)
			if e != nil {
				return Report{}, e
			}
			digests[ref] = hash
		}
		for _, ref := range mod.TestRefs {
			if !strings.HasSuffix(ref, "_test.go") && !strings.HasSuffix(ref, ".test.mjs") && !strings.HasSuffix(ref, ".test.py") {
				return Report{}, fmt.Errorf("%s test evidence not an executable test file: %s", id, ref)
			}
		}
		out.Results = append(out.Results, Result{ModuleID: id, UpstreamModule: mod.UpstreamModule, Status: mod.Status, SourceValidated: true, SourceDigests: digests, Test: TestOutcome{Status: "not-run"}, Limitations: mod.Limitations})
	}
	if err = validateJavaContract(root); err != nil {
		return Report{}, fmt.Errorf("Java API compatibility: %w", err)
	}
	return out, nil
}

// The historical source contains additional fields and is intentionally decoded
// permissively; the entire frozen snapshot must remain unchanged by this audit.
func readHistorical(path string, out any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, out)
}

type goGroup struct {
	Directory string
	Package   string
	Owners    map[string]map[string]bool
}

func nearestGoModule(root, relative string) (directory, goPackage string, err error) {
	current := filepath.Dir(relative)
	for {
		if _, e := os.Stat(filepath.Join(root, current, "go.mod")); e == nil {
			pkg := strings.TrimPrefix(strings.TrimPrefix(filepath.Dir(relative), current), string(filepath.Separator))
			if pkg == "" {
				pkg = "."
			} else {
				pkg = "./" + filepath.ToSlash(pkg)
			}
			return current, pkg, nil
		}
		if current == "." || current == "" {
			return "", "", fmt.Errorf("no Go module for %s", relative)
		}
		current = filepath.Dir(current)
	}
}

func updateTest(report *Report, id, status string, pass, skip int, detail string) {
	for i := range report.Results {
		if report.Results[i].ModuleID != id {
			continue
		}
		old := report.Results[i].Test
		if old.Status == "failed" {
			return
		}
		if old.Status == "not-run" {
			old.Status = status
		} else if status == "failed" {
			old.Status = "failed"
		}
		old.Passed += pass
		old.Skipped += skip
		if detail != "" {
			old.Detail = detail
		}
		report.Results[i].Test = old
		return
	}
}

// RunTests executes the *actual test names* inside the recorded Go files.
// Passing another test in the same package never counts as an owned test.
// No package or module is marked certified by running these tests.
func RunTests(ctx context.Context, root string, report *Report, matrix Matrix, opts Options) error {
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Minute
	}
	groups := map[string]*goGroup{}
	js := map[string][]string{}
	for _, mod := range matrix.Modules {
		if len(opts.Selected) > 0 && !opts.Selected[mod.ID] {
			continue
		}
		for _, ref := range mod.TestRefs {
			switch {
			case strings.HasSuffix(ref, ".test.mjs"):
				js[mod.ID] = append(js[mod.ID], ref)
			case strings.HasSuffix(ref, "_test.go"):
				directory, pkg, err := nearestGoModule(root, ref)
				if err != nil {
					return err
				}
				data, err := os.ReadFile(filepath.Join(root, ref))
				if err != nil {
					return err
				}
				matches := goTestFunc.FindAllSubmatch(data, -1)
				if len(matches) == 0 {
					return fmt.Errorf("no runnable test functions in %s", ref)
				}
				key := directory + "\x00" + pkg
				g := groups[key]
				if g == nil {
					g = &goGroup{Directory: directory, Package: pkg, Owners: map[string]map[string]bool{}}
					groups[key] = g
				}
				if g.Owners[mod.ID] == nil {
					g.Owners[mod.ID] = map[string]bool{}
				}
				for _, m := range matches {
					g.Owners[mod.ID][string(m[1])] = true
				}
			default:
				return fmt.Errorf("no supported runtime test executor for %s", ref)
			}
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		g := groups[key]
		allNames := map[string]bool{}
		for _, names := range g.Owners {
			for n := range names {
				allNames[n] = true
			}
		}
		unique := make([]string, 0, len(allNames))
		for n := range allNames {
			unique = append(unique, n)
		}
		sort.Strings(unique)
		pattern := "^(" + strings.Join(unique, "|") + ")$"
		c, cancel := context.WithTimeout(ctx, opts.Timeout)
		cmd := exec.CommandContext(c, "go", "test", "-count=1", "-json", "-timeout", opts.Timeout.String(), "-run", pattern, g.Package)
		cmd.Dir = filepath.Join(root, g.Directory)
		output, commandErr := cmd.Output()
		timedOut := c.Err()
		cancel()
		found := map[string]string{}
		var packageFail bool
		for _, line := range bytes.Split(output, []byte("\n")) {
			var e struct {
				Action string `json:"Action"`
				Test   string `json:"Test"`
			}
			if json.Unmarshal(line, &e) != nil {
				continue
			}
			if e.Test != "" && (e.Action == "pass" || e.Action == "fail" || e.Action == "skip") {
				found[e.Test] = e.Action
			}
			if e.Test == "" && e.Action == "fail" {
				packageFail = true
			}
		}
		for id, names := range g.Owners {
			passed, skipped := 0, 0
			for name := range names {
				switch found[name] {
				case "pass":
					passed++
				case "skip":
					skipped++
				}
			}
			nestedSkipped := 0
			for testName, action := range found {
				if action != "skip" {
					continue
				}
				for name := range names {
					if strings.HasPrefix(testName, name+"/") {
						nestedSkipped++
						break
					}
				}
			}
			skipped += nestedSkipped
			success := commandErr == nil && !packageFail && passed == len(names) && skipped == 0
			status := "passed"
			detail := ""
			if !success {
				status = "failed"
				detail = "package failed, test skipped, or one or more expected tests did not execute"
				if commandErr != nil {
					detail = commandErr.Error()
				}
				if timedOut != nil {
					detail = timedOut.Error()
				}
			}
			updateTest(report, id, status, passed, skipped, detail)
		}
	}
	jsIDs := make([]string, 0, len(js))
	for id := range js {
		jsIDs = append(jsIDs, id)
	}
	sort.Strings(jsIDs)
	for _, id := range jsIDs {
		for _, ref := range js[id] {
			c, cancel := context.WithTimeout(ctx, opts.Timeout)
			cmd := exec.CommandContext(c, "node", "--experimental-strip-types", "--test", ref)
			cmd.Dir = root
			output, e := cmd.CombinedOutput()
			timedOut := c.Err()
			cancel()
			pass := 0
			for _, line := range strings.Split(string(output), "\n") {
				if strings.HasPrefix(line, "# pass ") {
					fmt.Sscanf(line, "# pass %d", &pass)
				}
			}
			success := e == nil && pass > 0 && bytes.Contains(output, []byte("# fail 0")) && bytes.Contains(output, []byte("# skipped 0"))
			status, detail := "passed", ""
			if !success {
				status = "failed"
				detail = "Node test failed or did not execute tests"
				if e != nil {
					detail = e.Error()
				}
				if timedOut != nil {
					detail = timedOut.Error()
				}
			}
			updateTest(report, id, status, pass, 0, detail)
		}
	}
	return nil
}

func LoadMatrix(root string) (Matrix, error) {
	var m Matrix
	err := readJSON(filepath.Join(root, MatrixPath), &m)
	return m, err
}
func WriteReport(path string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0644)
}
