package extensionlifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionjava"
	"gitflic.ru/skif4er/launcher/services/api/internal/extensionresolver"
	"gitflic.ru/skif4er/launcher/services/api/internal/extensiontrust"
	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

// JavaCheck0305 is returned to operators; no secrets, tokens, or private paths appear.
type JavaCheck0305 struct {
	Target        string `json:"target"`
	Class         string `json:"class"`
	JavaMinimum   int    `json:"javaMinimum"`
	JavaAvailable int    `json:"javaAvailable"`
	ClassCount    int    `json:"classCount"`
}

type JavaDiagnostic0305 struct {
	ExtensionID string          `json:"extensionId"`
	Version     string          `json:"version"`
	Scope       string          `json:"scope"`
	ScopeID     string          `json:"scopeId,omitempty"`
	Healthy     bool            `json:"healthy"`
	JavaTargets []JavaCheck0305 `json:"javaTargets"`
	Errors      []string        `json:"errors"`
}

func isJavaTarget0305(target model.ExtensionTarget) bool {
	return (target.Kind == "backend" || target.Kind == "cli") && strings.EqualFold(filepath.Ext(target.Entrypoint), ".jar")
}

// inspectPayload0305 runs against extracted/staged bytes before any filesystem activation.
// The publisher signature and package digest have already been verified by prepareArtifact0204.
func (m *Manager) inspectPayload0305(ctx context.Context, root string, manifest model.ExtensionManifest) ([]JavaCheck0305, error) {
	var checks []JavaCheck0305
	for _, target := range manifest.Targets {
		if !isJavaTarget0305(target) {
			continue
		}
		if target.Entrypoint == "" || filepath.IsAbs(target.Entrypoint) || strings.Contains(target.Entrypoint, "\\") {
			return nil, errors.New("Java JAR target has invalid relative path")
		}
		rel := filepath.Clean(filepath.FromSlash(target.Entrypoint))
		if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, errors.New("Java JAR target escapes payload")
		}
		full := filepath.Join(root, rel)
		for parent := filepath.Dir(full); parent != root; parent = filepath.Dir(parent) {
			info, err := os.Lstat(parent)
			if err != nil {
				return nil, fmt.Errorf("Java target parent: %w", err)
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("Java target parent is not a regular directory")
			}
		}
		jar, err := extensionjava.Inspect(full)
		if err != nil {
			return nil, fmt.Errorf("Java target %s: %w", target.Entrypoint, err)
		}
		runtime, err := extensionjava.ProbeRuntime(ctx, m.JavaExecutable, jar.MinimumJava)
		if err != nil {
			return nil, fmt.Errorf("Java target %s: %w", target.Entrypoint, err)
		}
		checks = append(checks, JavaCheck0305{Target: target.Kind, Class: jar.EntrypointClass, JavaMinimum: jar.MinimumJava, JavaAvailable: runtime.Feature, ClassCount: jar.ClassFiles})
	}
	return checks, nil
}

func (m *Manager) checkGraph0305(ctx context.Context, manifest model.ExtensionManifest, scope Scope, requireEnabled bool) error {
	installs, err := m.Repo.ListExtensionInstallStates(ctx, "", "")
	if err != nil {
		return err
	}
	byKey := map[string]model.ExtensionInstall{}
	for _, item := range installs {
		if item.CurrentState == model.ExtensionInstallStateAbsent {
			continue
		}
		byKey[item.Scope+"\x00"+item.ScopeID+"\x00"+item.ExtensionID] = item
	}
	resolve := func(id string) (model.ExtensionInstall, bool) {
		id = strings.ToLower(strings.TrimSpace(id))
		if scope.Scope == "project" {
			if v, ok := byKey["project\x00"+scope.ScopeID+"\x00"+id]; ok {
				return v, true
			}
		}
		v, ok := byKey["global\x00\x00"+id]
		return v, ok
	}
	for _, dep := range manifest.Dependencies {
		current, ok := resolve(dep.ID)
		if !ok {
			if dep.Optional {
				continue
			}
			return fmt.Errorf("required dependency %s %s is missing", dep.ID, dep.Version)
		}
		if !extensionresolver.Matches(current.CurrentVersion, dep.Version) {
			return fmt.Errorf("dependency %s@%s does not satisfy %s", dep.ID, current.CurrentVersion, dep.Version)
		}
		if requireEnabled && !dep.Optional && current.CurrentState != model.ExtensionInstallStateEnabled {
			return fmt.Errorf("required dependency %s is disabled", dep.ID)
		}
		if dep.ID == manifest.ID {
			return fmt.Errorf("extension %s depends on itself", manifest.ID)
		}
	}
	for _, conflict := range manifest.Conflicts {
		if current, ok := resolve(conflict.ID); ok && extensionresolver.Matches(current.CurrentVersion, conflict.Version) {
			return fmt.Errorf("conflict with %s@%s", conflict.ID, current.CurrentVersion)
		}
	}
	// Do not silently break installed dependents by updating/rolling back an API provider.
	// Global modifications cover projects, except where a project shadows this package ID.
	for _, dependent := range installs {
		if dependent.ExtensionID == manifest.ID || dependent.CurrentState == model.ExtensionInstallStateAbsent {
			continue
		}
		affected := false
		if scope.Scope == "global" {
			affected = dependent.Scope == "global" || dependent.Scope == "project"
			if dependent.Scope == "project" {
				_, shadowed := byKey["project\x00"+dependent.ScopeID+"\x00"+manifest.ID]
				if shadowed {
					affected = false
				}
			}
		} else {
			affected = dependent.Scope == "project" && dependent.ScopeID == scope.ScopeID
		}
		if !affected {
			continue
		}
		ver, e := m.Repo.GetExtensionVersion(ctx, dependent.ExtensionID, dependent.CurrentVersion)
		if e != nil {
			return fmt.Errorf("load dependent %s: %w", dependent.ExtensionID, e)
		}
		for _, dep := range ver.Manifest.Dependencies {
			if dep.ID == manifest.ID && !extensionresolver.Matches(manifest.Version, dep.Version) {
				return fmt.Errorf("update would break %s: requires %s %s", dependent.ExtensionID, manifest.ID, dep.Version)
			}
		}
		for _, conflict := range ver.Manifest.Conflicts {
			if conflict.ID == manifest.ID && extensionresolver.Matches(manifest.Version, conflict.Version) {
				return fmt.Errorf("update conflicts with dependent %s", dependent.ExtensionID)
			}
		}
	}
	// Detect cycles involving the candidate, including transitive installed dependencies.
	active := map[string]bool{}
	done := map[string]bool{}
	var visit func(model.ExtensionManifest) error
	visit = func(mf model.ExtensionManifest) error {
		if active[mf.ID] {
			return fmt.Errorf("dependency cycle containing %s", mf.ID)
		}
		if done[mf.ID] {
			return nil
		}
		active[mf.ID] = true
		defer delete(active, mf.ID)
		for _, dep := range mf.Dependencies {
			installed, ok := resolve(dep.ID)
			if !ok {
				continue
			}
			if installed.ExtensionID == manifest.ID {
				if err := visit(manifest); err != nil {
					return err
				}
				continue
			}
			version, err := m.Repo.GetExtensionVersion(ctx, installed.ExtensionID, installed.CurrentVersion)
			if err != nil {
				return fmt.Errorf("dependency manifest %s: %w", installed.ExtensionID, err)
			}
			if err := visit(version.Manifest); err != nil {
				return err
			}
		}
		done[mf.ID] = true
		return nil
	}
	if len(manifest.Dependencies) == 0 {
		return nil
	}
	return visit(manifest)
}

// ValidateCandidate0305 is used by direct installs, update transactions, enable and rollback.
// It validates the graph, JAR structure and real JVM before any new Java payload is activated.
func (m *Manager) ValidateCandidate0305(ctx context.Context, root string, manifest model.ExtensionManifest, scope Scope, requireEnabled bool) error {
	if err := m.checkGraph0305(ctx, manifest, scope, requireEnabled); err != nil {
		return err
	}
	_, err := m.inspectPayload0305(ctx, root, manifest)
	return err
}

// DiagnoseJava0305 verifies active bytes and live JVM, without executing plugin code.
func (m *Manager) DiagnoseJava0305(ctx context.Context, id string, scope Scope) (JavaDiagnostic0305, error) {
	scope, err := normalizeScope0204(scope)
	if err != nil {
		return JavaDiagnostic0305{}, err
	}
	id, err = safeExtensionID0204(id)
	if err != nil {
		return JavaDiagnostic0305{}, err
	}
	install, err := m.Repo.GetExtensionInstallState(ctx, id, scope.Scope, scope.ScopeID)
	if err != nil {
		return JavaDiagnostic0305{}, err
	}
	if install.CurrentState == model.ExtensionInstallStateAbsent {
		return JavaDiagnostic0305{}, repository.ErrNotFound
	}
	result := JavaDiagnostic0305{ExtensionID: id, Version: install.CurrentVersion, Scope: scope.Scope, ScopeID: scope.ScopeID, JavaTargets: []JavaCheck0305{}, Errors: []string{}}
	add := func(err error) {
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
	}
	ver, err := m.Repo.GetExtensionVersion(ctx, id, install.CurrentVersion)
	if err != nil {
		add(err)
		return result, nil
	}
	if err := m.VerifyLockfile(ctx, id, scope); err != nil {
		add(fmt.Errorf("lockfile: %w", err))
	}
	if strings.HasPrefix(install.Source, "registry:") || strings.HasPrefix(install.Source, "rollback:") {
		pub, e := m.Repo.GetExtensionRegistryVersion(ctx, id, install.CurrentVersion)
		if e != nil {
			add(fmt.Errorf("signed registry publication: %w", e))
		} else {
			if pub.Artifact.PackageIdentity != install.CurrentPackageIdentity {
				add(errors.New("active package identity does not match signed registry publication"))
			}
			if _, e := extensiontrust.EvaluatePublication(ctx, m.Repo, pub); e != nil {
				add(fmt.Errorf("publisher trust: %w", e))
			}
		}
	}
	if err := m.checkGraph0305(ctx, ver.Manifest, scope, install.CurrentState == model.ExtensionInstallStateEnabled); err != nil {
		add(fmt.Errorf("dependencies: %w", err))
	}
	checks, err := m.inspectPayload0305(ctx, currentDir0204(m.Root, scope, id), ver.Manifest)
	if err != nil {
		add(err)
	} else {
		result.JavaTargets = checks
	}
	sort.Strings(result.Errors)
	result.Healthy = len(result.Errors) == 0
	return result, nil
}
