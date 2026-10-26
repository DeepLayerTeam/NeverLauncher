// Package extensionpolicy validates the signed sandbox policy and enforces
// version-scoped consent for every privilege-policy change.
package extensionpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

var resourceName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var hostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func normalizedSet(values []string, check func(string) bool) ([]string, error) {
	if len(values) > 128 {
		return nil, errors.New("sandbox grant list too large")
	}
	m := make(map[string]bool, len(values))
	for _, v := range values {
		if v == "" || strings.TrimSpace(v) != v || v != strings.ToLower(v) || !check(v) {
			return nil, fmt.Errorf("invalid sandbox grant %q", v)
		}
		if m[v] {
			return nil, fmt.Errorf("duplicate sandbox grant %q", v)
		}
		m[v] = true
	}
	result := make([]string, 0, len(m))
	for v := range m {
		result = append(result, v)
	}
	sort.Strings(result)
	return result, nil
}
func fsGrant(v string) bool {
	if v == "package" || v == "scratch" {
		return true
	}
	if !strings.HasPrefix(v, "shared:") {
		return false
	}
	return resourceName.MatchString(strings.TrimPrefix(v, "shared:"))
}
func netGrant(v string) bool {
	host, port, err := net.SplitHostPort(v)
	if err != nil || port == "" || host == "" || strings.ContainsAny(host, "/%*\\") {
		return false
	}
	if !hostname.MatchString(host) && net.ParseIP(host) == nil {
		return false
	}
	n, e := strconv.Atoi(port)
	return e == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}
func Validate(in *model.ExtensionSandboxPolicy) (*model.ExtensionSandboxPolicy, error) {
	if in == nil {
		return nil, nil
	} // legacy packages retain explicit unconfined behavior
	p := *in
	if p.Version != "1" {
		return nil, errors.New("sandbox.version must be 1")
	}
	if p.Mode != "isolated" && p.Mode != "trusted" {
		return nil, errors.New("sandbox.mode must be isolated or trusted")
	}
	var err error
	if p.FilesystemRead, err = normalizedSet(p.FilesystemRead, func(v string) bool { return v == "package" || fsGrant(v) && v != "scratch" }); err != nil {
		return nil, err
	}
	if p.FilesystemWrite, err = normalizedSet(p.FilesystemWrite, func(v string) bool { return v == "scratch" || (strings.HasPrefix(v, "shared:") && fsGrant(v)) }); err != nil {
		return nil, err
	}
	if p.NetworkOutbound, err = normalizedSet(p.NetworkOutbound, netGrant); err != nil {
		return nil, err
	}
	if p.Secrets, err = normalizedSet(p.Secrets, resourceName.MatchString); err != nil {
		return nil, err
	}
	if p.MaxProcesses < 0 || p.MaxProcesses > 128 || p.MaxMemoryBytes < 0 || p.MaxMemoryBytes > 64<<30 || p.MaxCPUPercent < 0 || p.MaxCPUPercent > 100 || p.TimeoutSeconds < 0 || p.TimeoutSeconds > 86400 {
		return nil, errors.New("invalid sandbox resource limit")
	}
	if p.Mode == "isolated" && (p.MaxProcesses == 0 || p.MaxMemoryBytes == 0 || p.TimeoutSeconds == 0 || p.MaxCPUPercent == 0) {
		return nil, errors.New("isolated sandbox requires finite process, memory, CPU and time limits")
	}
	return &p, nil
}

func LaunchAllowed(m model.ExtensionManifest) error {
	p, err := Validate(m.Sandbox)
	if err != nil {
		return err
	}
	if p != nil && p.Mode == "isolated" {
		return errors.New("sandbox-unavailable: isolated extension requires enforced OS sandbox; refusing unsandboxed launch")
	}
	return nil
}

// ApprovalDigest binds reviewer acknowledgement to precisely the signed
// permissions and sandbox policy of the target version (including its ID).
func ApprovalDigest(m model.ExtensionManifest) (string, error) {
	normalized, err := Validate(m.Sandbox)
	if err != nil {
		return "", err
	}
	perms := append([]string{}, m.Permissions...)
	sort.Strings(perms)
	b, err := json.Marshal(struct {
		ID          string                        `json:"id"`
		Version     string                        `json:"version"`
		Permissions []string                      `json:"permissions"`
		Sandbox     *model.ExtensionSandboxPolicy `json:"sandbox"`
	}{m.ID, m.Version, perms, normalized})
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// ChangesRequireApproval compares the exact security-relevant policy. Even a
// narrowing or reordering that changes meaning is reviewed, never inferred.
func ChangesRequireApproval(before, after model.ExtensionManifest) (bool, error) {
	a, err := Validate(before.Sandbox)
	if err != nil {
		return true, err
	}
	b, err := Validate(after.Sandbox)
	if err != nil {
		return true, err
	}
	old, err := json.Marshal(struct {
		Permissions []string
		Sandbox     *model.ExtensionSandboxPolicy
	}{before.Permissions, a})
	if err != nil {
		return true, err
	}
	next, err := json.Marshal(struct {
		Permissions []string
		Sandbox     *model.ExtensionSandboxPolicy
	}{after.Permissions, b})
	if err != nil {
		return true, err
	}
	return string(old) != string(next), nil
}

func RequireReview(before, after model.ExtensionManifest, submittedDigest string) error {
	changed, err := ChangesRequireApproval(before, after)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	want, err := ApprovalDigest(after)
	if err != nil {
		return err
	}
	if submittedDigest != want {
		return fmt.Errorf("sandbox/permission policy changed: explicit owner review required; target approvalDigest=%s", want)
	}
	return nil
}
