//go:build linux

package extensionhost

import (
	"os"
	"strconv"
	"strings"
)

func canRead0311(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func capabilityFromFile0311(path string) Capability0311 {
	if canRead0311(path) {
		return Capability0311{"detected", "kernel-interface-present-not-enforced"}
	}
	return Capability0311{"unknown", "kernel-interface-unavailable"}
}

func probePlatformIsolation0311(d *IsolationDiagnostics0311) {
	d.Identity = Capability0311{"unknown", "dedicated-uid-not-configured-or-verified"}
	d.NoNewPrivileges = Capability0311{"unknown", "child-no-new-privs-not-set"}
	d.Namespaces = capabilityFromFile0311("/proc/self/ns/user")
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		n, e := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if e == nil && n <= 0 {
			d.Namespaces = Capability0311{"blocked", "user-namespace-limit-zero"}
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(b)) == "0" && os.Geteuid() != 0 {
		d.Namespaces = Capability0311{"blocked", "unprivileged-user-namespace-disabled"}
	}
	d.Seccomp = capabilityFromFile0311("/proc/sys/kernel/seccomp/actions_avail")
	d.Landlock = capabilityFromFile0311("/sys/kernel/security/landlock")
	d.CgroupsV2 = capabilityFromFile0311("/sys/fs/cgroup/cgroup.controllers")
	// Seeing cgroup.controllers alone does not mean the service can delegate
	// subtrees: inability to write cgroup.subtree_control blocks delegation.
	if d.CgroupsV2.State == "detected" {
		if f, err := os.OpenFile("/sys/fs/cgroup/cgroup.subtree_control", os.O_WRONLY, 0); err == nil {
			_ = f.Close()
			d.CgroupsV2.ReasonCode = "v2-hierarchy-visible-delegation-not-proven"
		} else {
			d.CgroupsV2 = Capability0311{"blocked", "cgroups-v2-delegation-not-writable"}
		}
	}
	d.EffectiveRestrictions = append(d.EffectiveRestrictions, "linux-process-group", "proc-pgid-rss-monitor")
	d.ReasonCodes = append(d.ReasonCodes, "process-group-is-not-process-tree-boundary", "network-and-filesystem-not-confined")
}
