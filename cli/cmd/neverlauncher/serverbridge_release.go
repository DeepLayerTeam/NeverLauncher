package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const serverBridge2CertificationReleaseFile = "SERVERBRIDGE2_CERTIFICATION.json"

var serverBridge2ReleaseTargets0150 = []string{"velocity", "bungeecord", "waterfall", "bukkit", "spigot", "paper", "purpur", "folia", "fabric", "forge", "neoforge"}

var serverBridge2AllowlistFields0150 = map[string]string{
	"velocity": "velocitySha256", "bungeecord": "bungeeCordSha256", "waterfall": "waterfallSha256",
	"bukkit": "bukkitSha256", "spigot": "spigotSha256", "paper": "paperSha256", "purpur": "purpurSha256",
	"folia": "foliaSha256", "fabric": "fabricSha256", "forge": "forgeSha256", "neoforge": "neoforgeSha256",
}

type serverBridge2CertifiedArtifact0150 struct {
	ID     string `json:"id"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type serverBridge2Certification0150 struct {
	SchemaVersion   string                               `json:"schemaVersion"`
	Release         string                               `json:"release"`
	Version         string                               `json:"version"`
	ProtocolVersion int                                  `json:"protocolVersion"`
	Status          string                               `json:"status"`
	TargetCount     int                                  `json:"targetCount"`
	ZeroPatch       bool                                 `json:"zeroPatch"`
	NodeIdentity    string                               `json:"nodeIdentity"`
	OneTimeJoin     bool                                 `json:"oneTimeJoin"`
	Artifacts       []serverBridge2CertifiedArtifact0150 `json:"artifacts"`
}

func serverBridge2CertificationRequired0150(ver string) bool {
	parts := strings.SplitN(strings.TrimSpace(ver), ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > 0 || (major == 0 && minor >= 15)
}

func verifyServerBridge2CertificationInBundle0150(dir, ver string) error {
	raw, err := os.ReadFile(filepath.Join(dir, serverBridge2CertificationReleaseFile))
	if err != nil {
		return fmt.Errorf("read %s: %w", serverBridge2CertificationReleaseFile, err)
	}
	var cert serverBridge2Certification0150
	if err := json.Unmarshal(raw, &cert); err != nil {
		return fmt.Errorf("invalid %s: %w", serverBridge2CertificationReleaseFile, err)
	}
	if cert.SchemaVersion != "1.0" || cert.Release != "ServerBridge 2" || cert.Version != ver || cert.ProtocolVersion != 2 || cert.Status != "certified" || !cert.ZeroPatch || cert.NodeIdentity != "Ed25519" || !cert.OneTimeJoin {
		return errors.New("ServerBridge 2 certification metadata mismatch")
	}
	if cert.TargetCount != len(serverBridge2ReleaseTargets0150) || len(cert.Artifacts) != len(serverBridge2ReleaseTargets0150) {
		return fmt.Errorf("ServerBridge 2 certification must contain %d artifacts", len(serverBridge2ReleaseTargets0150))
	}

	allowRaw, err := os.ReadFile(filepath.Join(dir, "BRIDGE_RELEASE_ALLOWLIST.json"))
	if err != nil {
		return fmt.Errorf("read BRIDGE_RELEASE_ALLOWLIST.json: %w", err)
	}
	var allow map[string]map[string][]string
	if err := json.Unmarshal(allowRaw, &allow); err != nil {
		return fmt.Errorf("invalid BRIDGE_RELEASE_ALLOWLIST.json: %w", err)
	}
	if len(allow) != 1 || allow[ver] == nil {
		return errors.New("ServerBridge release allowlist must contain only exact bundle version")
	}
	policy := allow[ver]

	seen := make(map[string]struct{}, len(cert.Artifacts))
	for i, expectedID := range serverBridge2ReleaseTargets0150 {
		item := cert.Artifacts[i]
		if item.ID != expectedID {
			return fmt.Errorf("ServerBridge 2 artifact #%d must be %s, got %s", i+1, expectedID, item.ID)
		}
		expectedFile := fmt.Sprintf("neverlauncher-%s-bridge-%s.jar", expectedID, ver)
		if item.File != expectedFile || item.Bytes <= 0 {
			return fmt.Errorf("%s: invalid certified artifact metadata", expectedID)
		}
		actual, size, err := hashFile(filepath.Join(dir, item.File))
		if err != nil {
			return fmt.Errorf("%s: hash release artifact: %w", expectedID, err)
		}
		if !strings.EqualFold(actual, item.SHA256) || size != item.Bytes {
			return fmt.Errorf("%s: certification hash/size mismatch", expectedID)
		}
		normalized := strings.ToLower(strings.TrimSpace(item.SHA256))
		if _, ok := seen[normalized]; ok {
			return fmt.Errorf("%s: duplicate platform artifact SHA-256", expectedID)
		}
		seen[normalized] = struct{}{}
		values := policy[serverBridge2AllowlistFields0150[expectedID]]
		if len(values) != 1 || !strings.EqualFold(strings.TrimSpace(values[0]), item.SHA256) {
			return fmt.Errorf("%s: release allowlist does not match certified artifact", expectedID)
		}
	}
	return nil
}
