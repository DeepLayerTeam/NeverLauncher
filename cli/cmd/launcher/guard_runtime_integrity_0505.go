package main

// A live JVM inventory is compiled ONLY from the externally Ed25519-verified
// compatibility policy. It is not a user-editable allowlist. Legacy ClientFactory
// does not have the native Rust Manifest's complete effective classpath, so it
// must not assert complete classpath-source enforcement (strictCode=false).
import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
)

func guardRuntimeInventory0505(root string, p guardCompatPolicy0502) (string, error) {
	if len(p.Artifacts) == 0 || len(p.Artifacts) > 4096 {
		return "", fmt.Errorf("Guard runtime inventory empty/oversized")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "integrity.required=true\nintegrity.code.strict=false\nintegrity.root=%s\nintegrity.count=%d\n",
		base64.StdEncoding.EncodeToString([]byte(absoluteRoot)), len(p.Artifacts))
	for i, a := range p.Artifacts {
		file, err := guardCompatPath0502(root, a.Path)
		if err != nil {
			return "", err
		}
		file, err = filepath.Abs(file)
		if err != nil {
			return "", err
		}
		hash, err := guardCompatHashFile0502(root, a.Path)
		if err != nil {
			return "", err
		}
		if hash != a.SHA256 {
			return "", fmt.Errorf("Guard runtime inventory changed: %s", a.Path)
		}
		for _, revoked := range p.RevokedDigests {
			if revoked == a.SHA256 {
				return "", fmt.Errorf("Guard runtime revoked artifact: %s", a.Path)
			}
		}
		kind := "code"
		if a.Kind == "native-library" {
			kind = "native"
		}
		fmt.Fprintf(&b, "integrity.%d.path=%s\nintegrity.%d.sha256=%s\nintegrity.%d.kind=%s\n",
			i, base64.StdEncoding.EncodeToString([]byte(file)), i, a.SHA256, i, kind)
	}
	return b.String(), nil
}
