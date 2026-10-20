package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const ManifestSchemaV3 = "3.0"
const ComponentCatalogSchema0241 = "1.0"

// ComponentCatalog0241 is the immutable, content-addressed list of components
// belonging to ONE signed release. 0.24.1 installs every listed component;
// user-controlled selection, dependencies and predicates belong to later releases.
// Never accept arbitrary files or executable actions from the local client.
type ComponentCatalog0241 struct {
	SchemaVersion string                 `json:"schemaVersion"`
	Revision      uint64                 `json:"revision"`
	Digest        string                 `json:"digest"`
	Components    []CatalogComponent0241 `json:"components"`
}
type CatalogComponent0241 struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Files []string `json:"files"`
}

// Canonical framing is language-independent (Go/Rust) and unambiguous:
// prefix, u32be component count, length-prefixed UTF-8 strings, u32be file
// count and length-prefixed paths. Array order is significant and signed.
func ComponentCatalogDigest0241(components []CatalogComponent0241) string {
	h := sha256.New()
	h.Write([]byte("neverlauncher.component-catalog.v1\x00"))
	var n [4]byte
	writeCount := func(x int) { binary.BigEndian.PutUint32(n[:], uint32(x)); h.Write(n[:]) }
	writeText := func(s string) { writeCount(len(s)); h.Write([]byte(s)) }
	writeCount(len(components))
	for _, c := range components {
		writeText(c.ID)
		writeText(c.Name)
		writeCount(len(c.Files))
		for _, file := range c.Files {
			writeText(file)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func NewComponentCatalog0241(components []CatalogComponent0241, revision uint64) ComponentCatalog0241 {
	if components == nil {
		components = []CatalogComponent0241{}
	}
	return ComponentCatalog0241{SchemaVersion: ComponentCatalogSchema0241, Revision: revision,
		Digest: ComponentCatalogDigest0241(components), Components: components}
}

func validComponentID0241(id string) bool {
	if len(id) == 0 || len(id) > 128 || !(id[0] >= 'a' && id[0] <= 'z' || id[0] >= '0' && id[0] <= '9') {
		return false
	}
	for _, b := range []byte(id) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.') {
			return false
		}
	}
	return !strings.Contains(id, "..")
}

func ValidateComponentCatalog0241(m Manifest) error {
	if m.SchemaVersion != ManifestSchemaV3 {
		if m.ComponentCatalog != nil {
			return errors.New("componentCatalog is only valid in manifest v3")
		}
		return nil
	}
	cat := m.ComponentCatalog
	if cat == nil || cat.SchemaVersion != ComponentCatalogSchema0241 || cat.Revision == 0 ||
		len(cat.Components) > 4096 || len(cat.Digest) != 64 || cat.Digest != ComponentCatalogDigest0241(cat.Components) {
		return errors.New("invalid v3 component catalog snapshot/digest")
	}
	files := make(map[string]ManifestFile, len(m.Files))
	for _, f := range m.Files {
		files[strings.ToLower(f.Path)] = f
	}
	owners := make(map[string]string)
	ids := make(map[string]bool)
	for _, c := range cat.Components {
		if !validComponentID0241(c.ID) || ids[c.ID] ||
			strings.TrimSpace(c.Name) == "" || len(c.Name) > 256 || strings.ContainsAny(c.Name, "\x00\r\n") ||
			len(c.Files) == 0 || len(c.Files) > 8192 {
			return fmt.Errorf("invalid/duplicate v3 component id, name or files: %q", c.ID)
		}
		ids[c.ID] = true
		for _, path := range c.Files {
			if !validFilePolicyPath0224(path, false) {
				return fmt.Errorf("unsafe component path %q", path)
			}
			key := strings.ToLower(path)
			if owner, exists := owners[key]; exists {
				return fmt.Errorf("component file %q already owned by %q", path, owner)
			}
			f, ok := files[key]
			if !ok || f.Path != path || f.Required || FileOwnership0224(f) != "optional" {
				return fmt.Errorf("component %q must reference a signed optional file: %q", c.ID, path)
			}
			owners[key] = c.ID
		}
	}
	for _, f := range m.Files {
		if FileOwnership0224(f) == "optional" && owners[strings.ToLower(f.Path)] == "" {
			return fmt.Errorf("v3 optional file has no component owner: %q", f.Path)
		}
	}
	return nil
}
