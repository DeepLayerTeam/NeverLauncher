package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// GravitOptionalMigration02411 is an owner-reviewable conversion, NEVER a
// trusted release. Only a draft package's already hashed, optional-owned files
// can be referenced. The normal catalog preview, CAS save and release signing
// pipeline is mandatory after import.
type GravitOptionalMigration02411 struct {
	Format       string                   `json:"format"`
	SourceSHA256 string                   `json:"sourceSha256"`
	Ready        bool                     `json:"ready"`
	Catalog      ComponentCatalog0241     `json:"catalog"`
	Fields       []GravitFieldResult02210 `json:"fields"`
	Summary      map[string]int           `json:"summary"`
}

var gravitSlug02411 = regexp.MustCompile(`[^a-z0-9]+`)

func gravitID02411(prefix, name string) string {
	s := strings.Trim(gravitSlug02411.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if s == "" {
		s = "component"
	}
	if len(s) > 70 {
		s = strings.TrimRight(s[:70], "-")
	}
	sum := sha256.Sum256([]byte(name))
	return prefix + s + "-" + hex.EncodeToString(sum[:4])
}

func gravitArray02411(raw json.RawMessage) ([]json.RawMessage, error) {
	var v []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil || v == nil {
		return nil, errors.New("expected non-null array")
	}
	return v, nil
}
func gravitString02411(raw json.RawMessage) (string, bool) {
	var s string
	return s, json.Unmarshal(raw, &s) == nil && bytes.TrimSpace(raw)[0] == '"'
}
func gravitBool02411(raw json.RawMessage) (bool, bool) {
	var b bool
	e := json.Unmarshal(raw, &b)
	return b, e == nil && (bytes.Equal(raw, []byte("true")) || bytes.Equal(raw, []byte("false")))
}
func gravitInt02411(raw json.RawMessage) (int, bool) {
	var n int
	e := json.Unmarshal(raw, &n)
	return n, e == nil && len(raw) > 0 && (raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9')) && !bytes.ContainsAny(raw, ".eE")
}

// ConvertGravitOptionalView02411 converts a Gravit ClientProfile's updateOptional
// or an explicit OptionalFile array. No network/download, signing, permission
// grants or foreign command execution occurs here. Unknown semantics are never
// silently dropped: Ready=false and each incompatibility is enumerated.
func ConvertGravitOptionalView02411(source []byte, base ComponentCatalog0241, signedFiles []ManifestFile) (GravitOptionalMigration02411, error) {
	if len(source) == 0 || len(source) > 1<<20 {
		return GravitOptionalMigration02411{}, errors.New("Gravit optional source must be 1 byte to 1 MiB")
	}
	sum := sha256.Sum256(source)
	out := GravitOptionalMigration02411{Format: "neverlauncher.gravit-optional-migration.v1", SourceSHA256: hex.EncodeToString(sum[:]), Fields: []GravitFieldResult02210{}, Summary: map[string]int{"mapped": 0, "transformed": 0, "manual": 0, "blocked": 0}}
	note := func(field, status, target, reason string) {
		out.Fields = append(out.Fields, GravitFieldResult02210{Field: field, Status: status, Target: target, Reason: reason})
		out.Summary[status]++
	}
	var raw json.RawMessage
	if bytes.HasPrefix(bytes.TrimSpace(source), []byte("[")) {
		raw = source
	} else {
		root, e := gravitObject02210(source)
		if e != nil {
			return out, e
		}
		raw = root["updateOptional"]
		if len(raw) == 0 {
			return out, errors.New("Gravit ClientProfile missing updateOptional")
		}
	}
	entries, e := gravitArray02411(raw)
	if e != nil {
		return out, fmt.Errorf("updateOptional: %w", e)
	}
	if len(entries) > 4096 {
		return out, errors.New("too many Gravit optional entries")
	}
	// Never overwrite existing components or retarget an existing file owner.
	cat := base
	cat.Components = append([]CatalogComponent0241(nil), base.Components...)
	cat.Categories = append([]CatalogCategory0242(nil), base.Categories...)
	cat.Groups = append([]CatalogGroup0242(nil), base.Groups...)
	cat.Presets = append([]CatalogPreset0242(nil), base.Presets...)
	cat.SchemaVersion = ComponentCatalogSchema0245
	if cat.Revision == 0 {
		cat.Revision = 1
	}
	fileMap := map[string]string{}
	for _, f := range signedFiles {
		if FileOwnership0224(f) == "optional" && !f.Required && len(f.SHA256) == 64 {
			fileMap[strings.ToLower(f.Path)] = f.Path
		}
	}
	owned := map[string]bool{}
	for _, c := range cat.Components {
		for _, p := range c.Files {
			owned[strings.ToLower(p)] = true
		}
	}
	existingIDs := map[string]bool{}
	for _, c := range cat.Components {
		existingIDs[c.ID] = true
	}
	categories := map[string]bool{}
	for _, c := range cat.Categories {
		categories[c.ID] = true
	}
	names := map[string]string{}
	opts := make([]map[string]json.RawMessage, len(entries))
	for i, entry := range entries {
		label := fmt.Sprintf("updateOptional[%d]", i)
		obj, err := gravitObject02210(entry)
		if err != nil {
			note(label, "blocked", "", err.Error())
			continue
		}
		opts[i] = obj
		name, ok := gravitString02411(obj["name"])
		if !ok || strings.TrimSpace(name) == "" || len(name) > 256 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
			note(label+".name", "blocked", "", "nonempty valid name required")
			continue
		}
		if _, dup := names[name]; dup {
			note(label+".name", "blocked", "", "duplicate Gravit name")
			continue
		}
		id := gravitID02411("gravit-", name)
		if existingIDs[id] {
			note(label+".name", "blocked", "", "stable ID already exists in catalog")
			continue
		}
		names[name] = id
		existingIDs[id] = true
	}
	for i, obj := range opts {
		if obj == nil {
			continue
		}
		label := fmt.Sprintf("updateOptional[%d]", i)
		name, ok := gravitString02411(obj["name"])
		if !ok || names[name] == "" {
			continue
		}
		id := names[name]
		c := CatalogComponent0241{ID: id, Name: name, Version: "1.0.0", Files: []string{}, Visible: func() *bool { b := true; return &b }()}
		note(label+".name", "transformed", "components."+id+".id", "stable ID derived from exact Gravit name; version 1.0.0 is a migration placeholder")
		known := map[string]bool{"name": true, "info": true, "mark": true, "visible": true, "limited": true, "permissions": true, "category": true, "subTreeLevel": true, "dependenciesFile": true, "conflictFile": true, "triggersList": true, "triggers": true, "actions": true, "groupFile": true, "isPreset": true}
		if raw, has := obj["groupFile"]; has && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			entries, err := gravitArray02411(raw)
			if err != nil || len(entries) != 0 {
				note(label+".groupFile", "blocked", "", "Gravit groupFile enforces at least one selected alternative; review exclusive groups manually")
			}
		}
		if raw, has := obj["isPreset"]; has {
			b, ok := gravitBool02411(raw)
			if !ok || b {
				note(label+".isPreset", "blocked", "", "Gravit isPreset has selection semantics not equivalent to Never presets")
			}
		}
		for key := range obj {
			if !known[key] {
				note(label+"."+key, "blocked", "", "unrecognized Gravit optional semantics")
			}
		}
		if v, has := obj["info"]; has && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			if s, ok := gravitString02411(v); ok && len(s) <= 4096 {
				c.Description = s
				note(label+".info", "mapped", "components."+id+".description", "description")
			} else {
				note(label+".info", "blocked", "", "invalid description")
			}
		}
		for _, field := range []string{"mark", "visible", "limited"} {
			if v, has := obj[field]; has {
				b, ok := gravitBool02411(v)
				if !ok {
					note(label+"."+field, "blocked", "", "expected boolean")
					continue
				}
				switch field {
				case "mark":
					c.Default = b
				case "visible":
					*c.Visible = b
				case "limited":
					c.Limited = b
					if b {
						note(label+".limited", "blocked", "", "Gravit permission mask cannot be imported as verified Never entitlements")
						continue
					}
				}
				note(label+"."+field, "mapped", "components."+id+"."+field, "boolean selection attribute")
			}
		}
		if v, has := obj["permissions"]; has {
			n, ok := gravitInt02411(v)
			if !ok || n != 0 {
				note(label+".permissions", "blocked", "", "Gravit permission bitmask cannot grant Never permissions")
			} else {
				note(label+".permissions", "mapped", "", "zero permissions")
			}
		}
		if v, has := obj["category"]; has && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			s, ok := gravitString02411(v)
			if !ok || len(s) > 120 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
				note(label+".category", "blocked", "", "invalid category")
			} else if s != "" && !strings.EqualFold(s, "GLOBAL") {
				cid := gravitID02411("gravit-category-", s)
				c.CategoryID = cid
				if !categories[cid] {
					cat.Categories = append(cat.Categories, CatalogCategory0242{ID: cid, Name: s})
					categories[cid] = true
				}
				note(label+".category", "transformed", "categories."+cid, "category name preserved")
			}
		}
		if v, has := obj["subTreeLevel"]; has {
			n, ok := gravitInt02411(v)
			if !ok || n < 0 || n > 32 {
				note(label+".subTreeLevel", "blocked", "", "invalid nesting level")
			} else if n > 1 {
				note(label+".subTreeLevel", "manual", "groups", "visual indentation has no semantic parent identity; review nested groups")
			}
		}
		for _, rel := range []struct {
			key        string
			dependency bool
		}{{"dependenciesFile", true}, {"conflictFile", false}} {
			if v, has := obj[rel.key]; has && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				list, err := gravitArray02411(v)
				if err != nil {
					note(label+"."+rel.key, "blocked", "", err.Error())
					continue
				}
				for j, rr := range list {
					fld := fmt.Sprintf("%s.%s[%d]", label, rel.key, j)
					r, e := gravitObject02210(rr)
					if e != nil {
						note(fld, "blocked", "", e.Error())
						continue
					}
					for k := range r {
						if k != "name" {
							note(fld+"."+k, "blocked", "", "unsupported relation attribute")
						}
					}
					rn, ok := gravitString02411(r["name"])
					rid := names[rn]
					if !ok || rid == "" {
						note(fld, "blocked", "", "dependency/conflict name is absent from this import")
						continue
					}
					if rel.dependency {
						c.Dependencies = append(c.Dependencies, ComponentRequirement0243{ID: rid})
					} else {
						c.Conflicts = append(c.Conflicts, ComponentRequirement0243{ID: rid})
					}
					note(fld, "mapped", "components."+id, "resolved by exact source name to stable ID")
				}
			}
		}
		if v, has := obj["triggers"]; has && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			a, err := gravitArray02411(v)
			if err != nil || len(a) > 0 {
				note(label+".triggers", "blocked", "", "legacy triggers semantics unsupported; use recognized triggersList")
			}
		}
		if v, has := obj["triggersList"]; has && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			a, err := gravitArray02411(v)
			if err != nil {
				note(label+".triggersList", "blocked", "", err.Error())
			} else {
				cond := ComponentConditions0244{SchemaVersion: "1.0"}
				seen := map[string]bool{}
				for j, rawTrigger := range a {
					fld := fmt.Sprintf("%s.triggersList[%d]", label, j)
					t, e := gravitObject02210(rawTrigger)
					if e != nil {
						note(fld, "blocked", "", e.Error())
						continue
					}
					kind, ok := gravitString02411(t["type"])
					kind = strings.ToLower(kind)
					required, rok := gravitBool02411(t["required"])
					inverted, iok := false, true
					if raw, has := t["inverted"]; has {
						inverted, iok = gravitBool02411(raw)
					}
					if !ok || !rok || !iok || !required || inverted || seen[kind] {
						note(fld, "blocked", "", "only distinct non-inverted required os/java/arch predicates preserve Never availability semantics")
						continue
					}
					seen[kind] = true
					allowed := map[string]bool{"type": true, "required": true, "inverted": true}
					switch kind {
					case "os":
						allowed["os"] = true
						v, valid := gravitString02411(t["os"])
						switch strings.ToUpper(v) {
						case "MUSTDIE":
							cond.OS = []string{"windows"}
						case "LINUX":
							cond.OS = []string{"linux"}
						case "MACOSX":
							cond.OS = []string{"macos"}
						default:
							valid = false
						}
						if !valid {
							note(fld, "blocked", "", "unsupported Gravit OS")
							continue
						}
					case "arch":
						allowed["arch"] = true
						v, valid := gravitString02411(t["arch"])
						switch strings.ToUpper(v) {
						case "X86_64":
							cond.Arch = []string{"x86_64"}
						case "AARCH64":
							cond.Arch = []string{"aarch64"}
						default:
							valid = false
						}
						if !valid {
							note(fld, "blocked", "", "unsupported Gravit architecture")
							continue
						}
					case "java":
						allowed["minVersion"] = true
						allowed["maxVersion"] = true
						min, okMin := 8, true
						if raw, has := t["minVersion"]; has {
							min, okMin = gravitInt02411(raw)
						}
						max, okMax := 999, true
						if raw, has := t["maxVersion"]; has {
							max, okMax = gravitInt02411(raw)
						}
						allowed["requireJavaFX"] = true
						if raw, has := t["requireJavaFX"]; has {
							fx, ok := gravitBool02411(raw)
							if !ok || fx {
								note(fld, "blocked", "", "JavaFX runtime requirement cannot be verified as a Never condition")
								continue
							}
						}
						if !okMin || !okMax || min < 0 || max < 0 || min > 99 || max > 999 || (max != 999 && max != 0 && max < min) {
							note(fld, "blocked", "", "invalid Java major range")
							continue
						}
						cond.JavaMajorMin = uint32(min)
						if max != 999 {
							cond.JavaMajorMax = uint32(max)
						}
					default:
						note(fld, "blocked", "", "unsupported trigger type")
						continue
					}
					for k := range t {
						if !allowed[k] {
							note(fld+"."+k, "blocked", "", "unknown trigger field")
						}
					}
					note(fld, "transformed", "components."+id+".conditions", "required trigger mapped to signed availability predicate")
				}
				if len(cond.OS) > 0 || len(cond.Arch) > 0 || cond.JavaMajorMin > 0 || cond.JavaMajorMax > 0 {
					c.Conditions = &cond
				}
			}
		}
		if v, has := obj["actions"]; has {
			actions, e := gravitArray02411(v)
			if e != nil {
				note(label+".actions", "blocked", "", e.Error())
			} else if len(actions) > 64 {
				note(label+".actions", "blocked", "", "too many optional actions")
			} else {
				type classPath02411 struct {
					field string
					paths []string
				}
				pendingCP := []classPath02411{}
				for j, ra := range actions {
					fld := fmt.Sprintf("%s.actions[%d]", label, j)
					a, e := gravitObject02210(ra)
					if e != nil {
						note(fld, "blocked", "", e.Error())
						continue
					}
					typ, ok := gravitString02411(a["type"])
					if !ok {
						note(fld, "blocked", "", "missing action type")
						continue
					}
					lower := strings.ToLower(typ)
					switch lower {
					case "file", "classpath":
						if lower == "classpath" {
							// Gravit OptionalActionClassPath has args: List<String> and
							// useAltClasspath. Never only supports the primary classpath.
							for k := range a {
								if k != "type" && k != "args" && k != "useAltClasspath" {
									note(fld+"."+k, "blocked", "", "unknown classpath action attribute")
								}
							}
							var paths []string
							if json.Unmarshal(a["args"], &paths) != nil || len(paths) == 0 || len(paths) > 64 {
								note(fld, "blocked", "", "invalid classpath args")
								continue
							}
							if v, has := a["useAltClasspath"]; has {
								alt, ok := gravitBool02411(v)
								if !ok || alt {
									note(fld, "blocked", "", "alternate system classpath is not equivalent to Never signed classpath")
									continue
								}
							}
							pendingCP = append(pendingCP, classPath02411{field: fld, paths: paths})
							continue
						}
						for k := range a {
							if k != "type" && k != "files" {
								note(fld+"."+k, "blocked", "", "unsupported file action field")
							}
						}
						rawFiles := a["files"]
						if len(rawFiles) == 0 {
							note(fld, "blocked", "", "missing files map")
							continue
						}
						fm, e := gravitObject02210(rawFiles)
						if e != nil || len(fm) == 0 {
							note(fld, "blocked", "", "expected nonempty file path map")
							continue
						}
						paths := make([]string, 0, len(fm))
						for p := range fm {
							paths = append(paths, p)
						}
						sort.Strings(paths)
						for _, sourcePath := range paths {
							v, ok := gravitString02411(fm[sourcePath])
							if !ok {
								note(fld+".files."+sourcePath, "blocked", "", "file destination must be string")
								continue
							}
							if v != "" && v != sourcePath {
								note(fld+".files."+sourcePath, "blocked", "", "file relocation/rename cannot be proven equivalent to signed managed ownership")
								continue
							}
							if !gravitSafePath02210(sourcePath) || gravitProtected02210(sourcePath) {
								note(fld+".files."+sourcePath, "blocked", "", "unsafe/protected source path")
								continue
							}
							exact := fileMap[strings.ToLower(sourcePath)]
							if exact != sourcePath || owned[strings.ToLower(sourcePath)] {
								note(fld+".files."+sourcePath, "blocked", "", "file not staged as unowned signed optional path in draft package")
								continue
							}
							c.Files = append(c.Files, sourcePath)
							c.Actions = append(c.Actions, ComponentAction0245{Type: "File", Path: sourcePath})
							owned[strings.ToLower(sourcePath)] = true
							note(fld+".files."+sourcePath, "mapped", "components."+id+".actions", "bound to actual SHA-256 optional file in draft release")
						}
					case "jvmargs", "clientargs":
						for k := range a {
							if k != "type" && k != "args" {
								note(fld+"."+k, "blocked", "", "unknown argument action field")
							}
						}
						var args []string
						if json.Unmarshal(a["args"], &args) != nil || len(args) == 0 || len(args) > 32 {
							note(fld, "blocked", "", "invalid args array")
							continue
						}
						kind := "JvmArgs"
						if lower == "clientargs" {
							kind = "ClientArgs"
						}
						valid := true
						for _, arg := range args {
							if !safeOptionalArgument0245(kind, arg) {
								valid = false
							}
						}
						if !valid {
							note(fld, "blocked", "", "unsafe or unsupported Never argument; no command execution or auth override permitted")
							continue
						}
						c.Actions = append(c.Actions, ComponentAction0245{Type: kind, Args: args})
						note(fld, "mapped", "components."+id+".actions", "safe signed argument action")
					default:
						note(fld, "blocked", "", "unsupported optional action type "+typ)
					}
				}
				for _, cp := range pendingCP {
					for _, p := range cp.paths {
						found := false
						for _, ownedPath := range c.Files {
							if ownedPath == p {
								found = true
								break
							}
						}
						if !found || !strings.HasSuffix(strings.ToLower(p), ".jar") {
							note(cp.field, "blocked", "", "classpath entries require a signed JAR owned by the same component: "+p)
							continue
						}
						c.Actions = append(c.Actions, ComponentAction0245{Type: "ClassPath", Path: p})
						note(cp.field, "mapped", "components."+id+".actions", "primary classpath bound to signed, owned JAR")
					}
				}
			}
		}
		if len(c.Files) == 0 {
			note(label, "blocked", "", "Never components require one or more staged, signed optional files")
		}
		cat.Components = append(cat.Components, c)
	}
	for _, f := range signedFiles {
		if FileOwnership0224(f) == "optional" && !owned[strings.ToLower(f.Path)] {
			note("files."+f.Path, "blocked", "", "staged optional file has no component owner; assign in editor before signing")
		}
	}
	cat = NewComponentCatalog0245(cat, base.Revision+1)
	sort.Slice(out.Fields, func(i, j int) bool {
		if out.Fields[i].Field == out.Fields[j].Field {
			return out.Fields[i].Status < out.Fields[j].Status
		}
		return out.Fields[i].Field < out.Fields[j].Field
	})
	out.Catalog = cat
	out.Ready = out.Summary["blocked"] == 0 && out.Summary["manual"] == 0
	return out, nil
}
