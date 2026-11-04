package main

// Install individual, exactly pinned Modrinth versions and their required
// transitive dependencies. This is NOT an .mrpack importer (0.27.5).
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
)

type modrinthVersion0274 struct {
	ID            string   `json:"id"`
	ProjectID     string   `json:"project_id"`
	VersionNumber string   `json:"version_number"`
	DatePublished string   `json:"date_published"`
	GameVersions  []string `json:"game_versions"`
	Loaders       []string `json:"loaders"`
	Files         []struct {
		Filename string `json:"filename"`
		URL      string `json:"url"`
		Primary  bool   `json:"primary"`
		Hashes   struct {
			SHA256 string `json:"sha256"`
		} `json:"hashes"`
	} `json:"files"`
	Dependencies []struct {
		VersionID string `json:"version_id"`
		ProjectID string `json:"project_id"`
		Type      string `json:"dependency_type"`
	} `json:"dependencies"`
}
type modrinthProject0274 struct {
	ID         string `json:"id"`
	ClientSide string `json:"client_side"`
	ServerSide string `json:"server_side"`
}

func modrinthID0274(v string) error {
	if len(v) < 1 || len(v) > 64 {
		return errors.New("invalid Modrinth id length")
	}
	for _, r := range v {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return fmt.Errorf("invalid Modrinth id %q", v)
		}
	}
	return nil
}
func modrinthFetch0274(ctx context.Context, client *http.Client, base, endpoint string, out any) error {
	rawURL := strings.TrimRight(base, "/") + endpoint
	if err := validateRemoteURL(rawURL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Modrinth HTTP %d for %s", resp.StatusCode, endpoint)
	}
	if resp.ContentLength > 4<<20 {
		return errors.New("Modrinth metadata response oversized")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return errors.New("Modrinth metadata response exceeded 4 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err = dec.Decode(out); err != nil {
		return err
	}
	if err = dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("unexpected extra Modrinth metadata")
	}
	return nil
}
func modrinthContains0274(options []string, wanted string) bool {
	for _, v := range options {
		if strings.EqualFold(v, wanted) {
			return true
		}
	}
	return false
}
func modrinthSelectProjectVersion0274(ctx context.Context, client *http.Client, base, project string, plan factoryPlan0271) (string, error) {
	if err := modrinthID0274(project); err != nil {
		return "", err
	}
	query := url.Values{}
	encoded, _ := json.Marshal([]string{plan.Loader})
	query.Set("loaders", string(encoded))
	encoded, _ = json.Marshal([]string{plan.MinecraftVersion})
	query.Set("game_versions", string(encoded))
	var versions []modrinthVersion0274
	if err := modrinthFetch0274(ctx, client, base, "/project/"+url.PathEscape(project)+"/version?"+query.Encode(), &versions); err != nil {
		return "", err
	}
	if len(versions) > 3000 {
		return "", errors.New("Modrinth project version list too large")
	}
	eligible := make([]modrinthVersion0274, 0, len(versions))
	for _, v := range versions {
		if v.ProjectID != project || modrinthID0274(v.ID) != nil {
			continue
		}
		if modrinthContains0274(v.GameVersions, plan.MinecraftVersion) && modrinthContains0274(v.Loaders, plan.Loader) {
			eligible = append(eligible, v)
		}
	}
	if len(eligible) == 0 {
		return "", fmt.Errorf("no compatible pinned Modrinth version for %s", project)
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].DatePublished == eligible[j].DatePublished {
			return eligible[i].ID < eligible[j].ID
		}
		return eligible[i].DatePublished > eligible[j].DatePublished
	})
	return eligible[0].ID, nil
}
func resolveModrinthMods0274(ctx context.Context, base string, rootVersion string, plan factoryPlan0271) ([]mirrorArtifact0274, error) {
	if plan.Loader == "vanilla" {
		return nil, errors.New("Modrinth mod installation requires a mod loader")
	}
	if err := modrinthID0274(rootVersion); err != nil {
		return nil, err
	}
	if base == "" {
		base = "https://api.modrinth.com/v2"
	}
	if err := validateRemoteURL(strings.TrimRight(base, "/") + "/version/" + url.PathEscape(rootVersion)); err != nil {
		return nil, err
	}
	client := secureHTTPClient()
	visiting := map[string]bool{}
	completed := map[string]bool{}
	seenPaths := map[string]bool{}
	byProject := map[string]string{}
	mods := []mirrorArtifact0274{}
	var walk func(id string, depth int) error
	walk = func(id string, depth int) error {
		if depth > 16 || len(completed) > 128 || len(mods) > 128 {
			return errors.New("Modrinth dependency graph exceeds safe limits")
		}
		if completed[id] {
			return nil
		}
		if visiting[id] {
			return fmt.Errorf("cyclic required Modrinth dependency involving %s", id)
		}
		if err := modrinthID0274(id); err != nil {
			return err
		}
		visiting[id] = true
		defer delete(visiting, id)
		var v modrinthVersion0274
		if err := modrinthFetch0274(ctx, client, base, "/version/"+url.PathEscape(id), &v); err != nil {
			return err
		}
		if v.ID != id || modrinthID0274(v.ProjectID) != nil {
			return fmt.Errorf("invalid Modrinth version/project identity: %s", id)
		}
		if !modrinthContains0274(v.GameVersions, plan.MinecraftVersion) || !modrinthContains0274(v.Loaders, plan.Loader) {
			return fmt.Errorf("Modrinth version %s incompatible with pinned %s/%s", id, plan.MinecraftVersion, plan.Loader)
		}
		if previous, exists := byProject[v.ProjectID]; exists && previous != id {
			return fmt.Errorf("conflicting versions of Modrinth project %s: %s and %s", v.ProjectID, previous, id)
		}
		byProject[v.ProjectID] = id
		var project modrinthProject0274
		if err := modrinthFetch0274(ctx, client, base, "/project/"+url.PathEscape(v.ProjectID), &project); err != nil {
			return err
		}
		if project.ID != v.ProjectID || project.ClientSide == "unsupported" {
			return fmt.Errorf("Modrinth project %s does not allow client installation", v.ProjectID)
		}
		for _, dep := range v.Dependencies {
			if dep.Type != "required" {
				continue
			} // optional/embedded are not silently installed
			depID := dep.VersionID
			if depID == "" {
				if dep.ProjectID == "" {
					return fmt.Errorf("required Modrinth dependency of %s lacks both IDs", id)
				}
				resolved, err := modrinthSelectProjectVersion0274(ctx, client, base, dep.ProjectID, plan)
				if err != nil {
					return err
				}
				depID = resolved
			}
			if err := walk(depID, depth+1); err != nil {
				return err
			}
		}
		if len(v.Files) == 0 {
			return fmt.Errorf("Modrinth version %s has no downloadable file", id)
		}
		var selected int = -1
		for i, f := range v.Files {
			if f.Primary {
				if selected >= 0 {
					return errors.New("multiple primary Modrinth files")
				}
				selected = i
			}
		}
		if selected < 0 {
			if len(v.Files) != 1 {
				return fmt.Errorf("Modrinth version %s requires manual selection among files", id)
			}
			selected = 0
		}
		f := v.Files[selected]
		if f.Filename == "" || path.Base(f.Filename) != f.Filename || !strings.HasSuffix(strings.ToLower(f.Filename), ".jar") {
			return fmt.Errorf("unsafe/unsupported Modrinth filename %q", f.Filename)
		}
		if !isSHA256Hex0271(f.Hashes.SHA256) {
			return fmt.Errorf("Modrinth version %s missing SHA-256", id)
		}
		if err := validateRemoteURL(f.URL); err != nil {
			return err
		}
		rel := "mods/" + f.Filename
		if seenPaths[rel] {
			return fmt.Errorf("Modrinth filename collision: %s", rel)
		}
		seenPaths[rel] = true
		mods = append(mods, mirrorArtifact0274{Path: rel, URL: f.URL, SHA256: strings.ToLower(f.Hashes.SHA256), Side: "client", ProjectID: v.ProjectID, VersionID: id})
		completed[id] = true
		return nil
	}
	if err := walk(rootVersion, 0); err != nil {
		return nil, err
	}
	if len(mods) == 0 {
		return nil, errors.New("Modrinth version resolved to no files")
	}
	return mods, nil
}
