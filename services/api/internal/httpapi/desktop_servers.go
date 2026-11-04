package httpapi

import (
	"net/http"
	"sort"
	"time"
)

// Desktop receives only discoverable server metadata. The authoritative
// ServerBridge join endpoint must still enforce the authenticated identity,
// project, profile, channel, device and attestation checks.
type desktopServer0229 struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Kind             string    `json:"kind"`
	Status           string    `json:"status"`
	Health           string    `json:"health"`
	PlayersOnline    int       `json:"playersOnline"`
	CapacityMax      int       `json:"capacityMax"`
	MinecraftVersion string    `json:"minecraftVersion,omitempty"`
	LastHeartbeatAt  time.Time `json:"lastHeartbeatAt,omitempty"`
}

func (s Server) desktopProfileServers0229(w http.ResponseWriter, r *http.Request) {
	projectID, profileID := r.PathValue("projectId"), r.PathValue("profileId")
	// Fail closed for unknown project/profile: never enumerate other projects.
	profiles, err := s.Repo.ListProfiles(projectID)
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	found := false
	for _, profile := range profiles {
		if profile.ID == profileID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}
	items := make([]desktopServer0229, 0)
	if s.State.ServerBridge != nil {
		for _, node := range s.State.ServerBridge.listServers() {
			if node.ProjectID != projectID || (node.ProfileID != "" && node.ProfileID != profileID) || node.Status != "active" {
				continue
			}
			item := desktopServer0229{ID: node.ID, Name: node.Name, Kind: node.Kind, Status: node.Status, MinecraftVersion: node.MinecraftVersion, LastHeartbeatAt: node.LastHeartbeatAt}
			// Unverified/stale telemetry is never represented as live server status.
			item.Health = "unknown"
			if node.Telemetry != nil {
				item.Health = "telemetry-unverified"
			}
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "projectId": projectID, "profileId": profileID})
}
