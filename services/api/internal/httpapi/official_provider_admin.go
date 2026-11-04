package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

func (s Server) officialProviderSettings02611(ctx context.Context) (repository.OfficialProviderRevision02611, error) {
	store, ok := s.Repo.(repository.OfficialProviderStore02611)
	if !ok {
		return repository.OfficialProviderRevision02611{}, errors.New("official provider store unavailable")
	}
	v, err := store.GetOfficialProvider02611(ctx)
	if err != nil {
		return v, err
	}
	if v.Revision == 0 {
		v.Settings = repository.DefaultOfficialProvider02611(s.Config.MinecraftMicrosoftClientID)
	}
	return v, nil
}
func (s Server) officialProviderPolicy02611(w http.ResponseWriter, r *http.Request, flow string) (repository.OfficialProviderSettings02611, bool) {
	v, err := s.officialProviderSettings02611(r.Context())
	if err != nil {
		writeError(w, 503, "official provider configuration unavailable")
		return v.Settings, false
	}
	if !v.Settings.Enabled || (flow == "browser" && !v.Settings.BrowserEnabled) || (flow == "device" && !v.Settings.DeviceEnabled) {
		writeError(w, 403, "official Minecraft authentication method disabled by administrator")
		return v.Settings, false
	}
	if err := v.Settings.Validate(); err != nil {
		writeError(w, 503, "official provider configuration invalid")
		return v.Settings, false
	}
	return v.Settings, true
}
func (s Server) officialProviderGet02611(w http.ResponseWriter, r *http.Request) {
	v, err := s.officialProviderSettings02611(r.Context())
	if err != nil {
		writeError(w, 503, "provider configuration unavailable")
		return
	}
	writeJSON(w, 200, v)
}
func (s Server) officialProviderHistory02611(w http.ResponseWriter, r *http.Request) {
	store, ok := s.Repo.(repository.OfficialProviderStore02611)
	if !ok {
		writeError(w, 503, "provider history unavailable")
		return
	}
	records, err := store.ListOfficialProviderHistory02611(r.Context(), 50)
	if err != nil {
		writeError(w, 503, "provider history unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"items": records})
}

type officialProviderUpdate02611 struct {
	ExpectedRevision int64                                    `json:"expectedRevision"`
	Settings         repository.OfficialProviderSettings02611 `json:"settings"`
	Reason           string                                   `json:"reason"`
}

func readOfficialProviderUpdate02611(w http.ResponseWriter, r *http.Request) (officialProviderUpdate02611, error) {
	var data officialProviderUpdate02611
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if err := d.Decode(&data); err != nil {
		return data, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return data, errors.New("trailing JSON payload")
	}
	data.Reason = strings.TrimSpace(data.Reason)
	if data.ExpectedRevision < 0 || len(data.Reason) < 3 || len(data.Reason) > 500 || strings.ContainsAny(data.Reason, "\r\n\x00") {
		return data, errors.New("invalid revision or reason")
	}
	if err := data.Settings.Validate(); err != nil {
		return data, err
	}
	return data, nil
}
func (s Server) officialProviderPut02611(w http.ResponseWriter, r *http.Request) {
	update, err := readOfficialProviderUpdate02611(w, r)
	if err != nil {
		writeError(w, 400, "invalid official provider settings: "+err.Error())
		return
	}
	store, ok := s.Repo.(repository.OfficialProviderStore02611)
	if !ok {
		writeError(w, 503, "provider store unavailable")
		return
	}
	actor, err := s.adminClaims(r)
	if err != nil {
		writeError(w, 401, "authentication required")
		return
	}
	changed, err := store.SaveOfficialProvider02611(r.Context(), update.ExpectedRevision, update.Settings, actor.Sub, update.Reason)
	if errors.Is(err, repository.ErrOfficialProviderConflict02611) {
		writeError(w, 409, "provider revision conflict; refresh settings")
		return
	}
	if err != nil {
		writeError(w, 503, "provider settings could not be saved")
		return
	}
	s.Repo.AddAuditEvent(model.AuditEvent{Actor: actor.Sub, Action: "official-provider:changed", Target: "revision:" + strconv.FormatInt(changed.Revision, 10), CreatedAt: time.Now().UTC()})
	writeJSON(w, 200, changed)
}

type providerProbe02611 struct {
	Service    string `json:"service"`
	Reachable  bool   `json:"reachable"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	Detail     string `json:"detail"`
}

// Probe only hard-coded provider hosts. HTTP 401/403/405 shows an endpoint is
// reachable, NOT that this app is approved or the user owns Minecraft Java.
func probeOfficialProvider02611(ctx context.Context, client *http.Client, service, url string) providerProbe02611 {
	result := providerProbe02611{Service: service, Detail: "network_failure"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result
	}
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	result.HTTPStatus = resp.StatusCode
	result.Reachable = resp.StatusCode >= 200 && resp.StatusCode < 500
	if result.Reachable {
		result.Detail = "endpoint_reachable_not_provider_approval"
	} else {
		result.Detail = "upstream_unavailable"
	}
	return result
}
func (s Server) officialProviderDiagnostics02611(w http.ResponseWriter, r *http.Request) {
	current, err := s.officialProviderSettings02611(r.Context())
	if err != nil {
		writeError(w, 503, "provider configuration unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	checks := make([]providerProbe02611, 0, 3)
	for _, e := range []struct{ service, url string }{
		{"microsoft-oidc", "https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration"},
		{"xbox-live", "https://user.auth.xboxlive.com/user/authenticate"},
		{"minecraft-services", "https://api.minecraftservices.com/minecraft/profile"},
	} {
		checks = append(checks, probeOfficialProvider02611(ctx, client, e.service, e.url))
	}
	actor, err := s.adminClaims(r)
	if err == nil {
		statuses := make([]string, 0, len(checks))
		for _, probe := range checks {
			statuses = append(statuses, probe.Service+":"+strconv.Itoa(probe.HTTPStatus))
		}
		s.Repo.AddAuditEvent(model.AuditEvent{Actor: actor.Sub, Action: "official-provider:diagnostics", Target: strings.Join(statuses, ","), CreatedAt: time.Now().UTC()})
	}
	writeJSON(w, 200, map[string]any{"checkedAt": time.Now().UTC(), "revision": current.Revision, "configured": current.Settings.ClientID != "" && current.Settings.Enabled, "issuer": current.Settings.Issuer, "checks": checks, "appApprovalStatus": "not_verified", "note": "Connectivity cannot validate registered redirect URIs, Xbox entitlement, Minecraft Services application admission or successful online-mode join. Run the authenticated 0.26.1 provider POC."})
}
