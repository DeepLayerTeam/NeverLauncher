package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/config"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

type liveTextureRepo0394 struct {
	repository.Repository
	repository.MinecraftRepository
	profile model.MinecraftProfile
	texture model.ServerBridgeTexture
	fail    error
	found   bool
}

func (r *liveTextureRepo0394) GetMinecraftProfileByUUID(uuid string) (model.MinecraftProfile, error) {
	if minecraftID119(uuid) != minecraftID119(r.profile.UUID) {
		return model.MinecraftProfile{}, repository.ErrNotFound
	}
	return r.profile, nil
}
func (r *liveTextureRepo0394) ReadTextureProfile0251(_ context.Context, uuid string) (model.ServerBridgeTexture, bool, error) {
	if r.fail != nil {
		return model.ServerBridgeTexture{}, false, r.fail
	}
	if minecraftID119(uuid) != minecraftID119(r.profile.UUID) || !r.found {
		return model.ServerBridgeTexture{}, false, nil
	}
	return r.texture, true, nil
}
func (r *liveTextureRepo0394) ListTextureAssignments0251(context.Context, model.MinecraftProfile) ([]model.TextureAssignment0251, error) {
	return nil, nil
}
func (r *liveTextureRepo0394) UpdateTextureSelection0251(context.Context, model.MinecraftProfile, string, int64, string, string, bool) (model.TextureAssignment0251, error) {
	return model.TextureAssignment0251{}, nil
}
func (r *liveTextureRepo0394) ListTextureRevisions0251(context.Context, model.MinecraftProfile, string) ([]model.TextureRevision0251, error) {
	return nil, nil
}

func requestLiveTexture0394(t *testing.T, s Server, uuid string) (int, http.Header, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", "/sessionserver/session/minecraft/profile/"+uuid+"?unsigned=false", nil)
	req.SetPathValue("uuid", uuid)
	out := httptest.NewRecorder()
	s.yggdrasilProfile119(out, req)
	var result map[string]any
	if out.Body.Len() > 0 {
		if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	return out.Code, out.Header(), result
}
func decodeTexture0394(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	properties := body["properties"].([]any)
	if len(properties) != 1 {
		t.Fatalf("missing Yggdrasil property: %#v", body)
	}
	property := properties[0].(map[string]any)
	if property["signature"] == nil {
		t.Fatal("signed profile missing RSA signature")
	}
	data, err := base64.StdEncoding.DecodeString(property["value"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestYggdrasilDelivery0394ActiveSkinCapeAndFailClosed(t *testing.T) {
	profile := model.MinecraftProfile{UUID: "12345678-1234-4234-9234-0123456789ab", Name: "LocalPlayer", Issuer: "neverlauncher", Realm: "local"}
	r := &liveTextureRepo0394{profile: profile, found: true}
	r.texture = model.ServerBridgeTexture{UUID: profile.UUID, Username: profile.Name, Model: "slim", SkinURL: "https://api.example.test/api/v1/textures/blob/" + strings.Repeat("a", 64), CapeURL: "https://api.example.test/api/v1/textures/blob/" + strings.Repeat("b", 64)}
	s := Server{Repo: r, State: NewRuntimeState(), Config: config.Config{Environment: "dev", PublicURL: "https://api.example.test"}}
	code, headers, body := requestLiveTexture0394(t, s, profile.UUID)
	if code != 200 || !strings.Contains(headers.Get("Cache-Control"), "no-store") {
		t.Fatalf("Yggdrasil response=%d, cache=%q", code, headers.Get("Cache-Control"))
	}
	v := decodeTexture0394(t, body)
	if v["profileId"] != minecraftID119(profile.UUID) {
		t.Fatalf("identity mismatch: %#v", v)
	}
	textures := v["textures"].(map[string]any)
	if textures["SKIN"].(map[string]any)["metadata"].(map[string]any)["model"] != "slim" || textures["CAPE"].(map[string]any)["url"] != r.texture.CapeURL {
		t.Fatalf("first skin/cape mismatch: %#v", textures)
	}
	// Change the selected skin/cape while the same Server instance is running.
	// The next request must read the current DB values, not an old bridge cache.
	r.texture.SkinURL = "https://api.example.test/api/v1/textures/blob/" + strings.Repeat("c", 64)
	r.texture.CapeURL = ""
	r.texture.Model = "classic"
	code, _, body = requestLiveTexture0394(t, s, profile.UUID)
	if code != 200 {
		t.Fatalf("updated profile status=%d", code)
	}
	next := decodeTexture0394(t, body)["textures"].(map[string]any)
	if next["SKIN"].(map[string]any)["url"] != r.texture.SkinURL {
		t.Fatalf("stale skin served: %#v", next)
	}
	if _, ok := next["CAPE"]; ok {
		t.Fatalf("removed cape still published: %#v", next)
	}
	if _, ok := next["SKIN"].(map[string]any)["metadata"]; ok {
		t.Fatalf("classic model must omit metadata: %#v", next)
	}
	r.fail = errors.New("database unavailable")
	code, _, _ = requestLiveTexture0394(t, s, profile.UUID)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("failed DB masked by empty skin: %d", code)
	}
}
