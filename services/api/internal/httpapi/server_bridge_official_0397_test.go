package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/officialminecraft"
	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
)

type officialJoinLinkStore0397 struct {
	owner string
	links []repository.OfficialNeverLink0268
	err   error
}

func (s officialJoinLinkStore0397) ListOfficialLinks0268(_ context.Context, owner string) ([]repository.OfficialNeverLink0268, error) {
	if s.err != nil {
		return nil, s.err
	}
	if owner != s.owner {
		return nil, nil
	}
	return s.links, nil
}
func (s officialJoinLinkStore0397) UpsertOfficialLink0268(context.Context, string, string, string) (repository.OfficialNeverLink0268, error) {
	return repository.OfficialNeverLink0268{}, errors.New("unexpected mutation")
}
func (s officialJoinLinkStore0397) RemoveOfficialLink0268(context.Context, string, string) error {
	return errors.New("unexpected mutation")
}

func TestOfficialBridgeProfileRequiresLinkedProviderIdentity0397(t *testing.T) {
	const uuid = "0123456789abcdef0123456789abcdef"
	const bearer = "minecraft-verified-access-token"
	account := officialminecraft.Profile{ID: uuid, Name: "OfficialUser"}
	link := repository.OfficialNeverLink0268{MinecraftUUID: uuid, MinecraftName: account.Name}
	cases := []struct {
		name, username, owner string
		store                 officialJoinLinkStore0397
		token                 string
		success               bool
	}{
		{"verified link", account.Name, "never-user", officialJoinLinkStore0397{owner: "never-user", links: []repository.OfficialNeverLink0268{link}}, bearer, true},
		{"wrong Never owner", account.Name, "attacker", officialJoinLinkStore0397{owner: "never-user", links: []repository.OfficialNeverLink0268{link}}, bearer, false},
		{"unlinked profile", account.Name, "never-user", officialJoinLinkStore0397{owner: "never-user"}, bearer, false},
		{"switched Minecraft name", "AnotherUser", "never-user", officialJoinLinkStore0397{owner: "never-user", links: []repository.OfficialNeverLink0268{link}}, bearer, false},
		{"provider bearer rejected", account.Name, "never-user", officialJoinLinkStore0397{owner: "never-user", links: []repository.OfficialNeverLink0268{link}}, "forged-bearer", false},
		{"invalid token content", account.Name, "never-user", officialJoinLinkStore0397{owner: "never-user", links: []repository.OfficialNeverLink0268{link}}, bearer + "\r\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &minecraftVerifierFixture0268{token: bearer, profile: account}
			got, err := verifiedOfficialBridgeProfile0397(context.Background(), verifier, tc.store, tc.owner, tc.username, tc.token)
			if (err == nil) != tc.success {
				t.Fatalf("verified %v expected success=%t", err, tc.success)
			}
			if tc.success && (got.ID != uuid || got.Name != account.Name) {
				t.Fatalf("wrong profile: %+v", got)
			}
		})
	}
}

func TestOfficialBridgeProofIsNonSecretAndBound0397(t *testing.T) {
	const bearer = "minecraft-access-token-must-not-be-saved"
	profile := officialminecraft.Profile{ID: "0123456789abcdef0123456789abcdef", Name: "OfficialUser"}
	now := time.Now().UTC()
	payload, err := officialJoinProof0397("never-user", "auth-session", "trusted-device", 7, profile, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, bearer) || strings.Contains(payload, "refreshToken") || strings.Contains(payload, "accessToken") {
		t.Fatal("official bearer leaked into join proof")
	}
	var proof model.MinecraftSession
	if err = json.Unmarshal([]byte(payload), &proof); err != nil {
		t.Fatal(err)
	}
	if proof.UserID != "never-user" || proof.NeverSessionID != "auth-session" || proof.ProfileUUID != profile.ID || proof.BindingEpoch != 7 {
		t.Fatal("wrong proof binding")
	}
	if proof.ExpiresAt.Before(now.Add(11*time.Hour)) || proof.ExpiresAt.After(now.Add(13*time.Hour)) {
		t.Fatal("proxy handoff verification window incorrect")
	}
	if _, err = officialJoinProof0397("never-user", "auth-session", "trusted-device", 7, officialminecraft.Profile{ID: "wrong", Name: "OfficialUser"}, nil, now); err == nil {
		t.Fatal("invalid official UUID accepted")
	}
}
