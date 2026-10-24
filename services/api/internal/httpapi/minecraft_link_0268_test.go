package httpapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/officialminecraft"
)

type minecraftVerifierFixture0268 struct {
	token   string
	profile officialminecraft.Profile
	err     error
	calls   int
}

func (f *minecraftVerifierFixture0268) Profile(_ context.Context, token string) (officialminecraft.Profile, error) {
	f.calls++
	if token != f.token {
		return officialminecraft.Profile{}, errors.New("invalid proof")
	}
	return f.profile, f.err
}
func TestOfficialLinkRequiresFreshNeverSession0268(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, v := range []struct {
		auth int64
		ok   bool
	}{
		{now.Unix(), true}, {now.Unix() - 899, true}, {now.Unix() - 901, false}, {0, false}, {now.Unix() + 1, false},
	} {
		if actual := freshNeverIdentity0268(authClaims{AuthTime: v.auth}, now); actual != v.ok {
			t.Errorf("freshNeverIdentity(%d)=%v", v.auth, actual)
		}
	}
}
func TestOfficialLinkProviderProof0268(t *testing.T) {
	const uuid = "0123456789abcdef0123456789abcdef"
	const token = "fixture-minecraft-access-token"
	for _, tc := range []struct {
		name, expected, access string
		profile                officialminecraft.Profile
		providerErr            error
		ok                     bool
		calls                  int
	}{
		{"matching", uuid, token, officialminecraft.Profile{ID: uuid, Name: "ValidUser"}, nil, true, 1},
		{"case-insensitive UUID", strings.ToUpper(uuid), token, officialminecraft.Profile{ID: uuid, Name: "ValidUser"}, nil, true, 1},
		{"mismatch", uuid, token, officialminecraft.Profile{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "ValidUser"}, nil, false, 1},
		{"bad username", uuid, token, officialminecraft.Profile{ID: uuid, Name: "invalid-name"}, nil, false, 1},
		{"revoked provider token", uuid, token, officialminecraft.Profile{}, officialminecraft.ErrExpired, false, 1},
		{"renderer token not accepted", uuid, "", officialminecraft.Profile{}, nil, false, 0},
		{"tampered expected UUID", "wrong", token, officialminecraft.Profile{}, nil, false, 0},
		{"header injection", uuid, token + "\r\n", officialminecraft.Profile{}, nil, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := &minecraftVerifierFixture0268{token: token, profile: tc.profile, err: tc.providerErr}
			_, err := verifiedLinkProfile0268(context.Background(), fixture, tc.access, tc.expected)
			if (err == nil) != tc.ok {
				t.Fatalf("provider validation: %v", err)
			}
			if fixture.calls != tc.calls {
				t.Fatalf("provider called %d times", fixture.calls)
			}
		})
	}
}
func TestOfficialLinkUUIDValidation0268(t *testing.T) {
	uuid, ok := canonicalMinecraftUUID0268("ABCDEF0123456789ABCDEF0123456789")
	if !ok || uuid != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("wrong normalized uuid: %s", uuid)
	}
	for _, bad := range []string{"", "1234", "12345678-1234-1234-1234-123456789012", strings.Repeat("z", 32), strings.Repeat("a", 31) + "/"} {
		if _, ok := canonicalMinecraftUUID0268(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}
