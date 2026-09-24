package httpapi

import (
	"context"
	"errors"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/repository"
)

func (b *serverBridgeStore) configureRepositoryV2(repo repository.Repository) {
	if b == nil {
		return
	}
	backend, _ := repo.(repository.ServerBridgeRepository)
	b.mu.Lock()
	b.backend = backend
	b.mu.Unlock()
}

func (b *serverBridgeStore) backendV2() repository.ServerBridgeRepository {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.backend
}

func bridgeContextV2() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

func bridgeServerToModelV2(v bridgeServerRecord) model.ServerBridgeNode {
	return model.ServerBridgeNode{ID: v.ID, Name: v.Name, Kind: v.Kind, ProjectID: v.ProjectID, ProfileID: v.ProfileID, Fingerprint: v.Fingerprint, TokenHash: v.TokenHash, TokenPrefix: v.TokenPrefix, KeyAlgorithm: v.KeyAlgorithm, PublicKey: v.PublicKey, KeyFingerprint: v.KeyFingerprint, IdentityEpoch: v.IdentityEpoch, IdentityRotatedAt: v.IdentityRotatedAt, Status: v.Status, ProtocolVersion: firstNonZeroV2(v.ProtocolVersion, 2), PluginVersion: v.PluginVersion, PluginSHA256: v.PluginSHA256, IntegrityStatus: v.IntegrityStatus, IntegrityVerifiedAt: v.IntegrityVerifiedAt, LastHeartbeatAt: v.LastHeartbeatAt, CreatedAt: v.CreatedAt, RotatedAt: v.RotatedAt}
}
func bridgeServerFromModelV2(v model.ServerBridgeNode) bridgeServerRecord {
	return bridgeServerRecord{ID: v.ID, Name: v.Name, Kind: v.Kind, ProjectID: v.ProjectID, ProfileID: v.ProfileID, Fingerprint: v.Fingerprint, TokenHash: v.TokenHash, TokenPrefix: v.TokenPrefix, KeyAlgorithm: v.KeyAlgorithm, PublicKey: v.PublicKey, KeyFingerprint: v.KeyFingerprint, IdentityEpoch: v.IdentityEpoch, IdentityRotatedAt: v.IdentityRotatedAt, Status: v.Status, ProtocolVersion: v.ProtocolVersion, PluginVersion: v.PluginVersion, PluginSHA256: v.PluginSHA256, IntegrityStatus: v.IntegrityStatus, IntegrityVerifiedAt: v.IntegrityVerifiedAt, LastHeartbeatAt: v.LastHeartbeatAt, CreatedAt: v.CreatedAt, RotatedAt: v.RotatedAt}
}
func bridgeJoinToModelV2(v bridgeJoinRecord) model.ServerBridgeJoinTicket {
	return model.ServerBridgeJoinTicket{ID: v.ID, Username: v.Username, UsernameNormalized: strings.ToLower(strings.TrimSpace(v.Username)), UUID: v.UUID, UserID: v.UserID, SessionID: v.SessionID, ServerID: v.ServerID, ProjectID: v.ProjectID, ProfileID: v.ProfileID, Channel: v.Channel, AccessTokenHash: v.AccessTokenHash, TrustedDeviceID: v.TrustedDeviceID, BindingEpoch: v.BindingEpoch, MinecraftSessionID: v.MinecraftSessionID, ProtocolVersion: firstNonZeroV2(v.ProtocolVersion, 2), Status: v.Status, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, ConsumedAt: v.ConsumedAt}
}
func bridgeJoinFromModelV2(v model.ServerBridgeJoinTicket) bridgeJoinRecord {
	return bridgeJoinRecord{ID: v.ID, Username: v.Username, UUID: v.UUID, UserID: v.UserID, SessionID: v.SessionID, ServerID: v.ServerID, ProjectID: v.ProjectID, ProfileID: v.ProfileID, Channel: v.Channel, AccessTokenHash: v.AccessTokenHash, TrustedDeviceID: v.TrustedDeviceID, BindingEpoch: v.BindingEpoch, MinecraftSessionID: v.MinecraftSessionID, ProtocolVersion: v.ProtocolVersion, Status: v.Status, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, ConsumedAt: v.ConsumedAt}
}
func bridgeTextureToModelV2(v bridgeTextureRecord) model.ServerBridgeTexture {
	return model.ServerBridgeTexture{UUID: v.UUID, Username: v.Username, SkinURL: v.SkinURL, CapeURL: v.CapeURL, Model: v.Model, UpdatedAt: v.UpdatedAt}
}
func bridgeTextureFromModelV2(v model.ServerBridgeTexture) bridgeTextureRecord {
	return bridgeTextureRecord{UUID: v.UUID, Username: v.Username, SkinURL: v.SkinURL, CapeURL: v.CapeURL, Model: v.Model, UpdatedAt: v.UpdatedAt}
}
func firstNonZeroV2(v, fallback int) int {
	if v != 0 {
		return v
	}
	return fallback
}

func (b *serverBridgeStore) consumeJoinV2(join bridgeJoinRecord) (bridgeJoinRecord, bool) {
	if backend := b.backendV2(); backend != nil {
		ctx, cancel := bridgeContextV2()
		defer cancel()
		v, err := backend.ConsumeServerBridgeJoinTicket(ctx, join.ID, time.Now().UTC())
		return bridgeJoinFromModelV2(v), err == nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := b.joinKey(join.Username, join.ServerID)
	current, ok := b.joins[key]
	if !ok || current.ID != join.ID || current.Status != "active" || !current.ExpiresAt.After(time.Now().UTC()) {
		return bridgeJoinRecord{}, false
	}
	current.Status = "consumed"
	current.ConsumedAt = time.Now().UTC()
	b.joins[key] = current
	return current, true
}

func isBridgeNotFoundV2(err error) bool {
	return errors.Is(err, repository.ErrNotFound)
}
