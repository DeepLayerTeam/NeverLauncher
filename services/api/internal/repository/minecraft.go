package repository

import (
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// MinecraftRepository keeps the Minecraft compatibility identity/session layer
// separate from the canonical auth repository contract. Production PostgreSQL and
// the in-memory test repository implement it.
type MinecraftRepository interface {
	GetMinecraftProfileByUser(userID string) (model.MinecraftProfile, error)
	GetMinecraftProfileByUUID(uuid string) (model.MinecraftProfile, error)
	GetMinecraftProfileByName(name string) (model.MinecraftProfile, error)
	SaveMinecraftProfile(profile model.MinecraftProfile) (model.MinecraftProfile, error)
	SaveMinecraftSession(session model.MinecraftSession) (model.MinecraftSession, error)
	GetMinecraftSession(id string) (model.MinecraftSession, error)
	GetMinecraftSessionByTokenHash(tokenHash string) (model.MinecraftSession, error)
	TouchMinecraftSession(id string) (model.MinecraftSession, error)
	RevokeMinecraftSession(id, reason string) error
	RevokeMinecraftSessionsByNeverSession(neverSessionID, reason string) int
	RevokeMinecraftSessionsByUser(userID, reason string) int
	SaveMinecraftJoin(join model.MinecraftJoin) error
	GetMinecraftJoin(username, serverID string) (model.MinecraftJoin, error)
	ConsumeMinecraftJoin(username, serverID, expectedSessionID string, now time.Time) (model.MinecraftJoin, error)
}
