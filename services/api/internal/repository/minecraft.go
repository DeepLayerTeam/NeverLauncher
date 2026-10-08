package repository

import (
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
)

// MinecraftRepository сохраняет Minecraft совместимость identity/session слой
// отдельный из канонический аутентификация репозиторий контракт. Рабочий PostgreSQL и
// в памяти процесса тест репозиторий implement это.
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
