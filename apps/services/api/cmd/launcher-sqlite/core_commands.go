package main

// Локальное обслуживание SQLite Core на уровне ОС. Команды выполняют настоящие
// транзакционные операции репозитория, а не имитацию HTTP Backend. Необходимы
// блокировка владельца БД, закрытый каталог и закрытый JSON-ввод; анонимного
// слушателя нет.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/model"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func isCoreAction(action string) bool {
	switch action {
	case "core-put", "core-draft", "core-update-manifest", "core-publish", "core-get":
		return true
	}
	return false
}

func readPrivateJSON(path string, out any) error {
	if path == "" {
		return errors.New("Требуется: --input")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 1048576 || st.Size() == 0 {
		return errors.New("Входные данные должны находиться в обычном файле с правами 0600 размером до 1 МиБ")
	}
	f, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 1048577))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err = decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("Во входном JSON обнаружены лишние данные")
	}
	return nil
}

func runCoreAction(args []string) int {
	action := args[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	db := flags.String("db", "", "Приватный локальный файл SQLite")
	input := flags.String("input", "", "Приватный JSON-файл с правами 0600")
	kind := flags.String("kind", "", "project|profile|channel|user|audit or get resource")
	actor := flags.String("actor", "", "Обязательный идентификатор исполнителя для записей аудита изменений")
	project := flags.String("project", "", "ID проекта")
	profile := flags.String("profile", "", "ID профиля")
	userID := flags.String("user", "", "ID пользователя")
	release := flags.String("release", "", "ID выпуска")
	channel := flags.String("channel", "", "ID канала")
	version := flags.String("version", "", "Версия выпуска")
	expected := flags.Int64("expected-revision", 0, "Ожидаемая ревизия текущей версии канала")
	rootHex := flags.String("trusted-root", "", "Настроенный оператором доверенный публичный ключ Ed25519 в hex")
	timeout := flags.Duration("timeout", 20*time.Second, "Предельное время выполнения операции")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if *db == "" || *timeout <= 0 || flags.NArg() != 0 || (action != "core-get" && strings.TrimSpace(*actor) == "") {
		fmt.Fprintln(os.Stderr, "Требуются --db, допустимый --timeout и --actor (для изменения данных)")
		return 2
	}
	if _, err := os.Stat(*db); err != nil {
		fmt.Fprintln(os.Stderr, "run core-init first:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	repo, err := sqlitecore.OpenExisting(ctx, sqlitedurable.Options{Path: *db})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer repo.Close()
	var output any
	switch action {
	case "core-put":
		switch *kind {
		case "project":
			var v model.Project
			err = readPrivateJSON(*input, &v)
			if err == nil {
				output, err = repo.SaveProject(ctx, v, *actor)
			}
		case "profile":
			var v model.Profile
			err = readPrivateJSON(*input, &v)
			if err == nil {
				output, err = repo.SaveProfile(ctx, v, *actor)
			}
		case "channel":
			var v model.ReleaseChannel
			err = readPrivateJSON(*input, &v)
			if err == nil {
				output, err = repo.SaveChannel(ctx, v, *actor)
			}
		case "user":
			// Явный passwordHash читается только из закрытого JSON-файла. Его отсутствие
			// сохраняет текущие учётные данные; роль и статус нужно передать явно во
			// избежание неявной повторной активации.
			var v struct {
				model.User
				PasswordHash *string `json:"passwordHash"`
			}
			err = readPrivateJSON(*input, &v)
			if err == nil && (v.RoleID == "" || v.Status == "") {
				err = errors.New("Для JSON пользователя требуется идентификатор роли и статус")
			}
			if err == nil && v.ID != "" {
				var old model.User
				old, readErr := repo.GetUser(ctx, v.ID)
				if readErr == nil {
					if v.PasswordHash == nil {
						v.User.PasswordHash = old.PasswordHash
						v.User.PasswordUpdatedAt = old.PasswordUpdatedAt
					}
					if v.LastLoginAt.IsZero() {
						v.User.LastLoginAt = old.LastLoginAt
					}
				} else if !errors.Is(readErr, sqlitecore.ErrNotFound) {
					err = readErr
				}
			}
			if err == nil && v.PasswordHash != nil {
				v.User.PasswordHash = *v.PasswordHash
			}
			if err == nil {
				output, err = repo.SaveUser(ctx, v.User, *actor)
			}
		case "audit":
			var v model.AuditEvent
			err = readPrivateJSON(*input, &v)
			if err == nil {
				v.Actor = *actor
				err = repo.RecordAudit(ctx, v)
				output = map[string]string{"status": "recorded"}
			}
		default:
			err = errors.New("Не поддерживается: «--kind for core-put»")
		}
	case "core-draft":
		output, err = repo.CreateDraft(ctx, *project, *profile, *channel, *version, *actor)
	case "core-update-manifest":
		var v model.Manifest
		err = readPrivateJSON(*input, &v)
		if err == nil {
			output, err = repo.UpdateDraftManifest(ctx, *project, *release, v, *actor)
		}
	case "core-publish":
		var key []byte
		key, err = hex.DecodeString(strings.TrimSpace(*rootHex))
		if err == nil && len(key) != ed25519.PublicKeySize {
			err = errors.New("--trusted-root должен содержать публичный ключ Ed25519 длиной 32 байта в шестнадцатеричном формате")
		}
		if err == nil {
			output, err = repo.PublishDraft(ctx, *project, *release, *expected, []ed25519.PublicKey{ed25519.PublicKey(key)}, *actor)
		}
	case "core-get":
		switch *kind {
		case "projects":
			output, err = repo.ListProjects(ctx)
		case "project":
			output, err = repo.GetProject(ctx, *project)
		case "profiles":
			output, err = repo.ListProfiles(ctx, *project)
		case "profile":
			output, err = repo.GetProfile(ctx, *project, *profile)
		case "revisions":
			output, err = repo.ListProfileRevisions(ctx, *project, *profile)
		case "channels":
			output, err = repo.ListChannels(ctx, *project)
		case "releases":
			output, err = repo.ListReleases(ctx, *project)
		case "release":
			output, err = repo.GetRelease(ctx, *project, *release)
		case "users":
			output, err = repo.ListUsers(ctx)
		case "user":
			output, err = repo.GetUser(ctx, *userID)
		case "roles":
			output, err = repo.ListRoles(ctx)
		case "audit":
			output, err = repo.ListAudit(ctx, 500)
		case "counts":
			output, err = repo.Count(ctx)
		default:
			err = errors.New("Не поддерживается: «--kind for core-get»")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Операция ядра SQLite отклонена:", err)
		return 1
	}
	// Хеши паролей пользователей скрыты JSON-тегами model.User.
	if err = json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
