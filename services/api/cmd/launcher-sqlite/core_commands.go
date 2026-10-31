package main

// OS-local SQLite core maintenance. These commands execute real transactional
// repository operations, not a mock HTTP backend. The DB owner-lock, private
// directory and private JSON input are required; no unauthenticated listener.

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
		return errors.New("--input required")
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
		return errors.New("input must be private regular file (mode 0600; max 1 MiB)")
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
		return errors.New("JSON input contains trailing data")
	}
	return nil
}

func runCoreAction(args []string) int {
	action := args[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	db := flags.String("db", "", "private local SQLite file")
	input := flags.String("input", "", "private JSON file; mode 0600")
	kind := flags.String("kind", "", "project|profile|channel|user|audit or get resource")
	actor := flags.String("actor", "", "required audit actor for mutations")
	project := flags.String("project", "", "project ID")
	profile := flags.String("profile", "", "profile ID")
	userID := flags.String("user", "", "user ID")
	release := flags.String("release", "", "release ID")
	channel := flags.String("channel", "", "channel ID")
	version := flags.String("version", "", "release version")
	expected := flags.Int64("expected-revision", 0, "expected channel head revision")
	rootHex := flags.String("trusted-root", "", "operator-configured Ed25519 trusted public key hex")
	timeout := flags.Duration("timeout", 20*time.Second, "operation deadline")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if *db == "" || *timeout <= 0 || flags.NArg() != 0 || (action != "core-get" && strings.TrimSpace(*actor) == "") {
		fmt.Fprintln(os.Stderr, "--db, valid --timeout and --actor (for mutation) required")
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
			// Explicit passwordHash is read only from a private JSON file.
			// Missing passwordHash preserves existing credentials; role/status
			// must be explicitly supplied to avoid implicit re-enablement.
			var v struct {
				model.User
				PasswordHash *string `json:"passwordHash"`
			}
			err = readPrivateJSON(*input, &v)
			if err == nil && (v.RoleID == "" || v.Status == "") {
				err = errors.New("user JSON requires roleId and status")
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
			err = errors.New("unsupported --kind for core-put")
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
			err = errors.New("--trusted-root must be 32-byte hex Ed25519 public key")
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
			err = errors.New("unsupported --kind for core-get")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "SQLite core operation refused:", err)
		return 1
	}
	// User password hashes are hidden by model.User's JSON tags.
	if err = json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
