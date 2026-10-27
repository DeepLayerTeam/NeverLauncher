package main

// Private local operational CLI for the functional DEP01 SQLite auth engine.
// This is not an unauthenticated HTTP API; it requires OS access to the
// database owner's private directory, 0600 input and independent MFA key.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/localpassword"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

func isAuthAction(action string) bool {
	switch action {
	case "auth-hash-password", "auth-login", "auth-rotate", "auth-check", "auth-revoke", "auth-revoke-all", "auth-mfa-start", "auth-mfa-confirm", "auth-mfa-disable", "auth-mfa-recovery-count", "auth-minecraft-bind", "auth-minecraft-issue", "auth-minecraft-check":
		return true
	}
	return false
}
func readAuthKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("--key-file required (32 raw bytes or 64 hex characters, mode 0600)")
	}
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128 {
		return nil, errors.New("MFA key must be private regular file (0600; <=128 bytes)")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(raw) == 32 {
		return raw, nil
	}
	key, e := hex.DecodeString(strings.TrimSpace(string(raw)))
	if e != nil || len(key) != 32 {
		return nil, errors.New("MFA key must contain exactly 32 bytes or 64 hex characters")
	}
	return key, nil
}
func runAuthAction(args []string) int {
	action := args[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	db := flags.String("db", "", "existing 0.32.3 SQLite database")
	keyPath := flags.String("key-file", "", "private 32-byte AES-GCM MFA key file")
	input := flags.String("input", "", "0600 JSON input containing secrets")
	timeout := flags.Duration("timeout", 20*time.Second, "operation deadline")
	if e := flags.Parse(args[1:]); e != nil {
		return 2
	}
	if *timeout <= 0 || flags.NArg() != 0 {
		return 2
	}
	// Offline password hashing needs no storage or MFA key and never accepts
	// password material from argv, process list or environment variables.
	if action == "auth-hash-password" {
		var v struct {
			Password string `json:"password"`
		}
		e := readPrivateJSON(*input, &v)
		if e == nil && v.Password != "" {
			var hash string
			hash, e = localpassword.Hash(v.Password)
			if e == nil {
				e = json.NewEncoder(os.Stdout).Encode(map[string]string{"passwordHash": hash})
			}
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		return 0
	}
	if *db == "" {
		fmt.Fprintln(os.Stderr, "--db required")
		return 2
	}
	if _, e := os.Stat(*db); e != nil {
		fmt.Fprintln(os.Stderr, "auth requires existing SQLite DB", e)
		return 1
	}
	key, e := readAuthKey(*keyPath)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	repo, e := sqlitecore.Open(ctx, sqlitedurable.Options{Path: *db})
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	defer repo.Close()
	auth, e := repo.Auth(key)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	var output any
	switch action {
	case "auth-login":
		var v struct{ Email, Password, Factor, Device string }
		e = readPrivateJSON(*input, &v)
		if e == nil {
			output, e = auth.LoginLocal(ctx, v.Email, v.Password, v.Factor, v.Device)
		}
	case "auth-rotate":
		var v struct {
			RefreshToken string `json:"refreshToken"`
		}
		e = readPrivateJSON(*input, &v)
		if e == nil {
			output, e = auth.RotateRefresh(ctx, v.RefreshToken)
		}
	case "auth-check":
		var v struct {
			AccessToken string `json:"accessToken"`
		}
		e = readPrivateJSON(*input, &v)
		if e == nil {
			output, e = auth.ValidateAccess(ctx, v.AccessToken)
		}
	case "auth-revoke":
		var v struct{ UserID, SessionID, Reason string }
		e = readPrivateJSON(*input, &v)
		if e == nil {
			e = auth.RevokeSession(ctx, v.UserID, v.SessionID, v.Reason)
			output = map[string]string{"status": "revoked"}
		}
	case "auth-revoke-all":
		var v struct{ UserID, Reason string }
		e = readPrivateJSON(*input, &v)
		if e == nil {
			output, e = auth.RevokeUserSessions(ctx, v.UserID, v.Reason)
		}
	case "auth-mfa-start":
		var v struct{ UserID, Password string }
		e = readPrivateJSON(*input, &v)
		if e == nil {
			var secret string
			secret, e = auth.StartTOTP(ctx, v.UserID, v.Password)
			output = map[string]string{"totpSecret": secret}
		}
	case "auth-mfa-confirm":
		var v struct{ UserID, Password, Code string }
		e = readPrivateJSON(*input, &v)
		if e == nil {
			output, e = auth.ConfirmTOTP(ctx, v.UserID, v.Password, v.Code)
		}
	case "auth-mfa-disable":
		var v struct{ UserID, Password, Factor string }
		e = readPrivateJSON(*input, &v)
		if e == nil {
			e = auth.DisableTOTP(ctx, v.UserID, v.Password, v.Factor)
			output = map[string]string{"status": "disabled"}
		}
	case "auth-mfa-recovery-count":
		var v struct{ UserID string }
		e = readPrivateJSON(*input, &v)
		if e == nil {
			output, e = auth.RecoveryRemaining(ctx, v.UserID)
		}
	case "auth-minecraft-bind":
		var v struct {
			Identity model.MinecraftProfile `json:"identity"`
			Actor    string                 `json:"actor"`
		}
		e = readPrivateJSON(*input, &v)
		if e == nil {
			output, e = auth.SaveMinecraftIdentity(ctx, v.Identity, v.Actor)
		}
	case "auth-minecraft-issue":
		var v struct {
			AccessToken string `json:"accessToken"`
			Seconds     int64  `json:"seconds"`
		}
		e = readPrivateJSON(*input, &v)
		if e == nil {
			var id, token string
			id, token, e = auth.IssueMinecraftSession(ctx, v.AccessToken, time.Duration(v.Seconds)*time.Second)
			output = map[string]string{"sessionId": id, "accessToken": token}
		}
	case "auth-minecraft-check":
		var v struct {
			AccessToken string `json:"accessToken"`
		}
		e = readPrivateJSON(*input, &v)
		if e == nil {
			output, e = auth.ValidateMinecraftSession(ctx, v.AccessToken)
		}
	default:
		return 2
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "auth operation rejected:", e)
		return 1
	}
	if e = json.NewEncoder(os.Stdout).Encode(output); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	return 0
}
