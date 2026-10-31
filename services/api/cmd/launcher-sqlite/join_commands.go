package main

// 0.32.4 operational CLI: durable one-time join tickets and signed node nonces.
// Credentials must enter via private JSON files; never command-line arguments.
import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/launcher/services/api/internal/sqlitedurable"
)

func isJoinAction(v string) bool {
	switch v {
	case "join-keygen", "join-sign", "join-node", "join-disable", "join-issue", "join-redeem", "join-ping", "join-status", "join-prune":
		return true
	}
	return false
}
func readNodeKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("--key-file required")
	}
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != ed25519.PrivateKeySize {
		return nil, errors.New("node key must be 0600 and exactly 64 raw bytes")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(raw) != 64 || !ed25519.PrivateKey(raw).Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(raw[32:])) {
		return nil, errors.New("invalid Ed25519 key")
	}
	return ed25519.PrivateKey(raw), nil
}
func runJoinAction(args []string) int {
	action := args[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	db := flags.String("db", "", "existing SQLite core DB")
	input := flags.String("input", "", "0600 JSON file (credentials never in argv)")
	keyFile := flags.String("key-file", "", "private Ed25519 node key, or 32-byte MFA key for join-issue")
	timeout := flags.Duration("timeout", 20*time.Second, "deadline")
	if e := flags.Parse(args[1:]); e != nil {
		return 2
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		return 2
	}
	if action == "join-keygen" {
		if *keyFile == "" {
			fmt.Fprintln(os.Stderr, "--key-file required")
			return 2
		}
		dir := filepath.Dir(*keyFile)
		info, e := os.Lstat(dir)
		if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			fmt.Fprintln(os.Stderr, "key directory must be private 0700")
			return 1
		}
		pub, private, e := ed25519.GenerateKey(rand.Reader)
		if e == nil {
			var f *os.File
			f, e = os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e == nil {
				_, e = f.Write(private)
				e = errors.Join(e, f.Sync(), f.Close())
			}
			if e == nil {
				var d *os.File
				d, e = os.Open(dir)
				if e == nil {
					e = errors.Join(d.Sync(), d.Close())
				}
			}
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		h := sha256.Sum256(pub)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"publicKeyHex": hex.EncodeToString(pub), "fingerprint": hex.EncodeToString(h[:])})
		return 0
	}
	if action == "join-sign" {
		var v struct {
			NodeID        string `json:"nodeId"`
			IdentityEpoch int64  `json:"identityEpoch"`
			Action        string `json:"action"`
			Ticket        string `json:"ticket"`
			Data          string `json:"data"`
		}
		e := readPrivateJSON(*input, &v)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		key, e := readNodeKey(*keyFile)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		var hash string
		if v.Action == "redeem" {
			if len(v.Ticket) != 47 || v.Ticket[:4] != "nlj_" {
				fmt.Fprintln(os.Stderr, "invalid join ticket")
				return 1
			}
			hash = sqlitecore.SignedPayloadHash([]byte(v.Ticket))
		} else if v.Action == "ping" {
			hash = sqlitecore.SignedPayloadHash([]byte(v.Data))
		} else {
			fmt.Fprintln(os.Stderr, "unsupported action")
			return 2
		}
		nonce := make([]byte, 24)
		if _, e = rand.Read(nonce); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
		proof := sqlitecore.NodeProof{NodeID: v.NodeID, IdentityEpoch: v.IdentityEpoch, Timestamp: time.Now().UTC().Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonce)}
		proof.Signature = hex.EncodeToString(ed25519.Sign(key, []byte(sqlitecore.CanonicalNodeRequest(v.Action, proof, hash))))
		if e = json.NewEncoder(os.Stdout).Encode(proof); e != nil {
			return 1
		}
		return 0
	}
	if *db == "" {
		fmt.Fprintln(os.Stderr, "--db required")
		return 2
	}
	if _, e := os.Stat(*db); e != nil {
		fmt.Fprintln(os.Stderr, "existing database required:", e)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	repo, e := sqlitecore.OpenExisting(ctx, sqlitedurable.Options{Path: *db})
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	defer repo.Close()
	var output any
	switch action {
	case "join-node":
		var v sqlitecore.NodeRegistration
		e = readPrivateJSON(*input, &v)
		if e == nil {
			output, e = repo.RegisterNode(ctx, v)
		}
	case "join-disable":
		var v struct {
			NodeID string `json:"nodeId"`
			Actor  string `json:"actor"`
		}
		e = readPrivateJSON(*input, &v)
		if e == nil {
			e = repo.DisableNode(ctx, v.NodeID, v.Actor)
			output = map[string]any{"disabled": e == nil}
		}
	case "join-issue":
		var v struct {
			AccessToken    string `json:"accessToken"`
			MinecraftToken string `json:"minecraftToken"`
			NodeID         string `json:"nodeId"`
		}
		e = readPrivateJSON(*input, &v)
		if e == nil {
			var key []byte
			key, e = readAuthKey(*keyFile)
			if e == nil {
				var auth *sqlitecore.Auth
				auth, e = repo.Auth(key)
				if e == nil {
					output, e = auth.IssueJoinTicket(ctx, v.AccessToken, v.MinecraftToken, v.NodeID)
				}
			}
			for i := range key {
				key[i] = 0
			}
		}
	case "join-redeem":
		var v struct {
			Ticket   string               `json:"ticket"`
			Proof    sqlitecore.NodeProof `json:"proof"`
			RemoteIP string               `json:"remoteIp"`
		}
		e = readPrivateJSON(*input, &v)
		if e == nil {
			output, e = repo.RedeemJoinTicket(ctx, v.Ticket, v.Proof, v.RemoteIP)
		}
	case "join-ping":
		var v struct {
			Proof sqlitecore.NodeProof `json:"proof"`
			Data  string               `json:"data"`
		}
		e = readPrivateJSON(*input, &v)
		if e == nil {
			e = repo.ConsumeSignedNonce(ctx, v.Proof, []byte(v.Data))
			output = map[string]bool{"accepted": e == nil}
		}
	case "join-status":
		var v struct {
			Ticket string `json:"ticket"`
		}
		e = readPrivateJSON(*input, &v)
		if e == nil {
			var status string
			status, e = repo.TicketStatus(ctx, v.Ticket)
			output = map[string]string{"status": status}
		}
	case "join-prune":
		output, e = repo.PruneExpiredReplayNonces(ctx)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "SQLite join refused:", e)
		return 1
	}
	if e = json.NewEncoder(os.Stdout).Encode(output); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	return 0
}
