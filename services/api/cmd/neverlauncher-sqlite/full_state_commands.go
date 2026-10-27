package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"gitflic.ru/skif4er/neverlauncher/services/api/internal/model"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitecore"
	"gitflic.ru/skif4er/neverlauncher/services/api/internal/sqlitedurable"
)

func isFullStateAction(a string) bool {
	switch a {
	case "bridge-runtime", "bridge-command-enqueue", "bridge-command-lease", "bridge-command-ack", "bridge-command-get",
		"package-import", "package-verify", "extension-publisher", "extension-revoke", "extension-publish", "extension-install", "extension-install-get", "extension-state-put", "extension-state-get":
		return true
	}
	return false
}
func readPackageFile(path string) ([]byte, error) {
	s, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Size() <= 0 || s.Size() > 16<<20 || s.Mode().Perm()&0077 != 0 {
		return nil, errors.New("package input must be private regular file 1..16 MiB")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, (16<<20)+1))
}
func runFullStateAction(args []string) int {
	action := args[0]
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	db := flags.String("db", "", "existing SQLite database")
	input := flags.String("input", "", "private 0600 JSON parameters")
	pkg := flags.String("package", "", "private 0600 binary package (package-import)")
	timeout := flags.Duration("timeout", 30*time.Second, "operation deadline")
	if e := flags.Parse(args[1:]); e != nil {
		return 2
	}
	if flags.NArg() != 0 || *db == "" || *input == "" || *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "--db and --input 0600 JSON required")
		return 2
	}
	var in struct {
		Actor        string                            `json:"actor"`
		ID           string                            `json:"id"`
		Key          string                            `json:"key"`
		PublicKeyHex string                            `json:"publicKeyHex"`
		Active       bool                              `json:"active"`
		Publisher    string                            `json:"publisher"`
		Scope        string                            `json:"scope"`
		ScopeID      string                            `json:"scopeId"`
		Version      string                            `json:"version"`
		Digest       string                            `json:"digest"`
		Expected     int64                             `json:"expected"`
		TTLSeconds   int                               `json:"ttlSeconds"`
		Worker       string                            `json:"worker"`
		After        int64                             `json:"after"`
		Epoch        int64                             `json:"epoch"`
		Sequence     int64                             `json:"sequence"`
		Token        string                            `json:"token"`
		RuntimeID    string                            `json:"runtimeId"`
		Status       string                            `json:"status"`
		Error        string                            `json:"error"`
		Result       map[string]string                 `json:"result"`
		Command      model.ServerBridgeControlCommand  `json:"command"`
		Proof        sqlitecore.NodeProof              `json:"proof"`
		Heartbeat    sqlitecore.BridgeRuntimeHeartbeat `json:"heartbeat"`
		Package      sqlitecore.ExtensionPackage       `json:"extensionPackage"`
		Install      sqlitecore.SQLiteExtensionInstall `json:"install"`
		State        sqlitecore.SQLiteExtensionState   `json:"state"`
	}
	if e := readPrivateJSON(*input, &in); e != nil {
		fmt.Fprintln(os.Stderr, e)
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
	case "bridge-runtime":
		e = repo.HeartbeatBridgeRuntime(ctx, in.Heartbeat)
		output = map[string]bool{"committed": e == nil}
	case "bridge-command-enqueue":
		var cmd model.ServerBridgeControlCommand
		var created bool
		cmd, created, e = repo.CreateBridgeCommand(ctx, in.Command)
		output = map[string]any{"command": cmd, "created": created}
	case "bridge-command-lease":
		var leased model.ServerBridgeControlCommand
		leased, e = repo.LeaseBridgeCommand(ctx, in.Proof, in.RuntimeID, in.Epoch, in.Worker, in.After, time.Duration(in.TTLSeconds)*time.Second)
		output = map[string]any{"command": leased, "leaseToken": leased.LeaseToken}
	case "bridge-command-get":
		output, e = repo.GetBridgeCommand(ctx, in.ID)
	case "bridge-command-ack":
		output, e = repo.CompleteBridgeCommand(ctx, in.Proof, in.ID, in.RuntimeID, in.Worker, in.Token, in.Epoch, in.Sequence, in.Status, in.Result, in.Error)
	case "package-import":
		var payload []byte
		payload, e = readPackageFile(*pkg)
		if e == nil {
			var created bool
			var entry sqlitecore.StoredPackage
			entry, created, e = repo.PutPackage(ctx, payload, in.Actor)
			output = map[string]any{"package": entry, "created": created}
		}
	case "package-verify":
		var data []byte
		data, e = repo.ReadPackage(ctx, in.Digest)
		if e == nil {
			output = map[string]any{"digest": in.Digest, "bytes": len(data), "verified": true}
		}
	case "extension-publisher":
		e = repo.RegisterExtensionPublisher(ctx, in.ID, in.PublicKeyHex, in.Actor)
		output = map[string]bool{"trusted": e == nil}
	case "extension-revoke":
		e = repo.SetExtensionPublisherActive(ctx, in.Publisher, in.Actor, in.Active)
		output = map[string]bool{"committed": e == nil}
	case "extension-publish":
		output, e = repo.PublishExtensionPackage(ctx, in.Package, in.Actor)
	case "extension-install":
		output, e = repo.ApplyExtensionInstall326(ctx, in.Install, in.Expected)
	case "extension-install-get":
		output, e = repo.GetExtensionInstall326(ctx, in.ID, in.Scope, in.ScopeID)
	case "extension-state-put":
		output, e = repo.PutExtensionState326(ctx, in.State, in.Expected, in.Actor)
	case "extension-state-get":
		output, e = repo.GetExtensionState326(ctx, in.ID, in.Scope, in.ScopeID, in.Key)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "sqlite 326 operation rejected:", e)
		return 1
	}
	returnError := json.NewEncoder(os.Stdout).Encode(output)
	if returnError != nil {
		fmt.Fprintln(os.Stderr, returnError)
		return 1
	}
	return 0
}
