package main

// A native, fail-closed game-session witness for the isolated migration
// rehearsal. Unlike operator-supplied probe scripts this code launches a real
// foreground client process and observes its UUID on a live Java server over
// authenticated loopback RCON. No RCON credentials, client output, or argv are
// sent to the backend. This is an operator-owned staging observation, not a
// remote attestation of the client or proof of Minecraft licensing.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type rehearsalLiveConfig0447 struct {
	ClientPath       string   `json:"clientPath"`
	ClientArgs       []string `json:"clientArgs"`
	PlayerName       string   `json:"playerName"`
	PlayerUUID       string   `json:"playerUuid"`
	RCONAddress      string   `json:"rconAddress"`
	RCONPasswordFile string   `json:"rconPasswordFile"`
	TimeoutSeconds   int      `json:"timeoutSeconds"`
}

type rehearsalLiveWitness0447 struct {
	ClientSHA256 string `json:"clientSha256"`
	PlayerName   string `json:"playerName"`
	PlayerUUID   string `json:"playerUuid"`
	BeforeSHA256 string `json:"beforeSha256"`
	JoinedSHA256 string `json:"joinedSha256"`
	StartedAt    string `json:"startedAt"`
	JoinedAt     string `json:"joinedAt"`
}

var rehearsalPlayerName0447 = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)
var rehearsalUUID0447 = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func rehearsalReadLiveConfig0447(root string) (rehearsalLiveConfig0447, error) {
	var cfg rehearsalLiveConfig0447
	raw, err := rehearsalRead03310(root, "live-session.json", 16<<10)
	if err != nil {
		return cfg, fmt.Errorf("live-session.json required: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return cfg, errors.New("trailing live-session configuration")
	}
	if !rehearsalPlayerName0447.MatchString(cfg.PlayerName) || !rehearsalUUID0447.MatchString(cfg.PlayerUUID) || len(cfg.ClientArgs) > 128 || cfg.TimeoutSeconds < 10 || cfg.TimeoutSeconds > 600 {
		return cfg, errors.New("invalid player, client arguments or timeout")
	}
	if cfg.ClientPath == "" || cfg.RCONPasswordFile == "" {
		return cfg, errors.New("clientPath and rconPasswordFile required")
	}
	for _, s := range cfg.ClientArgs {
		if len(s) > 4096 || strings.ContainsRune(s, 0) {
			return cfg, errors.New("invalid client argument")
		}
	}
	host, port, err := net.SplitHostPort(cfg.RCONAddress)
	if err != nil {
		return cfg, errors.New("invalid RCON address")
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || n <= 0 || n > 65535 {
		return cfg, errors.New("RCON must be on a numeric loopback address and valid port")
	}
	return cfg, nil
}

func rehearsalRCONPacket0447(w io.Writer, id, kind int32, body string) error {
	if len(body) > 4096 {
		return errors.New("RCON request too large")
	}
	raw := make([]byte, 14+len(body))
	binary.LittleEndian.PutUint32(raw[:4], uint32(len(raw)-4))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(id))
	binary.LittleEndian.PutUint32(raw[8:12], uint32(kind))
	copy(raw[12:], body)
	_, err := w.Write(raw)
	return err
}
func rehearsalRCONRead0447(r io.Reader) (int32, int32, string, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return 0, 0, "", err
	}
	n := binary.LittleEndian.Uint32(prefix[:])
	if n < 10 || n > 16384 {
		return 0, 0, "", errors.New("invalid RCON packet length")
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return 0, 0, "", err
	}
	if raw[len(raw)-1] != 0 || raw[len(raw)-2] != 0 {
		return 0, 0, "", errors.New("invalid RCON terminator")
	}
	return int32(binary.LittleEndian.Uint32(raw[:4])), int32(binary.LittleEndian.Uint32(raw[4:8])), string(raw[8 : len(raw)-2]), nil
}

func rehearsalRCONList0447(ctx context.Context, address, password string) (string, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	c, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("staging RCON unavailable: %w", err)
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 4*time.Second {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	}
	if err = rehearsalRCONPacket0447(c, 71, 3, password); err != nil {
		return "", err
	}
	authorized := false
	for i := 0; i < 3; i++ {
		id, kind, _, e := rehearsalRCONRead0447(c)
		if e != nil {
			return "", e
		}
		if id == -1 {
			return "", errors.New("RCON authentication rejected")
		}
		if id == 71 && kind == 2 {
			authorized = true
			break
		}
	}
	if !authorized {
		return "", errors.New("RCON authentication not acknowledged")
	}
	if err = rehearsalRCONPacket0447(c, 72, 2, "list uuids"); err != nil {
		return "", err
	}
	for i := 0; i < 3; i++ {
		id, _, text, e := rehearsalRCONRead0447(c)
		if e != nil {
			return "", e
		}
		if id == 72 {
			return text, nil
		}
	}
	return "", errors.New("RCON list uuids response missing")
}
func rehearsalRCONHasPlayer0447(result, name, uuid string) bool {
	// Java Edition /list uuids prints `PlayerName (uuid)`. Never accept a
	// UUID mentioned elsewhere in a message or another player's record.
	pattern := regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])` + regexp.QuoteMeta(name) + `\s*\(\s*` + regexp.QuoteMeta(uuid) + `\s*\)`)
	return pattern.MatchString(result)
}
func rehearsalHashFile0447(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 512<<20 {
		return "", errors.New("invalid client executable size")
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, (512<<20)+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func rehearsalLaunchLive0447(ctx context.Context, root string, snapshot rehearsalSnapshot03310) (rehearsalLiveWitness0447, func() error, func(), error) {
	var proof rehearsalLiveWitness0447
	noop := func() {}
	noverify := func() error { return errors.New("no live session") }
	cfg, err := rehearsalReadLiveConfig0447(root)
	if err != nil {
		return proof, noverify, noop, err
	}
	mapped := false
	for _, p := range snapshot.Players {
		if p.UUID == cfg.PlayerUUID {
			mapped = true
			break
		}
	}
	if !mapped {
		return proof, noverify, noop, errors.New("live player UUID not in source snapshot")
	}
	executable, err := rehearsalPath03310(root, cfg.ClientPath)
	if err != nil {
		return proof, noverify, noop, err
	}
	st, err := os.Stat(executable)
	if err != nil {
		return proof, noverify, noop, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return proof, noverify, noop, errors.New("client is not an executable regular file")
	}
	hash, err := rehearsalHashFile0447(executable)
	if err != nil {
		return proof, noverify, noop, err
	}
	passwordBytes, err := rehearsalRead03310(root, cfg.RCONPasswordFile, 4096)
	if err != nil {
		return proof, noverify, noop, fmt.Errorf("RCON credential file: %w", err)
	}
	password := strings.TrimRight(string(passwordBytes), "\r\n")
	if password == "" || strings.ContainsAny(password, "\r\n\x00") {
		return proof, noverify, noop, errors.New("invalid staging RCON credential")
	}
	defer func() {
		for i := range passwordBytes {
			passwordBytes[i] = 0
		}
	}()
	preCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	before, err := rehearsalRCONList0447(preCtx, cfg.RCONAddress, password)
	cancel()
	if err != nil {
		return proof, noverify, noop, err
	}
	if rehearsalRCONHasPlayer0447(before, cfg.PlayerName, cfg.PlayerUUID) {
		return proof, noverify, noop, errors.New("player already online before staged client launch")
	}
	clientCtx, stop := context.WithCancel(ctx)
	cmd := exec.CommandContext(clientCtx, executable, cfg.ClientArgs...)
	cmd.Dir = root
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "LANG=C.UTF-8"}
	for _, key := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if v, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+v)
		}
	}
	// Discard all process output. Game logs may contain tokens; they must not be
	// copied into evidence, stdout, the API or a diagnostic archive.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		stop()
		return proof, noverify, noop, fmt.Errorf("client launch failed: %w", err)
	}
	exited := make(chan error, 1)
	finished := make(chan struct{})
	go func() { exited <- cmd.Wait(); close(finished) }()
	verify := func() error {
		select {
		case <-finished:
			return errors.New("staged client process exited before rehearsal finished")
		default:
		}
		queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		answer, err := rehearsalRCONList0447(queryCtx, cfg.RCONAddress, password)
		cancel()
		if err != nil || !rehearsalRCONHasPlayer0447(answer, cfg.PlayerName, cfg.PlayerUUID) {
			return errors.New("staging player left server before rehearsal finished")
		}
		select {
		case <-finished:
			return errors.New("staged client process exited during rehearsal")
		default:
		}
		return nil
	}
	cleanup := func() {
		stop()
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
		}
	}
	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()
	started := time.Now().UTC()
	deadline := time.NewTimer(time.Duration(cfg.TimeoutSeconds) * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(1200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case e := <-exited:
			return proof, noverify, noop, fmt.Errorf("client exited before observed server join: %v", e)
		case <-ctx.Done():
			return proof, noverify, noop, ctx.Err()
		case <-deadline.C:
			return proof, noverify, noop, errors.New("client did not join staging server before deadline")
		case <-tick.C:
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			answer, qerr := rehearsalRCONList0447(qctx, cfg.RCONAddress, password)
			cancel()
			if qerr != nil {
				continue
			}
			if !rehearsalRCONHasPlayer0447(answer, cfg.PlayerName, cfg.PlayerUUID) {
				continue
			}
			// Recheck the *same* live session after a hold interval. No cached logs
			// or successful launcher exit substitute for an active multiplayer join.
			select {
			case e := <-exited:
				return proof, noverify, noop, fmt.Errorf("client exited during join: %v", e)
			case <-ctx.Done():
				return proof, noverify, noop, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			qctx, cancel = context.WithTimeout(ctx, 5*time.Second)
			confirmed, checkErr := rehearsalRCONList0447(qctx, cfg.RCONAddress, password)
			cancel()
			if checkErr != nil || !rehearsalRCONHasPlayer0447(confirmed, cfg.PlayerName, cfg.PlayerUUID) {
				continue
			}
			select {
			case e := <-exited:
				return proof, noverify, noop, fmt.Errorf("client exited during confirmation: %v", e)
			default:
			}
			h1 := sha256.Sum256([]byte(before))
			h2 := sha256.Sum256([]byte(confirmed))
			proof = rehearsalLiveWitness0447{ClientSHA256: hash, PlayerName: cfg.PlayerName, PlayerUUID: cfg.PlayerUUID, BeforeSHA256: hex.EncodeToString(h1[:]), JoinedSHA256: hex.EncodeToString(h2[:]), StartedAt: started.Format(time.RFC3339Nano), JoinedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			success = true
			return proof, verify, cleanup, nil
		}
	}
}
