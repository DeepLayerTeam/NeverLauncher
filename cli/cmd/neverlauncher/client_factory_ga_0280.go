package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// The GA gate is deliberately separate from build/verify/export. A successful
// materialization or a fixture certificate must never imply a public release.
const factoryGASchema0280 = "neverlauncher.factory.ga-join-attestation.v1"

var factoryCommit0280 = regexp.MustCompile(`^[0-9a-f]{40}$`)

type factoryJoinEvidence0280 struct {
	Status               string `json:"status"`
	MinecraftVersion     string `json:"minecraftVersion"`
	ClientVersion        string `json:"clientVersion"`
	ServerVersion        string `json:"serverVersion"`
	ServerHost           string `json:"serverHost"`
	ClientJoinedServer   bool   `json:"clientJoinedServer"`
	ServerVersionMatched bool   `json:"serverVersionMatched"`
	ActualClient         bool   `json:"actualClient"`
	ServerProcessAlive   bool   `json:"serverProcessAlive"`
}
type factoryJoinAttestation0280 struct {
	Schema         string `json:"schema"`
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	EvidenceSHA256 string `json:"evidenceSha256"`
	CreatedAt      string `json:"createdAt"`
	PublicKey      string `json:"publicKey"`
	Signature      string `json:"signature"`
}
type factoryGAReport0280 struct {
	Schema             string `json:"schema"`
	Status             string `json:"status"`
	Version            string `json:"version"`
	Commit             string `json:"commit"`
	CertifiedTargets   int    `json:"certifiedTargets"`
	CertifiedFamilies  int    `json:"certifiedFamilies"`
	ServerJoinVersion  string `json:"serverJoinVersion"`
	JoinEvidenceSHA256 string `json:"joinEvidenceSha256"`
}

func factoryJoinMessage0280(a factoryJoinAttestation0280) ([]byte, error) {
	a.Signature = ""
	return json.Marshal(a)
}
func factoryReadJoinEvidence0280(path string) (factoryJoinEvidence0280, string, error) {
	var e factoryJoinEvidence0280
	b, err := os.ReadFile(path)
	if err != nil {
		return e, "", err
	}
	if len(b) > 2<<20 {
		return e, "", errors.New("server join evidence exceeds 2 MiB")
	}
	if err = json.Unmarshal(b, &e); err != nil {
		return e, "", err
	}
	if e.Status != "passed" || !e.ClientJoinedServer || !e.ActualClient || !e.ServerProcessAlive || !e.ServerVersionMatched || e.MinecraftVersion == "" || e.MinecraftVersion != e.ClientVersion || e.MinecraftVersion != e.ServerVersion || e.ServerHost != "127.0.0.1" {
		return e, "", errors.New("matching-server evidence does not prove a real exact-version client join")
	}
	sum := sha256.Sum256(b)
	return e, hex.EncodeToString(sum[:]), nil
}
func factorySignJoin0280(evidence, privatePath, ver, commit, out string) (factoryJoinAttestation0280, error) {
	var a factoryJoinAttestation0280
	if ver != "0.28.0" || !factoryCommit0280.MatchString(commit) || out == "" || out == "-" {
		return a, errors.New("GA join signing requires release 0.28.0, exact 40-character commit and output file")
	}
	_, sha, err := factoryReadJoinEvidence0280(evidence)
	if err != nil {
		return a, err
	}
	key, err := certPrivateKey02712(privatePath)
	if err != nil {
		return a, err
	}
	a = factoryJoinAttestation0280{Schema: factoryGASchema0280, Version: ver, Commit: commit, EvidenceSHA256: sha, CreatedAt: time.Now().UTC().Format(time.RFC3339), PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	msg, err := factoryJoinMessage0280(a)
	if err != nil {
		return a, err
	}
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg))
	if err = writeOrPrintJSON(out, a); err != nil {
		return a, err
	}
	return a, nil
}
func factoryVerifyJoin0280(evidence, attestation, publicKey, ver, commit string) (factoryJoinEvidence0280, string, error) {
	var a factoryJoinAttestation0280
	e, sha, err := factoryReadJoinEvidence0280(evidence)
	if err != nil {
		return e, "", err
	}
	b, err := os.ReadFile(attestation)
	if err != nil {
		return e, "", err
	}
	if len(b) > 1<<20 {
		return e, "", errors.New("server join attestation exceeds 1 MiB")
	}
	if err = json.Unmarshal(b, &a); err != nil {
		return e, "", err
	}
	if a.Schema != factoryGASchema0280 || a.Version != ver || a.Commit != commit || !factoryCommit0280.MatchString(a.Commit) || a.EvidenceSHA256 != sha {
		return e, "", errors.New("server join attestation does not match exact release, commit or evidence")
	}
	issued, err := time.Parse(time.RFC3339, a.CreatedAt)
	if err != nil || issued.After(time.Now().Add(5*time.Minute)) || time.Since(issued) > 30*24*time.Hour {
		return e, "", errors.New("server join attestation expired or has invalid timestamp")
	}
	pub, err := certReadPublic02712(publicKey)
	if err != nil {
		return e, "", err
	}
	if a.PublicKey != base64.StdEncoding.EncodeToString(pub) {
		return e, "", errors.New("untrusted server join signing key")
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return e, "", err
	}
	msg, err := factoryJoinMessage0280(a)
	if err != nil {
		return e, "", err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return e, "", errors.New("invalid server join signature")
	}
	return e, sha, nil
}
func factoryVerifyGA0280(matrix, clientPub, joinEvidence, joinAttestation, joinPub, ver, commit string) (factoryGAReport0280, error) {
	report := factoryGAReport0280{Schema: "neverlauncher.factory.ga-report.v1", Status: "blocked", Version: ver, Commit: commit}
	if ver != "0.28.0" || !factoryCommit0280.MatchString(commit) {
		return report, errors.New("GA requires exact v0.28.0 and commit SHA")
	}
	if clientPub != "" && joinPub != "" {
		runtimeKey, runtimeErr := certReadPublic02712(clientPub)
		joinKey, joinErr := certReadPublic02712(joinPub)
		if runtimeErr != nil {
			return report, runtimeErr
		}
		if joinErr != nil {
			return report, joinErr
		}
		if string(runtimeKey) == string(joinKey) {
			return report, errors.New("GA requires an independent server-join trust root")
		}
	}
	if matrix == "" || clientPub == "" || joinEvidence == "" || joinAttestation == "" || joinPub == "" {
		return report, errors.New("GA requires independent runtime matrix and signed matching-server join evidence")
	}
	certs, err := certifyMatrix02712(matrix, clientPub, "", true)
	if err != nil {
		return report, fmt.Errorf("runtime matrix: %w", err)
	}
	// A single family fixture cannot satisfy the GA matrix. Enforce an actual
	// certificate for all five families and all requested targets.
	if certs.Total < 5 || certs.Failed != 0 {
		return report, errors.New("incomplete client runtime certification")
	}
	join, sha, err := factoryVerifyJoin0280(joinEvidence, joinAttestation, joinPub, ver, commit)
	if err != nil {
		return report, fmt.Errorf("matching-server join: %w", err)
	}
	report.Status = "passed"
	report.CertifiedTargets = certs.Passed
	report.CertifiedFamilies = 5
	report.ServerJoinVersion = join.MinecraftVersion
	report.JoinEvidenceSHA256 = sha
	return report, nil
}
func handleFactoryGA0280(args []string) error {
	if len(args) == 0 {
		return errors.New("require certify-ga|ga-sign-join")
	}
	t := args[1:]
	switch args[0] {
	case "ga-sign-join":
		_, err := factorySignJoin0280(flagValue(t, "--join-evidence", ""), flagValue(t, "--private-key", ""), flagValue(t, "--version", ""), strings.ToLower(flagValue(t, "--commit", "")), flagValue(t, "--output", ""))
		return err
	case "certify-ga":
		report, err := factoryVerifyGA0280(flagValue(t, "--matrix", ""), flagValue(t, "--runtime-public-key", ""), flagValue(t, "--join-evidence", ""), flagValue(t, "--join-attestation", ""), flagValue(t, "--join-public-key", ""), flagValue(t, "--version", ""), strings.ToLower(flagValue(t, "--commit", "")))
		if err != nil {
			return err
		}
		return writeOrPrintJSON(flagValue(t, "--output", "-"), report)
	default:
		return fmt.Errorf("unknown Client Factory GA command %q", args[0])
	}
}
