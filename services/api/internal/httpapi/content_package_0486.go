package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gitflic.ru/skif4er/launcher/services/api/internal/extensionhost"
)

const maxJavaContentTransform0486 = 24 << 10

var contentExtensionID0486 = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,127}$`)

type preparedJavaContent0486 struct {
	DataBase64      string `json:"dataBase64"`
	SHA256          string `json:"sha256"`
	Size            int    `json:"size"`
	RequiresSigning bool   `json:"requiresSigning"`
	ErrorCode       string `json:"errorCode"`
}

// Verify byte-for-byte output from an UNTRUSTED Java callback before it is
// handed to the existing unsigned package file store. The *core* still does
// integrity validation, Ed25519 signing and separate publication.
func decodeJavaPreparedContent0486(raw json.RawMessage) ([]byte, error) {
	var answer preparedJavaContent0486
	if len(raw) == 0 || len(raw) > 64<<10 || json.Unmarshal(raw, &answer) != nil {
		return nil, errors.New("invalid content provider response")
	}
	if answer.ErrorCode != "" {
		return nil, fmt.Errorf("Java provider rejected package: %s", answer.ErrorCode)
	}
	if !answer.RequiresSigning || answer.Size < 0 || answer.Size > maxJavaContentTransform0486 || len(answer.DataBase64) > (maxJavaContentTransform0486+2)/3*4+8 {
		return nil, errors.New("unsigned content preparation response invalid or too large")
	}
	bytes, err := base64.StdEncoding.DecodeString(answer.DataBase64)
	if err != nil || len(bytes) != answer.Size {
		return nil, errors.New("content provider size/base64 mismatch")
	}
	digest := sha256.Sum256(bytes)
	if !strings.EqualFold(answer.SHA256, hex.EncodeToString(digest[:])) {
		return nil, errors.New("content provider digest mismatch")
	}
	return bytes, nil
}

// Explicit opt-in on the already file:write-authorized package upload route.
// Requires a RUNNING approved project-scoped extension, with live
// release:prepare permission checked by the Go Host before and after RPC.
// There is no fallback to unsigned untransformed bytes on provider failure.
func (s Server) prepareJavaPackageFile0486(ctx context.Context, extensionID, projectID, filename string, raw []byte) ([]byte, error) {
	if s.ExtensionHost == nil {
		return nil, errors.New("Java extension Host unavailable")
	}
	if !contentExtensionID0486.MatchString(extensionID) {
		return nil, errors.New("invalid content extension ID")
	}
	if projectID == "" || filename == "" {
		return nil, errors.New("package project and path required")
	}
	if len(raw) > maxJavaContentTransform0486 {
		return nil, errors.New("Java content transform supports files <=24 KiB; larger files require the core package upload pipeline")
	}
	req, err := json.Marshal(map[string]any{"projectId": projectID, "name": filename, "dataBase64": base64.StdEncoding.EncodeToString(raw)})
	if err != nil {
		return nil, err
	}
	answer, err := s.ExtensionHost.CallJavaRPC0304(ctx, extensionhost.Key{ExtensionID: extensionID, Scope: "project", ScopeID: projectID}, "content.package.prepare", req)
	if err != nil {
		return nil, fmt.Errorf("Java content provider unavailable or unauthorized: %w", err)
	}
	return decodeJavaPreparedContent0486(answer)
}
