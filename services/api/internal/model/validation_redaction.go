package model

import (
	"regexp"
	"strings"
)

// Secrets are *always* redacted. Account identifiers are redacted by the
// conservative V12 policy (there is no HTTP override). Digests remain intact.
var validationSecrets03412 = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\b(?:authorization\s*:\s*bearer|bearer)\s+)[^\s,"'<>]+`),
	regexp.MustCompile(`(?i)(["'](?:access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|api[_-]?key|session[_-]?id|credentials|authorization|account[_-]?id|player[_-]?name|username|uuid|xuid)["']\s*:\s*["'])[^"']+`),
	regexp.MustCompile(`(?i)(\b(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|api[_-]?key|session[_-]?id|credentials|authorization|account[_-]?id|player[_-]?name|username|uuid|xuid)\b\s*[=:]\s*["']?)[^\s,;"'&<>]+`),
	regexp.MustCompile(`(?i)(--(?:accessToken|clientToken|refreshToken|password|username|uuid|session|authorization)\s+)[^\s,"'<>]+`),
	regexp.MustCompile(`(?i)(-D[^\s=]*(?:token|password|secret|key|session)[^\s=]*=)[^\s,"'<>]+`),
	regexp.MustCompile(`(?i)([?&](?:access_token|refresh_token|token|code|password|secret|session)=)[^\s&"'<>]+`),
}
var validationIdentifiers03412 = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`),
	regexp.MustCompile(`(?i)\b[0-9a-f]{32}\b`),
	regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`),
}

func RedactValidationDetail03412(detail string) string {
	// Bound the input *before* processing and never log the unredacted content.
	if len(detail) > 4096 {
		detail = detail[:4096]
	}
	detail = strings.ToValidUTF8(detail, "[invalid-utf8]")
	for _, re := range validationSecrets03412 {
		detail = re.ReplaceAllString(detail, "${1}[REDACTED]")
	}
	for _, re := range validationIdentifiers03412 {
		detail = re.ReplaceAllString(detail, "[IDENTIFIER]")
	}
	if len(detail) > 2048 {
		detail = detail[:2048]
	}
	return detail
}
