package internal

import "regexp"

var (
	reAccessKeyID = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reSecretKey   = regexp.MustCompile(`(?i)(?:secret|password|token|key)\s*[=:]\s*[0-9a-zA-Z/+=]{20,}`)
)

// Sanitize replaces potential credentials in a string with [REDACTED].
func Sanitize(s string) string {
	s = reAccessKeyID.ReplaceAllString(s, "[REDACTED]")
	s = reSecretKey.ReplaceAllString(s, "[REDACTED]")
	return s
}
