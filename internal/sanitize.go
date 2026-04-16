package internal

import "regexp"

var (
	// Matches AWS access key IDs (always start with AKIA)
	reAccessKeyID = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

	// Matches AWS temporary session tokens (long base64 strings in credential-like contexts)
	reSessionToken = regexp.MustCompile(`(?i)(?:session.?token|security.?token)\s*[=:]\s*[A-Za-z0-9/+=]{50,}`)
)

// Sanitize replaces potential credentials in a string with [REDACTED].
func Sanitize(s string) string {
	s = reAccessKeyID.ReplaceAllString(s, "[REDACTED]")
	s = reSessionToken.ReplaceAllString(s, "[REDACTED]")
	return s
}
