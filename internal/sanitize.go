package internal

import "regexp"

var (
	// Matches AWS access key IDs: AKIA (long-term) and ASIA (temporary/STS)
	reAccessKeyID = regexp.MustCompile(`A[KS]IA[0-9A-Z]{16}`)

	// Matches AWS secret access keys in key=value context
	reSecretAccessKey = regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`)

	// Matches AWS temporary session tokens (long base64 strings in credential-like contexts)
	reSessionToken = regexp.MustCompile(`(?i)(?:session.?token|security.?token)\s*[=:]\s*[A-Za-z0-9/+=]{50,}`)
)

// Sanitize replaces potential credentials in a string with [REDACTED].
func Sanitize(s string) string {
	s = reAccessKeyID.ReplaceAllString(s, "[REDACTED]")
	s = reSecretAccessKey.ReplaceAllString(s, "[REDACTED]")
	s = reSessionToken.ReplaceAllString(s, "[REDACTED]")
	return s
}
