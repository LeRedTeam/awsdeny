package internal

import "strings"

// ExtractAccountFromARN extracts the account ID from an ARN.
func ExtractAccountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// ExtractRegionFromARN extracts the region from an ARN.
func ExtractRegionFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}
