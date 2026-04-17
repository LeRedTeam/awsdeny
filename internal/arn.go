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

// PartitionFromRegion infers the AWS partition from the region string.
func PartitionFromRegion(region string) string {
	if strings.HasPrefix(region, "us-gov-") {
		return "aws-us-gov"
	}
	if strings.HasPrefix(region, "cn-") {
		return "aws-cn"
	}
	return "aws"
}
