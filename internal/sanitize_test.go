package internal

import (
	"strings"
	"testing"
)

func TestSanitize_AccessKeyID(t *testing.T) {
	input := "User with key AKIAIOSFODNN7EXAMPLE failed"
	result := Sanitize(input)
	if strings.Contains(result, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("access key ID should be redacted")
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Error("should contain [REDACTED]")
	}
}

func TestSanitize_SessionToken(t *testing.T) {
	input := "session_token=FwoGZXIvYXdzEBYaDHqa0AP1Vy1PxGSoSSLIAdTEl5COnfneGmKOxerTyABCDEF1234567890abcdefghij"
	result := Sanitize(input)
	if strings.Contains(result, "FwoGZXIvYXdzEBYaDHqa0AP1Vy1PxGSoSSLIAdTEl5COnfneGmKOxerTyABCDEF1234567890abcdefghij") {
		t.Error("session token should be redacted")
	}
}

func TestSanitize_NoFalsePositiveOnARN(t *testing.T) {
	input := "arn:aws:iam::123456789012:role/MyRole"
	result := Sanitize(input)
	if result != input {
		t.Errorf("ARN should not be redacted, got %q", result)
	}
}

func TestSanitize_NoFalsePositiveOnAction(t *testing.T) {
	input := "s3:GetObject"
	result := Sanitize(input)
	if result != input {
		t.Errorf("action should not be redacted, got %q", result)
	}
}

func TestSanitize_NoFalsePositiveOnKMSKeyID(t *testing.T) {
	input := "key=arn:aws:kms:us-east-1:123:key/abcd-1234-efgh-5678"
	result := Sanitize(input)
	if result != input {
		t.Errorf("KMS key ARN should not be redacted, got %q", result)
	}
}

func TestSanitize_EmptyString(t *testing.T) {
	result := Sanitize("")
	if result != "" {
		t.Errorf("empty string should remain empty, got %q", result)
	}
}

func TestSanitize_MultipleAccessKeys(t *testing.T) {
	input := "AKIAIOSFODNN7EXAMPLE and AKIAI44QH8DHBEXAMPLE"
	result := Sanitize(input)
	if strings.Contains(result, "AKIA") {
		t.Error("all access key IDs should be redacted")
	}
}

func TestSanitize_SecretAccessKey(t *testing.T) {
	input := "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	result := Sanitize(input)
	if strings.Contains(result, "wJalrXUtnFEMI") {
		t.Error("secret access key should be redacted")
	}
}

func TestSanitize_SecretAccessKeyLowercase(t *testing.T) {
	input := "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	result := Sanitize(input)
	if strings.Contains(result, "wJalrXUtnFEMI") {
		t.Error("secret access key (lowercase) should be redacted")
	}
}
