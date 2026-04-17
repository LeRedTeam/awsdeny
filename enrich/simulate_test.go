package enrich

import "testing"

func TestNormalizeToIAMArn_AssumedRole(t *testing.T) {
	input := "arn:aws:sts::123456789012:assumed-role/MyRole/session-name"
	expected := "arn:aws:iam::123456789012:role/MyRole"
	result := normalizeToIAMArn(input)
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestNormalizeToIAMArn_AssumedRoleWithEmail(t *testing.T) {
	input := "arn:aws:sts::123456789012:assumed-role/MySSO_Role_abc123/user@example.com"
	expected := "arn:aws:iam::123456789012:role/MySSO_Role_abc123"
	result := normalizeToIAMArn(input)
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestNormalizeToIAMArn_IAMRole(t *testing.T) {
	input := "arn:aws:iam::123456789012:role/MyRole"
	result := normalizeToIAMArn(input)
	if result != input {
		t.Errorf("IAM role ARN should pass through unchanged, got %q", result)
	}
}

func TestNormalizeToIAMArn_IAMUser(t *testing.T) {
	input := "arn:aws:iam::123456789012:user/dev"
	result := normalizeToIAMArn(input)
	if result != input {
		t.Errorf("IAM user ARN should pass through unchanged, got %q", result)
	}
}

func TestNormalizeToIAMArn_GovCloud(t *testing.T) {
	input := "arn:aws-us-gov:sts::123456789012:assumed-role/GovRole/session"
	expected := "arn:aws-us-gov:iam::123456789012:role/GovRole"
	result := normalizeToIAMArn(input)
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestNormalizeToIAMArn_ShortARN(t *testing.T) {
	input := "arn:aws:sts"
	result := normalizeToIAMArn(input)
	if result != input {
		t.Errorf("short ARN should pass through unchanged, got %q", result)
	}
}

func TestNormalizeToIAMArn_EmptyString(t *testing.T) {
	result := normalizeToIAMArn("")
	if result != "" {
		t.Errorf("empty string should return empty, got %q", result)
	}
}
