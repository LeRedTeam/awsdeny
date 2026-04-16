package enrich

import "testing"

func TestExtractPolicyID_FullARN(t *testing.T) {
	arn := "arn:aws:organizations::111111111111:policy/o-abc123/service_control_policy/p-xyz789"
	result := extractPolicyID(arn)
	if result != "p-xyz789" {
		t.Errorf("expected p-xyz789, got %q", result)
	}
}

func TestExtractPolicyID_SimpleARN(t *testing.T) {
	arn := "arn:aws:organizations::111:policy/o-xxx/p-yyy"
	result := extractPolicyID(arn)
	if result != "p-yyy" {
		t.Errorf("expected p-yyy, got %q", result)
	}
}

func TestExtractPolicyID_NoPolicyID(t *testing.T) {
	arn := "arn:aws:iam::123:policy/MyPolicy"
	result := extractPolicyID(arn)
	if result != "" {
		t.Errorf("expected empty for non-org policy, got %q", result)
	}
}

func TestExtractPolicyID_EmptyString(t *testing.T) {
	result := extractPolicyID("")
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestExtractPolicyID_MidPathPolicyID(t *testing.T) {
	// p-xxx in the middle of the path
	arn := "arn:aws:organizations::111:policy/p-abc/extra"
	result := extractPolicyID(arn)
	if result != "p-abc" {
		t.Errorf("expected p-abc, got %q", result)
	}
}
