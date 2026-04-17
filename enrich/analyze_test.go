package enrich

import (
	"testing"
)

func TestParsePolicyDocument(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "DenyS3Public",
				"Effect": "Deny",
				"Action": "s3:*",
				"Resource": "*",
				"Condition": {
					"StringNotEquals": {
						"aws:SourceVpce": ["vpce-abc123"]
					}
				}
			},
			{
				"Effect": "Allow",
				"Action": ["s3:GetObject", "s3:PutObject"],
				"Resource": "arn:aws:s3:::my-bucket/*"
			}
		]
	}`

	stmts, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	// Check first statement
	if stmts[0].Sid != "DenyS3Public" {
		t.Errorf("expected Sid=DenyS3Public, got %q", stmts[0].Sid)
	}
	if stmts[0].Effect != "Deny" {
		t.Errorf("expected Effect=Deny, got %q", stmts[0].Effect)
	}
	if len(stmts[0].Actions) != 1 || stmts[0].Actions[0] != "s3:*" {
		t.Errorf("expected Action=[s3:*], got %v", stmts[0].Actions)
	}
	if stmts[0].Conditions == nil {
		t.Error("expected conditions to be set")
	}

	// Check second statement
	if stmts[1].Effect != "Allow" {
		t.Errorf("expected Effect=Allow, got %q", stmts[1].Effect)
	}
	if len(stmts[1].Actions) != 2 {
		t.Errorf("expected 2 actions, got %d", len(stmts[1].Actions))
	}
}

func TestFindMatchingStatements(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
			{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"},
			{"Effect": "Deny", "Action": "ec2:*", "Resource": "*"}
		]
	}`

	stmts, _ := ParsePolicyDocument(doc)
	matches := FindMatchingStatements(stmts, "s3:GetObject", "arn:aws:s3:::bucket/key")

	if len(matches) != 2 {
		t.Errorf("expected 2 matching statements (Deny s3:* and Allow s3:GetObject), got %d", len(matches))
	}
}

func TestMatchActionPattern(t *testing.T) {
	tests := []struct {
		pattern  string
		action   string
		expected bool
	}{
		{"*", "anything", true},
		{"s3:*", "s3:GetObject", true},
		{"s3:*", "ec2:RunInstances", false},
		{"s3:GetObject", "s3:GetObject", true},
		{"s3:GetObject", "s3:PutObject", false},
		// Actions are case-insensitive
		{"s3:GetObject", "S3:getobject", true},
		{"S3:GETOBJECT", "s3:GetObject", true},
	}

	for _, tt := range tests {
		result := matchActionPattern(tt.pattern, tt.action)
		if result != tt.expected {
			t.Errorf("matchActionPattern(%q, %q) = %v, want %v", tt.pattern, tt.action, result, tt.expected)
		}
	}
}

func TestMatchResourcePattern(t *testing.T) {
	tests := []struct {
		pattern  string
		resource string
		expected bool
	}{
		{"*", "anything", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::other-bucket/key", false},
		// Resource ARNs are case-sensitive (e.g., S3 object keys)
		{"arn:aws:s3:::bucket/Key", "arn:aws:s3:::bucket/Key", true},
		{"arn:aws:s3:::bucket/Key", "arn:aws:s3:::bucket/key", false},
		// Mid-string wildcards
		{"arn:aws:s3:::bucket/*/data.csv", "arn:aws:s3:::bucket/folder/data.csv", true},
		{"arn:aws:s3:::bucket/*/data.csv", "arn:aws:s3:::bucket/a/b/data.csv", true},
		{"arn:aws:s3:::bucket/*/data.csv", "arn:aws:s3:::bucket/folder/other.csv", false},
		{"arn:aws:s3:::bucket-*-prod/*", "arn:aws:s3:::bucket-us-prod/key", true},
		{"arn:aws:s3:::bucket-*-prod/*", "arn:aws:s3:::bucket-us-dev/key", false},
		// Multiple wildcards
		{"arn:aws:logs:*:*:log-group:*", "arn:aws:logs:us-east-1:123:log-group:my-logs", true},
		{"arn:aws:logs:*:*:log-group:*", "arn:aws:logs:us-east-1:123:other:my-logs", false},
		// Exact match (no wildcards)
		{"arn:aws:s3:::exact-bucket", "arn:aws:s3:::exact-bucket", true},
		{"arn:aws:s3:::exact-bucket", "arn:aws:s3:::other-bucket", false},
	}

	for _, tt := range tests {
		result := matchResourcePattern(tt.pattern, tt.resource)
		if result != tt.expected {
			t.Errorf("matchResourcePattern(%q, %q) = %v, want %v", tt.pattern, tt.resource, result, tt.expected)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern  string
		value    string
		expected bool
	}{
		// Basic
		{"*", "anything", true},
		{"exact", "exact", true},
		{"exact", "other", false},
		// Suffix wildcard
		{"prefix*", "prefixsuffix", true},
		{"prefix*", "other", false},
		// Prefix wildcard
		{"*suffix", "anysuffix", true},
		{"*suffix", "anyother", false},
		// Mid-string wildcard
		{"pre*suf", "presuf", true},
		{"pre*suf", "pre-middle-suf", true},
		{"pre*suf", "pre-middle-other", false},
		// Multiple wildcards
		{"a*b*c", "abc", true},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbY", false},
		{"*a*b*", "xaxbx", true},
		// Empty pattern segments
		{"**", "anything", true},
		// Empty value
		{"*", "", true},
		{"a", "", false},
	}

	for _, tt := range tests {
		result := globMatch(tt.pattern, tt.value)
		if result != tt.expected {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, result, tt.expected)
		}
	}
}

func TestAnalyzeStatements_ExplicitDeny(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [
			{"Sid": "BlockAll", "Effect": "Deny", "Action": "s3:*", "Resource": "*"}
		]
	}`

	stmts, _ := ParsePolicyDocument(doc)
	denyType, reason := AnalyzeStatements(stmts, "s3:GetObject", "arn:aws:s3:::bucket/key")

	if denyType != "explicit" {
		t.Errorf("expected explicit, got %q", denyType)
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestAnalyzeStatements_ImplicitDeny(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}
		]
	}`

	stmts, _ := ParsePolicyDocument(doc)
	denyType, _ := AnalyzeStatements(stmts, "s3:GetObject", "arn:aws:s3:::bucket/key")

	if denyType != "implicit" {
		t.Errorf("expected implicit, got %q", denyType)
	}
}
