package enrich

import (
	"testing"
)

func TestNotAction_DenyAllExcept(t *testing.T) {
	// Common SCP pattern: deny everything except specific actions
	doc := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "DenyAllExceptAllowed",
				"Effect": "Deny",
				"NotAction": [
					"s3:GetObject",
					"s3:PutObject",
					"sts:AssumeRole"
				],
				"Resource": "*"
			}
		]
	}`

	stmts, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}

	// s3:GetObject should NOT match (it's in NotAction exclusion list)
	matches := FindMatchingStatements(stmts, "s3:GetObject", "arn:aws:s3:::bucket/key")
	if len(matches) != 0 {
		t.Errorf("s3:GetObject should not match NotAction deny (it's excluded), got %d matches", len(matches))
	}

	// ec2:RunInstances SHOULD match (it's NOT in the exclusion list)
	matches = FindMatchingStatements(stmts, "ec2:RunInstances", "arn:aws:ec2:us-east-1:123:instance/*")
	if len(matches) != 1 {
		t.Errorf("ec2:RunInstances should match NotAction deny, got %d matches", len(matches))
	}

	// lambda:Invoke SHOULD match
	matches = FindMatchingStatements(stmts, "lambda:InvokeFunction", "arn:aws:lambda:us-east-1:123:function:my-func")
	if len(matches) != 1 {
		t.Errorf("lambda:InvokeFunction should match NotAction deny, got %d matches", len(matches))
	}
}

func TestNotAction_AnalyzeStatements(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "DenyNonS3",
				"Effect": "Deny",
				"NotAction": ["s3:*"],
				"Resource": "*"
			}
		]
	}`

	stmts, _ := ParsePolicyDocument(doc)

	// ec2 action should be explicitly denied
	denyType, _ := AnalyzeStatements(stmts, "ec2:RunInstances", "*")
	if denyType != "explicit" {
		t.Errorf("expected explicit deny for ec2 action, got %q", denyType)
	}

	// s3 action should not be explicitly denied by this statement
	denyType, _ = AnalyzeStatements(stmts, "s3:GetObject", "*")
	if denyType != "implicit" {
		t.Errorf("expected implicit deny for s3 action (not covered by NotAction deny), got %q", denyType)
	}
}

func TestNotAction_ParsesCorrectly(t *testing.T) {
	doc := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Deny",
				"NotAction": ["iam:*", "sts:*"],
				"Resource": "*"
			}
		]
	}`

	stmts, err := ParsePolicyDocument(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stmts[0].NotActions) != 2 {
		t.Errorf("expected 2 NotActions, got %d", len(stmts[0].NotActions))
	}
	if len(stmts[0].Actions) != 0 {
		t.Errorf("expected 0 Actions when NotAction is used, got %d", len(stmts[0].Actions))
	}
}
