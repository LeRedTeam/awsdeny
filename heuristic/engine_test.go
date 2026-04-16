package heuristic

import (
	"testing"

	"github.com/leredteam/awsdeny/internal"
)

func TestAnalyze_SCPExplicitDeny(t *testing.T) {
	parsed := internal.ParsedError{
		Action:     "s3:GetObject",
		Resource:   "arn:aws:s3:::bucket/key",
		Principal:  "arn:aws:iam::123:role/MyRole",
		DenyType:   "explicit",
		PolicyType: "scp",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "SCP-001")
	assertContains(t, expl.SourceType, "scp")
	assertContains(t, expl.DenyType, "explicit")
}

func TestAnalyze_PermissionBoundary(t *testing.T) {
	parsed := internal.ParsedError{
		Action:     "ec2:RunInstances",
		Resource:   "arn:aws:ec2:us-east-1:123:instance/*",
		Principal:  "arn:aws:iam::123:role/MyRole",
		DenyType:   "implicit",
		PolicyType: "boundary",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "BOUNDARY-001")
	assertContains(t, expl.SourceType, "boundary")
}

func TestAnalyze_NoIdentityPolicy(t *testing.T) {
	parsed := internal.ParsedError{
		Action:     "s3:GetObject",
		Resource:   "arn:aws:s3:::bucket/key",
		Principal:  "arn:aws:iam::123:role/MyRole",
		DenyType:   "implicit",
		PolicyType: "identity",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "IDENT-001")
	assertContains(t, expl.SourceType, "identity")
}

func TestAnalyze_CrossAccountAssumeRole(t *testing.T) {
	parsed := internal.ParsedError{
		Action:    "sts:AssumeRole",
		Resource:  "arn:aws:iam::222:role/TargetRole",
		Principal: "arn:aws:iam::111:user/dev",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "XACCT-001")
	assertContains(t, expl.SourceType, "cross-account")
}

func TestAnalyze_CrossAccountResourceAccess(t *testing.T) {
	parsed := internal.ParsedError{
		Action:    "s3:GetObject",
		Resource:  "arn:aws:s3:::other-account-bucket/key",
		Principal: "arn:aws:iam::111:role/MyRole",
	}

	// S3 buckets don't have account IDs in ARNs, so this won't match cross-account
	expl := Analyze(parsed)
	// Should still get a result (default or another match)
	if expl.Summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestAnalyze_KMSKeyPolicy(t *testing.T) {
	parsed := internal.ParsedError{
		Action:    "kms:Decrypt",
		Resource:  "arn:aws:kms:us-east-1:123:key/abc",
		Principal: "arn:aws:iam::123:role/MyRole",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "RSPOL-003")
}

func TestAnalyze_SessionPolicy(t *testing.T) {
	parsed := internal.ParsedError{
		Action:     "s3:PutObject",
		Resource:   "arn:aws:s3:::bucket/key",
		Principal:  "arn:aws:iam::123:role/MyRole",
		PolicyType: "session",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "SESSION-001")
	assertContains(t, expl.SourceType, "session")
}

func TestAnalyze_S3MinimalError(t *testing.T) {
	parsed := internal.ParsedError{
		Action:   "s3:GetObject",
		Format:   "E",
		Resource: "",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "MISC-005")
}

func TestAnalyze_EC2Encoded(t *testing.T) {
	parsed := internal.ParsedError{
		Format:         "D",
		EncodedMessage: "ABCDEF123456",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "MISC-006")
}

func TestAnalyze_ServiceLinkedRole(t *testing.T) {
	parsed := internal.ParsedError{
		Action:    "iam:PutRolePolicy",
		Resource:  "arn:aws:iam::123:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS",
		Principal: "arn:aws:iam::123:user/admin",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "MISC-004")
}

func TestAnalyze_RootUser(t *testing.T) {
	parsed := internal.ParsedError{
		Action:    "s3:PutObject",
		Resource:  "arn:aws:s3:::bucket/key",
		Principal: "arn:aws:iam::123:root",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "MISC-003")
}

func TestAnalyze_S3BucketPolicyDeny(t *testing.T) {
	parsed := internal.ParsedError{
		Action:     "s3:PutObject",
		Resource:   "arn:aws:s3:::bucket/key",
		Principal:  "arn:aws:iam::123:role/MyRole",
		DenyType:   "explicit",
		PolicyType: "resource",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "RSPOL-001")
}

func TestAnalyze_DefaultExplanation(t *testing.T) {
	parsed := internal.ParsedError{
		Action:    "custom:SomeAction",
		Principal: "arn:aws:iam::123:role/MyRole",
	}

	expl := Analyze(parsed)
	if expl.Summary == "" {
		t.Error("expected non-empty summary for default explanation")
	}
	if expl.Confidence == "" {
		t.Error("expected confidence to be set")
	}
}

func TestAnalyze_MFARequired(t *testing.T) {
	parsed := internal.ParsedError{
		Action:    "s3:DeleteObject",
		Resource:  "arn:aws:s3:::bucket/key",
		Principal: "arn:aws:iam::123:user/dev",
		Reason:    "Condition key aws:MultiFactorAuthPresent not met",
		RawMessage: "Condition key aws:MultiFactorAuthPresent not met",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "COND-003")
}

func TestAnalyze_WildcardResourceNeeded(t *testing.T) {
	parsed := internal.ParsedError{
		Action:    "iam:ListUsers",
		Resource:  "arn:aws:iam::123:user/specific",
		Principal: "arn:aws:iam::123:role/MyRole",
	}

	expl := Analyze(parsed)
	assertContains(t, expl.HeuristicID, "IDENT-002")
}

func TestAnalyzeWithEnrichment(t *testing.T) {
	parsed := internal.ParsedError{
		Action:     "s3:GetObject",
		Resource:   "arn:aws:s3:::bucket/key",
		Principal:  "arn:aws:iam::123:role/MyRole",
		DenyType:   "explicit",
		PolicyType: "scp",
	}

	enrichment := &internal.EnrichmentResult{
		PolicyFetched:    true,
		SimulationRan:    true,
		SimulationResult: "explicitDeny",
		SimulationConfirms: true,
	}

	expl := AnalyzeWithEnrichment(parsed, enrichment)
	if expl.Level != 3 {
		t.Errorf("expected level 3, got %d", expl.Level)
	}
	if expl.Confidence != "very-high" {
		t.Errorf("expected very-high confidence, got %s", expl.Confidence)
	}
}

// --- helpers ---

func assertContains(t *testing.T, field, expected string) {
	t.Helper()
	if field != expected {
		t.Errorf("expected %q, got %q", expected, field)
	}
}
