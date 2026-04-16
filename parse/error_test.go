package parse

import (
	"testing"
)

func TestParseFormatA_Classic(t *testing.T) {
	input := "User: arn:aws:iam::123456789012:user/dev is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::my-bucket/data.csv"
	p := Parse(input)

	assertEqual(t, "A", p.Format)
	assertEqual(t, "s3:GetObject", p.Action)
	assertEqual(t, "arn:aws:s3:::my-bucket/data.csv", p.Resource)
	assertEqual(t, "arn:aws:iam::123456789012:user/dev", p.Principal)
}

func TestParseFormatB_EnrichedExplicitDeny(t *testing.T) {
	input := "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key with an explicit deny in a service control policy"
	p := Parse(input)

	assertEqual(t, "B", p.Format)
	assertEqual(t, "s3:GetObject", p.Action)
	assertEqual(t, "arn:aws:s3:::bucket/key", p.Resource)
	assertEqual(t, "arn:aws:iam::123:role/MyRole", p.Principal)
	assertEqual(t, "explicit", p.DenyType)
	assertEqual(t, "scp", p.PolicyType)
}

func TestParseFormatB_PermissionsBoundary(t *testing.T) {
	input := "User: arn:aws:iam::123:role/MyRole is not authorized to perform: ec2:RunInstances on resource: arn:aws:ec2:us-east-1:123:instance/* with an implicit deny in a permissions boundary"
	p := Parse(input)

	assertEqual(t, "B", p.Format)
	assertEqual(t, "implicit", p.DenyType)
	assertEqual(t, "boundary", p.PolicyType)
}

func TestParseFormatC_EnrichedWithReason(t *testing.T) {
	input := "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key because no identity-based policy allows the s3:GetObject action"
	p := Parse(input)

	assertEqual(t, "C", p.Format)
	assertEqual(t, "s3:GetObject", p.Action)
	assertEqual(t, "implicit", p.DenyType)
	assertEqual(t, "identity", p.PolicyType)
	if p.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestParseFormatD_EC2Encoded(t *testing.T) {
	input := "UnauthorizedOperation: You are not authorized to perform this operation. Encoded authorization failure message: ABCDEF123456789"
	p := Parse(input)

	assertEqual(t, "D", p.Format)
	assertEqual(t, "ABCDEF123456789", p.EncodedMessage)
}

func TestParseFormatE_S3Minimal(t *testing.T) {
	input := "Access Denied"
	p := Parse(input)

	assertEqual(t, "E", p.Format)
}

func TestParseFormatF_AssumeRole(t *testing.T) {
	input := "User: arn:aws:iam::111:user/dev is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::222:role/TargetRole"
	p := Parse(input)

	assertEqual(t, "A", p.Format) // Uses classic format regex
	assertEqual(t, "sts:AssumeRole", p.Action)
	assertEqual(t, "arn:aws:iam::222:role/TargetRole", p.Resource)
	assertEqual(t, "arn:aws:iam::111:user/dev", p.Principal)
}

func TestParseFormatG_CLIWrapper(t *testing.T) {
	input := `An error occurred (AccessDeniedException) when calling the Invoke operation: User: arn:aws:iam::123:role/MyRole is not authorized to perform: lambda:InvokeFunction on resource: arn:aws:lambda:us-east-1:123:function:my-func because no identity-based policy allows the lambda:InvokeFunction action`
	p := Parse(input)

	assertEqual(t, "C", p.Format) // Inner message is format C
	assertEqual(t, "AccessDeniedException", p.ErrorCode)
	assertEqual(t, "Invoke", p.Operation)
	assertEqual(t, "lambda:InvokeFunction", p.Action)
	assertEqual(t, "arn:aws:lambda:us-east-1:123:function:my-func", p.Resource)
	assertEqual(t, "arn:aws:iam::123:role/MyRole", p.Principal)
}

func TestParseFormatG_CLIWrapperMinimal(t *testing.T) {
	input := "An error occurred (AccessDenied) when calling the GetObject operation: Access Denied"
	p := Parse(input)

	// Should extract operation and error code, then inner "Access Denied" is Format E
	assertEqual(t, "E", p.Format)
	assertEqual(t, "AccessDenied", p.ErrorCode)
	assertEqual(t, "GetObject", p.Operation)
	assertEqual(t, "s3:GetObject", p.Action) // Inferred from operation
}

func TestParseFormatH_KMS(t *testing.T) {
	input := "User: arn:aws:iam::123:role/MyRole is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:us-east-1:123:key/key-id because no resource-based policy allows the kms:Decrypt action"
	p := Parse(input)

	assertEqual(t, "C", p.Format)
	assertEqual(t, "kms:Decrypt", p.Action)
	assertEqual(t, "resource", p.PolicyType)
}

func TestParseFormatI_SCPWithARN(t *testing.T) {
	input := "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:PutObject on resource: arn:aws:s3:::bucket/key with an explicit deny in a service control policy arn:aws:organizations::111:policy/o-xxx/p-yyy"
	p := Parse(input)

	assertEqual(t, "I", p.Format)
	assertEqual(t, "explicit", p.DenyType)
	assertEqual(t, "scp", p.PolicyType)
	assertEqual(t, "arn:aws:organizations::111:policy/o-xxx/p-yyy", p.PolicyARN)
}

func TestParseFormatB_SessionPolicy(t *testing.T) {
	input := "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key with an implicit deny in a session policy"
	p := Parse(input)

	assertEqual(t, "B", p.Format)
	assertEqual(t, "implicit", p.DenyType)
	assertEqual(t, "session", p.PolicyType)
}

func TestParseFormatB_ResourcePolicy(t *testing.T) {
	input := "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key with an explicit deny in a resource-based policy"
	p := Parse(input)

	assertEqual(t, "B", p.Format)
	assertEqual(t, "explicit", p.DenyType)
	assertEqual(t, "resource", p.PolicyType)
}

func TestParseFormatB_IdentityWithArticleAn(t *testing.T) {
	// AWS uses "an identity-based policy" (not "a identity-based policy")
	input := "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key with an implicit deny in an identity-based policy"
	p := Parse(input)

	assertEqual(t, "B", p.Format)
	assertEqual(t, "implicit", p.DenyType)
	assertEqual(t, "identity", p.PolicyType)
}

func TestParseGovCloud(t *testing.T) {
	input := "User: arn:aws-us-gov:iam::123456789012:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws-us-gov:s3:::bucket/key"
	p := Parse(input)

	assertEqual(t, "A", p.Format)
	assertEqual(t, "s3:GetObject", p.Action)
	assertEqual(t, "arn:aws-us-gov:s3:::bucket/key", p.Resource)
	assertEqual(t, "arn:aws-us-gov:iam::123456789012:role/MyRole", p.Principal)
}

func TestParseChinaPartition(t *testing.T) {
	input := "User: arn:aws-cn:iam::123456789012:role/MyRole is not authorized to perform: s3:PutObject on resource: arn:aws-cn:s3:::bucket/key with an explicit deny in a service control policy"
	p := Parse(input)

	assertEqual(t, "B", p.Format)
	assertEqual(t, "explicit", p.DenyType)
	assertEqual(t, "scp", p.PolicyType)
	assertEqual(t, "arn:aws-cn:iam::123456789012:role/MyRole", p.Principal)
}

func TestParse_UnknownFormat(t *testing.T) {
	input := "Something went wrong with permission"
	p := Parse(input)

	assertEqual(t, "unknown", p.Format)
}

func TestParse_PreservesRawMessage(t *testing.T) {
	input := "User: arn:aws:iam::123:user/dev is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key"
	p := Parse(input)

	assertEqual(t, input, p.RawMessage)
}

func TestParse_TrimWhitespace(t *testing.T) {
	input := "  Access Denied  \n"
	p := Parse(input)
	assertEqual(t, "E", p.Format)
}

func TestParseFormatC_ResourcePolicyReason(t *testing.T) {
	input := "User: arn:aws:iam::123:role/MyRole is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:us-east-1:123:key/abc because no resource-based policy allows the kms:Decrypt action"
	p := Parse(input)

	assertEqual(t, "implicit", p.DenyType)
	assertEqual(t, "resource", p.PolicyType)
}

// --- helpers ---

func assertEqual(t *testing.T, expected, actual string) {
	t.Helper()
	if expected != actual {
		t.Errorf("expected %q, got %q", expected, actual)
	}
}
