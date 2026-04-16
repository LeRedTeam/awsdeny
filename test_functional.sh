#!/bin/bash
# Functional test suite for awsdeny
# Tests the binary end-to-end for correctness and usefulness.

set -euo pipefail

BINARY="./awsdeny"
PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  FAIL: $1"; echo "    $2"; }

assert_contains() {
    local output="$1" expected="$2" label="$3"
    if echo "$output" | grep -qiF "$expected"; then
        pass "$label"
    else
        fail "$label" "expected to contain (case-insensitive): $expected"
    fi
}

assert_not_contains() {
    local output="$1" expected="$2" label="$3"
    if echo "$output" | grep -qF "$expected"; then
        fail "$label" "should NOT contain: $expected"
    else
        pass "$label"
    fi
}

assert_exit_code() {
    local actual="$1" expected="$2" label="$3"
    if [ "$actual" -eq "$expected" ]; then
        pass "$label"
    else
        fail "$label" "expected exit code $expected, got $actual"
    fi
}

assert_valid_json() {
    local output="$1" label="$2"
    if echo "$output" | jq . > /dev/null 2>&1; then
        pass "$label"
    else
        fail "$label" "output is not valid JSON"
    fi
}

echo "========================================"
echo "awsdeny Functional Test Suite"
echo "========================================"
echo ""

# ──────────────────────────────────────────────
echo "--- Format A: Classic error ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123456789012:user/dev is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::my-bucket/data.csv" 2>&1)
assert_contains "$OUT" "s3:GetObject" "Format A: extracts action"
assert_contains "$OUT" "arn:aws:s3:::my-bucket/data.csv" "Format A: extracts resource"
assert_contains "$OUT" "arn:aws:iam::123456789012:user/dev" "Format A: extracts principal"
assert_contains "$OUT" "Access Denied" "Format A: shows header"
assert_contains "$OUT" "Suggested fixes" "Format A: shows suggestions"
assert_contains "$OUT" "Confidence:" "Format A: shows confidence"

# ──────────────────────────────────────────────
echo ""
echo "--- Format B: Enriched with explicit deny in SCP ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key with an explicit deny in a service control policy" 2>&1)
assert_contains "$OUT" "Explicit deny" "Format B SCP: identifies explicit deny"
assert_contains "$OUT" "Service Control Policy" "Format B SCP: identifies SCP"
assert_contains "$OUT" "organization administrator" "Format B SCP: suggests contacting admin"
assert_contains "$OUT" "very-high" "Format B SCP: high confidence"

# ──────────────────────────────────────────────
echo ""
echo "--- Format B: Permission boundary ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: ec2:RunInstances on resource: arn:aws:ec2:us-east-1:123:instance/* with an implicit deny in a permissions boundary" 2>&1)
assert_contains "$OUT" "Implicit deny" "Format B Boundary: identifies implicit deny"
assert_contains "$OUT" "Permissions boundary" "Format B Boundary: identifies boundary"
assert_contains "$OUT" "permission boundary" "Format B Boundary: explains boundary"

# ──────────────────────────────────────────────
echo ""
echo "--- Format B: Session policy ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key with an implicit deny in a session policy" 2>&1)
assert_contains "$OUT" "Session policy" "Format B Session: identifies session policy"
assert_contains "$OUT" "session policy" "Format B Session: explains session policy"

# ──────────────────────────────────────────────
echo ""
echo "--- Format B: Resource policy ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:PutObject on resource: arn:aws:s3:::bucket/key with an explicit deny in a resource-based policy" 2>&1)
assert_contains "$OUT" "Resource-based policy" "Format B Resource: identifies resource policy"
assert_contains "$OUT" "bucket policy" "Format B Resource: S3-specific explanation"

# ──────────────────────────────────────────────
echo ""
echo "--- Format C: Enriched with reason (no identity policy) ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key because no identity-based policy allows the s3:GetObject action" 2>&1)
assert_contains "$OUT" "Implicit deny" "Format C Identity: identifies implicit deny"
assert_contains "$OUT" "Identity-based policy" "Format C Identity: identifies identity policy"
assert_contains "$OUT" "identity-based policy" "Format C Identity: clear explanation"
assert_contains "$OUT" '"Effect": "Allow"' "Format C Identity: provides policy snippet"

# ──────────────────────────────────────────────
echo ""
echo "--- Format C: KMS with resource policy reason ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:us-east-1:123:key/abc because no resource-based policy allows the kms:Decrypt action" 2>&1)
assert_contains "$OUT" "kms:Decrypt" "Format C KMS: extracts KMS action"
assert_contains "$OUT" "KMS key polic" "Format C KMS: KMS-specific explanation"
assert_contains "$OUT" "key policy" "Format C KMS: mentions key policy"

# ──────────────────────────────────────────────
echo ""
echo "--- Format D: EC2 Encoded ---"
OUT=$($BINARY explain --error "UnauthorizedOperation: You are not authorized to perform this operation. Encoded authorization failure message: ABCDEF123456789xyz" 2>&1)
assert_contains "$OUT" "encoded authorization failure" "Format D: identifies EC2 encoded"
assert_contains "$OUT" "decode-authorization-message" "Format D: suggests decoding"
assert_contains "$OUT" "enrich" "Format D: suggests enrichment"

# ──────────────────────────────────────────────
echo ""
echo "--- Format E: S3 Minimal ---"
OUT=$($BINARY explain --error "Access Denied" 2>&1)
assert_contains "$OUT" "Access Denied" "Format E: handles bare Access Denied"
assert_contains "$OUT" "Confidence:" "Format E: still shows confidence"

# ──────────────────────────────────────────────
echo ""
echo "--- Format F: Cross-account AssumeRole ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::111111111111:user/dev is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::222222222222:role/TargetRole" 2>&1)
assert_contains "$OUT" "Cross-account" "Format F: identifies cross-account"
assert_contains "$OUT" "trust policy" "Format F: mentions trust policy"
assert_contains "$OUT" "sts:AssumeRole" "Format F: extracts action"
assert_contains "$OUT" "222222222222" "Format F: shows target account"

# ──────────────────────────────────────────────
echo ""
echo "--- Format G: AWS CLI wrapper ---"
OUT=$($BINARY explain --error 'An error occurred (AccessDeniedException) when calling the Invoke operation: User: arn:aws:iam::123:role/MyRole is not authorized to perform: lambda:InvokeFunction on resource: arn:aws:lambda:us-east-1:123:function:my-func because no identity-based policy allows the lambda:InvokeFunction action' 2>&1)
assert_contains "$OUT" "lambda:InvokeFunction" "Format G: extracts action from wrapped error"
assert_contains "$OUT" "arn:aws:lambda:us-east-1:123:function:my-func" "Format G: extracts resource"
assert_contains "$OUT" "arn:aws:iam::123:role/MyRole" "Format G: extracts principal"
assert_contains "$OUT" "identity-based policy" "Format G: matches heuristic through wrapper"

# ──────────────────────────────────────────────
echo ""
echo "--- Format G: CLI wrapper with minimal S3 ---"
OUT=$($BINARY explain --error "An error occurred (AccessDenied) when calling the GetObject operation: Access Denied" 2>&1)
assert_contains "$OUT" "s3:GetObject" "Format G Minimal: infers action from operation"
assert_contains "$OUT" "object might not exist" "Format G Minimal: warns about S3 404 masking"

# ──────────────────────────────────────────────
echo ""
echo "--- Format I: SCP with ARN ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:PutObject on resource: arn:aws:s3:::bucket/key with an explicit deny in a service control policy arn:aws:organizations::111:policy/o-xxx/p-yyy" 2>&1)
assert_contains "$OUT" "Explicit deny" "Format I: identifies explicit deny"
assert_contains "$OUT" "SCP" "Format I: identifies SCP"
assert_contains "$OUT" "arn:aws:organizations::111:policy/o-xxx/p-yyy" "Format I: shows policy ARN"

# ──────────────────────────────────────────────
echo ""
echo "--- Heuristic: VPC Endpoint condition ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key. Condition key aws:SourceVpce not satisfied" 2>&1)
assert_contains "$OUT" "VPC endpoint" "Heuristic VPCE: detected"
assert_contains "$OUT" "Route your request" "Heuristic VPCE: actionable suggestion"

# ──────────────────────────────────────────────
echo ""
echo "--- Heuristic: IP restriction ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key. Condition SourceIp does not match" 2>&1)
assert_contains "$OUT" "IP address" "Heuristic IP: detected"
assert_contains "$OUT" "VPN" "Heuristic IP: suggests VPN"

# ──────────────────────────────────────────────
echo ""
echo "--- Heuristic: MFA required ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:user/dev is not authorized to perform: s3:DeleteObject on resource: arn:aws:s3:::bucket/key. Condition key aws:MultiFactorAuthPresent not met" 2>&1)
assert_contains "$OUT" "MFA" "Heuristic MFA: detected"
assert_contains "$OUT" "get-session-token" "Heuristic MFA: provides MFA command"

# ──────────────────────────────────────────────
echo ""
echo "--- Heuristic: Encryption required ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:PutObject on resource: arn:aws:s3:::bucket/key. Condition aws:SecureTransport is false" 2>&1)
assert_contains "$OUT" "encryption" "Heuristic Encryption: detected"
assert_contains "$OUT" "HTTPS" "Heuristic Encryption: suggests HTTPS"

# ──────────────────────────────────────────────
echo ""
echo "--- Heuristic: Service-linked role ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:user/admin is not authorized to perform: iam:PutRolePolicy on resource: arn:aws:iam::123:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS" 2>&1)
assert_contains "$OUT" "service-linked role" "Heuristic SLR: detected"

# ──────────────────────────────────────────────
echo ""
echo "--- Heuristic: Root user ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:root is not authorized to perform: s3:PutObject on resource: arn:aws:s3:::bucket/key" 2>&1)
assert_contains "$OUT" "root user" "Heuristic Root: detected"
assert_contains "$OUT" "IAM role/user instead" "Heuristic Root: suggests IAM principal"

# ──────────────────────────────────────────────
echo ""
echo "--- Heuristic: Tag-based ABAC ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key. Condition aws:ResourceTag/Environment not matched" 2>&1)
assert_contains "$OUT" "tag" "Heuristic ABAC: detected"
assert_contains "$OUT" "list-role-tags" "Heuristic ABAC: suggests checking tags"

# ──────────────────────────────────────────────
echo ""
echo "--- JSON output format ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key because no identity-based policy allows the s3:GetObject action" --format json 2>&1)
assert_valid_json "$OUT" "JSON: valid JSON output"
assert_contains "$OUT" '"status": "denied"' "JSON: has status field"
assert_contains "$OUT" '"action": "s3:GetObject"' "JSON: has action"
assert_contains "$OUT" '"confidence":' "JSON: has confidence"
assert_contains "$OUT" '"suggestions":' "JSON: has suggestions"
assert_contains "$OUT" '"matched_heuristic": "IDENT-001"' "JSON: shows heuristic ID"

# ──────────────────────────────────────────────
echo ""
echo "--- SARIF output format ---"
set +e
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key because no identity-based policy allows the s3:GetObject action" --format sarif 2>&1)
set -e
# SARIF is a Pro feature, should show license error
assert_contains "$OUT" "requires a Pro license" "SARIF: requires Pro license"

# ──────────────────────────────────────────────
echo ""
echo "--- GitHub markdown output format ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key with an explicit deny in a service control policy" --format github 2>&1)
assert_contains "$OUT" "## AWS AccessDenied Explanation" "GitHub: has markdown header"
assert_contains "$OUT" "s3:GetObject" "GitHub: has action"
assert_contains "$OUT" "### Suggested Fixes" "GitHub: has fixes section"
assert_contains "$OUT" "Generated by" "GitHub: has attribution"

# ──────────────────────────────────────────────
echo ""
echo "--- Stdin piping ---"
OUT=$(echo "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key" | $BINARY explain --stdin 2>&1)
assert_contains "$OUT" "s3:GetObject" "Stdin: works via pipe"
assert_contains "$OUT" "Access Denied" "Stdin: shows header"

# ──────────────────────────────────────────────
echo ""
echo "--- Stdin piping with JSON format ---"
OUT=$(echo "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key" | $BINARY explain --stdin --format json 2>&1)
assert_valid_json "$OUT" "Stdin JSON: valid JSON via pipe"

# ──────────────────────────────────────────────
echo ""
echo "--- CloudTrail: requires Pro license ---"
set +e
OUT=$($BINARY explain --cloudtrail testdata/cloudtrail/s3_denied.json 2>&1)
set -e
assert_contains "$OUT" "requires a Pro license" "CloudTrail: requires Pro license"

# ──────────────────────────────────────────────
echo ""
echo "--- Exit code: success ---"
$BINARY explain --error "User: arn:aws:iam::123:role/R is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::b/k" > /dev/null 2>&1
assert_exit_code $? 0 "Exit code: 0 on success"

# ──────────────────────────────────────────────
echo ""
echo "--- Exit code: parse error ---"
set +e
$BINARY explain --error "just some random text that isnt an aws error" > /dev/null 2>&1
RC=$?
set -e
assert_exit_code $RC 3 "Exit code: 3 on parse failure"

# ──────────────────────────────────────────────
echo ""
echo "--- Exit code: no input ---"
set +e
$BINARY explain > /dev/null 2>&1
RC=$?
set -e
if [ "$RC" -ne 0 ]; then
    pass "Exit code: non-zero on no input"
else
    fail "Exit code: non-zero on no input" "got exit code 0"
fi

# ──────────────────────────────────────────────
echo ""
echo "--- Version command ---"
OUT=$($BINARY version 2>&1)
assert_contains "$OUT" "awsdeny" "Version: shows name"

# ──────────────────────────────────────────────
echo ""
echo "--- License status (no key) ---"
OUT=$(AWSDENY_LICENSE_KEY="" $BINARY license status 2>&1)
assert_contains "$OUT" "Free tier" "License: shows free tier"

# ──────────────────────────────────────────────
echo ""
echo "--- Enrich without license ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/R is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::b/k" --enrich 2>&1)
assert_contains "$OUT" "requires a Pro license" "Enrich no license: warns about Pro"
assert_contains "$OUT" "Falling back" "Enrich no license: falls back to L1"
# Should still produce output (graceful degradation)
assert_contains "$OUT" "Access Denied" "Enrich no license: still produces output"

# ──────────────────────────────────────────────
echo ""
echo "--- Sanitization: access key in input ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized. Key AKIAIOSFODNN7EXAMPLE was used" 2>&1)
assert_not_contains "$OUT" "AKIAIOSFODNN7EXAMPLE" "Sanitize: access key ID redacted"

# ──────────────────────────────────────────────
echo ""
echo "--- Sanitization: secret key in input ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized. aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" 2>&1)
assert_not_contains "$OUT" "wJalrXUtnFEMI" "Sanitize: secret key redacted"

# ──────────────────────────────────────────────
echo ""
echo "--- Positional args (no --error flag) ---"
OUT=$($BINARY explain "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key" 2>&1)
assert_contains "$OUT" "s3:GetObject" "Positional args: works without --error flag"

# ──────────────────────────────────────────────
echo ""
echo "--- AWSDENY_FORMAT env var ---"
OUT=$(AWSDENY_FORMAT=json $BINARY explain --error "User: arn:aws:iam::123:role/R is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::b/k" 2>&1)
assert_valid_json "$OUT" "Env format: AWSDENY_FORMAT=json works"

# ──────────────────────────────────────────────
echo ""
echo "--- Deterministic output ---"
OUT1=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key because no identity-based policy allows the s3:GetObject action" --format json 2>&1)
OUT2=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key because no identity-based policy allows the s3:GetObject action" --format json 2>&1)
if [ "$OUT1" = "$OUT2" ]; then
    pass "Determinism: same input produces same output"
else
    fail "Determinism: same input produces same output" "outputs differ"
fi

# ──────────────────────────────────────────────
echo ""
echo "--- Multiple errors in same format ---"
OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key with an explicit deny in a service control policy" --format json 2>&1)
HEURISTIC=$(echo "$OUT" | jq -r '.analysis.matched_heuristic')
assert_contains "$HEURISTIC" "SCP-001" "JSON heuristic: SCP-001 for SCP explicit deny"

OUT=$($BINARY explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key because no identity-based policy allows the s3:GetObject action" --format json 2>&1)
HEURISTIC=$(echo "$OUT" | jq -r '.analysis.matched_heuristic')
assert_contains "$HEURISTIC" "IDENT-001" "JSON heuristic: IDENT-001 for missing identity policy"

OUT=$($BINARY explain --error "User: arn:aws:iam::111:user/dev is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::222:role/Target" --format json 2>&1)
HEURISTIC=$(echo "$OUT" | jq -r '.analysis.matched_heuristic')
assert_contains "$HEURISTIC" "XACCT-001" "JSON heuristic: XACCT-001 for cross-account AssumeRole"

# ──────────────────────────────────────────────
echo ""
echo "========================================"
echo "Results: $PASS passed, $FAIL failed out of $TOTAL tests"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
