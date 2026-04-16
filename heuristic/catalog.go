package heuristic

import (
	"strings"

	"github.com/leredteam/awsdeny/internal"
)

// catalog is the full list of heuristic patterns.
var catalog = []Heuristic{
	// ──────────────────────────────── SCP Patterns ────────────────────────────────
	{
		ID:              "SCP-001",
		Name:            "SCP Explicit Deny",
		Category:        "scp",
		ConfidenceBoost: 0.25,
		Match: func(p internal.ParsedError) bool {
			return p.DenyType == "explicit" && p.PolicyType == "scp"
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			reason := "Your organization has a Service Control Policy (SCP) that explicitly denies this action. SCPs are set by your AWS Organization administrators and apply to all accounts in the organization (or specific OUs). Individual account policies cannot override an SCP deny."
			return internal.Explanation{
				Summary:    "Blocked by organization SCP (explicit deny)",
				DenyType:   "explicit",
				SourceType: "scp",
				SourceARN:  p.PolicyARN,
				Reason:     reason,
				Suggestions: []internal.Suggestion{
					{Action: "Contact your organization administrator to review the SCP", Difficulty: "medium", Requires: "org admin"},
					{Action: "Check if the SCP has conditions you can satisfy (e.g., VPC endpoint, region, tag)", Difficulty: "easy"},
					{Action: "Use an alternative approach that doesn't require this specific action", Difficulty: "varies"},
				},
			}
		},
	},
	{
		ID:              "SCP-002",
		Name:            "SCP Region Restriction",
		Category:        "scp",
		ConfidenceBoost: 0.15,
		Match: func(p internal.ParsedError) bool {
			if p.PolicyType != "scp" {
				return false
			}
			// Globally available services are unlikely to be region-restricted
			globalActions := []string{"sts:", "iam:", "cloudfront:", "route53:", "waf:", "organizations:"}
			for _, ga := range globalActions {
				if strings.HasPrefix(p.Action, ga) {
					return false
				}
			}
			return true
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Likely blocked by SCP region restriction",
				DenyType:   p.DenyType,
				SourceType: "scp",
				SourceARN:  p.PolicyARN,
				Reason:     "Many organizations use SCPs to restrict which AWS regions can be used. Your request may be targeting a region that is denied by SCP.",
				Suggestions: []internal.Suggestion{
					{Action: "Check which regions your organization allows", Difficulty: "easy"},
					{Action: "Use an allowed region for this operation", Difficulty: "easy"},
					{Action: "Request region access from your org admin", Difficulty: "medium", Requires: "org admin"},
				},
			}
		},
	},
	{
		ID:              "SCP-003",
		Name:            "SCP Service Restriction",
		Category:        "scp",
		ConfidenceBoost: 0.15,
		Match: func(p internal.ParsedError) bool {
			return p.PolicyType == "scp" && p.DenyType != "explicit"
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Likely blocked by SCP service restriction",
				DenyType:   "implicit",
				SourceType: "scp",
				SourceARN:  p.PolicyARN,
				Reason:     "Your organization may have an SCP that only allows specific AWS services. Services not on the allow-list are implicitly denied.",
				Suggestions: []internal.Suggestion{
					{Action: "Check your organization's allowed services list", Difficulty: "easy"},
					{Action: "Request service access from your org admin", Difficulty: "medium", Requires: "org admin"},
				},
			}
		},
	},

	// ──────────────────────────── Permission Boundary ─────────────────────────────
	{
		ID:              "BOUNDARY-001",
		Name:            "Permission Boundary Limit",
		Category:        "boundary",
		ConfidenceBoost: 0.25,
		Match: func(p internal.ParsedError) bool {
			return p.PolicyType == "boundary"
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Blocked by permission boundary",
				DenyType:   p.DenyType,
				SourceType: "boundary",
				SourceARN:  p.PolicyARN,
				Reason:     "Your IAM principal has a permission boundary attached. Permission boundaries set the MAXIMUM permissions that identity-based policies can grant. Even if your role/user policy allows this action, if the permission boundary doesn't also allow it, the request is denied.",
				Suggestions: []internal.Suggestion{
					{Action: "Check the permission boundary policy attached to your role/user", Difficulty: "easy"},
					{Action: "Request boundary modification from your IAM admin", Difficulty: "medium", Requires: "IAM admin"},
					{Action: "Ensure both your identity policy AND permission boundary allow this action", Difficulty: "easy"},
				},
			}
		},
	},

	// ──────────────────────────── Condition Patterns ──────────────────────────────
	{
		ID:              "COND-001",
		Name:            "Missing VPC Endpoint",
		Category:        "condition",
		ConfidenceBoost: 0.2,
		Match: func(p internal.ParsedError) bool {
			lower := strings.ToLower(p.Reason + p.RawMessage)
			return strings.Contains(lower, "sourcevpce") ||
				strings.Contains(lower, "vpceid") ||
				strings.Contains(lower, "vpc endpoint")
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Blocked by VPC endpoint condition",
				DenyType:   orDefault(p.DenyType, "explicit"),
				SourceType: orDefault(p.PolicyType, "unknown"),
				SourceARN:  p.PolicyARN,
				Reason:     "The policy requires requests to come through a specific VPC endpoint. Your request was made from outside the VPC or without using the endpoint.",
				Suggestions: []internal.Suggestion{
					{Action: "Route your request through the required VPC endpoint", Difficulty: "medium"},
					{Action: "If running locally, use AWS VPN or Direct Connect to access through VPC", Difficulty: "hard"},
					{Action: "If in CI/CD, ensure the runner is in the VPC with endpoint access", Difficulty: "medium"},
				},
			}
		},
	},
	{
		ID:              "COND-002",
		Name:            "IP Restriction",
		Category:        "condition",
		ConfidenceBoost: 0.2,
		Match: func(p internal.ParsedError) bool {
			lower := strings.ToLower(p.Reason + p.RawMessage)
			return strings.Contains(lower, "sourceip") ||
				strings.Contains(lower, "source ip") ||
				strings.Contains(lower, "ipaddress")
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Blocked by IP address restriction",
				DenyType:   orDefault(p.DenyType, "explicit"),
				SourceType: orDefault(p.PolicyType, "unknown"),
				SourceARN:  p.PolicyARN,
				Reason:     "The policy restricts access to specific source IP addresses or CIDR ranges. Your request came from an IP address not in the allowed list.",
				Suggestions: []internal.Suggestion{
					{Action: "Check the allowed IP ranges in the policy", Difficulty: "easy"},
					{Action: "Connect from an allowed network (VPN, office network)", Difficulty: "easy"},
					{Action: "Request your IP to be added to the allow list", Difficulty: "medium", Requires: "IAM admin"},
					{Action: "Note: If using VPC endpoint, aws:SourceIp doesn't apply — use aws:SourceVpce instead", Difficulty: "info"},
				},
			}
		},
	},
	{
		ID:              "COND-003",
		Name:            "MFA Required",
		Category:        "condition",
		ConfidenceBoost: 0.2,
		Match: func(p internal.ParsedError) bool {
			lower := strings.ToLower(p.Reason + p.RawMessage)
			hasMFAKeyword := strings.Contains(lower, "multifactorauth") ||
				strings.Contains(lower, "multi-factor")
			// Session context alone is not enough — many CloudTrail events have mfa=false
			// without MFA being relevant. Require MFA keyword in error OR both session
			// context and a generic "mfa" mention.
			if hasMFAKeyword {
				return true
			}
			fromSession := p.SessionContext != nil && p.SessionContext["mfaAuthenticated"] == "false"
			return fromSession && strings.Contains(lower, "mfa")
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Blocked by MFA requirement",
				DenyType:   orDefault(p.DenyType, "explicit"),
				SourceType: orDefault(p.PolicyType, "unknown"),
				SourceARN:  p.PolicyARN,
				Reason:     "The policy requires Multi-Factor Authentication (MFA) for this action. Your current session was not authenticated with MFA.",
				Suggestions: []internal.Suggestion{
					{Action: "Re-authenticate with MFA: aws sts get-session-token --serial-number <mfa-device> --token-code <code>", Difficulty: "easy"},
					{Action: "Use an MFA-authenticated role session", Difficulty: "easy"},
					{Action: "If in CI/CD, this action may not be possible without infrastructure changes", Difficulty: "hard"},
				},
			}
		},
	},
	{
		ID:              "COND-004",
		Name:            "Encryption Required",
		Category:        "condition",
		ConfidenceBoost: 0.2,
		Match: func(p internal.ParsedError) bool {
			lower := strings.ToLower(p.Reason + p.RawMessage)
			return strings.Contains(lower, "securetransport") ||
				strings.Contains(lower, "server-side-encryption") ||
				strings.Contains(lower, "x-amz-server-side-encryption") ||
				strings.Contains(lower, "kms:viaservice")
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Blocked by encryption requirement",
				DenyType:   orDefault(p.DenyType, "explicit"),
				SourceType: orDefault(p.PolicyType, "unknown"),
				SourceARN:  p.PolicyARN,
				Reason:     "The policy requires encryption. This could mean: HTTPS required (aws:SecureTransport), server-side encryption required, or specific KMS key usage required.",
				Suggestions: []internal.Suggestion{
					{Action: "Ensure you're using HTTPS (not HTTP) for the request", Difficulty: "easy"},
					{Action: "Add server-side encryption headers: --sse AES256 or --sse aws:kms", Difficulty: "easy"},
					{Action: "Use the required KMS key for encryption", Difficulty: "medium"},
				},
			}
		},
	},
	{
		ID:              "COND-005",
		Name:            "Tag-Based ABAC Mismatch",
		Category:        "condition",
		ConfidenceBoost: 0.15,
		Match: func(p internal.ParsedError) bool {
			lower := strings.ToLower(p.Reason + p.RawMessage)
			return strings.Contains(lower, "resourcetag") ||
				strings.Contains(lower, "principaltag") ||
				strings.Contains(lower, "requesttag") ||
				strings.Contains(lower, "aws:resourcetag") ||
				strings.Contains(lower, "aws:principaltag")
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Blocked by tag-based access control (ABAC)",
				DenyType:   orDefault(p.DenyType, "implicit"),
				SourceType: orDefault(p.PolicyType, "unknown"),
				SourceARN:  p.PolicyARN,
				Reason:     "The policy uses Attribute-Based Access Control (ABAC) with tags. Either your principal doesn't have the required tag, the resource doesn't have the expected tag, or you didn't include the required tag in your request.",
				Suggestions: []internal.Suggestion{
					{Action: "Check required tags on your IAM principal: aws iam list-role-tags --role-name <role>", Difficulty: "easy"},
					{Action: "Check required tags on the target resource", Difficulty: "easy"},
					{Action: "Add required tags to your request if applicable", Difficulty: "easy"},
					{Action: "Request tag modifications from your admin", Difficulty: "medium", Requires: "IAM admin"},
				},
			}
		},
	},
	{
		ID:              "COND-006",
		Name:            "Time-Based Restriction",
		Category:        "condition",
		ConfidenceBoost: 0.15,
		Match: func(p internal.ParsedError) bool {
			lower := strings.ToLower(p.Reason + p.RawMessage)
			return strings.Contains(lower, "currenttime") ||
				strings.Contains(lower, "dategreaterthan") ||
				strings.Contains(lower, "datelessthan") ||
				strings.Contains(lower, "epochtime")
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Blocked by time-based restriction",
				DenyType:   orDefault(p.DenyType, "explicit"),
				SourceType: orDefault(p.PolicyType, "unknown"),
				SourceARN:  p.PolicyARN,
				Reason:     "The policy has a time-based condition. Your access may be restricted to specific hours, dates, or the permission may have expired.",
				Suggestions: []internal.Suggestion{
					{Action: "Check if the policy has time windows and retry within the allowed period", Difficulty: "easy"},
					{Action: "Request updated time restrictions from your admin", Difficulty: "medium", Requires: "IAM admin"},
				},
			}
		},
	},

	// ──────────────────────────── Cross-Account ──────────────────────────────────
	{
		ID:              "XACCT-001",
		Name:            "Missing Trust Policy",
		Category:        "cross-account",
		ConfidenceBoost: 0.25,
		Match: func(p internal.ParsedError) bool {
			if p.Action != "sts:AssumeRole" {
				return false
			}
			principalAcct := internal.ExtractAccountFromARN(p.Principal)
			resourceAcct := internal.ExtractAccountFromARN(p.Resource)
			return principalAcct != "" && resourceAcct != "" && principalAcct != resourceAcct
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Cross-account AssumeRole denied",
				DenyType:   orDefault(p.DenyType, "unknown"),
				SourceType: "cross-account",
				Reason:     "Cross-account AssumeRole requires BOTH: (1) the calling account's policy allows sts:AssumeRole on the target role, AND (2) the target role's trust policy allows the calling principal. One or both of these is missing.",
				Suggestions: []internal.Suggestion{
					{Action: "Check the target role's trust policy allows your principal", Difficulty: "easy", Requires: "target account access"},
					{Action: "Check your identity policy allows sts:AssumeRole on the target role ARN", Difficulty: "easy"},
					{Action: "Ensure the trust policy specifies the correct principal ARN", Difficulty: "easy"},
					{Action: "Check for ExternalId condition in the trust policy", Difficulty: "easy"},
				},
			}
		},
	},
	{
		ID:              "XACCT-002",
		Name:            "Cross-Account Resource Access",
		Category:        "cross-account",
		ConfidenceBoost: 0.15,
		Match: func(p internal.ParsedError) bool {
			if p.Action == "sts:AssumeRole" {
				return false
			}
			principalAcct := internal.ExtractAccountFromARN(p.Principal)
			resourceAcct := internal.ExtractAccountFromARN(p.Resource)
			return principalAcct != "" && resourceAcct != "" && principalAcct != resourceAcct
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Cross-account resource access denied",
				DenyType:   orDefault(p.DenyType, "unknown"),
				SourceType: "cross-account",
				Reason:     "You're accessing a resource in a different AWS account. Cross-account access requires: your identity policy allows the action, AND the resource policy in the other account grants access to your principal/account.",
				Suggestions: []internal.Suggestion{
					{Action: "Check the resource policy grants access to your account/principal", Difficulty: "medium", Requires: "resource account access"},
					{Action: "Use AssumeRole to get credentials in the target account instead", Difficulty: "medium"},
					{Action: "Check for conditions in the resource policy (e.g., aws:PrincipalOrgID)", Difficulty: "easy"},
				},
			}
		},
	},
	{
		ID:              "XACCT-003",
		Name:            "Missing ExternalId",
		Category:        "cross-account",
		ConfidenceBoost: 0.1,
		Match: func(p internal.ParsedError) bool {
			if p.Action != "sts:AssumeRole" {
				return false
			}
			principalAcct := internal.ExtractAccountFromARN(p.Principal)
			resourceAcct := internal.ExtractAccountFromARN(p.Resource)
			isCrossAccount := principalAcct != "" && resourceAcct != "" && principalAcct != resourceAcct
			// Generic error with cross-account AssumeRole hints at ExternalId
			return isCrossAccount && p.DenyType == "" && p.PolicyType == ""
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Cross-account AssumeRole likely missing ExternalId",
				DenyType:   "unknown",
				SourceType: "cross-account",
				Reason:     "The target role's trust policy likely requires an ExternalId. This is a security mechanism to prevent the 'confused deputy' problem.",
				Suggestions: []internal.Suggestion{
					{Action: "Include the correct ExternalId in your AssumeRole call: --external-id <value>", Difficulty: "easy"},
					{Action: "Get the required ExternalId from the role owner", Difficulty: "easy"},
				},
			}
		},
	},

	// ──────────────────────────── Resource Policy ────────────────────────────────
	{
		ID:              "RSPOL-001",
		Name:            "S3 Bucket Policy Deny",
		Category:        "resource-policy",
		ConfidenceBoost: 0.2,
		Match: func(p internal.ParsedError) bool {
			return strings.HasPrefix(p.Action, "s3:") &&
				p.DenyType == "explicit" && p.PolicyType == "resource"
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Blocked by S3 bucket policy (explicit deny)",
				DenyType:   "explicit",
				SourceType: "resource",
				SourceARN:  p.PolicyARN,
				Reason:     "The S3 bucket has a bucket policy that explicitly denies this action. Bucket policies apply to all principals accessing the bucket, regardless of their identity policies.",
				Suggestions: []internal.Suggestion{
					{Action: "Check the bucket policy: aws s3api get-bucket-policy --bucket <bucket>", Difficulty: "easy"},
					{Action: "Look for conditions in the bucket policy you might need to satisfy", Difficulty: "easy"},
					{Action: "Request bucket policy modification from the bucket owner", Difficulty: "medium", Requires: "bucket owner"},
				},
			}
		},
	},
	{
		ID:              "RSPOL-002",
		Name:            "S3 Block Public Access",
		Category:        "resource-policy",
		ConfidenceBoost: 0.1,
		Match: func(p internal.ParsedError) bool {
			lower := strings.ToLower(p.Reason + p.RawMessage)
			return strings.HasPrefix(p.Action, "s3:") &&
				(strings.Contains(lower, "public access") || strings.Contains(lower, "block public"))
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Blocked by S3 Block Public Access",
				DenyType:   "explicit",
				SourceType: "resource",
				Reason:     "S3 Block Public Access settings may be preventing your access. These settings can be at the account level or bucket level and override bucket policies that grant public access.",
				Suggestions: []internal.Suggestion{
					{Action: "Check S3 Block Public Access at bucket level", Difficulty: "easy"},
					{Action: "Check S3 Block Public Access at account level", Difficulty: "easy"},
					{Action: "If you need public access, modify the block settings", Difficulty: "medium", Requires: "account/bucket admin"},
				},
			}
		},
	},
	{
		ID:              "RSPOL-003",
		Name:            "KMS Key Policy Deny",
		Category:        "resource-policy",
		ConfidenceBoost: 0.2,
		Match: func(p internal.ParsedError) bool {
			if !strings.HasPrefix(p.Action, "kms:") {
				return false
			}
			// Only match when policy type is unknown or resource-based.
			// If we know the deny came from an SCP or identity policy, don't
			// attribute it to the KMS key policy.
			return p.PolicyType == "" || p.PolicyType == "resource"
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "KMS key policy denies access",
				DenyType:   orDefault(p.DenyType, "unknown"),
				SourceType: "resource",
				SourceARN:  p.PolicyARN,
				Reason:     "KMS key policies are resource-based policies that are the PRIMARY authorization mechanism for KMS. Unlike most AWS services, KMS key policies are required to grant access — IAM policies alone are not sufficient unless the key policy delegates to IAM.",
				Suggestions: []internal.Suggestion{
					{Action: "Check the KMS key policy: aws kms get-key-policy --key-id <key-id> --policy-name default", Difficulty: "easy"},
					{Action: "Ensure the key policy has the standard 'Enable IAM policies' statement", Difficulty: "easy"},
					{Action: "If cross-account, ensure access is configured in both key policy and IAM policy", Difficulty: "medium"},
				},
			}
		},
	},

	// ──────────────────────────── Identity Policy ────────────────────────────────
	{
		ID:              "IDENT-001",
		Name:            "No Identity Policy Allows",
		Category:        "identity",
		ConfidenceBoost: 0.25,
		Match: func(p internal.ParsedError) bool {
			if p.DenyType == "implicit" && p.PolicyType == "identity" {
				return true
			}
			return strings.Contains(strings.ToLower(p.Reason), "no identity-based policy allows")
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			suggestion := "Add the required permission to your role/user policy"
			if p.Action != "" && p.Resource != "" {
				suggestion = "Add to your policy: {\"Effect\": \"Allow\", \"Action\": \"" + p.Action + "\", \"Resource\": \"" + p.Resource + "\"}"
			}
			return internal.Explanation{
				Summary:    "No identity policy grants this permission",
				DenyType:   "implicit",
				SourceType: "identity",
				Reason:     "No identity-based policy (attached to your role/user/group) grants the required permission. This is an implicit deny — there's no explicit Deny statement, but there's also no Allow.",
				Suggestions: []internal.Suggestion{
					{Action: suggestion, Difficulty: "easy", Requires: "IAM admin"},
					{Action: "Attach an AWS managed policy that includes this permission", Difficulty: "easy", Requires: "IAM admin"},
					{Action: "Use a different role/user that already has this permission", Difficulty: "easy"},
				},
			}
		},
	},
	{
		ID:              "IDENT-002",
		Name:            "Wildcard Resource Needed",
		Category:        "identity",
		ConfidenceBoost: 0.1,
		Match: func(p internal.ParsedError) bool {
			wildcardActions := map[string]bool{
				"s3:ListAllMyBuckets":    true,
				"s3:ListBucket":          true,
				"iam:ListUsers":          true,
				"iam:ListRoles":          true,
				"iam:ListGroups":         true,
				"sts:GetCallerIdentity":  true,
				"ec2:DescribeInstances":  true,
				"ec2:DescribeRegions":    true,
				"ec2:DescribeVpcs":       true,
				"iam:CreateRole":         true,
				"iam:CreateUser":         true,
				"dynamodb:ListTables":    true,
				"lambda:ListFunctions":   true,
				"sqs:ListQueues":         true,
				"sns:ListTopics":         true,
			}
			return wildcardActions[p.Action]
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Action may require Resource: \"*\"",
				DenyType:   "implicit",
				SourceType: "identity",
				Reason:     "Some AWS actions require Resource: \"*\" and cannot be scoped to a specific resource ARN. If your policy specifies a specific resource for an action that requires \"*\", it won't match.",
				Suggestions: []internal.Suggestion{
					{Action: "Set Resource to \"*\" for this specific action in your policy", Difficulty: "easy"},
					{Action: "Common actions that require Resource \"*\": ListBuckets, ListUsers, ListRoles, GetCallerIdentity, DescribeRegions", Difficulty: "info"},
				},
			}
		},
	},

	// ──────────────────────────── Session Policy ─────────────────────────────────
	{
		ID:              "SESSION-001",
		Name:            "Session Policy Restriction",
		Category:        "session",
		ConfidenceBoost: 0.25,
		Match: func(p internal.ParsedError) bool {
			return p.PolicyType == "session"
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Blocked by session policy",
				DenyType:   orDefault(p.DenyType, "implicit"),
				SourceType: "session",
				Reason:     "The IAM session was created with a session policy (passed during AssumeRole, GetFederationToken, or similar). Session policies limit the effective permissions to the intersection of the identity policy and the session policy.",
				Suggestions: []internal.Suggestion{
					{Action: "Check the session policy used when creating this session", Difficulty: "medium"},
					{Action: "Remove or broaden the session policy in the AssumeRole call", Difficulty: "easy"},
					{Action: "Add the required permission to the session policy", Difficulty: "easy"},
				},
			}
		},
	},

	// ──────────────────────────── Network Patterns ───────────────────────────────
	{
		ID:              "NET-001",
		Name:            "VPC Endpoint Policy Deny",
		Category:        "network",
		ConfidenceBoost: 0.1,
		Match: func(p internal.ParsedError) bool {
			// Only match if we have CloudTrail context showing VPC endpoint
			return p.VPCEndpointID != "" && p.ParseLevel >= 4
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "May be blocked by VPC endpoint policy",
				DenyType:   orDefault(p.DenyType, "unknown"),
				SourceType: "vpce",
				Reason:     "Your request went through VPC endpoint " + p.VPCEndpointID + ". VPC endpoints can have their own policies that restrict which actions/resources are allowed. Even if your IAM policy allows the action, the VPC endpoint policy might deny it.",
				Suggestions: []internal.Suggestion{
					{Action: "Check the VPC endpoint policy: aws ec2 describe-vpc-endpoints --vpc-endpoint-ids " + p.VPCEndpointID, Difficulty: "easy"},
					{Action: "Modify the endpoint policy to allow this action", Difficulty: "medium", Requires: "VPC admin"},
				},
			}
		},
	},

	// ──────────────────────────── Common Misconfigs ──────────────────────────────
	{
		ID:              "MISC-001",
		Name:            "Wrong Region",
		Category:        "common",
		ConfidenceBoost: 0.05,
		Match: func(p internal.ParsedError) bool {
			if p.Resource == "" || p.Region == "" {
				return false
			}
			resourceRegion := internal.ExtractRegionFromARN(p.Resource)
			return resourceRegion != "" && resourceRegion != p.Region
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Possible region mismatch",
				DenyType:   orDefault(p.DenyType, "unknown"),
				SourceType: "unknown",
				Reason:     "You might be targeting the wrong region. The resource exists in a different region than where you're making the API call.",
				Suggestions: []internal.Suggestion{
					{Action: "Specify the correct region with --region <region>", Difficulty: "easy"},
					{Action: "Check which region the resource was created in", Difficulty: "easy"},
				},
			}
		},
	},
	{
		ID:              "MISC-003",
		Name:            "Root User Restrictions",
		Category:        "common",
		ConfidenceBoost: 0.1,
		Match: func(p internal.ParsedError) bool {
			return strings.Contains(p.Principal, ":root")
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Root user action restricted",
				DenyType:   orDefault(p.DenyType, "unknown"),
				SourceType: orDefault(p.PolicyType, "unknown"),
				Reason:     "Some AWS actions are restricted even for the root user, or SCPs may restrict the root user in member accounts.",
				Suggestions: []internal.Suggestion{
					{Action: "Use an IAM role/user instead of root (best practice)", Difficulty: "easy"},
					{Action: "Check if SCPs restrict root user actions in your account", Difficulty: "medium"},
				},
			}
		},
	},
	{
		ID:              "MISC-004",
		Name:            "Service-Linked Role Restriction",
		Category:        "common",
		ConfidenceBoost: 0.15,
		Match: func(p internal.ParsedError) bool {
			return strings.Contains(p.Resource, "aws-service-role/")
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "Cannot modify service-linked role",
				DenyType:   "explicit",
				SourceType: "identity",
				Reason:     "Service-linked roles are managed by AWS services and have restrictions on modification. You cannot directly modify the policies or trust policies of service-linked roles.",
				Suggestions: []internal.Suggestion{
					{Action: "Do not attempt to modify service-linked roles directly", Difficulty: "info"},
					{Action: "Configure the service that owns the role to adjust its behavior", Difficulty: "medium"},
				},
			}
		},
	},
	{
		ID:              "MISC-005",
		Name:            "S3 404 Masking as 403",
		Category:        "common",
		ConfidenceBoost: 0.1,
		Match: func(p internal.ParsedError) bool {
			return strings.HasPrefix(p.Action, "s3:") &&
				p.Format == "E" &&
				p.DenyType == "" && p.PolicyType == ""
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "S3 Access Denied (may be a 404 in disguise)",
				DenyType:   "unknown",
				SourceType: "unknown",
				Reason:     "S3 returns 'Access Denied' for non-existent objects when you don't have s3:ListBucket permission. This might not be a permission issue — the object might not exist.",
				Suggestions: []internal.Suggestion{
					{Action: "Verify the object actually exists (check path and bucket name)", Difficulty: "easy"},
					{Action: "Check if you have s3:ListBucket on the bucket (for S3 404-masking)", Difficulty: "easy"},
					{Action: "Check bucket policy and your identity policy for s3:GetObject permission", Difficulty: "easy"},
					{Action: "Check if you're being throttled", Difficulty: "easy"},
				},
			}
		},
	},
	{
		ID:              "MISC-006",
		Name:            "EC2 Encoded Authorization Failure",
		Category:        "common",
		ConfidenceBoost: 0.15,
		Match: func(p internal.ParsedError) bool {
			return p.Format == "D" && p.EncodedMessage != ""
		},
		Explain: func(p internal.ParsedError) internal.Explanation {
			return internal.Explanation{
				Summary:    "EC2 authorization failure (encoded message)",
				DenyType:   "unknown",
				SourceType: "unknown",
				Reason:     "EC2 returns an encoded authorization failure message. Decode it with: aws sts decode-authorization-message --encoded-message <message>",
				Suggestions: []internal.Suggestion{
					{Action: "Decode the message: aws sts decode-authorization-message --encoded-message <encoded>", Difficulty: "easy"},
					{Action: "Use --enrich flag to automatically decode the message", Difficulty: "easy"},
					{Action: "Ensure you have sts:DecodeAuthorizationMessage permission", Difficulty: "easy"},
				},
			}
		},
	},
}

// Helper functions for catalog

func orDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}
