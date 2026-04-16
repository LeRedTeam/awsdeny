package parse

import "regexp"

// Compiled regex patterns for known AccessDenied error formats.
// Ordered from most specific to least specific.
var (
	// Format I: Enriched with SCP ARN
	// "...with an explicit deny in a service control policy arn:aws:organizations::111:policy/o-xxx/p-yyy"
	reEnrichedWithPolicyARN = regexp.MustCompile(
		`User: (?P<principal>arn:aws:[^\s]+) is not authorized to perform: (?P<action>[^\s]+) on resource: (?P<resource>arn:aws:[^\s]+) with an (?P<deny_type>explicit deny|implicit deny) in a (?P<policy_type>service control policy|identity-based policy|resource-based policy|permissions boundary|session policy) (?P<policy_arn>arn:aws:[^\s]+)`,
	)

	// Format B: Enriched with policy type (no ARN)
	// "...with an explicit deny in a service control policy"
	reEnrichedDeny = regexp.MustCompile(
		`User: (?P<principal>arn:aws:[^\s]+) is not authorized to perform: (?P<action>[^\s]+) on resource: (?P<resource>arn:aws:[^\s]+) with an (?P<deny_type>explicit deny|implicit deny) in a (?P<policy_type>service control policy|identity-based policy|resource-based policy|permissions boundary|session policy)`,
	)

	// Format C: Enriched with reason
	// "...because no identity-based policy allows the s3:GetObject action"
	reEnrichedReason = regexp.MustCompile(
		`User: (?P<principal>arn:aws:[^\s]+) is not authorized to perform: (?P<action>[^\s]+) on resource: (?P<resource>arn:aws:[^\s]+) because (?P<reason>.+)$`,
	)

	// Format A: Classic
	// "User: arn:aws:iam::123:user/dev is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key"
	reClassic = regexp.MustCompile(
		`User: (?P<principal>arn:aws:[^\s]+) is not authorized to perform: (?P<action>[^\s]+) on resource: (?P<resource>arn:aws:[^\s]+)`,
	)

	// Format D: EC2 Encoded
	// "UnauthorizedOperation: You are not authorized to perform this operation. Encoded authorization failure message: <base64>"
	reEC2Encoded = regexp.MustCompile(
		`(?:UnauthorizedOperation|Client\.UnauthorizedOperation)[:\s].*Encoded authorization failure message: (?P<encoded>[A-Za-z0-9+/=_-]+)`,
	)

	// Format G: AWS CLI wrapper
	// "An error occurred (AccessDeniedException) when calling the Invoke operation: <inner message>"
	reCLIWrapper = regexp.MustCompile(
		`An error occurred \((?P<error_code>\w+)\) when calling the (?P<operation>\w+) operation: (?P<message>.+)`,
	)

	// Format E: S3 Minimal with operation
	// "An error occurred (AccessDenied) when calling the GetObject operation: Access Denied"
	reS3Minimal = regexp.MustCompile(
		`(?i)^access denied$`,
	)

	// Reason extraction from enriched "because" messages
	reReasonNoPolicy = regexp.MustCompile(
		`no (?P<policy_type>identity-based policy|resource-based policy) allows the (?P<action>[^\s]+) action`,
	)

	// Principal-only extraction for partial matches
	rePrincipal = regexp.MustCompile(`arn:aws:(?:iam|sts)::[0-9]+:(?:user|role|assumed-role|federated-user)/[^\s"']+`)
	// Tighter pattern: service must be 2-30 lowercase chars, action must be PascalCase and 3+ chars
	reAction = regexp.MustCompile(`[a-z]{2,30}:[A-Z][a-zA-Z]{2,}`)
)

// policyTypeMap normalizes policy type strings from AWS error messages.
var policyTypeMap = map[string]string{
	"service control policy": "scp",
	"identity-based policy":  "identity",
	"resource-based policy":  "resource",
	"permissions boundary":   "boundary",
	"session policy":         "session",
}

// operationToAction maps AWS API operation names to IAM action names.
var operationToAction = map[string]string{
	// S3
	"GetObject":          "s3:GetObject",
	"PutObject":          "s3:PutObject",
	"DeleteObject":       "s3:DeleteObject",
	"ListObjects":        "s3:ListBucket",
	"ListObjectsV2":      "s3:ListBucket",
	"HeadObject":         "s3:GetObject",
	"CopyObject":         "s3:PutObject",
	"HeadBucket":         "s3:ListBucket",
	"GetBucketLocation":  "s3:GetBucketLocation",
	"GetBucketPolicy":    "s3:GetBucketPolicy",
	"PutBucketPolicy":    "s3:PutBucketPolicy",
	"ListBuckets":        "s3:ListAllMyBuckets",
	"CreateBucket":       "s3:CreateBucket",
	"DeleteBucket":       "s3:DeleteBucket",
	"GetBucketAcl":       "s3:GetBucketAcl",
	"PutBucketAcl":       "s3:PutBucketAcl",
	"GetObjectAcl":       "s3:GetObjectAcl",
	"PutObjectAcl":       "s3:PutObjectAcl",
	"GetBucketVersioning": "s3:GetBucketVersioning",
	// Lambda
	"Invoke":          "lambda:InvokeFunction",
	"CreateFunction":  "lambda:CreateFunction",
	"DeleteFunction":  "lambda:DeleteFunction",
	"GetFunction":     "lambda:GetFunction",
	"UpdateFunctionCode": "lambda:UpdateFunctionCode",
	"ListFunctions":   "lambda:ListFunctions",
	// DynamoDB
	"GetItem":         "dynamodb:GetItem",
	"PutItem":         "dynamodb:PutItem",
	"DeleteItem":      "dynamodb:DeleteItem",
	"UpdateItem":      "dynamodb:UpdateItem",
	"Query":           "dynamodb:Query",
	"Scan":            "dynamodb:Scan",
	"CreateTable":     "dynamodb:CreateTable",
	"DeleteTable":     "dynamodb:DeleteTable",
	"DescribeTable":   "dynamodb:DescribeTable",
	"ListTables":      "dynamodb:ListTables",
	// STS
	"AssumeRole":         "sts:AssumeRole",
	"AssumeRoleWithSAML": "sts:AssumeRoleWithSAML",
	"AssumeRoleWithWebIdentity": "sts:AssumeRoleWithWebIdentity",
	"GetCallerIdentity":  "sts:GetCallerIdentity",
	"GetSessionToken":    "sts:GetSessionToken",
	// EC2
	"RunInstances":       "ec2:RunInstances",
	"DescribeInstances":  "ec2:DescribeInstances",
	"StartInstances":     "ec2:StartInstances",
	"StopInstances":      "ec2:StopInstances",
	"TerminateInstances": "ec2:TerminateInstances",
	"CreateSecurityGroup": "ec2:CreateSecurityGroup",
	"AuthorizeSecurityGroupIngress": "ec2:AuthorizeSecurityGroupIngress",
	// IAM
	"CreateRole":    "iam:CreateRole",
	"DeleteRole":    "iam:DeleteRole",
	"GetRole":       "iam:GetRole",
	"ListRoles":     "iam:ListRoles",
	"AttachRolePolicy": "iam:AttachRolePolicy",
	"DetachRolePolicy": "iam:DetachRolePolicy",
	"CreateUser":    "iam:CreateUser",
	"DeleteUser":    "iam:DeleteUser",
	"ListUsers":     "iam:ListUsers",
	"GetUser":       "iam:GetUser",
	// SQS
	"SendMessage":     "sqs:SendMessage",
	"ReceiveMessage":  "sqs:ReceiveMessage",
	"DeleteMessage":   "sqs:DeleteMessage",
	"CreateQueue":     "sqs:CreateQueue",
	"DeleteQueue":     "sqs:DeleteQueue",
	"GetQueueUrl":     "sqs:GetQueueUrl",
	// SNS
	"Publish":           "sns:Publish",
	"Subscribe":         "sns:Subscribe",
	"CreateTopic":       "sns:CreateTopic",
	"DeleteTopic":       "sns:DeleteTopic",
	"ListSubscriptions": "sns:ListSubscriptions",
	// KMS
	"Decrypt":       "kms:Decrypt",
	"Encrypt":       "kms:Encrypt",
	"GenerateDataKey": "kms:GenerateDataKey",
	"CreateKey":     "kms:CreateKey",
	"DescribeKey":   "kms:DescribeKey",
	"ListKeys":      "kms:ListKeys",
	// Secrets Manager
	"GetSecretValue":    "secretsmanager:GetSecretValue",
	"CreateSecret":      "secretsmanager:CreateSecret",
	"DeleteSecret":      "secretsmanager:DeleteSecret",
	"ListSecrets":       "secretsmanager:ListSecrets",
	"PutSecretValue":    "secretsmanager:PutSecretValue",
	// CloudFormation
	"CreateStack":  "cloudformation:CreateStack",
	"DeleteStack":  "cloudformation:DeleteStack",
	"DescribeStacks": "cloudformation:DescribeStacks",
	"UpdateStack":  "cloudformation:UpdateStack",
	// ECR
	"GetAuthorizationToken": "ecr:GetAuthorizationToken",
	"BatchGetImage":         "ecr:BatchGetImage",
	"PutImage":              "ecr:PutImage",
	// ECS
	"RunTask":       "ecs:RunTask",
	"StopTask":      "ecs:StopTask",
	"DescribeTasks": "ecs:DescribeTasks",
	"ListTasks":     "ecs:ListTasks",
	// SSM
	"GetParameter":     "ssm:GetParameter",
	"GetParameters":    "ssm:GetParameters",
	"PutParameter":     "ssm:PutParameter",
	"DescribeParameters": "ssm:DescribeParameters",
}
