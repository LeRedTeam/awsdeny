# awsdeny

**Instantly understand and fix AWS AccessDenied errors.**

AWS IAM debugging costs teams hours per incident. `awsdeny` converts cryptic AccessDenied errors into clear, actionable explanations — telling you exactly what blocked the request, why, and how to fix it.

[![CI](https://github.com/leredteam/awsdeny/actions/workflows/ci.yml/badge.svg)](https://github.com/leredteam/awsdeny/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](COPYING)

## Why awsdeny?

Every AWS developer has seen this:

```
User: arn:aws:iam::123456789012:role/MyRole is not authorized to perform: s3:GetObject
on resource: arn:aws:s3:::my-bucket/data.csv
```

This error doesn't tell you:
- **Which policy** blocked it (SCP? Permission boundary? Bucket policy? Missing identity policy?)
- **Why** it was denied (a condition failed? wrong region? cross-account trust?)
- **How to fix it** (what exact policy change is needed?)

`awsdeny` answers all three in seconds.

## What it does

```
$ awsdeny explain --error "User: arn:aws:iam::123456789012:role/MyRole is not authorized
to perform: s3:GetObject on resource: arn:aws:s3:::my-bucket/data.csv because no
identity-based policy allows the s3:GetObject action"

  Access Denied

  Action:    s3:GetObject
  Resource:  arn:aws:s3:::my-bucket/data.csv
  Principal: arn:aws:iam::123456789012:role/MyRole

  Analysis:
    Type:   Implicit deny
    Source: Identity-based policy
    Reason: No identity-based policy (attached to your role/user/group) grants the
            required permission. This is an implicit deny — there's no explicit
            Deny statement, but there's also no Allow.

  Suggested fixes:
    1. Add to your policy: {"Effect": "Allow", "Action": "s3:GetObject",
       "Resource": "arn:aws:s3:::my-bucket/data.csv"}
    2. Attach an AWS managed policy that includes this permission
    3. Use a different role/user that already has this permission

  Confidence: very-high (heuristic match)

  CloudWatch Insights query to find similar events:
    fields @timestamp, errorCode, errorMessage, eventName,
    userIdentity.arn | filter errorCode = 'AccessDenied' and eventName =
    'GetObject' and userIdentity.arn = 'arn:aws:iam::123456789012:role/MyRole'
    | sort @timestamp desc | limit 20
```

## Key features

- **23 built-in heuristic patterns** covering SCPs, permission boundaries, resource policies, cross-account access, conditions (VPC endpoint, IP, MFA, encryption, ABAC), and common misconfigurations
- **Ready-to-paste policy fix snippets** for identity policies, trust policies, KMS key policies, permission boundaries, and session policies
- **Action typo detection** — catches mistakes like `s3:GetObjects` instead of `s3:GetObject`
- **CloudWatch Insights queries** — auto-generates the query to find similar events in your logs
- **Offline policy analysis** — analyze local policy files without AWS credentials (`--policy-file`)
- **AWS enrichment** (Pro) — fetches the actual policy, lists attached policies, ranks which one to edit, and simulates the call to verify
- **CloudTrail analysis** (Pro) — parse CloudTrail events with full context (source IP, VPC endpoint, MFA status)
- **CI/CD native** — GitHub Action with PR comments, job summary, SARIF output, and structured outputs
- **Works everywhere** — single binary for Linux, macOS, and Windows; supports AWS, GovCloud, and China partitions

## Installation

### Binary

Download from [GitHub Releases](https://github.com/leredteam/awsdeny/releases):

```bash
# macOS (Apple Silicon)
curl -Lo awsdeny.tar.gz https://github.com/leredteam/awsdeny/releases/latest/download/awsdeny_darwin_arm64.tar.gz
tar xzf awsdeny.tar.gz && sudo mv awsdeny /usr/local/bin/

# Linux (amd64)
curl -Lo awsdeny.tar.gz https://github.com/leredteam/awsdeny/releases/latest/download/awsdeny_linux_amd64.tar.gz
tar xzf awsdeny.tar.gz && sudo mv awsdeny /usr/local/bin/
```

### From source

```bash
go install github.com/leredteam/awsdeny@latest
```

## Quick start

```bash
# Explain an error
awsdeny explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key"

# Pipe from your terminal
aws s3 cp s3://bucket/key . 2>&1 | awsdeny explain --stdin

# Analyze a local policy file (no AWS credentials needed)
awsdeny explain --error "<error>" --policy-file my-policy.json

# JSON output for automation
awsdeny explain --error "<error>" --format json

# Deep analysis with AWS credentials (Pro)
awsdeny explain --error "<error>" --enrich --profile my-profile
```

## How it works

`awsdeny` uses a pragmatic, layered approach — starting with offline heuristics and going deeper with AWS API calls when requested:

| Level | What it does | Requires |
|-------|-------------|----------|
| 1 | Parse error + match against 23 heuristic patterns | Nothing (offline) |
| 2 | Fetch and analyze policy documents + rank attached policies | AWS credentials or `--policy-file` |
| 3 | Run `iam:SimulatePrincipalPolicy` with context to verify | AWS credentials |
| 4 | Parse CloudTrail events for full context (IP, VPC, MFA) | CloudTrail JSON |

Level 1 and `--policy-file` are free and work offline. Levels 2-4 with `--enrich` require a Pro license.

## Supported error patterns

**Policy types:** SCP explicit/implicit deny, permission boundaries, identity policies, resource policies (S3, KMS), session policies, VPC endpoint policies

**Conditions:** VPC endpoint, IP/CIDR/network restrictions, MFA, encryption (SecureTransport, SSE), tag-based ABAC, time-based

**Cross-account:** AssumeRole trust policy issues, resource access, missing ExternalId

**Common issues:** S3 404-as-403, service-linked roles, root user restrictions, EC2 encoded errors, wildcard resource requirements, action typos

## GitHub Action

```yaml
- name: Deploy
  id: deploy
  run: aws s3 cp ./dist s3://my-bucket/
  continue-on-error: true

- uses: LeRedTeam/awsdeny@v0.1.0
  if: failure()
  with:
    error: ${{ steps.deploy.outputs.stderr }}
    enrich: true
    comment-on-pr: true
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    AWSDENY_LICENSE_KEY: ${{ secrets.AWSDENY_LICENSE_KEY }}
```

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| Human | `--format human` (default) | Terminal debugging |
| JSON | `--format json` | Automation and scripting |
| SARIF | `--format sarif` (Pro) | GitHub Code Scanning, VS Code |
| GitHub | `--format github` (Pro) | PR comments |

## AWS permissions for enrichment

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListAttachedRolePolicies",
      "iam:SimulatePrincipalPolicy"
    ],
    "Resource": "*"
  }]
}
```

Optional: `sts:DecodeAuthorizationMessage`, `organizations:DescribePolicy`

If any API call fails, awsdeny gracefully falls back to offline analysis.

## Free vs Pro

| Feature | Free | Pro |
|---------|:----:|:---:|
| Error parsing + 23 heuristic patterns | Yes | Yes |
| Action typo detection | Yes | Yes |
| CloudWatch Insights query | Yes | Yes |
| Human + JSON output | Yes | Yes |
| Offline policy analysis (`--policy-file`) | Yes | Yes |
| Stdin piping | Yes | Yes |
| GitHub Action job summary | Yes | Yes |
| `--enrich` (policy fetch + simulation) | | Yes |
| Ranked policy suggestions | | Yes |
| Principal introspection | | Yes |
| CloudTrail analysis | | Yes |
| SARIF output | | Yes |
| GitHub Action PR comments | | Yes |

## Security

- **No credentials stored** — uses the AWS default credential chain only
- **No telemetry** — zero phone-home, zero analytics, zero tracking
- **No data transmitted** — all analysis is local (AWS API calls only with `--enrich`)
- **Credential sanitization** — output is scanned for access keys, secret keys, session tokens, and known STS token patterns
- **Offline license validation** — cryptographic signature verification, no license server
- **All AWS partitions** — supports `aws`, `aws-us-gov`, and `aws-cn`

## How is this different?

Existing IAM tools generate policies, lint policies, or audit permissions. None of them explain **why a specific API call failed** or **what to change to fix it**. `awsdeny` fills that gap — it's a debugging tool, not a policy tool.

## License

AGPL-3.0 ([COPYING](COPYING)). Commercial licenses available for proprietary use.

## Contributing

The most valuable contributions are unmatched error patterns. Please file an issue with:
1. The AccessDenied error message (anonymize account IDs if needed)
2. What you expected awsdeny to explain
3. What it actually output

## Related

- [iampg](https://github.com/leredteam/iampg) — Generate least-privilege IAM policies from real AWS API calls
