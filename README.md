# awsdeny

**Stop guessing why your AWS calls fail.**

`awsdeny` explains AWS AccessDenied errors with actionable fix suggestions. Instead of hours of debugging IAM policies, get a clear explanation in seconds.

## The Problem

```
User: arn:aws:iam::123456789012:role/MyRole is not authorized to perform: s3:GetObject
on resource: arn:aws:s3:::my-bucket/data.csv
```

This tells you **what** failed but not **why** or **how to fix it**. Was it an SCP? A permission boundary? A missing condition? A cross-account trust issue?

## The Solution

```bash
$ awsdeny explain --error "User: arn:aws:iam::123456789012:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::my-bucket/data.csv with an explicit deny in a service control policy"

  Access Denied

  Action:    s3:GetObject
  Resource:  arn:aws:s3:::my-bucket/data.csv
  Principal: arn:aws:iam::123456789012:role/MyRole

  Analysis:
    Type:   Explicit deny
    Source: Service Control Policy (SCP)
    Reason: Your organization has a Service Control Policy (SCP) that explicitly
            denies this action. SCPs are set by your AWS Organization
            administrators and apply to all accounts in the organization (or
            specific OUs). Individual account policies cannot override an SCP deny.

  Suggested fixes:
    1. Contact your organization administrator to review the SCP
    2. Check if the SCP has conditions you can satisfy (e.g., VPC endpoint,
       region, tag)
    3. Use an alternative approach that doesn't require this specific action

  Confidence: very-high (heuristic match)
```

## Installation

### Binary (Linux, macOS, Windows)

Download from [GitHub Releases](https://github.com/leredteam/awsdeny/releases):

```bash
# macOS (Apple Silicon)
curl -Lo awsdeny https://github.com/leredteam/awsdeny/releases/latest/download/awsdeny_darwin_arm64.tar.gz
tar xzf awsdeny_darwin_arm64.tar.gz
chmod +x awsdeny
sudo mv awsdeny /usr/local/bin/

# Linux (amd64)
curl -Lo awsdeny https://github.com/leredteam/awsdeny/releases/latest/download/awsdeny_linux_amd64.tar.gz
tar xzf awsdeny_linux_amd64.tar.gz
chmod +x awsdeny
sudo mv awsdeny /usr/local/bin/
```

### From Source

```bash
go install github.com/leredteam/awsdeny@latest
```

## Usage

### Basic (Free - no credentials needed)

```bash
# Pass error directly
awsdeny explain --error "User: arn:aws:iam::123:role/MyRole is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::bucket/key"

# Pipe from terminal
some-command 2>&1 | awsdeny explain --stdin

# JSON output
awsdeny explain --error "<error>" --format json
```

### Enriched Analysis (Pro - uses AWS credentials)

```bash
# Fetch the actual policy and run simulation
awsdeny explain --error "<error>" --enrich

# Use specific AWS profile
awsdeny explain --error "<error>" --enrich --profile my-profile --region us-east-1
```

### CloudTrail Analysis (Pro)

```bash
# Single event
awsdeny explain --cloudtrail event.json

# Directory of events
awsdeny explain --cloudtrail events/
```

### GitHub Action

```yaml
- name: Deploy
  id: deploy
  run: aws s3 cp ./dist s3://my-bucket/
  continue-on-error: true

- uses: leredteam/awsdeny@v1
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

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Human | `--format human` (default) | Readable terminal output |
| JSON | `--format json` | Structured JSON for automation |
| SARIF | `--format sarif` | For code scanning tools (Pro) |
| GitHub | `--format github` | Markdown for PR comments (Pro) |

## How It Works

`awsdeny` uses a **pragmatic, layered approach**:

| Level | What it does | Requires |
|-------|-------------|----------|
| 1 | Parse error + match against 20+ heuristic patterns | Nothing (offline) |
| 2 | Fetch the actual policy document mentioned in the error | AWS credentials |
| 3 | Run `iam:SimulatePrincipalPolicy` to verify | AWS credentials |
| 4 | Parse CloudTrail events for full context | CloudTrail JSON |

Level 1 is free and works offline. Levels 2-4 require a Pro license and AWS credentials.

## Supported Error Patterns

`awsdeny` recognizes and explains these AccessDenied scenarios:

**Policy Types:**
- SCP explicit/implicit deny (region restrictions, service restrictions)
- Permission boundary limits
- Identity policy missing permissions
- Resource policy denials (S3 bucket policy, KMS key policy)
- Session policy restrictions
- VPC endpoint policy denials

**Conditions:**
- Missing VPC endpoint (`aws:SourceVpce`)
- IP address restrictions (`aws:SourceIp`)
- MFA required (`aws:MultiFactorAuthPresent`)
- Encryption required (`aws:SecureTransport`, SSE)
- Tag-based ABAC mismatches
- Time-based restrictions

**Cross-Account:**
- Missing trust policy for AssumeRole
- Cross-account resource access
- Missing ExternalId

**Common Issues:**
- S3 404 masquerading as 403
- Service-linked role restrictions
- Root user restrictions
- EC2 encoded authorization failures
- Actions requiring `Resource: "*"`

## AWS Permissions for Enrichment

When using `--enrich`, your AWS credentials need:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:SimulatePrincipalPolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

Optional for enhanced analysis:
- `sts:DecodeAuthorizationMessage` (EC2 encoded errors)
- `organizations:DescribePolicy` (SCP details)

If any API call fails, `awsdeny` gracefully falls back to Level 1 analysis.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Could not parse error format |
| 4 | License validation failed |
| 5 | Enrichment failed (fell back to Level 1) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AWSDENY_LICENSE_KEY` | Pro license key |
| `AWSDENY_FORMAT` | Default output format |
| `AWS_PROFILE` | AWS profile for enrichment |
| `AWS_REGION` | AWS region for API calls |

## Free vs Pro

| Feature | Free | Pro |
|---------|------|-----|
| Error parsing + heuristic analysis | Yes | Yes |
| 20+ built-in patterns | Yes | Yes |
| Human-readable + JSON output | Yes | Yes |
| Pipe from stdin | Yes | Yes |
| GitHub Action job summary | Yes | Yes |
| `--enrich` (policy fetch + simulation) | | Yes |
| CloudTrail analysis | | Yes |
| SARIF output | | Yes |
| GitHub Action PR comments | | Yes |
| Priority support | | Yes |

## Security

- **No credentials stored**: Uses ambient AWS credential chain only
- **No telemetry**: Zero phone-home, zero analytics
- **No data transmitted**: All analysis is local (except AWS API calls when using `--enrich`)
- **Credential sanitization**: Output is scanned for accidental credential leaks
- **Offline license validation**: Ed25519 signature verification, no license server

## License

AGPL-3.0. See [COPYING](COPYING).

Commercial licenses available for proprietary use without AGPL compliance.

## Contributing

Bug reports and unmatched error patterns are the most valuable contributions. Please file an issue with:
1. The AccessDenied error message (anonymize account IDs if needed)
2. What you expected `awsdeny` to explain
3. What it actually output

## Related Tools

- [iampg](https://github.com/leredteam/iampg) - Generate least-privilege IAM policies from real AWS API calls
