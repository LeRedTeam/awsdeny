# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-17

### Added
- `explain` command with `--error`, `--stdin`, `--cloudtrail`, and `--policy-file` input modes
- Error parsing engine supporting 9 known AccessDenied error formats (A-I)
  including non-ARN resource identifiers (e.g., Secrets Manager secret names)
- 23 heuristic patterns covering:
  - SCP denials (explicit deny, region restrictions, service restrictions)
  - Permission boundary limits (with policy fix snippets)
  - Condition failures (VPC endpoint, IP/CIDR/network, MFA, encryption, tags, time)
  - Cross-account access (trust policy with snippet, resource access, ExternalId)
  - Resource policies (S3 bucket policy, S3 Block Public Access, KMS key policy with snippet)
  - Identity policy issues (missing allow with snippet, wildcard resource needed)
  - Session policy restrictions (with policy fix snippet)
  - VPC endpoint policy denials
  - Common misconfigurations (wrong region, root user, service-linked roles, S3 404-as-403, EC2 encoded errors)
  - Action name typo detection with "Did you mean?" suggestions (Levenshtein distance)
- AWS enrichment via `--enrich` flag (Pro):
  - Policy fetch (`iam:GetPolicy`, `iam:GetPolicyVersion`)
  - SCP fetch (`organizations:DescribePolicy`)
  - Principal introspection (`iam:ListAttachedRolePolicies`) with ranked policy suggestions
  - Simulation (`iam:SimulatePrincipalPolicy`) with CloudTrail context entries
  - EC2 decode (`sts:DecodeAuthorizationMessage`)
  - STS assumed-role ARN normalization for SimulatePrincipalPolicy
- Offline policy analysis via `--policy-file` flag (Free tier)
- Graceful degradation (enrichment failure falls back to Level 1)
- CloudTrail event parsing (single events, Records arrays, directories with summary)
- Output formats: human-readable (default), JSON, SARIF (with confidence-mapped levels), GitHub markdown
- CloudWatch Logs Insights query tip in human output
- Ed25519 offline license validation for Pro features
- GitHub Action with Docker, job summary (free), PR comments (Pro), structured outputs
- GoReleaser config for cross-platform binary distribution (6 targets)
- CI/CD workflows (test + lint + 127 functional tests, 8 GitHub Action integration tests, release)
- AWS partition support (aws, aws-us-gov, aws-cn) in all regex patterns and ARN construction
- Operation-to-IAM-action mapping for 100+ AWS API operations
- Credential sanitization (AKIA/ASIA keys, secret keys, session tokens, known STS token base64 prefixes)
- IAM-style wildcard matching with mid-string `*` support (glob matching)
- Makefile for development builds with license key embedding
