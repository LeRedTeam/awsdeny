# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-16

### Added
- `explain` command with `--error`, `--stdin`, and `--cloudtrail` input modes
- Error parsing engine supporting 9 known AccessDenied error formats (A-I)
- Heuristic engine with 22 built-in patterns covering:
  - SCP denials (explicit deny, region restrictions, service restrictions)
  - Permission boundary limits
  - Condition failures (VPC endpoint, IP, MFA, encryption, tags, time)
  - Cross-account access (trust policy, resource access, ExternalId)
  - Resource policies (S3 bucket policy, S3 Block Public Access, KMS key policy)
  - Identity policy issues (missing allow, wildcard resource needed)
  - Session policy restrictions
  - VPC endpoint policy denials
  - Common misconfigurations (wrong region, root user, service-linked roles, S3 404-as-403, EC2 encoded errors)
- Confidence scoring algorithm combining parse depth, heuristic match, and enrichment data
- Output formats: human-readable (default), JSON, SARIF, GitHub markdown
- AWS enrichment via `--enrich` flag:
  - Policy fetch (`iam:GetPolicy`, `iam:GetPolicyVersion`)
  - SCP fetch (`organizations:DescribePolicy`)
  - Simulation (`iam:SimulatePrincipalPolicy`)
  - EC2 decode (`sts:DecodeAuthorizationMessage`)
- Graceful degradation (enrichment failure falls back to Level 1)
- CloudTrail event parsing (single events, Records arrays, directories)
- Ed25519 offline license validation for Pro features
- GitHub Action with job summary (free) and PR comments (Pro)
- GoReleaser config for cross-platform binary distribution
- CI/CD workflows (test, lint, release)
- Operation-to-IAM-action mapping for 80+ AWS API operations
- Credential sanitization in output
