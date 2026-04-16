#!/bin/sh
set -e

# Set license key from input
if [ -n "$INPUT_LICENSE_KEY" ]; then
    export AWSDENY_LICENSE_KEY="$INPUT_LICENSE_KEY"
fi

# Build command arguments as discrete values (no eval)
set -- explain

if [ -n "$INPUT_ERROR" ]; then
    set -- "$@" --error "$INPUT_ERROR"
fi

if [ -n "$INPUT_CLOUDTRAIL" ]; then
    set -- "$@" --cloudtrail "$INPUT_CLOUDTRAIL"
fi

if [ "$INPUT_ENRICH" = "true" ]; then
    set -- "$@" --enrich
fi

# Run once with JSON to capture structured data (discard stderr so warnings don't corrupt JSON)
JSON_OUTPUT=$(awsdeny "$@" --format json 2>/dev/null) || true

# Display human-readable output to the log
awsdeny "$@" --format human || true

# Generate GitHub markdown once, reuse for summary and PR comment
GITHUB_MD=$(awsdeny "$@" --format github 2>/dev/null) || true

# Write to job summary
if [ -n "$GITHUB_STEP_SUMMARY" ] && [ -n "$GITHUB_MD" ]; then
    echo "$GITHUB_MD" >> "$GITHUB_STEP_SUMMARY"
fi

# Post PR comment if requested
if [ "$INPUT_COMMENT_ON_PR" = "true" ] && [ -n "$GITHUB_TOKEN" ]; then
    PR_NUMBER=$(echo "$GITHUB_REF" | sed -n 's|refs/pull/\([0-9]*\)/.*|\1|p')
    if [ -n "$PR_NUMBER" ] && [ -n "$GITHUB_MD" ]; then
        ESCAPED=$(printf '%s' "$GITHUB_MD" | jq -Rs .)
        curl -sf \
            -H "Authorization: token $GITHUB_TOKEN" \
            -H "Content-Type: application/json" \
            "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
            -d "{\"body\": $ESCAPED}" \
            >/dev/null 2>&1 || echo "Warning: Failed to post PR comment" >&2
    fi
fi

# Set outputs from the JSON we already captured
echo "explanation<<EOF" >> "$GITHUB_OUTPUT"
echo "$JSON_OUTPUT" >> "$GITHUB_OUTPUT"
echo "EOF" >> "$GITHUB_OUTPUT"

CONFIDENCE=$(printf '%s' "$JSON_OUTPUT" | jq -r '.confidence // empty' 2>/dev/null || true)
ACTION_NAME=$(printf '%s' "$JSON_OUTPUT" | jq -r '.action // empty' 2>/dev/null || true)
RESOURCE=$(printf '%s' "$JSON_OUTPUT" | jq -r '.resource // empty' 2>/dev/null || true)

echo "confidence=$CONFIDENCE" >> "$GITHUB_OUTPUT"
echo "action=$ACTION_NAME" >> "$GITHUB_OUTPUT"
echo "resource=$RESOURCE" >> "$GITHUB_OUTPUT"
