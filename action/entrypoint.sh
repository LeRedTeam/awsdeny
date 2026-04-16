#!/bin/sh
set -e

# Set license key from input
if [ -n "$INPUT_LICENSE_KEY" ]; then
    export AWSDENY_LICENSE_KEY="$INPUT_LICENSE_KEY"
fi

# Build args
ARGS="explain"

if [ -n "$INPUT_ERROR" ]; then
    ARGS="$ARGS --error \"$INPUT_ERROR\""
fi

if [ -n "$INPUT_CLOUDTRAIL" ]; then
    ARGS="$ARGS --cloudtrail $INPUT_CLOUDTRAIL"
fi

if [ "$INPUT_ENRICH" = "true" ]; then
    ARGS="$ARGS --enrich"
fi

if [ -n "$INPUT_FORMAT" ]; then
    ARGS="$ARGS --format $INPUT_FORMAT"
fi

# Run awsdeny and capture output
OUTPUT=$(eval awsdeny $ARGS 2>&1) || true

echo "$OUTPUT"

# Write to job summary
if [ -n "$GITHUB_STEP_SUMMARY" ]; then
    # Get github-formatted output for summary
    SUMMARY=$(eval awsdeny $ARGS --format github 2>&1) || true
    echo "$SUMMARY" >> "$GITHUB_STEP_SUMMARY"
fi

# Post PR comment if requested
if [ "$INPUT_COMMENT_ON_PR" = "true" ] && [ -n "$GITHUB_TOKEN" ]; then
    PR_NUMBER=$(echo "$GITHUB_REF" | grep -oP '(?<=pull/)\d+' || true)
    if [ -n "$PR_NUMBER" ]; then
        COMMENT=$(eval awsdeny $ARGS --format github 2>&1) || true
        ESCAPED=$(echo "$COMMENT" | jq -Rs .)
        curl -s -X POST \
            -H "Authorization: token $GITHUB_TOKEN" \
            -H "Content-Type: application/json" \
            "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
            -d "{\"body\": $ESCAPED}"
    fi
fi

# Set outputs
JSON_OUTPUT=$(eval awsdeny $ARGS --format json 2>&1) || true
echo "explanation<<EOF" >> "$GITHUB_OUTPUT"
echo "$JSON_OUTPUT" >> "$GITHUB_OUTPUT"
echo "EOF" >> "$GITHUB_OUTPUT"

CONFIDENCE=$(echo "$JSON_OUTPUT" | jq -r '.confidence // empty' 2>/dev/null || true)
ACTION_NAME=$(echo "$JSON_OUTPUT" | jq -r '.action // empty' 2>/dev/null || true)
RESOURCE=$(echo "$JSON_OUTPUT" | jq -r '.resource // empty' 2>/dev/null || true)

echo "confidence=$CONFIDENCE" >> "$GITHUB_OUTPUT"
echo "action=$ACTION_NAME" >> "$GITHUB_OUTPUT"
echo "resource=$RESOURCE" >> "$GITHUB_OUTPUT"
