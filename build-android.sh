#!/usr/bin/env bash
# Build wireproxy for Android arm64 and copy into the Unity native libs folder.
#
# Usage:
#   ./wireproxy/build-android.sh
#
# Requires: Go 1.26+ (or whatever go.mod specifies)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/Bifrost.Unity/Assets/Plugins/Android/libs/arm64-v8a"
OUTPUT_FILE="$OUTPUT_DIR/libwireproxy.so"

cd "$SCRIPT_DIR"

TAG=$(git describe --always --tags $(git rev-list --tags --max-count=1 2>/dev/null || echo HEAD) --match 'v*' 2>/dev/null || echo "dev")

echo "Building wireproxy ($TAG) for android/arm64..."

GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
    go build \
    -trimpath \
    -ldflags "-s -w -X 'main.version=${TAG}'" \
    -o "$OUTPUT_FILE" \
    ./cmd/wireproxy

echo "Built: $OUTPUT_FILE ($(du -h "$OUTPUT_FILE" | cut -f1))"
