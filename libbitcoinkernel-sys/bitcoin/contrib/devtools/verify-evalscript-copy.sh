#!/usr/bin/env bash
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Verifies that a commit copies EvalScript() without modifying the function body.
# Usage: ./contrib/devtools/verify-evalscript-copy.sh <commit_hash>

export LC_ALL=C

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <commit_hash>"
    exit 1
fi

readonly COMMIT="$1"
readonly PARENT="${COMMIT}^"
readonly FILE="src/script/interpreter.cpp"

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/verify-evalscript-copy.XXXXXX")
readonly TEMP_DIR
readonly ORIGINAL_BODY="${TEMP_DIR}/original_body"
readonly COPIED_BODY="${TEMP_DIR}/copied_body"

cleanup() {
    rm -f "$ORIGINAL_BODY" "$COPIED_BODY"
    rmdir "$TEMP_DIR"
}
trap cleanup EXIT

extract_body() {
    local revision="$1"
    local signature_pattern="$2"
    local output="$3"

    git show "${revision}:${FILE}" | awk -v signature_pattern="$signature_pattern" '
        complete { next }
        !found && $0 ~ signature_pattern { found = 1; next }
        found {
            print
            opens = gsub(/{/, "{")
            closes = gsub(/}/, "}")
            if (opens > 0) seen_open = 1
            brace_count += opens - closes
            if (seen_open && brace_count == 0) complete = 1
        }
        END {
            if (!complete) exit 1
        }
    ' > "$output"
}

echo "=== Verifying EvalScript copy in commit $COMMIT ==="

if ! extract_body "$PARENT" '^bool EvalScript.*ScriptExecutionData& execdata, ScriptError' "$ORIGINAL_BODY"; then
    echo "ERROR: Could not extract original EvalScript from parent commit"
    exit 1
fi
if ! extract_body "$COMMIT" '^bool EvalScript.*varops_budget' "$COPIED_BODY"; then
    echo "ERROR: Could not extract copied EvalScript from commit"
    exit 1
fi

echo "Original body: $(wc -l < "$ORIGINAL_BODY" | tr -d ' ') lines"
echo "Copied body:   $(wc -l < "$COPIED_BODY" | tr -d ' ') lines"

if BODY_DIFF=$(diff -u "$ORIGINAL_BODY" "$COPIED_BODY" 2>&1); then
    echo "SUCCESS: Function bodies are identical"
else
    echo "FAILURE: Function bodies differ"
    echo "$BODY_DIFF"
    exit 1
fi
