#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Rewrite requirements.txt and .github/ci/requirements-test.txt with fresh transitive pins and hashes
# (ops #1113). Run it after you add a package or move a TOP-LEVEL pin by hand. A Dependabot bump of a
# top-level pin needs no run: the PR checks install the file as it is.
#
#   tools/relock-console-requirements.sh          # needs `uv` on PATH (pip install uv, in a scratch venv)
#
# What it keeps: the top-level names and their current versions (read from requirements.txt), and each
# file's leading comment block. What it rewrites: everything below the comment block.
# Python 3.9 is the floor for the console (RHEL/Rocky 9), so requirements.txt is resolved for 3.9 and up
# with markers; the test file is resolved for 3.10 and up (pytest 9 needs it), against requirements.txt.
set -euo pipefail

cd "$(dirname "$0")/.."
command -v uv >/dev/null || { echo "uv is not on PATH (python3 -m venv /tmp/uvvenv && /tmp/uvvenv/bin/pip install uv)" >&2; exit 1; }

TOP_LEVEL="flask werkzeug gunicorn psutil pyyaml pystun3"
TEST_TOP_LEVEL="pytest pytest-xdist pytest-timeout"
REQ=requirements.txt
TEST=.github/ci/requirements-test.txt

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The version a top-level name has now: the first unmarked `name==version` line.
pin_of() {
    local name="$1" file="$2" v
    v="$(grep -iE "^${name}==" "$file" | head -1 | sed -E 's/^[^=]+==([^ ;\\]+).*/\1/')"
    [ -n "$v" ] || { echo "no pin for $name in $file" >&2; exit 1; }
    echo "$name==$v"
}

: > "$work/req.in"
for n in $TOP_LEVEL; do pin_of "$n" "$REQ" >> "$work/req.in"; done
: > "$work/test.in"
for n in $TEST_TOP_LEVEL; do pin_of "$n" "$TEST" >> "$work/test.in"; done

# Keep each file's leading comment block (up to the first line that is not a comment).
header_of() { awk '/^#/ {print; next} {exit}' "$1"; }
header_of "$REQ" > "$work/req.head"
header_of "$TEST" > "$work/test.head"

uv pip compile "$work/req.in" --universal --python-version 3.9 --generate-hashes --no-header --no-annotate -o "$work/req.body"
uv pip compile "$work/test.in" -c "$work/req.body" --universal --python-version 3.10 --generate-hashes --no-header --no-annotate -o "$work/test.body"

cat "$work/req.head" "$work/req.body" > "$REQ"
cat "$work/test.head" "$work/test.body" > "$TEST"
echo "rewrote $REQ and $TEST"
