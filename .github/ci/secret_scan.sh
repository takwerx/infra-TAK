#!/usr/bin/env bash
# Secret check (ops #1433): fail when a commit adds a key, token or password.
#
#   .github/ci/secret_scan.sh RANGE        scan the commits in RANGE (a git rev range, e.g. origin/dev..HEAD)
#   .github/ci/secret_scan.sh --last N     scan the last N commits of HEAD (a push with no usable base)
#
# Why a commit range and not just the files: a key that is added and removed inside one PR is gone
# from the files but stays in the public git history for ever. Scanning every commit catches it.
# Why only the new commits: the two old credentials in dev's history (ops #1433) cannot be removed
# without rewriting a public repo, so they are handled by rotating the key, not by this check.
#
# The scanner is gitleaks, downloaded from its GitHub release and checked against a SHA-256 pinned
# here (the same idea as the hashed pip locks in this repo). To move to a new version, change the
# three GITLEAKS_* lines together, from that release's own checksums file.
#
# The findings are printed with the value hidden (--redact): CI logs of a public repo are public.
#
# A finding that is a real false alarm (a made-up password in a test) gets `gitleaks:allow` in a
# comment on the same line. Never allow a real credential: rotate it instead.
#
# Exit codes: 0 clean, 1 a secret was found, 2 the check itself could not run (never a pass).
set -uo pipefail

GITLEAKS_VERSION=8.30.1
GITLEAKS_ASSET="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

root=$(git rev-parse --show-toplevel) || exit 2
cd "$root" || exit 2
config="$root/.github/ci/gitleaks.toml"

case "${1:-}" in
  --last)
    n="${2:-}"
    case "$n" in ''|*[!0-9]*) echo "usage: $0 --last N" >&2; exit 2 ;; esac
    log_opts="-$n HEAD"
    ;;
  ''|-*)
    echo "usage: $0 RANGE | --last N" >&2
    exit 2
    ;;
  *)
    log_opts="$1"
    ;;
esac

# GITLEAKS_BIN lets a developer use their own copy (the self-test and the Studio do). CI downloads
# the pinned one.
bin="${GITLEAKS_BIN:-}"
if [ -z "$bin" ]; then
  if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
    echo "secret_scan.sh: the pinned download is for Linux x86_64; set GITLEAKS_BIN to your own gitleaks $GITLEAKS_VERSION" >&2
    exit 2
  fi
  dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gitleaks-$GITLEAKS_VERSION"
  bin="$dir/gitleaks"
  if [ ! -x "$bin" ]; then
    mkdir -p "$dir" || exit 2
    url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${GITLEAKS_ASSET}"
    curl -sSfL --retry 5 --retry-all-errors --max-time 120 -o "$dir/$GITLEAKS_ASSET" "$url" || {
      echo "secret_scan.sh: could not download $url" >&2; exit 2; }
    got=$(sha256sum "$dir/$GITLEAKS_ASSET" | cut -d' ' -f1)
    if [ "$got" != "$GITLEAKS_SHA256" ]; then
      echo "secret_scan.sh: SHA-256 of $GITLEAKS_ASSET is not the pinned one; refusing to run it" >&2
      exit 2
    fi
    tar -xzf "$dir/$GITLEAKS_ASSET" -C "$dir" gitleaks || exit 2
  fi
fi
[ -x "$bin" ] || { echo "secret_scan.sh: $bin is not executable" >&2; exit 2; }

# A range git cannot read (a branch that was not fetched, a typo) must stop here: gitleaks alone
# would scan nothing and report "no leaks".
# shellcheck disable=SC2086
git rev-list $log_opts >/dev/null 2>&1 || {
  echo "secret_scan.sh: git cannot read the range '$log_opts' (is the base branch fetched?)" >&2
  exit 2
}

report=$(mktemp) || exit 2
trap 'rm -f "$report"' EXIT

# --redact: values never reach the log. --exit-code 1: a finding is exit 1, every other failure is
# a different code, which this script turns into 2 (a scanner that did not run is not a pass).
# shellcheck disable=SC2086  # log_opts is "-N HEAD" or a range: word splitting is the point
"$bin" git --no-banner --redact --exit-code 1 --config "$config" \
  --report-format json --report-path "$report" --log-opts "$log_opts" "$root"
rc=$?

if [ "$rc" -eq 0 ]; then
  echo "secret check: no secrets found in $log_opts"
  exit 0
fi
if [ "$rc" -ne 1 ]; then
  echo "secret_scan.sh: gitleaks stopped with exit $rc; the check did not run" >&2
  exit 2
fi

# A short list a person can act on: rule, file:line, commit. Never the value.
echo "::error::secret check failed: a commit adds something that looks like a key, token or password"
python3 -I - "$report" <<'PY'
import json, sys
for f in json.load(open(sys.argv[1])):
    print("  %s  %s:%s  commit %s" % (f.get("RuleID"), f.get("File"), f.get("StartLine"), (f.get("Commit") or "")[:8]))
print("Remove it from the code AND rotate it (it stays in git history). A made-up value in a test: add 'gitleaks:allow' in a comment on that line.")
PY
exit 1
