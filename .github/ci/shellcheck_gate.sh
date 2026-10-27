#!/usr/bin/env bash
# Shell lint, errors only, with a baseline so existing findings don't block a PR.
#
#   .github/ci/shellcheck_gate.sh            fail on any error-level finding not in the baseline
#   .github/ci/shellcheck_gate.sh --update   rewrite the baseline from the current tree
#
# Baseline lines are "<file> <SC code>" with no line numbers, so editing a file
# doesn't shift them. Lower the baseline by fixing a finding and running --update;
# never run --update to make a new finding pass.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2
baseline=.github/ci/shellcheck-baseline.txt

files=()
while IFS= read -r -d '' f; do
  case "$f" in
    *.sh) files+=("$f") ;;
    *.*) ;;
    *) head -c 200 "$f" 2>/dev/null | head -n1 | grep -qE '^#!.*(ba|da|k)?sh([[:space:]]|$)' && files+=("$f") ;;
  esac
done < <(git ls-files -z)

raw=$(shellcheck -S error -f gcc "${files[@]}" 2>&1)
rc=$?
if [ "$rc" -gt 1 ]; then
  echo "$raw"
  echo "shellcheck could not process every file (exit $rc)" >&2
  exit 2
fi

# "path:line:col: error: message [SC1234]" -> "path SC1234"
current=$(printf '%s\n' "$raw" | sed -nE 's/^([^:]+):[0-9]+:[0-9]+: error: .*\[(SC[0-9]+)\]$/\1 \2/p' | LC_ALL=C sort)

if [ "${1:-}" = "--update" ]; then
  printf '%s\n' "$current" | sed '/^$/d' > "$baseline"
  echo "wrote $(wc -l < "$baseline" | tr -d ' ') entr(ies) to $baseline"
  exit 0
fi

known=$(LC_ALL=C sort "$baseline" 2>/dev/null)
new=$(LC_ALL=C comm -13 <(printf '%s\n' "$known") <(printf '%s\n' "$current") | sed '/^$/d')
gone=$(LC_ALL=C comm -23 <(printf '%s\n' "$known") <(printf '%s\n' "$current") | sed '/^$/d')

echo "shellcheck: ${#files[@]} script(s), $(printf '%s\n' "$current" | sed '/^$/d' | wc -l | tr -d ' ') error-level finding(s), $(printf '%s\n' "$known" | sed '/^$/d' | wc -l | tr -d ' ') in the baseline"

if [ -n "$gone" ]; then
  echo "::notice::Baseline entries no longer reported (fixed? run .github/ci/shellcheck_gate.sh --update): $(printf '%s' "$gone" | tr '\n' ';')"
fi

if [ -n "$new" ]; then
  printf '%s\n' "$new" | while read -r file code; do
    # Show the full shellcheck message(s) for each new finding.
    printf '%s\n' "$raw" | grep -F "$file:" | grep -F "[$code]" | sed -E 's/^([^:]+):([0-9]+):([0-9]+): error: (.*)$/::error file=\1,line=\2,col=\3::\4/'
  done
  echo "New shellcheck error(s) above. Fix them; the baseline only holds findings that existed before this check." >&2
  exit 1
fi
echo "no new shellcheck errors"
