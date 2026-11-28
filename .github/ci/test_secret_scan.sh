#!/usr/bin/env bash
# Proof test for .github/ci/secret_scan.sh (ops #1433). CI runs it in the secret-scan job; run it
# locally with your own gitleaks:   GITLEAKS_BIN=$(command -v gitleaks) bash .github/ci/test_secret_scan.sh
#
# It builds throw-away git repos in a temp folder, with made-up credentials created at run time
# (never written in this file, so no scanner flags this file). It checks that the check:
#   1. fails when a commit adds a key, and does not print the key;
#   2. still fails when the NEXT commit removes the key (git history keeps it);
#   3. fails for a private-key block too;
#   4. passes for a clean range, and for a made-up value marked gitleaks:allow;
#   5. fails (exit 2, not 0) when the range is not a real range, so a broken check is never a pass.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
fails=0

ok()   { echo "ok   - $1"; }
bad()  { echo "FAIL - $1"; fails=$((fails + 1)); }

newrepo() {
  r="$tmp/$1"
  mkdir -p "$r/.github/ci"
  cp "$here/secret_scan.sh" "$here/gitleaks.toml" "$r/.github/ci/"
  git -C "$r" init -q
  git -C "$r" config user.email t@example.invalid
  git -C "$r" config user.name t
  git -C "$r" config commit.gpgsign false
  echo "print('hello')" > "$r/app.py"
  git -C "$r" add -A
  git -C "$r" commit -q -m base
  git -C "$r" branch base
}

# A made-up value with enough randomness for the scanner. Never printed, never written to this file.
fake=$(python3 -I -c "import secrets; print(secrets.token_urlsafe(30))")

scan() { # scan REPO RANGE -> sets $out and $rc
  out=$(cd "$tmp/$1" && bash .github/ci/secret_scan.sh "$2" 2>&1)
  rc=$?
}

# 1 + 2: a key is added, then removed in the next commit.
newrepo add-remove
printf 'ors_api_key = "%s"\n' "$fake" > "$tmp/add-remove/plugin.py"
git -C "$tmp/add-remove" add -A && git -C "$tmp/add-remove" commit -q -m "add key"
scan add-remove "base..HEAD"
[ "$rc" -eq 1 ] && ok "a commit that adds a key fails the check" || bad "key commit: exit $rc, wanted 1"
case "$out" in *"$fake"*) bad "the log shows the key value" ;; *) ok "the log does not show the key value" ;; esac
case "$out" in *plugin.py*) ok "the log names the file" ;; *) bad "the log does not name the file" ;; esac

git -C "$tmp/add-remove" rm -q plugin.py && git -C "$tmp/add-remove" commit -q -m "remove key"
scan add-remove "base..HEAD"
[ "$rc" -eq 1 ] && ok "removing the key in the next commit still fails (it stays in history)" || bad "add+remove: exit $rc, wanted 1"

# 3: a private-key block, put together here so this file holds no key block.
newrepo pem
{
  printf -- '-----BEGIN %s PRIVATE KEY-----\n' RSA
  python3 -I -c "import secrets; [print(secrets.token_urlsafe(48)) for _ in range(6)]"
  printf -- '-----END %s PRIVATE KEY-----\n' RSA
} > "$tmp/pem/id_test"
git -C "$tmp/pem" add -A && git -C "$tmp/pem" commit -q -m "add private key"
scan pem "base..HEAD"
[ "$rc" -eq 1 ] && ok "a private-key block fails the check" || bad "private key: exit $rc, wanted 1"

# 4: clean range, and a made-up value that is marked.
newrepo clean
echo "x = 1" > "$tmp/clean/more.py"
git -C "$tmp/clean" add -A && git -C "$tmp/clean" commit -q -m "clean change"
scan clean "base..HEAD"
[ "$rc" -eq 0 ] && ok "a clean range passes" || bad "clean range: exit $rc, wanted 0"

printf 'ors_api_key = "%s"  # gitleaks:allow\n' "$fake" > "$tmp/clean/fixture.py"
git -C "$tmp/clean" add -A && git -C "$tmp/clean" commit -q -m "marked fixture"
scan clean "base..HEAD"
[ "$rc" -eq 0 ] && ok "a made-up value marked gitleaks:allow passes" || bad "marked value: exit $rc, wanted 0"

# 5: a range that does not exist must not look like a pass.
scan clean "no-such-ref..HEAD"
[ "$rc" -eq 2 ] && ok "a range that cannot be read is exit 2, not a pass" || bad "bad range: exit $rc, wanted 2"

# 6: the --last form (a push with no usable base) sees the key commit.
scan add-remove "--last"
[ "$rc" -eq 2 ] && ok "--last without a number is a usage error (exit 2)" || bad "--last alone: exit $rc, wanted 2"
out=$(cd "$tmp/add-remove" && bash .github/ci/secret_scan.sh --last 5 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok "--last 5 sees the key in recent history" || bad "--last 5: exit $rc, wanted 1"

if [ "$fails" -ne 0 ]; then
  echo "$fails check(s) failed"
  exit 1
fi
echo "all secret-check proof tests passed"
