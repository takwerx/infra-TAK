#!/bin/bash
# Regenerate static/fonts/material-symbols-outlined.woff2 — the SUBSET icon font.
#
# The console ships fonts locally so it renders correctly with no route to the
# internet (Setup AP, air-gapped). Material Symbols is a LIGATURE font: any icon
# name NOT in the subset paints as its raw text — "shopping_cart" in the sidebar
# instead of a cart (2026-08-09, caused by subsetting from templates/ alone while
# the sidebar nav is emitted from app.py).
#
# So: whenever you add a new <span class="material-symbols-outlined">name</span>
# ANYWHERE — app.py, templates/, static/ — re-run this.
#
#   ./scripts/regen-icon-font.sh
#
# Prints the icon list it found; diff it against the previous run if surprised.
set -euo pipefail
cd "$(dirname "$0")/.."
UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36'

# Names set from JavaScript (el.textContent = 'visibility_off') are invisible to a
# markup scan — the password toggle rendered an eye followed by the literal text
# "_off" because of exactly this. Keep such names here, explicitly.
EXTRA_ICONS='visibility_off'

ICONS=$( { grep -rhoE 'material-symbols-outlined[^>]*>[^<]{1,40}' app.py templates/ static/ 2>/dev/null \
    | sed 's/.*>//'
  # any string assigned to .textContent that looks like an icon ligature
  grep -rhoE "textContent\s*=\s*(show \? )?'[a-z0-9_]{3,30}'" app.py templates/ static/ 2>/dev/null \
    | grep -oE "'[a-z0-9_]+'" | tr -d "'"
  printf '%s\n' $EXTRA_ICONS
  } | tr -d ' \t' | grep -E '^[a-z0-9_]+$' | sort -u)
COUNT=$(printf '%s\n' "$ICONS" | wc -l | tr -d ' ')
echo "Found $COUNT distinct icons:"; printf '%s\n' "$ICONS" | tr '\n' ' '; echo
CSV=$(printf '%s\n' "$ICONS" | tr '\n' ',' | sed 's/,$//')

CSS=$(curl -fsS -A "$UA" \
  "https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0&icon_names=$CSV")
URL=$(printf '%s' "$CSS" | grep -o 'https://fonts.gstatic.com/[^)]*' || true)
[ -n "$URL" ] || { echo "ERROR: no font URL returned — an icon name is probably invalid"; exit 1; }

curl -fsS -A "$UA" "$URL" -o static/fonts/material-symbols-outlined.woff2
echo "Wrote static/fonts/material-symbols-outlined.woff2 ($(wc -c < static/fonts/material-symbols-outlined.woff2) bytes)"
