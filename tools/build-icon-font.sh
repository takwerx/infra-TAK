#!/usr/bin/env bash
# Regenerate static/fonts/material-symbols-outlined.woff2
#
# WHY THIS EXISTS: the subset was originally produced ad hoc with no recorded
# recipe, and it silently shipped WITHOUT the `dark_mode` glyph. The console is
# dark by default, so `light_mode` (the icon shown in dark mode) was captured and
# `dark_mode` — which only renders once a user switches to light mode — was not.
# With font-display:block and no matching ligature the browser falls back to the
# literal text, so light-mode users saw a giant "DARK_MODE" word in the sidebar
# instead of an icon (field report, 2026-08-31). An unreproducible binary asset is
# how that goes unnoticed; this script makes the glyph list reviewable in a diff.
#
# Requires: pip install fonttools brotli
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="static/fonts/material-symbols-outlined.woff2"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Every ligature the console renders. ADD TO THIS LIST when you use a new icon —
# a name that is not here renders as raw text, not as a missing glyph.
LIGS="add_circle add_circle_outline check cloud_done control_point dark_mode dashboard
delete delete_outline description drive_folder_upload expand_more fact_check file_upload
filter_alt folder_open folder_zip group help help_outline hide home_work https hub launch
light_mode list local_grocery_store lock lock_open lock_open_right lock_outline
maps_home_work open_in_new outgoing_mail people people_alt people_outline policy
remove_red_eye report_problem rocket_launch router shield shield_lock shield_locked
shield_toggle shopping_cart travel tune upload visibility visibility_off warning
warning_amber"

URL='https://raw.githubusercontent.com/google/material-design-icons/master/variablefont/MaterialSymbolsOutlined%5BFILL%2CGRAD%2Copsz%2Cwght%5D.ttf'
echo "Downloading upstream variable font..."
curl -fsSL -o "$TMP/var.ttf" "$URL"

echo "Instancing to a static face (FILL=0 GRAD=0 opsz=24 wght=400)..."
python3 - "$TMP" <<'PY'
import sys
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer
tmp = sys.argv[1]
f = TTFont(f"{tmp}/var.ttf")
inst = instancer.instantiateVariableFont(
    f, {'FILL': 0, 'GRAD': 0, 'opsz': 24, 'wght': 400}, inplace=False)
inst.save(f"{tmp}/static.ttf")
PY

echo "Resolving ligature target glyphs..."
python3 - "$TMP" <<'PY'
import sys, os
from fontTools.ttLib import TTFont
tmp = sys.argv[1]
want = set(os.environ['LIGS'].split())
f = TTFont(f"{tmp}/static.ttf")
tgt = {}
for lk in f['GSUB'].table.LookupList.Lookup:
    for st in lk.SubTable:
        st = getattr(st, 'ExtSubTable', st)
        if getattr(st, 'ligatures', None):
            for first, ls in st.ligatures.items():
                for l in ls:
                    tgt[(first + ''.join(l.Component)).replace('underscore', '_')] = l.LigGlyph
missing = sorted(w for w in want if w not in tgt)
if missing:
    raise SystemExit(f"ERROR: not in upstream font: {missing}")
open(f"{tmp}/glyphs.txt", "w").write(','.join(sorted({tgt[w] for w in want})))
PY

LETTERS="$(printf '%s' "$LIGS" | tr -d ' \n' | fold -w1 | sort -u | tr -d '\n')"

# --no-layout-closure is REQUIRED: without it the `liga` closure over a-z drags in
# all ~4275 icon glyphs and the file balloons from ~5K to ~240K.
pyftsubset "$TMP/static.ttf" \
  --glyphs="$(cat "$TMP/glyphs.txt")" \
  --text="$LETTERS" \
  --layout-features+=liga,dlig,clig,rlig \
  --no-layout-closure \
  --flavor=woff2 \
  --output-file="$OUT"

echo "Verifying every requested ligature survived..."
LIGS="$LIGS" python3 - "$OUT" <<'PY'
import sys, os
from fontTools.ttLib import TTFont
f = TTFont(sys.argv[1]); got = set()
for lk in f['GSUB'].table.LookupList.Lookup:
    for st in lk.SubTable:
        st = getattr(st, 'ExtSubTable', st)
        if getattr(st, 'ligatures', None):
            for first, ls in st.ligatures.items():
                for l in ls:
                    got.add((first + ''.join(l.Component)).replace('underscore', '_'))
want = set(os.environ['LIGS'].split())
missing = sorted(want - got)
if missing:
    raise SystemExit(f"FAIL: dropped by subsetting: {missing}")
print(f"OK — {len(want)} ligatures present, {os.path.getsize(sys.argv[1])} bytes")
PY
