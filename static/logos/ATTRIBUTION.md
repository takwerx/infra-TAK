# Third-party assets in `static/logos/`

## `tak-client-skittle.png`

Derived from **`atak/ATAK/app/src/main/assets/icons/roles/team.png`** in
[TAK-Product-Center/atak-civ](https://github.com/TAK-Product-Center/atak-civ),
licensed **GPL-3.0**.

infra-TAK is licensed AGPL-3.0. AGPLv3 §13 expressly permits combining with GPLv3
work, so incorporating this asset is compatible; this file is the attribution that
compatibility requires.

**Modification:** the upstream asset is an untinted 8-bit grayscale+alpha mask, which
ATAK colors with the user's team color at runtime. We multiplied it by **Cyan** —
ATAK's own default team color (`call_sign_preference.xml`, `locationTeam`
`android:defaultValue="Cyan"`) — and re-encoded it as 8-bit RGBA. The alpha channel
and the luminance structure (outline ring, figure silhouette) are unchanged.
