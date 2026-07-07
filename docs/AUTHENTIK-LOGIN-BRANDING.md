# Authentik login page — branding, CSS, and theme

infra-TAK deploys Authentik; the **login / flow** UI is Authentik’s **flow executor** (`ak-flow-executor`), not the infra-TAK console. Styling is **not** intuitive: login text, backgrounds, and theme are controlled in **different** places.

---

## Where things live (two boxes — don’t mix them)

| What you want | Where in Authentik Admin |
|----------------|---------------------------|
| Black (or custom) **page/card backgrounds**, hide default image | **System → Brands →** (your brand) → **Branding settings → Custom CSS** |
| **Light vs dark** text colors (PatternFly palette) | **Same brand → Other global settings → Attributes** (YAML or JSON) — **not** the CSS editor |
| **Logo, favicon, flow background image, browser tab title** | **Same brand → Branding settings** (Title, Logo, Favicon, Default flow background) |
| **“Welcome to …” line and other flow wording** | **Flows and Stages → Flows** → edit the flow your brand uses (often **Default authentication flow**) — see [external guides](#external-guides) |

There is **no full live preview** of the login page while you edit; save, then open the real **`/if/flow/...`** URL (hard refresh or private window).

---

## Starter TAK logo (infra-TAK ships a generic shield)

infra-TAK bundles the **same official TAK shield SVG** the console uses (`tak.gov` brand asset) under **`static/authentik-branding/tak-gov-brand.svg`**.

On **Authentik deploy** or **Update config & reconnect** (local) — and on **remote Authentik deploy** — the console copies it to:

`~/authentik/media/public/infra-tak-defaults/tak-gov-brand.svg`

(on the host that runs Authentik’s `docker compose`; same tree users see as `${HOME:-/home/takwerx}/authentik/...` when deployed as root).

You still **assign** it in **System → Brands** (upload from your machine, or copy that path off the server and upload). Authentik does not auto-wire brand images from disk. Details: **[static/authentik-branding/README.md](../static/authentik-branding/README.md)**.

---

## The usual trap: black background + grey unreadable text

If you force a **black** background in **Custom CSS** but leave the flow executor on **`theme="light"`** (Authentik default for many brands), PatternFly still uses **dark/grey text** meant for a **light** background. You get **low contrast** (“Welcome …” and labels almost invisible).

**Fix (recommended):** set the brand to **dark** theme via **Attributes**, *then* keep your black CSS if you still want `#000` everywhere.

**Attributes** (JSON example — same field allows YAML):

```json
{
  "settings": {
    "theme": {
      "base": "dark"
    }
  }
}
```

Equivalent YAML:

```yaml
settings:
  theme:
    base: dark
```

Other values Authentik supports include `light` and `automatic` (follow browser preference).

After saving, inspect `ak-flow-executor` on the login page — you want **`theme="dark"`** when pairing with a dark custom background.

---

## Example Custom CSS — all-black shell (backgrounds only)

Paste under **Branding settings → Custom CSS**. Adjust if your Authentik version uses slightly different class names; use browser **Inspect** if a layer ignores these rules.

```css
/* Full page — black, no background image */
html,
body {
  background-color: #000000 !important;
  background-image: none !important;
}

.pf-c-background-image {
  display: none !important;
}

/* Login layout shell */
.pf-c-login {
  background-color: #000000 !important;
}

/* The “card” / main panel */
.pf-c-login__main {
  background: #000000 !important;
  --pf-c-login__main--BackgroundColor: #000000;
}

.pf-c-login__main-header {
  background: #000000 !important;
}

/* Inner card (newer PatternFly) */
.pf-c-login__main .pf-c-card,
.pf-c-login__main .pf-v5-c-card {
  background: #000000 !important;
  --pf-v5-c-card--BackgroundColor: #000000;
}
```

**Do not** rely only on `color: #fff` scattered everywhere to “fix” grey text if the executor is still `theme="light"` — you will fight PatternFly and theme variables. Prefer **`settings.theme.base: dark`** in **Attributes** first.

---

## Wrong brand = wrong Title / wrong CSS

Brands match **hostname** (suffix rules). If users hit `tak.example.com` but you edited a brand whose **Domain** doesn’t match, they may see **defaults** (including “authentik” wording or a brand without your CSS). Edit the brand that actually matches the URL users open.

---

## External guides (community / third-party)

- **Changing login flow text** (which menu to open): e.g. [Tricked — Change authentik logo/branding](https://github.com/Tricked-dev/tricked.dev/blob/master/src/pages/blog/authentik-change-logo.md) — describes editing the **default authentication flow** for on-screen copy.
- **Official:** [Brands](https://docs.goauthentik.io/docs/brands/), [Custom CSS](https://docs.goauthentik.io/brands/custom-css/), [Customization overview](https://docs.goauthentik.io/customize/).

Add other bookmarks here as you find them.

---

## Quick checklist

1. **System → Brands** — correct **Domain** for your `tak.*` host; **Title**, **Logo**, **Favicon**, optional **Default flow background**.
2. **Attributes** — `settings.theme.base: dark` if you use a dark custom background.
3. **Custom CSS** — backgrounds / layout only unless you know exactly which selector you need.
4. **Flows** — custom welcome / copy on the authentication flow.
5. **Test** — private window, `/if/flow/default-authentication-flow/` (or your actual flow slug).
