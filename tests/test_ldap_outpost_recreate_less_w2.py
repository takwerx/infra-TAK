# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""v10.4.3 W2: recreate the LDAP outpost less.

akres E3c: each outpost recreate under load is a ~3-in-5 chance TAK gives every user no
groups; server/worker/PG/PgBouncer recreates were 0/9. So:
  * post-update hardening recreates ldap only when the ldap service section changed;
  * the deploy's final `restart ldap` (which never applied a compose change) is
    `up -d --no-deps ldap` — recreated only when its config changed;
  * the number of force-recreate / restart sites is pinned: a new one needs a reason here.
"""
import re

import yaml

from test_tak_ldap_recycle import APP

# Every remaining site, with why it must restart the outpost (v10.4.3 W2 audit):
#  ldap-internal-host, compose-heal-ldap      — compose ldap env changed / heal of a broken outpost
#  ldap-routing-repair (+2 rollbacks)          — outpost routing/env changed
#  ldap-fqdn-move (+2 rollbacks)               — outpost AUTHENTIK_HOST changed
#  pgbouncer-image-restart                     — recovery: LDAP already failing after the swap
#  reconfigure-ldap-recreate                   — Authentik domain changed
#  ldap-flow-recreate (local + remote)         — bind flow changed (upstream #27402 on 2026.8.x)
#  _repair_ldap_outpost_token                  — outpost token changed
#  ldap-sa-recreate (local + remote)           — SA password reset
#  webadmin-ldap-recreate (5)                  — webadmin sync; flushes the bind cache
#  startup/post-update-yaml-heal-ldap          — one-time YAML heal; flushes the bind cache
#  post-update-hardening-recreate              — only if the ldap section changed (W2)
EXPECTED_SITES = 23

_SITE = re.compile(r"""'--force-recreate'(?:,\s*'[^']*')*,\s*'ldap'\]|--force-recreate(?: --\S+)* ldap\b"""
                   r"""|'restart',\s*'ldap'\]|compose restart ldap\b""")


def _sites():
    lines = APP.splitlines()
    out = []
    for m in _SITE.finditer(APP):
        line = lines[APP.count('\n', 0, m.start())].strip()
        if line.startswith(('#', 'plog')) or 'manually' in line or 'CompletedProcess(' in line:
            continue
        out.append(line)
    return out


def test_outpost_restart_sites_are_pinned():
    sites = _sites()
    assert len(sites) <= EXPECTED_SITES, (
        f'{len(sites) - EXPECTED_SITES} new LDAP outpost force-recreate/restart site(s). Each one is a '
        f'~3-in-5 TAK risk under load (akres E3c): prefer `up -d --no-deps ldap` (recreates only '
        f'on a config change), or add it with its reason to the list above.')
    assert len(sites) == EXPECTED_SITES, 'a site was removed — lower EXPECTED_SITES and the list'


def test_deploy_final_step_does_not_restart_the_outpost():
    i = APP.index("'deploy-ldap-final-restart'")
    call = APP[APP.rfind('_ak_compose_subprocess(', 0, i):i]
    assert "'up', '-d', '--no-deps', 'ldap'" in call and "'restart'" not in call


def test_post_update_recreates_ldap_only_when_its_section_changed():
    i = APP.index("_authentik_compose_lock('post-update-hardening-recreate')")
    block = APP[APP.rindex('# v10.4.3 W2: every outpost recreate', 0, i):i + 2500]
    assert ".get('services') or {}).get('ldap')" in block
    gate = block.index('if _ldap_section_changed and _ldap_core_gate(')
    assert gate < block.index("'--force-recreate', '--no-deps', 'ldap'")


def test_the_section_compare_ignores_other_services():
    # the same expression the console uses, on a cap_drop change to server only vs ldap
    def changed(a, b):
        return (((yaml.safe_load(a) or {}).get('services') or {}).get('ldap')
                != ((yaml.safe_load(b) or {}).get('services') or {}).get('ldap'))
    base = 'services:\n  server: {image: s}\n  ldap: {image: l}\n'
    assert not changed('services:\n  server: {image: s, cap_drop: [ALL]}\n  ldap: {image: l}\n', base)
    assert changed('services:\n  server: {image: s}\n  ldap: {image: l, cap_drop: [ALL]}\n', base)
