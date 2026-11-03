# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""v10.3.5 W3-W13, the certificate Rotate / Revoke rework (ops #452).

Those thirteen commits went straight to dev with no tests. These cover the parts that are plain
logic: the issued-cert validity cap (W9), the day-23/29 reminders and the window state (W10, W12),
the batched signature checks and account classification (W11), the trust-list rules (W6), the
reminder mails (W10/W12) and the targeted CloudTAK sign-out (W13). The Revoke route itself
(password gate, 8089 decision, root-signed refusal) is in test_ca_info_revoke_live_truststore_ops174.py.

openssl is real, on real certs made per test; everything that talks to a box is faked.
"""

import ast
import hashlib
import html
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import tempfile
import types
import urllib.parse
from datetime import datetime, timedelta

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

needs_openssl = pytest.mark.skipif(not shutil.which('openssl'), reason='needs openssl')


def _func(name):
    for n in TREE.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _const(name):
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == name for t in n.targets):
            return ast.get_source_segment(APP, n)
    raise AssertionError(f'{name} was renamed or removed')


def _load(funcs=(), consts=(), **extra):
    ns = {'os': os, 're': re, 'json': json, 'shlex': shlex, 'subprocess': subprocess, 'tempfile': tempfile,
          'shutil': shutil, 'hashlib': hashlib, 'html': html, 'datetime': datetime, 'time': __import__('time'),
          'urllib': urllib}
    ns.update(extra)
    for c in consts:
        exec(_const(c), ns)
    for f in funcs:
        exec(compile(_func(f), 'app.py', 'exec'), ns)
    return ns


# ── real certs ──────────────────────────────────────────────────────────────

def _ssl(d, *args):
    subprocess.run(['openssl', *args], check=True, capture_output=True, cwd=d)


def _ca(d, cn, days=365):
    """A self-signed CA called `cn`; files cn.pem / cn.key in d."""
    _ssl(d, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', f'{cn}.key',
         '-subj', f'/OU=TAK/CN={cn}', '-days', str(days), '-out', f'{cn}.pem')
    return (d / f'{cn}.pem').read_text()


def _signed(d, cn, issuer, days=365):
    """A cert called `cn` signed by the CA files issuer.pem / issuer.key."""
    _ssl(d, 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', f'{cn}.key',
         '-subj', f'/OU=TAK/CN={cn}', '-out', f'{cn}.csr')
    _ssl(d, 'x509', '-req', '-in', f'{cn}.csr', '-CA', f'{issuer}.pem', '-CAkey', f'{issuer}.key',
         '-CAcreateserial', '-days', str(days), '-out', f'{cn}.pem')
    return (d / f'{cn}.pem').read_text()


# ── W9: issued certs never outlive the intermediate that signed them ─────────────────

CLAMP = ('_pem_cn_and_expiry', '_tak_issued_validity_cap', '_tak_issued_validity', '_coreconfig_clamp_issued_validity')


def _validity_ns(cert_dir):
    return _load(CLAMP, _read_priv=lambda p: pathlib.Path(p).read_text())


@needs_openssl
def test_validity_is_capped_to_the_intermediates_remaining_life(tmp_path):
    _ca(tmp_path, 'ca', days=100)
    ns = _validity_ns(tmp_path)
    cap = ns['_tak_issued_validity_cap'](str(tmp_path))
    assert cap in (98, 99), cap                      # remaining days minus one
    assert ns['_tak_issued_validity'](3650, str(tmp_path)) == cap      # the old 3650 default
    assert ns['_tak_issued_validity'](30, str(tmp_path)) == 30         # shorter asks are kept
    assert ns['_tak_issued_validity']('not a number', str(tmp_path)) == min(730, cap)
    assert ns['_tak_issued_validity'](0, str(tmp_path)) == 1           # never zero or negative


@needs_openssl
def test_an_expired_intermediate_caps_at_one_day(tmp_path):
    _ca(tmp_path, 'ca', days=1)
    ns = _validity_ns(tmp_path)
    ns['_pem_cn_and_expiry'] = lambda pem: ('ca', datetime.utcnow() - timedelta(days=5))
    assert ns['_tak_issued_validity_cap'](str(tmp_path)) == 1


def test_validity_is_left_alone_when_ca_pem_cannot_be_read(tmp_path):
    ns = _validity_ns(tmp_path)               # no ca.pem here
    assert ns['_tak_issued_validity_cap'](str(tmp_path)) is None
    assert ns['_tak_issued_validity'](3650, str(tmp_path)) == 3650   # the caller keeps its value


@needs_openssl
def test_coreconfig_validity_is_clamped_and_untouched_when_already_short(tmp_path):
    _ca(tmp_path, 'ca', days=100)
    ns = _validity_ns(tmp_path)
    cap = ns['_tak_issued_validity_cap'](str(tmp_path))
    cfg = '<x><TAKServerCAConfig keystore="JKS" validityDays="3650" signatureAlg="SHA256WithRSA"/></x>'
    new, change = ns['_coreconfig_clamp_issued_validity'](cfg, str(tmp_path))
    assert change == (3650, cap) and f'validityDays="{cap}"' in new and 'signatureAlg="SHA256WithRSA"' in new
    again, change = ns['_coreconfig_clamp_issued_validity'](new, str(tmp_path))
    assert change is None and again == new
    plain = '<x><Other validityDays="3650"/></x>'
    assert ns['_coreconfig_clamp_issued_validity'](plain, str(tmp_path)) == (plain, None)


# ── W10: the window state file ──────────────────────────────────────────────────────

def _state_ns(tmp_path):
    return _load(('_ca_rotation_state_path', '_ca_rotation_state_load', '_ca_rotation_state_save'),
                 CONFIG_DIR=str(tmp_path / 'cfg'))


def test_window_state_round_trips_privately_and_an_empty_state_removes_it(tmp_path):
    ns = _state_ns(tmp_path)
    assert ns['_ca_rotation_state_load']() == {}
    st = {'old_ca_cn': 'INT-CA-01', 'new_ca_cn': 'INT-CA-02', 'rotated_at': 1, 'cutoff_at': 2, 'notices_sent': []}
    ns['_ca_rotation_state_save'](st)
    path = pathlib.Path(ns['_ca_rotation_state_path']())
    assert ns['_ca_rotation_state_load']() == st
    assert oct(path.stat().st_mode & 0o777) == '0o600'
    assert [p.name for p in path.parent.iterdir()] == [path.name]      # no temp file left behind
    ns['_ca_rotation_state_save']({})
    assert not path.exists() and ns['_ca_rotation_state_load']() == {}
    ns['_ca_rotation_state_save']({})                                  # removing nothing is fine


@pytest.mark.parametrize('content', ['not json', '[]', '{"new_ca_cn": "x"}', ''])
def test_a_damaged_or_ownerless_state_file_means_no_window(tmp_path, content):
    ns = _state_ns(tmp_path)
    p = pathlib.Path(ns['_ca_rotation_state_path']())
    p.parent.mkdir(parents=True)
    p.write_text(content)
    assert ns['_ca_rotation_state_load']() == {}


def test_day0_text_depends_on_who_signed_the_server_cert():
    ns = _load(('_ca_rotation_date', '_ca_rotation_day0_text'), consts=('CA_ROTATION_WINDOW_DAYS',))
    cutoff = (datetime(2026, 12, 3) - datetime(1970, 1, 1)).total_seconds()
    assert ns['_ca_rotation_date'](cutoff) == 'December 3, 2026'
    root = ns['_ca_rotation_day0_text'](cutoff, 'root')
    assert root.startswith('You have 30 days (until December 3, 2026)') and 'scan a new QR code' in root
    inter = ns['_ca_rotation_day0_text'](cutoff, 'intermediate')
    assert 'disconnected until they move' in inter and 'December 3, 2026' in inter


def test_email_relay_ready_needs_host_and_user():
    ns = _load(('_email_relay_ready',), load_settings=lambda: {})
    ready = ns['_email_relay_ready']
    assert ready({'email_relay': {'relay_host': 'h', 'smtp_user': 'u'}}) is True
    assert ready({'email_relay': {'relay_host': 'h'}}) is False
    assert ready({'email_relay': {'smtp_user': 'u'}}) is False
    assert ready({}) is False
    assert ready(None) is False


# ── W12: day-23 and day-29 reminders, each once ──────────────────────────────────────

DAY = 86400
T0 = 1_800_000_000


class _Window:
    """In-memory window state + a clock + a recorded sender around the real reminder code."""

    def __init__(self, day, notices=(), relay=True, state=True):
        self.now = T0 + day * DAY + 60
        self.state = ({'old_ca_cn': 'INT-CA-01', 'new_ca_cn': 'INT-CA-02', 'rotated_at': T0, 'cutoff_at': T0 + 30 * DAY,
                       'notices_sent': list(notices)} if state else {})
        self.sent = []
        self.ns = _load(('_ca_rotation_reminder_text', '_ca_rotation_reminder_once', '_ca_rotation_date'),
                        consts=('CA_ROTATION_REMINDER_DAYS',),
                        time=types.SimpleNamespace(time=lambda: self.now),
                        _ca_rotation_state_load=lambda: dict(self.state),
                        _ca_rotation_state_save=self._save,
                        _email_relay_ready=lambda: relay,
                        _ca_rotation_send=lambda kind, st, notice: self.sent.append((kind, notice)) or {'sent': True})

    def _save(self, st):
        self.state = dict(st)

    def once(self, kind=None):
        return self.ns['_ca_rotation_reminder_once'](kind)


def test_nothing_goes_out_before_day_23():
    w = _Window(22)
    assert w.once()['sent'] is None and w.sent == []


def test_day_23_reminder_goes_once():
    w = _Window(23)
    assert w.once()['sent'] == 'day23'
    assert [k for k, _ in w.sent] == ['day23'] and w.state['notices_sent'] == ['day23']
    assert w.once()['sent'] is None and len(w.sent) == 1          # the next 6-hour check sends nothing


def test_day_29_reminder_follows_and_both_are_then_done():
    w = _Window(29, notices=['day23'])
    assert w.once()['sent'] == 'day29'
    assert w.state['notices_sent'] == ['day23', 'day29']
    assert w.once()['sent'] is None


def test_a_box_that_was_down_from_day_22_to_30_sends_only_the_latest():
    w = _Window(30)
    assert w.once()['sent'] == 'day29'
    assert [k for k, _ in w.sent] == ['day29']
    assert w.state['notices_sent'] == ['day23', 'day29']          # day 23 is marked done, not sent late


def test_no_relay_marks_nothing_so_a_later_relay_still_reminds():
    w = _Window(24, relay=False)
    r = w.once()
    assert r['sent'] is None and 'Email Relay' in r['reason'] and w.sent == []
    assert w.state['notices_sent'] == []


def test_no_window_sends_nothing():
    w = _Window(24, state=False)
    assert w.once()['sent'] is None and w.sent == []


def test_forced_reminder_is_sent_and_marked_like_the_scheduled_one():
    w = _Window(2)
    assert w.once('day29')['sent'] == 'day29'
    assert w.state['notices_sent'] == ['day29'] and len(w.sent) == 1


def test_reminder_text_counts_days_left_and_names_the_old_ca():
    w = _Window(23)
    text = w.ns['_ca_rotation_reminder_text'](w.state)
    assert text.startswith('6 days left') and 'INT-CA-01' in text and 'log out and back in' in text
    w.now = T0 + 29 * DAY + 60 + 18 * 3600
    assert w.ns['_ca_rotation_reminder_text'](w.state).startswith('0 days left')
    w.now = T0 + 29 * DAY - 3600
    assert w.ns['_ca_rotation_reminder_text'](w.state).startswith('1 day left')   # singular


# ── W10/W12: who gets the mail (D2: users only see their own lines) ──────────────────

def _send_ns(rows, opt_in, emails, relay=True, admin='admin@example.com'):
    mails = []

    def send(to, subj, body, force=False):
        mails.append((to, subj, body))
        return True

    ns = _load(('_ca_rotation_send', '_ca_rotation_date'),
               time=types.SimpleNamespace(time=lambda: T0 + 24 * DAY),
               socket=types.SimpleNamespace(gethostname=lambda: 'box'),
               load_settings=lambda: {'guarddog_alert_email': admin},
               _email_relay_ready=lambda s=None: relay,
               _tak_ca_migration=lambda: {'ok': True, 'rows': rows, 'current_ca': 'INT-CA-02'},
               _guarddog_server_identifier=lambda s: 'tak.example.com',
               _ca_rotation_user_emails=lambda: emails,
               _safe_alert_email_list=lambda v: v or '',
               _guarddog_send_alert_email_via_relay=send)
    state = {'old_ca_cn': 'INT-CA-01', 'new_ca_cn': 'INT-CA-02', 'cutoff_at': T0 + 30 * DAY, 'user_email_opt_in': opt_in}
    return ns, state, mails


ROWS = [{'user': 'alice', 'moving': ['scan a new QR on A1'], 'gone': []},
        {'user': 'bob', 'moving': ['log out and back in to CloudTAK'], 'gone': ['old phone: no longer trusted']},
        {'user': 'carol', 'moving': [], 'gone': []}]


def test_admin_copy_lists_everyone_still_to_move_and_users_are_not_mailed_by_default():
    ns, state, mails = _send_ns(ROWS, opt_in=False, emails=None)
    res = ns['_ca_rotation_send']('day23', state, 'NOTICE')
    assert [m[0] for m in mails] == ['admin@example.com']
    body = mails[0][2]
    assert 'alice: scan a new QR on A1' in body and 'bob: log out and back in to CloudTAK' in body
    assert 'carol' not in body and '2 of 3 accounts still need to move from INT-CA-01 to INT-CA-02' in body
    assert 'Not listed: 1 device cert' in body                       # bob's cut-off phone is counted, not listed
    assert '6 days left' in mails[0][1] and res['sent'] and res['users'] == 0


def test_with_the_user_opt_in_each_user_gets_their_own_message_with_only_their_lines():
    ns, state, mails = _send_ns(ROWS, opt_in=True, emails={'alice': 'alice@example.com', 'bob': 'bob@example.com'})
    res = ns['_ca_rotation_send']('day23', state, 'NOTICE')
    by_to = {m[0]: m for m in mails}
    assert set(by_to) == {'admin@example.com', 'alice@example.com', 'bob@example.com'}   # one envelope each
    assert all(',' not in m[0] for m in mails)
    assert 'scan a new QR on A1' in by_to['alice@example.com'][2] and 'bob' not in by_to['alice@example.com'][2]
    assert 'CloudTAK' in by_to['bob@example.com'][2] and 'A1' not in by_to['bob@example.com'][2]
    assert 'alice@example.com' not in by_to['admin@example.com'][2]   # addresses never appear in a body
    assert res['users'] == 2 and res['no_email'] == []


def test_users_with_no_email_are_named_to_the_admin_not_mailed():
    ns, state, mails = _send_ns(ROWS, opt_in=True, emails={'alice': 'alice@example.com'})
    res = ns['_ca_rotation_send']('day29', state, 'NOTICE')
    assert res['no_email'] == ['bob'] and 'No email on file (1)' in mails[0][2] and 'bob' in mails[0][2]
    assert sorted(m[0] for m in mails) == ['admin@example.com', 'alice@example.com']


def test_no_relay_sends_nothing_and_says_why():
    ns, state, mails = _send_ns(ROWS, opt_in=True, emails={}, relay=False)
    res = ns['_ca_rotation_send']('day0', state, 'NOTICE')
    assert mails == [] and res['sent'] is False and "Email Relay isn't set up" in res['message']


# ── W11: batched signature checks and account classification ─────────────────────────

@needs_openssl
def test_one_openssl_call_gives_each_leaf_its_own_verdict(tmp_path):
    root = _ca(tmp_path, 'root')
    other = _ca(tmp_path, 'other')
    mine = _signed(tmp_path, 'mine', 'root')
    theirs = _signed(tmp_path, 'theirs', 'other')
    ns = _load(('_ca_mig_signed_by_many',))
    assert ns['_ca_mig_signed_by_many']([mine, theirs, mine], root) == [True, False, True]
    assert ns['_ca_mig_signed_by_many']([mine, theirs], other) == [False, True]
    assert ns['_ca_mig_signed_by_many']([], root) == []
    assert ns['_ca_mig_signed_by_many']([mine], '') == [None]                  # no CA to judge by: can't tell
    assert ns['_ca_mig_signed_by_many']([mine, 'garbage'], root)[0] is True    # one bad cert doesn't sink the rest


@needs_openssl
def test_signature_not_the_name_decides_whether_a_cert_is_on_the_current_ca(tmp_path):
    old_dir, new_dir = tmp_path / 'old', tmp_path / 'new'
    old_dir.mkdir()
    new_dir.mkdir()
    old_ca = _ca(old_dir, 'INT-CA')              # the CA being replaced...
    new_ca = _ca(new_dir, 'INT-CA')              # ...and a re-made one with the SAME CN
    on_old = _signed(old_dir, 'phone1', 'INT-CA')
    on_new = _signed(new_dir, 'phone2', 'INT-CA')
    ns = _load(('_ca_mig_issuers', '_ca_mig_signed_by_many', '_ca_mig_classify', '_pem_issuer_cn'),
               consts=('_CA_MIG_CLASS_CACHE',))
    # TAK still trusts the old CA (the overlap window), the current one is the new CA.
    got = ns['_ca_mig_classify']([on_old, on_new], new_ca, old_ca + '\n' + new_ca)
    assert [g['current'] for g in got] == [False, True]
    assert [g['trusted'] for g in got] == [True, True]
    assert [g['issuer'] for g in got] == ['INT-CA', 'INT-CA']
    # After Revoke the live trust list holds only the new CA: the old phone is cut off.
    got = ns['_ca_mig_classify']([on_old, on_new], new_ca, new_ca)
    assert [g['current'] for g in got] == [False, True] and [g['trusted'] for g in got] == [False, True]
    # A trust list that couldn't be read says "can't tell", never "cut off".
    got = ns['_ca_mig_classify']([on_old], new_ca, '')
    assert got[0]['trusted'] is None


def test_account_name_is_the_cn_of_a_dn_or_the_plain_value():
    f = _load(('_tak_cert_username',))['_tak_cert_username']
    assert f('CN=jdoe,OU=people,DC=tak') == 'jdoe'
    assert f('uid=x, cn = Jane Doe ,ou=y') == 'Jane Doe'
    assert f('jdoe') == 'jdoe'
    assert f('  ') == '' and f(None) == ''
    assert len(f('a' * 500)) == 200


# ── W6: TAK Server's trust list holds intermediates only ─────────────────────────────

class _Keytool:
    """sh(argv) -> (ok, output) for `keytool -list -rfc` over a dict of {alias: pem}, `-delete` removes."""

    def __init__(self, entries, fail_delete=()):
        self.entries = dict(entries)
        self.fail_delete = set(fail_delete)
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if '-list' in argv:
            return True, ''.join(f'Alias name: {a}\nEntry type: trustedCertEntry\n\n{p}\n\n' for a, p in self.entries.items())
        if '-delete' in argv:
            alias = argv[argv.index('-alias') + 1]
            if alias in self.fail_delete:
                return False, 'keytool error'
            self.entries.pop(alias, None)
            return True, ''
        return False, 'unexpected'


DROP = ('_pem_dn', '_pem_self_signed', '_pem_key', '_rotate_truststore_entries', '_tak_truststore_drop_roots')


@needs_openssl
def test_roots_leave_the_trust_list_and_intermediates_stay(tmp_path):
    root = _ca(tmp_path, 'root-ca')
    int_a = _signed(tmp_path, 'INT-CA-02', 'root-ca')
    int_b = _signed(tmp_path, 'INT-CA-03', 'root-ca')
    kt = _Keytool({'int-ca-02': int_a, 'ca-ps-root-ca-01': root, 'root-ca': root, 'mykey': int_b})
    logs = []
    ns = _load(DROP, _read_priv=lambda p: root)
    ok, removed = ns['_tak_truststore_drop_roots']('/x/truststore-INT-CA-03.jks', 'pw', kt, logs.append, '/x')
    assert ok and sorted(removed) == ['ca-ps-root-ca-01', 'root-ca']       # matched by subject, whatever the alias
    assert sorted(kt.entries) == ['int-ca-02', 'mykey']
    assert any('Undo:' in m and 'root-ca.pem' in m for m in logs)           # the log says how to put it back


@needs_openssl
def test_a_trust_list_of_only_roots_is_left_alone(tmp_path):
    root = _ca(tmp_path, 'root-ca')
    kt = _Keytool({'root-ca': root})
    logs = []
    ns = _load(DROP, _read_priv=lambda p: root)
    assert ns['_tak_truststore_drop_roots']('/x/t.jks', 'pw', kt, logs.append, '/x') == (False, [])
    assert kt.entries == {'root-ca': root} and not any('-delete' in c for c in kt.calls)


@needs_openssl
def test_a_root_that_cannot_be_deleted_is_reported_not_hidden(tmp_path):
    root = _ca(tmp_path, 'root-ca')
    inter = _signed(tmp_path, 'INT-CA-02', 'root-ca')
    kt = _Keytool({'int-ca-02': inter, 'root-ca': root}, fail_delete=['root-ca'])
    logs = []
    ns = _load(DROP, _read_priv=lambda p: root)
    ok, removed = ns['_tak_truststore_drop_roots']('/x/t.jks', 'pw', kt, logs.append, '/x')
    assert ok is False and removed == [] and any('Could not remove root-ca' in m for m in logs)


def test_an_unreadable_trust_list_changes_nothing():
    ns = _load(DROP)
    ok, removed = ns['_tak_truststore_drop_roots']('/x/t.jks', 'pw', lambda argv: (False, 'bad password'), lambda m: None)
    assert (ok, removed) == (False, [])


@needs_openssl
def test_self_signed_means_subject_equals_issuer(tmp_path):
    root = _ca(tmp_path, 'root-ca')
    inter = _signed(tmp_path, 'INT-CA-02', 'root-ca')
    f = _load(('_pem_dn', '_pem_self_signed'))['_pem_self_signed']
    assert f(root) is True and f(inter) is False
    assert f('') is False and f('garbage') is False


def test_client_truststore_is_rebuilt_beside_the_old_one_with_the_root_added_last():
    cmds = []

    def run(cmd):
        cmds.append(cmd)
        return True
    ns = _load(('_tak_client_truststore_rebuild',))
    assert ns['_tak_client_truststore_rebuild']('/f/truststore-INT-CA-03.jks', "p'w", run, '/f') is True
    assert cmds[0] == 'rm -f /f/truststore-INT-CA-03.p12.new'
    assert '-importkeystore' in cmds[1] and '-srckeystore /f/truststore-INT-CA-03.jks' in cmds[1]
    assert '-destkeystore /f/truststore-INT-CA-03.p12.new' in cmds[1]
    assert "'\"'\"'" in cmds[1]                                              # the password is quoted, not pasted
    assert '-alias root-ca' in cmds[2] and '-file /f/root-ca.pem' in cmds[2]
    assert cmds[3] == 'mv -f /f/truststore-INT-CA-03.p12.new /f/truststore-INT-CA-03.p12'   # moved over, not merged


def test_a_failed_rebuild_removes_its_temp_file_and_keeps_the_old_p12():
    cmds = []

    def run(cmd):
        cmds.append(cmd)
        return '-importcert' not in cmd
    ns = _load(('_tak_client_truststore_rebuild',))
    assert ns['_tak_client_truststore_rebuild']('/f/t.jks', 'pw', run, '/f') is False
    assert cmds[-1] == 'rm -f /f/t.p12.new' and not any(c.startswith('mv ') for c in cmds)


# ── W6/W7: one running flag across every certificate job ─────────────────────────────

@pytest.mark.parametrize('busy', ['tak_server_cert_job', 'rotate_rootca_status', 'rotate_intca_status', 'revoke_ca_status'])
def test_any_running_certificate_job_blocks_a_new_one(busy):
    idle = {'tak_server_cert_job': {'running': False}, 'rotate_rootca_status': {'running': False},
            'rotate_intca_status': {'running': False}, 'revoke_ca_status': {'running': False}}
    ns = _load(('_tak_cert_job_busy',), **idle)
    assert ns['_tak_cert_job_busy']() is False
    ns[busy] = {'running': True}
    assert ns['_tak_cert_job_busy']() is True


# ── W13: sign out exactly the users who were reset ──────────────────────────────────

def _signout_ns(sessions, delete_code=200, list_code=200, sql_result=2, boot=()):
    """`calls`: the session API + SQL calls. `probes`: the API readiness probes (GET /api/server),
    answered with the codes in `boot` first, then 200."""
    calls, probes, boot = [], [], list(boot)

    def req(method, url, headers=None, timeout=0):
        if url.endswith('/api/server'):
            code = boot.pop(0) if boot else 200
            probes.append(code)
            return code == 200, code, {}
        calls.append((method, url))
        if method == 'GET':
            return (list_code == 200), list_code, ({'items': sessions} if list_code == 200 else None)
        return (delete_code == 200), delete_code, None
    ns = _load(('_cloudtak_signout_users',), _cloudtak_signing_secret=lambda: 's', _cloudtak_admin_token=lambda s: 'jwt',
               _cloudtak_request_json=req, _cloudtak_postgis_json=lambda sql: calls.append(('SQL', sql)) or sql_result)
    ns['time'] = type('T', (), {'sleep': staticmethod(lambda s: probes.append(('slept', s)))})
    ns['_probes'] = probes
    return ns, calls


def test_each_reset_user_has_their_sessions_ended_through_cloudtaks_api():
    ns, calls = _signout_ns([{'id': 's1'}, {'id': 's2'}])
    out = ns['_cloudtak_signout_users'](['alice', 'bob', 'alice', '?', ''], lambda m: None)
    assert out == {'signout': 'ok', 'users': 2, 'sessions': 4}
    gets = [u for m, u in calls if m == 'GET']
    assert [u.split('/api/user/')[1].split('/')[0] for u in gets] == ['alice', 'bob']   # once each, '?' skipped
    assert sum(1 for m, _ in calls if m == 'DELETE') == 4 and not any(m == 'SQL' for m, _ in calls)


def test_usernames_are_url_quoted_and_the_dry_run_deletes_nothing():
    ns, calls = _signout_ns([{'id': 'a/b'}])
    ns['_cloudtak_signout_users'](['a b/c'], lambda m: None, dry_run=True)
    assert calls == [('GET', 'http://127.0.0.1:5000/api/user/a%20b%2Fc/session?limit=100')]


def test_signout_waits_for_a_restarting_cloudtak_api_instead_of_falling_back_to_sql():
    # T&E 2026-11-03 (test6 Revoke): the CA heal had just restarted cloudtak-api; the session call
    # got HTTP 502 and the SQL fallback ran, so no logout reached the open tab.
    ns, calls = _signout_ns([{'id': 's1'}], boot=(502, 0, 503))
    out = ns['_cloudtak_signout_users'](['alice'], lambda m: None)
    assert out == {'signout': 'ok', 'users': 1, 'sessions': 1}
    assert [p for p in ns['_probes'] if not isinstance(p, tuple)] == [502, 0, 503, 200]
    assert sum(1 for p in ns['_probes'] if isinstance(p, tuple)) == 3          # slept between probes
    assert not any(m == 'SQL' for m, _ in calls) and ('DELETE', 'http://127.0.0.1:5000/api/user/alice/session/s1') in calls


def test_an_old_cloudtak_without_the_session_api_is_reported_not_forced():
    ns, calls = _signout_ns([], list_code=404)
    assert ns['_cloudtak_signout_users'](['alice'], lambda m: None)['signout'] == 'old'
    assert not any(m in ('DELETE', 'SQL') for m, _ in calls)


def test_when_the_api_refuses_the_delete_the_session_rows_are_removed_in_sql():
    ns, calls = _signout_ns([{'id': 's1'}], delete_code=500, sql_result=1)
    out = ns['_cloudtak_signout_users'](['alice'], lambda m: None)
    assert out == {'signout': 'ok', 'users': 1, 'sessions': 1}
    sql = [q for m, q in calls if m == 'SQL']
    assert len(sql) == 1 and hashlib.md5(b'alice').hexdigest() in sql[0] and 'alice' not in sql[0]   # no name in the SQL


def test_when_nothing_works_it_says_failed_and_no_users_or_secret_means_none():
    ns, _calls = _signout_ns([{'id': 's1'}], delete_code=500, sql_result=None)
    assert ns['_cloudtak_signout_users'](['alice'], lambda m: None)['signout'] == 'failed'
    ns, calls = _signout_ns([])
    assert ns['_cloudtak_signout_users']([], lambda m: None)['signout'] == 'none' and calls == []
    ns['_cloudtak_signing_secret'] = lambda: ''
    assert ns['_cloudtak_signout_users'](['alice'], lambda m: None)['signout'] == 'none'
