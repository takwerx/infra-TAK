# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
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
"""ATLAS W461: TAK Server's revoked certificates, copied for ATLAS's renewal."""

import os
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules import atlas_instances as ai  # noqa: E402
from modules import atlas_renewal as ar  # noqa: E402
import modules.atlas as atlas  # noqa: E402
from test_atlas_renewal import FakeAuthentik, _ctx, deployment  # noqa: E402,F401

NL = '\n'
FP1 = ':'.join(['6C'] * 32)
FP2 = ':'.join(['A0'] * 32)
CRL_A = '-----BEGIN X509 CRL-----' + NL + 'QUFBQQ==' + NL + '-----END X509 CRL-----'
CRL_B = '-----BEGIN X509 CRL-----' + NL + 'QkJCQg==' + NL + '-----END X509 CRL-----'
PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)


def _db(answer=(True, FP1 + NL + FP2.lower() + NL), seen=None):
    def psql(cfg, sql):
        if seen is not None:
            seen.append((cfg, sql))
        return answer
    return psql


def _with_db(ctx, psql):
    return dict(ctx, _cotdb_psql=psql, _get_tak_deployment_config=lambda s: {'mode': 'local'})


@pytest.fixture
def certs(tmp_path):
    d = tmp_path / 'files'
    d.mkdir()
    (d / 'INTERMEDIATE-CA-01.crl').write_text(CRL_A + NL)
    (d / 'ca.crl').write_text(CRL_A + NL)       # the same CRL twice: written once
    (d / 'INTERMEDIATE-CA-02.crl').write_text(CRL_B + NL)
    (d / 'takserver.key').write_text(CRL_B.replace('QkJC', 'S0VZ') + NL)  # not a .crl
    return d


# ------------------------------------------------------------- the database

def test_the_query_is_tak_servers_own_record_of_revocation():
    seen = []
    prints = ar.revoked_fingerprints(_with_db(_ctx(), _db(seen=seen)))
    assert prints == [FP1, FP2]
    assert seen[0][1] == ('SELECT hash FROM certificate WHERE revocation_date IS NOT NULL '
                          'ORDER BY hash')
    assert seen[0][0] == {'mode': 'local'}


def test_nothing_revoked_is_an_empty_list_not_a_failure():
    assert ar.revoked_fingerprints(_with_db(_ctx(), _db((True, '')))) == []


@pytest.mark.parametrize('answer', [(False, 'could not connect'),
                                    # ⚠️ A failure with no text must not read as "nothing revoked".
                                    (False, ''),
                                    (True, FP1 + NL + 'ERROR: relation "certificate" does not exist')])
def test_a_database_that_cannot_answer_is_none(answer):
    assert ar.revoked_fingerprints(_with_db(_ctx(), _db(answer))) is None


# ------------------------------------------------------------------ the CRLs

def test_every_cas_crl_is_copied_once_and_nothing_else(certs):
    pem = ar.tak_crls(str(certs))
    assert pem.count('BEGIN X509 CRL') == 2
    assert 'QUFBQQ' in pem and 'QkJCQg' in pem and 'S0VZ' not in pem


def test_no_crls_is_empty(tmp_path):
    assert ar.tak_crls(str(tmp_path / 'missing')) == ''


# ------------------------------------------------------------------ the files

def _secrets(deployment):
    d = deployment / ar.SECRETS_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_the_list_says_when_it_was_taken(deployment):
    sdir = _secrets(deployment)
    ar.write_revocations(str(deployment), [FP1], CRL_A + NL, None, now=lambda: 1_800_000_000)
    text = (sdir / ar.REVOKED_FILE).read_text()
    assert text == 'written=2027-01-15T08:00:00Z' + NL + FP1 + NL
    assert (sdir / ar.CRL_FILE).read_text() == CRL_A + NL
    if os.name == 'posix':
        assert oct((sdir / ar.REVOKED_FILE).stat().st_mode & 0o777) == '0o400'


def test_the_list_goes_last_so_its_time_covers_the_crls(deployment, monkeypatch):
    _secrets(deployment)
    order = []
    real = ar._write_secret
    monkeypatch.setattr(ar, '_write_secret',
                        lambda path, body, uid: (order.append(os.path.basename(path)), real(path, body, uid)))
    ar.write_revocations(str(deployment), [], '', None)
    assert order == [ar.CRL_FILE, ar.REVOKED_FILE]


def test_refresh_writes_both(deployment, certs):
    sdir = _secrets(deployment)
    logs = []
    assert ar.refresh_revocations(_with_db(_ctx(), _db()), PLAIN, str(deployment), logs.append,
                                  cert_dir=str(certs))
    assert FP1 in (sdir / ar.REVOKED_FILE).read_text()
    assert (sdir / ar.CRL_FILE).read_text().count('BEGIN X509 CRL') == 2


def test_an_unreadable_database_leaves_the_old_copy_to_age_out(deployment, certs):
    """Nothing written, so the container refuses within the hour: fail closed."""
    sdir = _secrets(deployment)
    (sdir / ar.REVOKED_FILE).write_text('written=2020-01-01T00:00:00Z' + NL)
    logs = []
    assert not ar.refresh_revocations(_with_db(_ctx(), _db((False, 'down'))), PLAIN,
                                      str(deployment), logs.append, cert_dir=str(certs))
    assert (sdir / ar.REVOKED_FILE).read_text() == 'written=2020-01-01T00:00:00Z' + NL
    assert any('renewal stops within an hour' in m for m in logs)


def test_nothing_is_written_where_renewal_is_off_or_not_set_up(deployment, certs):
    ctx = _with_db(_ctx(), _db())
    assert not ar.refresh_revocations(ctx, PLAIN, str(deployment), print, cert_dir=str(certs))
    assert not (deployment / ar.SECRETS_DIR).exists()
    _secrets(deployment)
    off = dict(PLAIN, renewal_disabled=True)
    assert not ar.refresh_revocations(ctx, off, str(deployment), print, cert_dir=str(certs))
    assert not (deployment / ar.SECRETS_DIR / ar.REVOKED_FILE).exists()


def test_setting_renewal_up_copies_the_revocations_at_once(deployment, monkeypatch):
    ak = FakeAuthentik()
    monkeypatch.setattr(ar, 'TAK_CERT_DIR', str(deployment))
    ctx = _with_db(_ctx(), _db())
    result = ar.ensure(ctx, PLAIN, str(deployment), lambda *a: False, print, opener=ak,
                       ca_path=str(deployment / 'root-ca.pem'))
    assert result['ready']
    text = (deployment / ar.SECRETS_DIR / ar.REVOKED_FILE).read_text()
    assert re.match(r'^written=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\n', text) and FP1 in text


# ------------------------------------------------------------------ the loop

def test_each_tick_refreshes_every_built_deployment(tmp_path, monkeypatch):
    corona = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)
    unbuilt = ai.make('unbuilt', ai.MODE_DYNAMIC, 50, 8762)
    monkeypatch.setattr(atlas, 'load_instances', lambda ctx: [PLAIN, corona, unbuilt])
    monkeypatch.setattr(atlas, 'compose_projects_present', lambda ctx: set())
    monkeypatch.setattr(atlas, 'instance_is_built', lambda ctx, inst, projects=None: inst is not unbuilt)
    monkeypatch.setattr(atlas, 'instance_paths',
                        lambda ctx, inst: {'dir': str(tmp_path / (inst.get('slug') or 'atlas'))})
    done = []
    monkeypatch.setattr(atlas.atlas_renewal, 'refresh_revocations',
                        lambda ctx, inst, dirpath, log: done.append(os.path.basename(dirpath)))
    atlas.revocation_tick({}, print)
    assert done == ['atlas', 'corona']


def test_the_loop_starts_once_and_survives_a_failed_tick():
    src = (ROOT / 'modules' / 'atlas.py').read_text(encoding='utf-8')
    start = src.index('def _start_revocation_loop(')
    body = src[start:src.index('\ndef ', start + 10)]
    assert 'if _revocation_loop_started:' in body and 'except Exception' in body
    assert 'time.sleep(atlas_renewal.REVOCATION_INTERVAL_S)' in body
    reg = src.index('def register(ctx):')
    assert '_start_revocation_loop(ctx)' in src[reg:reg + 400]
    assert ar.REVOCATION_INTERVAL_S * 6 <= 3600  # well inside the container's hour


def test_the_console_hands_modules_the_tak_database():
    app = (ROOT / 'app.py').read_text(encoding='utf-8')
    assert "'_cotdb_psql': _cotdb_psql," in app


# ------------------------------------------------------- review fixes (ops #510)

def test_a_box_without_renewal_never_asks_docker(monkeypatch):
    """The tick runs every five minutes on every box; most have no ATLAS."""
    off = dict(PLAIN, renewal_disabled=True)
    for listed in ([], [off]):
        monkeypatch.setattr(atlas, 'load_instances', lambda ctx, listed=listed: listed)
        monkeypatch.setattr(atlas, 'compose_projects_present',
                            lambda ctx: pytest.fail('docker asked with no renewal to copy for'))
        atlas.revocation_tick({}, print)


def test_two_writers_never_overlap(deployment):
    """The loop and a deploy both write the list; one fixed .tmp name means a
    second writer could unlink the first one's file and publish an empty list."""
    import threading

    sdir = _secrets(deployment)
    with ar._REVOCATION_LOCK:
        t = threading.Thread(target=ar.write_revocations, args=(str(deployment), [FP1], '', None))
        t.start()
        t.join(0.3)
        assert t.is_alive() and not (sdir / ar.REVOKED_FILE).exists()
    t.join(5)
    assert FP1 in (sdir / ar.REVOKED_FILE).read_text()
