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
"""A phone with a refused certificate can still reach enrollment (v10.3.4, W1).

test6, 2026-11-01: after an intermediate-CA rotation and revoke, phones still holding the
old cert retried :8089, the takserver jail banned them on every TAK port including 8446,
and the fresh QR could not connect ("TAK server registration failed"). The takserver
filter now ignores refused-cert lines and the new takserver-badcert filter counts only
those. `_f2b_tak_failure_kind()` (console and ban e-mail) must say bad_cert for exactly the
lines the badcert filter counts.

The lines below are the real shapes from test6's messaging log (every cause/port shape
seen there, addresses changed). `Certificate error: peer not verified` is on all of them,
scanners included, which is why it can't be the bad-cert marker.
"""

import ast
import pathlib
import re
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

PFX = ('2026-11-01-09:56:23.112 [epollEventLoopGroup-4-9] ERROR c.b.m.n.n.h.NioNettyHandlerBase - '
       'NioNettyServerHandler error. Cause: ')


def _line(cause, ip, tail='Certificate error: peer not verified; ', port=8089):
    return f'{PFX}{cause}. Additional info: Remote address: {ip}; Remote port: 48545; Local port: {port}; {tail}'


OSSL = 'io.netty.handler.ssl.ReferenceCountedOpenSslEngine$OpenSslHandshakeException: '
BAD_CERT = [
    _line('javax.net.ssl.SSLHandshakeException: General OpenSslEngine problem', '203.0.113.9'),
    _line('javax.net.ssl.SSLHandshakeException: General OpenSslEngine problem', '203.0.113.9', port=8060),
    _line('javax.net.ssl.SSLHandshakeException: General OpenSslEngine problem', '203.0.113.10',
          'Peer certificate Subject DN: OU=TAK, O=PUBLIC SAFETY, CN=test2bse; '),
]
SCANNER = [
    _line(OSSL + 'error:100000c0:SSL routines:OPENSSL_internal:PEER_DID_NOT_RETURN_A_CERTIFICATE', '198.51.100.7'),
    _line('io.netty.handler.ssl.NotSslRecordException: not an SSL/TLS record', '198.51.100.8'),
    _line(OSSL + 'error:1000010a:SSL routines:OPENSSL_internal:NO_SHARED_GROUP', '198.51.100.9', port=7001),
    _line(OSSL + 'error:100000b8:SSL routines:OPENSSL_internal:NO_SHARED_CIPHER', '198.51.100.10'),
    _line(OSSL + 'error:100000f0:SSL routines:OPENSSL_internal:UNSUPPORTED_PROTOCOL', '198.51.100.11'),
    _line('some.future.Exception: not seen yet', '198.51.100.12'),
]
RESETS = [
    _line('recvAddress(..) failed with error(-104): Connection reset by peer', '203.0.113.9'),
    _line('recvAddress(..) failed with error(-104): Connection reset by peer', '203.0.113.10',
          'Peer certificate Subject DN: OU=TAK, O=PUBLIC SAFETY, CN=test2bse; '),
    _line('recvAddress(..) failed with error(-110): Connection timed out', '203.0.113.9'),
]


def _table(name):
    i = APP.index(name + ' = {')
    depth, j = 0, APP.index('{', i)
    for k in range(j, len(APP)):
        depth += {'{': 1, '}': -1}.get(APP[k], 0)
        if depth == 0:
            return eval(APP[j:k + 1])
    raise AssertionError(name)


def _values(conf, key):
    """Every regex of a (possibly multi-line) fail2ban option, as compiled Python regexes."""
    m = re.search(rf'^{key} = ?(.*(?:\n[ \t]+\S.*)*)', conf, re.M)
    out = [v.strip() for v in m.group(1).split('\n') if v.strip()]
    return [re.compile(v.replace('<HOST>', r'(?P<host>[^;\s]+)')) for v in out]


def _hits(conf, line):
    """Hosts fail2ban would count for this line (one entry per matching failregex)."""
    if any(r.search(line) for r in _values(conf, 'ignoreregex')):
        return []
    return [m.group('host') for r in _values(conf, 'failregex') for m in [r.search(line)] if m]


def _kind_fns():
    ns = {'re': re}
    for n in TREE.body:
        if isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == '_F2B_TAK_FAIL_RE' for t in n.targets):
            exec(ast.get_source_segment(APP, n), ns)
        if isinstance(n, ast.FunctionDef) and n.name == '_f2b_tak_failure_kind':
            exec(ast.get_source_segment(APP, n), ns)
    i = APP.index("_F2B_NOTIFY_SCRIPT = r'''") + len("_F2B_NOTIFY_SCRIPT = r'''")
    mod = types.ModuleType('notify')
    exec(compile(APP[i:APP.index("'''", i)], 'notify', 'exec'), mod.__dict__)

    def console(line):
        m = ns['_F2B_TAK_FAIL_RE'].search(line)
        return ns['_f2b_tak_failure_kind'](m['cause'], m['rest'])

    def email(line):
        m = mod._TAK_FAIL_RE.search(line)
        return mod._tak_failure_kind(m['cause'], m['rest'])
    return console, email


def test_refused_certs_go_to_the_badcert_jail_only():
    f = _table('_F2B_OWNED_FILTERS')
    for line in BAD_CERT:
        ip = re.search(r'Remote address: ([^;]+);', line).group(1)
        assert _hits(f['takserver-badcert'], line) == [ip], line
        assert _hits(f['takserver'], line) == [], line


def test_scanners_still_go_to_the_takserver_jail_only():
    f = _table('_F2B_OWNED_FILTERS')
    for line in SCANNER:
        ip = re.search(r'Remote address: ([^;]+);', line).group(1)
        assert _hits(f['takserver'], line) == [ip], line
        assert _hits(f['takserver-badcert'], line) == [], line


def test_resets_count_in_neither_jail():
    f = _table('_F2B_OWNED_FILTERS')
    for line in RESETS:
        assert _hits(f['takserver'], line) == [] and _hits(f['takserver-badcert'], line) == [], line


def test_console_and_email_classify_exactly_like_the_filters():
    console, email = _kind_fns()
    for line in BAD_CERT:
        assert console(line) == email(line) == 'bad_cert', line
    for line in SCANNER:
        assert console(line) == email(line) != 'bad_cert', line


def test_badcert_filter_keeps_the_takserver_datepattern():
    f = _table('_F2B_OWNED_FILTERS')
    date = re.compile(r'^datepattern = .*(?:\n[ \t]+\S.*)*', re.M)
    assert date.search(f['takserver-badcert']).group(0) == date.search(f['takserver']).group(0)


def test_the_v1022_filter_is_legacy_so_every_box_upgrades():
    legacy = _table('_F2B_LEGACY_FILTERS')['takserver']
    new = _table('_F2B_OWNED_FILTERS')['takserver']
    assert new not in legacy
    v1022 = legacy[-1]
    assert 'Cause: recvAddress' in v1022 and 'General OpenSslEngine' not in v1022
    assert _hits(v1022, BAD_CERT[0]) == ['203.0.113.9']     # the bug this release fixes
