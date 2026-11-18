# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""ops #897: a WiFi network name with a colon or a backslash is read correctly from nmcli.

`nmcli -t` puts ':' between fields and writes a ':' or a '\\' inside a value with a backslash
before it (nmcli(1), --escape, default yes). The console read those lines with split(':') and
rsplit(':'), so a network named `Ops: Truck 5` showed as `Ops\\: Truck 5` in the scan list, was
missing from the saved list, and could not be picked or joined.

The functions are taken from app.py and run against a stand-in for nmcli that writes its terse
lines by nmcli's own rule (taken from its source, src/nmcli/utils.c: every value, every field
count).
"""
import ast
import pathlib
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

NAMES = ['Ops: Truck 5', 'back\\slash', 'a:b:c', 'end\\', ':lead', 'Field Kit 5G', "Chief's iPhone", 'x\\:y']


def _terse(*values):
    """One terse line, as nmcli prints it: each value escaped, ':' between values."""
    return ':'.join(str(v).replace('\\', '\\\\').replace(':', '\\:') for v in values)


def _load(*names, **stubs):
    """The named top-level functions of app.py, in a namespace with these stand-ins."""
    ns = {'__builtins__': __builtins__}
    ns.update(stubs)
    found = set()
    for node in TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name in names and node.name not in stubs:
            exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py', 'exec'), ns)
            found.add(node.name)
    missing = set(names) - found - set(stubs)
    assert not missing, 'not in app.py: %s' % sorted(missing)
    return ns


def _nmcli(tables):
    """subprocess.run stand-in. `tables` maps the -f field list to rows (tuples of raw values)."""
    calls = []

    def run(argv, **kw):
        calls.append(list(argv))
        out = ''
        if argv[0] == 'nmcli' and '-t' in argv and '-f' in argv:
            rows = tables.get(argv[argv.index('-f') + 1], [])
            out = ''.join(_terse(*row) + '\n' for row in rows)
        return types.SimpleNamespace(returncode=0, stdout=out, stderr='')
    return run, calls


def _ns(tables, *names, **more):
    run, calls = _nmcli(tables)
    stubs = dict(
        shutil=types.SimpleNamespace(which=lambda n: '/usr/bin/' + n),
        subprocess=types.SimpleNamespace(run=run),
        _sudo_wrap=lambda argv: argv,
        _ensure_nm_wifi=lambda: None,
        _conn_wifi_iface=lambda: 'wlan0',
        _conn_clear_dead_ethernet=lambda: None,
        time=types.SimpleNamespace(sleep=lambda s: None, time=lambda: 0.0),
    )
    stubs.update(more)
    # The line reader is loaded when app.py has it, so that on a tree without the fix these
    # tests fail on what the functions return, not on a missing helper.
    helper = [n.name for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == '_nmcli_terse_split']
    return _load(*(helper + list(names)), **stubs), calls


@pytest.mark.parametrize('values', [('Ops: Truck 5', '75'), ('back\\slash', '1'), ('a:b:c', 'd:e', '\\'), ('',),
                                    ('plain', '802-11-wireless'), ('end\\', ''), ('', '', '')])
def test_a_terse_line_splits_back_into_the_values_nmcli_had(values):
    ns = _load('_nmcli_terse_split')
    assert ns['_nmcli_terse_split'](_terse(*values)) == list(values)


def test_the_scan_list_has_the_exact_names_and_their_signal():
    ns, _ = _ns({'SSID,SIGNAL': [(n, 40 + i) for i, n in enumerate(NAMES)]}, '_conn_wifi_scan')
    assert ns['_conn_wifi_scan']() == [{'ssid': n, 'signal': str(40 + i)} for i, n in enumerate(NAMES)]


def test_the_in_range_list_has_the_exact_names():
    ns, _ = _ns({'SSID': [(n,) for n in NAMES] + [('',)]}, '_conn_wifi_visible')
    assert sorted(ns['_conn_wifi_visible']()) == sorted(NAMES)


def test_the_saved_list_has_every_wifi_profile_by_its_exact_name():
    rows = [(n, '802-11-wireless') for n in NAMES] + [('Wired: 1', '802-3-ethernet'), ('lo', 'loopback')]
    ns, _ = _ns({'NAME,TYPE': rows}, '_conn_wifi_saved')
    assert ns['_conn_wifi_saved']() == NAMES


@pytest.mark.parametrize('name', NAMES)
def test_the_connected_network_is_shown_by_its_exact_name(name):
    rows = [('eth0', 'ethernet', 'connected', 'Wired: 1'), ('wlan0', 'wifi', 'connected', name)]
    ns, _ = _ns({'DEVICE,TYPE,STATE,CONNECTION': rows}, '_conn_wifi_current')
    assert ns['_conn_wifi_current']() == name


@pytest.mark.parametrize('name', NAMES)
def test_rejoin_brings_up_the_saved_network_by_its_exact_name(name):
    tables = {'NAME,TYPE': [('takwerx-hotspot', '802-11-wireless'), (name, '802-11-wireless')],
              'SSID': [(name,)], 'IP4.ADDRESS': [('192.0.2.5/24',)]}
    ns, calls = _ns(tables, '_conn_join_best_saved', '_conn_wifi_visible')
    ns['_conn_join_best_saved']()
    ups = [c for c in calls if c[:3] == ['nmcli', 'connection', 'up']]
    assert ups and ups[0] == ['nmcli', 'connection', 'up', name]
