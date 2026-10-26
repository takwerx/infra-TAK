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
"""tools/pick-tests.py picks test tiers from changed files (ops #242)."""
import importlib.util
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location('pick_tests', os.path.join(ROOT, 'tools', 'pick-tests.py'))
pick_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pick_tests)
TIER_MAP = pick_tests.load_map(os.path.join(ROOT, 'tools', 'test-tiers.json'))


def diff(path, added=(), removed=(), ctx=''):
    out = ['diff --git a/%s b/%s' % (path, path), '--- a/%s' % path, '+++ b/%s' % path,
           '@@ -10,1 +10,1 @@ %s' % ctx]
    out += ['-' + r for r in removed] + ['+' + a for a in added]
    return '\n'.join(out) + '\n'


def ids(text):
    result = pick_tests.build_result(pick_tests.parse_diff(text), TIER_MAP)
    return [it['id'] for it in result['required']], result


def test_map_is_valid_json_with_compilable_rules():
    for rule in TIER_MAP['rules']:
        pick_tests.compile_all(rule.get('content', []))
        pick_tests.compile_all(rule.get('context', []))
        assert rule['id'] and rule['label']


def test_docs_only_change_needs_tier1_and_box_only():
    got, result = ids(diff('README.md', added=['changelog about pgbouncer and start.sh']))
    assert got == ['tier1', 'box']
    assert result['required'][1]['boxes'] == ['any free dev box']


def test_start_sh_is_install_path():
    got, result = ids(diff('start.sh', added=['echo hi']))
    assert 'install' in got and 'database' not in got
    assert result['required'][1]['boxes'] == ['nuc', 'aws-arm']


def test_pkg_install_inside_app_py_is_install_path():
    got, _ = ids(diff('app.py', added=["    _pkg_install(['jq'])"], ctx='def _setup_thing():'))
    assert 'install' in got


def test_deploy_function_context_is_install_path():
    got, _ = ids(diff('app.py', added=['    x = 1'], ctx='def run_caddy_deploy(domain):'))
    assert 'install' in got


def test_plain_app_py_change_is_not_install_or_db():
    got, _ = ids(diff('app.py', added=['    label = "Hello"'], ctx='def home():'))
    assert got == ['tier1', 'box']


def test_pgbouncer_change_is_database_and_soak_and_test8():
    got, result = ids(diff('app.py', added=['PGBOUNCER_POOL = 20'], ctx='def x():'))
    assert 'database' in got and 'soak' in got
    assert 'test8' in result['required'][1]['boxes']


def test_guarddog_db_script_is_database_and_soak_by_path():
    got, _ = ids(diff('scripts/guarddog/tak-retention-guard.sh', added=['true']))
    assert 'database' in got and 'soak' in got


def test_authentik_change_is_soak_only():
    got, _ = ids(diff('app.py', added=['AUTHENTIK_TIMEOUT = 30'], ctx='def y():'))
    assert 'soak' in got and 'database' not in got


def test_cert_renewal_change_is_soak():
    got, _ = ids(diff('app.py', added=['    run_certbot_renew()'], ctx='def z():'))
    assert 'soak' in got


def test_tests_and_docs_do_not_trigger_content_rules():
    got, _ = ids(diff('tests/test_x.py', added=['_pkg_install pgbouncer authentik']))
    assert got == ['tier1', 'box']


def test_two_files_combine_and_boxes_are_deduped():
    text = diff('start.sh', added=['x']) + diff('scripts/guarddog/tak-db-watch.sh', added=['y'])
    got, result = ids(text)
    assert got == ['tier1', 'box', 'install', 'database', 'soak']
    assert result['required'][1]['boxes'] == ['nuc', 'aws-arm', 'test8']


def test_rename_matches_old_or_new_path():
    text = ('diff --git a/old.txt b/start.sh\nsimilarity index 90%\n'
            'rename from old.txt\nrename to start.sh\n')
    got, _ = ids(text)
    assert 'install' in got


def test_glob_semantics():
    rx = pick_tests.glob_to_regex
    assert rx('**/*.service').match('a/b/x.service') and rx('**/*.service').match('x.service')
    assert rx('scripts/*.sh').match('scripts/a.sh') and not rx('scripts/*.sh').match('scripts/g/a.sh')
    assert rx('start.sh').match('start.sh') and not rx('start.sh').match('xstart.sh')


def test_markdown_output_is_a_short_checklist():
    _, result = ids(diff('start.sh', added=['x']))
    md = pick_tests.render_markdown(result)
    lines = md.splitlines()
    assert lines[0].startswith('**Tests required before merge**')
    assert any(l.startswith('- [ ] Tier 3 fresh install') for l in lines)
    assert 'Tier 1 PR checks' in md and 'Worker box test' in md
    assert lines[-1].startswith('Lead: do not merge')


def test_json_output_round_trips():
    _, result = ids(diff('start.sh', added=['x']))
    assert json.loads(json.dumps(result)) == result


def test_cli_diff_file(tmp_path, capsys):
    p = tmp_path / 'c.diff'
    p.write_text(diff('start.sh', added=['x']))
    assert pick_tests.main(['--diff-file', str(p), '--format', 'json']) == 0
    out = json.loads(capsys.readouterr().out)
    assert [i['id'] for i in out['required']] == ['tier1', 'box', 'install']


def test_editing_the_map_or_the_picker_itself_adds_no_tiers():
    text = (diff('tools/test-tiers.json', added=['"_pkg_install pgbouncer authentik"'])
            + diff('tools/pick-tests.py', added=['# systemctl retention']))
    got, _ = ids(text)
    assert got == ['tier1', 'box']
