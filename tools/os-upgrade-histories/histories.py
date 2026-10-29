#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Box-history matrix for one-way, in-place upgrades (ops #285).

Plain stdlib script, no Claude, no cloud calls. It knows the matrix (scenarios.json) and judges
what the box scripts collected. The cloud side is box.sh; the console side is drive.py.

    histories.py list                      # every cell of the matrix, one per line
    histories.py plan CELL                 # the steps to replay, the snapshot name, the pass rule
    histories.py cell CELL                 # the resolved cell as JSON (for scripts)
    histories.py judge CELL INPUT.json --stage start    # is this snapshot a real history?
    histories.py judge CELL INPUT.json --stage end      # did the upgrade pass its rule?
    histories.py assemble --prefix P --boxes core,db    # the judge's input, from the files run-scenario.sh wrote
    histories.py release-line RESULT.json...            # 'Tested on histories:' line for release notes

CELL is a scenario id, or 'scenario-id:variant' for the h1 variants. Exit status of judge: 0 pass,
1 fail, 2 bad input.

Pass rule (ops #285): per scenario the upgrade status is `done`, the log has no `failed`, the box
is Ubuntu 24.04, the expected PostgreSQL clusters are on the expected ports, TAK Server + console
(+ Authentik where the history has it) are up, and the client check passes. An unsafe scenario
passes only if the console REFUSED before any change: preflight red, a next step named, and the
box exactly as it was.
"""
import argparse
import copy
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCENARIOS = os.path.join(HERE, 'scenarios.json')

STEP_ARG = {
    'infratak-install': 'ref',
    'console-update': 'ref',
    'takserver-deploy': 'version',
    'takserver-58-migrate': 'version',
    'start-old-cluster': 'cluster',
    'module-deploy': 'module',
    'two-server-deploy': 'version',
    'os-upgrade-released': 'ref',
}

# Always-true services of a healthy box that the upgrade was run on.
CORE_SERVICES_ALWAYS = ['takwerx-console']
OS_FROM = '22.04'


class Bad(Exception):
    """Bad input or an unknown cell: exit status 2."""


def load(path=SCENARIOS):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def step_label(step):
    """'module-deploy:authentik' — the line box.sh note-step writes to the box's provenance log."""
    arg = STEP_ARG.get(step['step'])
    return step['step'] + (':' + str(step[arg]) if arg else '')


def _scenario(data, sid):
    for s in data['scenarios']:
        if s['id'] == sid:
            return s
    raise Bad('unknown scenario %r (try: histories.py list)' % sid)


def _own_steps(scn, variant):
    steps = copy.deepcopy(scn['history'])
    if not variant:
        return steps
    v = (scn.get('variants') or {}).get(variant)
    if v is None:
        raise Bad('scenario %s has no variant %r' % (scn['id'], variant))
    for old, new in (v.get('replace_step') or {}).items():
        steps = [new if s['step'] == old else s for s in steps]
    return steps + copy.deepcopy(v.get('extra_steps') or [])


def resolve(data, cell):
    """The concrete cell: full replay history (a derived scenario starts from its parent's
    history), expected start state and pass rule, snapshot name."""
    sid, _, variant = cell.partition(':')
    scn = _scenario(data, sid)
    if (scn.get('variants') or {}) and not variant:
        raise Bad('%s has variants (%s): name one, e.g. %s:%s' % (
            sid, ', '.join(scn['variants']), sid, next(iter(scn['variants']))))
    steps = _own_steps(scn, variant)
    if scn.get('derive_from'):
        parent = resolve(data, scn['derive_from'])
        steps = parent['history'] + steps
    expect = copy.deepcopy(scn['expect'])
    if variant:
        expect.update(scn['variants'][variant].get('expect') or {})
    short = sid.split('-')[0] + (('-' + variant.split('-')[0]) if variant else '')
    return {
        'cell': cell, 'id': sid, 'variant': variant, 'title': scn['title'], 'why': scn.get('why', ''),
        'boxes': scn['boxes'], 'history': steps,
        'labels': [step_label(s) for s in steps],
        'start': copy.deepcopy(scn['start']), 'run': scn['run'], 'expect': expect,
        'snapshot': 'snap-' + short,
        'derive_from': scn.get('derive_from', ''),
        'post_prepare': list(scn.get('post_prepare') or []),
    }


def cells(data):
    out = []
    for s in data['scenarios']:
        if s.get('variants'):
            out += ['%s:%s' % (s['id'], v) for v in s['variants']]
        else:
            out.append(s['id'])
    return out


def expected_labels(cell, box):
    """Provenance a box must carry. The first box carries the whole replay; a second box
    (the database server) is stock image + the two-server deploy."""
    if box == cell['boxes'][0]:
        return cell['labels']
    return ['image'] + [step_label(s) for s in cell['history'] if s['step'] == 'two-server-deploy']


# ---- judging --------------------------------------------------------------------------------

class Report:
    def __init__(self, cell):
        self.cell = cell
        self.checks = []

    def add(self, name, ok, detail=''):
        self.checks.append({'name': name, 'ok': bool(ok), 'detail': detail})
        return bool(ok)

    @property
    def passed(self):
        return bool(self.checks) and all(c['ok'] for c in self.checks)

    def as_dict(self, stage):
        return {'cell': self.cell, 'stage': stage, 'passed': self.passed, 'checks': self.checks}


def _clusters(rows):
    """Normalise [[ver, name, port, status], ...] so 'down,recovery' and 'down' compare equal."""
    out = []
    for r in rows or []:
        r = list(r)
        out.append([str(r[0]), str(r[1]), str(r[2]), 'down' if str(r[3]).startswith('down') else str(r[3])])
    return sorted(out)


def _fmt_clusters(rows):
    return ', '.join('%s/%s:%s %s' % tuple(r) for r in _clusters(rows)) or 'none'


def _need(d, key, where):
    if key not in d:
        raise Bad('input is missing %s in %s' % (key, where))
    return d[key]


def _service_checks(rep, tag, facts, expect, check_baseline=True):
    services = facts.get('services') or {}
    want = sorted(set(CORE_SERVICES_ALWAYS + list(expect.get('services_active') or [])))
    down = [u for u in want if services.get(u) != 'active']
    rep.add('%s: console running' % tag, not down, 'not active: ' + ', '.join(down) if down else ', '.join(want))
    cont = facts.get('containers') or {}
    if expect.get('tak_in_container'):
        up = any(c == 'takserver' for c in (cont.get('running') or []))
        rep.add('%s: TAK Server running' % tag, up, 'takserver container running' if up else 'no takserver container is running')
    else:
        up = services.get('takserver') == 'active'
        rep.add('%s: TAK Server running' % tag, up, 'takserver.service active' if up else 'takserver.service is %s' % (services.get('takserver') or 'missing'))
    if check_baseline:
        base_s = [u for u, v in (facts.get('baseline_services') or {}).items() if v == 'active']
        gone = [u for u in base_s if services.get(u) != 'active']
        rep.add('%s: every service from before the upgrade is back' % tag, not gone,
                'missing: ' + ', '.join(gone) if gone else '%d service(s)' % len(base_s))
    running = cont.get('running') or []
    bad = list(cont.get('unhealthy') or [])
    rep.add('%s: no unhealthy or restarting container' % tag, not bad, ', '.join(bad) if bad else '%d running' % len(running))
    lost = sorted(set(facts.get('baseline_containers') or []) - set(running)) if check_baseline else []
    rep.add('%s: every container from before the upgrade is back' % tag, not lost, ', '.join(lost) if lost else 'ok')
    for sub in expect.get('containers_match') or []:
        rep.add('%s: a %s container is running' % (tag, sub), any(sub in c for c in running),
                'found' if any(sub in c for c in running) else 'none of: ' + (', '.join(running) or 'no containers'))


def judge_start(cell, inp):
    """Is this snapshot a REAL history? Provenance recorded by the replay, in order, and the
    start state the matrix promises. A hand-crafted end state has no provenance and fails."""
    rep = Report(cell['cell'])
    boxes = _need(inp, 'boxes', 'input')
    for box in cell['boxes']:
        facts = _need(boxes, box, 'boxes')
        want = expected_labels(cell, box)
        got = list(facts.get('provenance') or [])
        rep.add('%s: replayed the real steps, in order' % box, got == want,
                'ok: ' + ' > '.join(got) if got == want else 'recorded %s, wanted %s' % (got or 'nothing', want))
        key = 'clusters' if box == cell['boxes'][0] else 'clusters_db'
        want_cl = cell['start'].get(key)
        if want_cl is not None:
            rep.add('%s: starting clusters' % box, _clusters(facts.get('clusters')) == _clusters(want_cl),
                    'have %s, want %s' % (_fmt_clusters(facts.get('clusters')), _fmt_clusters(want_cl)))
        if box == cell['boxes'][0]:
            want_os = cell['start'].get('os_release', OS_FROM)
            rep.add('%s: starting Ubuntu' % box, facts.get('os_release') == want_os,
                    'have %s, want %s' % (facts.get('os_release'), want_os))
            want_st = cell['start'].get('status', '')
            rep.add('%s: starting upgrade status' % box, (facts.get('status') or '') == want_st,
                    'have %r, want %r' % (facts.get('status') or '', want_st))
            rep.add('%s: console running' % box, (facts.get('services') or {}).get('takwerx-console') == 'active', '')
    return rep


def judge_done(cell, inp, data):
    rep = Report(cell['cell'])
    ex = cell['expect']
    boxes = _need(inp, 'boxes', 'input')
    core_name = cell['boxes'][0]
    core = _need(boxes, core_name, 'boxes')
    before, after = core.get('before') or {}, _need(core, 'after', 'boxes.%s' % core_name)
    fin = inp.get('final_status')
    rep.add('upgrade status is done', fin == 'done', 'status is %r' % fin)
    cfg = data['defaults']
    log = after.get('log') or ''
    rep.add('the log is there', bool(log.strip()), '%d chars' % len(log))
    pat = re.compile(cfg['log_fail_pattern'])
    allow = [re.compile(a) for a in cfg.get('log_allow') or []]
    bad = [l.strip()[:160] for l in log.splitlines() if pat.search(l) and not any(a.search(l) for a in allow)]
    rep.add('the log has no "failed"', not bad, '; '.join(bad[:3]) + (' (+%d more)' % (len(bad) - 3) if len(bad) > 3 else '') if bad else 'clean')
    for rx in ex.get('log_must_match') or []:
        rep.add('the log says: %s' % rx, re.search(rx, log) is not None, 'found' if re.search(rx, log) else 'not in the log')
    rep.add('Ubuntu %s' % cfg['os_to'], after.get('os_release') == cfg['os_to'], 'lsb_release says %s' % after.get('os_release'))
    rep.add('PostgreSQL clusters as expected', _clusters(after.get('clusters')) == _clusters(ex.get('clusters')),
            'have %s, want %s' % (_fmt_clusters(after.get('clusters')), _fmt_clusters(ex.get('clusters'))))
    _service_checks(rep, core_name, after, ex)
    if ex.get('no_automatic_reboot'):
        rep.add('the box did not reboot by itself', bool(before.get('boot_id')) and before.get('boot_id') == after.get('boot_id'),
                'boot id %s -> %s' % (before.get('boot_id') or '?', after.get('boot_id') or '?'))
    if ex.get('also_upgrade_db_box'):
        db_name = cell['boxes'][1]
        db = _need(boxes, db_name, 'boxes').get('after') or {}
        rep.add('%s: status is done' % db_name, (db.get('status') or '') == 'done', 'status is %r' % db.get('status'))
        rep.add('%s: Ubuntu %s' % (db_name, cfg['os_to']), db.get('os_release') == cfg['os_to'], 'lsb_release says %s' % db.get('os_release'))
        rep.add('%s: PostgreSQL clusters as expected' % db_name, _clusters(db.get('clusters')) == _clusters(ex.get('clusters_db')),
                'have %s, want %s' % (_fmt_clusters(db.get('clusters')), _fmt_clusters(ex.get('clusters_db'))))
    _candidate_check(rep, inp, after)
    cc = inp.get('client_check') or {}
    rep.add('client check passes', cc.get('passed') is True and cc.get('anon_named', 0) == 0,
            'passed' if cc.get('passed') is True else 'not passed or not run')
    return rep


def _candidate_check(rep, inp, after):
    """When the run names the candidate sha, the box must be running exactly that code."""
    want = (inp.get('candidate_sha') or '').strip()
    if want:
        have = (after.get('infratak_sha') or '').strip()
        rep.add('the box runs the candidate %s' % want[:8], bool(have) and (have.startswith(want) or want.startswith(have)),
                'box is on %s' % (have[:8] or 'unknown'))


def judge_refused(cell, inp):
    rep = Report(cell['cell'])
    ex = cell['expect']
    boxes = _need(inp, 'boxes', 'input')
    core_name = cell['boxes'][0]
    core = _need(boxes, core_name, 'boxes')
    before, after = core.get('before') or {}, _need(core, 'after', 'boxes.%s' % core_name)
    pf = inp.get('preflight') or {}
    checks = {c.get('name'): c for c in pf.get('checks') or []}
    rep.add('preflight is red', pf.get('ok') is False, 'preflight ok=%r' % pf.get('ok'))
    named = checks.get(ex['refused_check']) or {}
    rep.add('the right check refused: %s' % ex['refused_check'], named.get('pass') is False,
            'check %s: pass=%r' % (ex['refused_check'], named.get('pass')))
    detail = named.get('detail') or ''
    for rx in ex.get('next_step_must_match') or []:
        rep.add('it names the next step: %s' % rx, re.search(rx, detail) is not None, detail[:200] or 'no detail')
    st = inp.get('start_response') or {}
    rep.add('Start was refused by the console', st.get('http_status') == 409 and st.get('ok') is False,
            'http %r ok=%r' % (st.get('http_status'), st.get('ok')))
    rep.add('no upgrade job was started', (after.get('status') or '') in ('', 'idle'), 'status is %r' % after.get('status'))
    rep.add('still Ubuntu %s' % OS_FROM, after.get('os_release') == OS_FROM, 'lsb_release says %s' % after.get('os_release'))
    rep.add('PostgreSQL clusters exactly as before', _clusters(after.get('clusters')) == _clusters(before.get('clusters')),
            'before %s, after %s' % (_fmt_clusters(before.get('clusters')), _fmt_clusters(after.get('clusters'))))
    rep.add('no reboot', bool(before.get('boot_id')) and before.get('boot_id') == after.get('boot_id'),
            'boot id %s -> %s' % (before.get('boot_id') or '?', after.get('boot_id') or '?'))
    rep.add('no upgrade settings left behind', not after.get('apt_conf_left'), 'apt/release-upgrade drop-ins present' if after.get('apt_conf_left') else 'none')
    rep.add('no package was moved', bool(before.get('pkg_hash')) and before.get('pkg_hash') == after.get('pkg_hash'),
            'package list hash %s -> %s' % (before.get('pkg_hash') or '?', after.get('pkg_hash') or '?'))
    _service_checks(rep, core_name, after, ex, check_baseline=False)
    _candidate_check(rep, inp, after)
    cc = inp.get('client_check') or {}
    rep.add('client check passes', cc.get('passed') is True and cc.get('anon_named', 0) == 0,
            'passed' if cc.get('passed') is True else 'not passed or not run')
    return rep


def judge(cell, inp, stage, data=None):
    data = data or load()
    if stage == 'start':
        return judge_start(cell, inp)
    if cell['expect']['result'] == 'refused':
        return judge_refused(cell, inp)
    return judge_done(cell, inp, data)


# ---- run input ------------------------------------------------------------------------------

def assemble(prefix, boxes, final='', candidate=''):
    """The judge's input, from the files run-scenario.sh wrote: PREFIX-preflight.json,
    PREFIX-start.json, PREFIX-client.json and PREFIX-<box>-before/after.json. A missing file
    reads as {}, so a step that never ran fails its check instead of passing by silence."""
    def rd(path):
        try:
            with open(path, encoding='utf-8') as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}
    start = rd(prefix + '-start.json')
    out = {'boxes': {}, 'preflight': rd(prefix + '-preflight.json'),
           'start_response': {'http_status': start.get('http_status'), 'ok': start.get('ok')},
           'final_status': final, 'client_check': rd(prefix + '-client.json'), 'candidate_sha': candidate}
    for b in boxes:
        out['boxes'][b] = {'before': rd('%s-%s-before.json' % (prefix, b)), 'after': rd('%s-%s-after.json' % (prefix, b))}
    return out


# ---- release notes --------------------------------------------------------------------------

def release_line(results):
    """One line for a release note that adds an in-place upgrade: which histories it was tested
    on and what each said. A failed or missing cell is listed as such, never dropped."""
    if not results:
        raise Bad('give at least one RESULT.json')
    parts = []
    for r in results:
        parts.append('%s %s' % (r['cell'], 'passed' if r.get('passed') else 'FAILED'))
    return 'Tested on box histories: ' + '; '.join(parts) + '.'


def release_line_all(results, data=None):
    """Same, but a cell with no result at all is named 'NOT RUN', so a release note cannot
    quietly leave out the history it never tried."""
    data = data or load()
    by = {r['cell']: r for r in results}
    parts = []
    for c in cells(data):
        r = by.get(c)
        parts.append('%s %s' % (c, 'NOT RUN' if r is None else ('passed' if r.get('passed') else 'FAILED')))
    return 'Tested on box histories: ' + '; '.join(parts) + '.'


# ---- command line ---------------------------------------------------------------------------

def render_plan(cell, data):
    d = data['defaults']
    azure = d['azure']
    out = ['%s — %s' % (cell['cell'], cell['title']), cell['why'], '',
           'Boxes: ' + ', '.join(cell['boxes']) + '   Snapshot: ' + cell['snapshot'] +
           (('   (built from ' + cell['derive_from'] + ')') if cell['derive_from'] else ''),
           'Resource group: %s (tags owner=%s, expires=<date>), auto-shutdown %s UTC set when the VM is created' % (
               azure['resource_group'], azure['owner'], azure['auto_shutdown_utc']),
           '', 'Replay these, in order, on the VM (each one is noted with box.sh note-step):']
    for i, s in enumerate(cell['history'], 1):
        out.append('  %d. %s — %s' % (i, step_label(s), data['steps'][s['step']]))
    out += ['', 'Check the starting state before the snapshot: histories.py judge %s INPUT.json --stage start' % cell['cell'],
            'Start state: clusters %s, status %r' % (_fmt_clusters(cell['start'].get('clusters')), cell['start'].get('status', '')),
            '', 'Run: %s' % cell['run']]
    ex = cell['expect']
    if ex['result'] == 'done':
        out.append('Passes when: status done; no "failed" in the log; Ubuntu 24.04; clusters %s; console + TAK Server up%s; client check passes.' % (
            _fmt_clusters(ex.get('clusters')), ' + ' + ', '.join(ex['containers_match']) if ex.get('containers_match') else ''))
    else:
        out.append('Passes when: the console REFUSES before any change (check %s, next step named) and the box is exactly as it was.' % ex['refused_check'])
    return '\n'.join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('list')
    for name in ('plan', 'cell'):
        p = sub.add_parser(name)
        p.add_argument('cell')
    j = sub.add_parser('judge')
    j.add_argument('cell')
    j.add_argument('input')
    j.add_argument('--stage', choices=('start', 'end'), default='end')
    a = sub.add_parser('assemble')
    a.add_argument('--prefix', required=True)
    a.add_argument('--boxes', required=True, help='comma separated, in cell order')
    a.add_argument('--final', default='')
    a.add_argument('--candidate', default='')
    r = sub.add_parser('release-line')
    r.add_argument('results', nargs='+')
    r.add_argument('--all-cells', action='store_true', help='name every cell of the matrix, "NOT RUN" where there is no result')
    args = ap.parse_args(argv)
    try:
        data = load()
        if args.cmd == 'list':
            for c in cells(data):
                print('%-40s %s' % (c, resolve(data, c)['title']))
            return 0
        if args.cmd == 'assemble':
            print(json.dumps(assemble(args.prefix, args.boxes.split(','), args.final, args.candidate)))
            return 0
        if args.cmd == 'release-line':
            results = []
            for path in args.results:
                with open(path, encoding='utf-8') as f:
                    results.append(json.load(f))
            print(release_line_all(results, data) if args.all_cells else release_line(results))
            return 0
        cell = resolve(data, args.cell)
        if args.cmd == 'cell':
            print(json.dumps(cell, indent=2))
            return 0
        if args.cmd == 'plan':
            print(render_plan(cell, data))
            return 0
        with open(args.input, encoding='utf-8') as f:
            inp = json.load(f)
        rep = judge(cell, inp, args.stage, data).as_dict(args.stage)
        print(json.dumps(rep, indent=2))
        for c in rep['checks']:
            print('%s %s%s' % ('PASS' if c['ok'] else 'FAIL', c['name'], '' if c['ok'] or not c['detail'] else ' — ' + c['detail']), file=sys.stderr)
        return 0 if rep['passed'] else 1
    except (Bad, OSError, ValueError) as e:
        print('histories.py: %s' % e, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
