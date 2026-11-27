#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Is each takwerx CloudTAK plugin really in the built CloudTAK web app? (ops #301)

The failure this exists for (ops #297): CloudTAK moved its web app from api/web/ to app/ in
13.102.0. The Dispatcher's install.sh kept copying into the old folder, reported success, and the
plugin never reached the build, so there was no menu item. Nothing looked at the finished app.

Three steps, run by .github/workflows/cloudtak-plugins-nightly.yml around a real `docker build`
of CloudTAK:

  install-catalog     install every plugin in manifest.json the way infra-TAK's catalog does
                      (copy into <web>/plugins/<dir>, server routes into api/stateless/routes),
                      then run infra-TAK's own pre-build shield from app.py on the tree
  install-dispatcher  run the Dispatcher repo's own install.sh --no-build (standalone users)
  verify              open the built web app and look for each plugin's menu entry
  verify-routes       check every CloudTAK API call the plugin's browser code makes still has a
                      route in this CloudTAK (ops #1414: the menu can load while the action is dead)
  routes-local        the same check for plugin checkouts you hold (the two private plugins, run on
                      the Studio: a GitHub-hosted run cannot read them)

Both install steps write expect.json, built from the plugin's OWN source (the key / label /
tooltip / description strings in its `menu.add({...})` call), so a plugin that renames its menu
entry does not need this file edited. verify then looks for those strings, together, in one chunk
of the built JavaScript. A plugin whose menu.add can't be read is an error, not a skip.

Stdlib only; runs with `python3 -I`.
"""

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
MANIFEST = HERE / 'manifest.json'

SRC_SUFFIXES = ('.ts', '.js', '.mjs', '.vue')
SKIP_DIRS = {'node_modules', 'dist', '.git', 'test', 'tests', '__tests__'}
# Properties of menu.add({...}) that show up as plain string literals in the built app.
MENU_PROPS = ('key', 'label', 'tooltip', 'description', 'route')


def load_manifest(path=MANIFEST):
    with open(path, encoding='utf-8') as f:
        return json.load(f)['plugins']


def web_dir(ct):
    """CloudTAK's web app root for this tree: app/ (13.102.0+) or api/web/ (before)."""
    ct = Path(ct)
    return ct / 'app' if (ct / 'app' / 'src').is_dir() else ct / 'api' / 'web'


# ── what the plugin says it registers ────────────────────────────────────────────

_STR = r'''(?:'((?:\\.|[^'\\\n])*)'|"((?:\\.|[^"\\\n])*)")'''
_CONST_RE = re.compile(r'\bconst\s+([A-Za-z_]\w*)\s*(?::\s*string\s*)?=\s*' + _STR)


def _unescape(s):
    return re.sub(r'\\(.)', r'\1', s)


def _consts(text):
    return {m.group(1): _unescape(m.group(2) if m.group(2) is not None else m.group(3))
            for m in _CONST_RE.finditer(text)}


def _object_after(text, start):
    """The text of the {...} literal that opens at or after `start` (string-aware brace match)."""
    i = text.find('{', start)
    if i < 0:
        return ''
    depth, quote, j = 0, None, i
    while j < len(text):
        c = text[j]
        if quote:
            if c == '\\':
                j += 1
            elif c == quote:
                quote = None
        elif c in '\'"`':
            quote = c
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
        j += 1
    return text[i:]


def derive_menu(plugin_dir):
    """[{prop: string}] for every `menu.add({...})` in the plugin's source. Empty when none."""
    entries = []
    for root, dirs, files in os.walk(plugin_dir):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(files):
            if not n.endswith(SRC_SUFFIXES) or n.endswith('.d.ts'):
                continue
            try:
                text = Path(root, n).read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            consts = _consts(text)
            for m in re.finditer(r'\bmenu\s*\.\s*add\s*\(\s*(?=\{)', text):
                body = _object_after(text, m.end())
                entry = {}
                for prop in MENU_PROPS:
                    pm = re.search(r'(?:^|[\s,{])' + prop + r'\s*:\s*(?:' + _STR + r'|([A-Za-z_]\w*)\b)', body)
                    if not pm:
                        continue
                    if pm.group(1) is not None or pm.group(2) is not None:
                        entry[prop] = _unescape(pm.group(1) if pm.group(1) is not None else pm.group(2))
                    elif pm.group(3) in consts:
                        entry[prop] = consts[pm.group(3)]
                if entry.get('key') and entry.get('label'):
                    entry['file'] = os.path.relpath(Path(root, n), plugin_dir).replace(os.sep, '/')
                    if entry not in entries:
                        entries.append(entry)
    return entries


# ── what the built app contains ──────────────────────────────────────────────────

def _forms(s):
    """How a string can appear in built JS: as written, or with non-ASCII / quotes escaped."""
    out = {s, json.dumps(s)[1:-1], json.dumps(s, ensure_ascii=False)[1:-1]}
    return sorted(out, key=len)


def _quoted_in(chunk, s):
    return any(q + f + q in chunk for f in _forms(s) for q in ('"', "'", '`'))


def _label_in(chunk, s):
    return any(re.search(r'\blabel\s*:\s*["\'`]' + re.escape(f) + r'["\'`]', chunk) for f in _forms(s))


def read_chunks(dist):
    chunks = {}
    for root, _dirs, files in os.walk(dist):
        for n in files:
            if n.endswith(('.js', '.mjs')):
                p = Path(root, n)
                chunks[os.path.relpath(p, dist).replace(os.sep, '/')] = p.read_text(encoding='utf-8', errors='replace')
    return chunks


def find_menu_entry(chunks, entry):
    """Name of the built chunk that registers this menu entry, or None. The label has to be the
    value of a `label:` property and every other string the plugin passed to menu.add() has to be
    in the same chunk, so one common word in an unrelated chunk is not enough."""
    for name, chunk in sorted(chunks.items()):
        if not _label_in(chunk, entry['label']):
            continue
        if all(_quoted_in(chunk, entry[p]) for p in MENU_PROPS if p != 'label' and entry.get(p)):
            return name
    return None


def snippet(chunks, name, entry, width=70):
    """The text around `label:"..."` in the chunk, to show what the built app really has."""
    for f in _forms(entry['label']):
        m = re.search(r'\blabel\s*:\s*["\'`]' + re.escape(f) + r'["\'`]', chunks[name])
        if m:
            return chunks[name][max(0, m.start() - width):m.end() + width].replace('\n', ' ')
    return ''


def verify_bundle(expect, dist):
    """(report lines, number of problems). One line per plugin."""
    chunks = read_chunks(dist)
    if not chunks:
        return [f'FAIL  no JavaScript found under {dist}: the web app did not build or was not copied out'], 1
    lines, problems = [], 0
    for p in expect['plugins']:
        label = f"{p['name']} ({p['key']})"
        if p.get('skipped'):
            lines.append(f"skip  {label}: {p['skipped']}")
            continue
        if p.get('error'):
            lines.append(f"FAIL  {label}: {p['error']}")
            problems += 1
            continue
        for e in p['menu']:
            chunk = find_menu_entry(chunks, e)
            if chunk:
                lines.append(f"ok    {label}: menu entry '{e['label']}' (key {e['key']}) is in {chunk}")
                lines.append(f"        ...{snippet(chunks, chunk, e)}...")
            else:
                lines.append(f"FAIL  {label}: menu entry '{e['label']}' (key {e['key']}) is NOT in the built app "
                             f"({len(chunks)} JS files searched). The plugin was installed but did not make it into the build.")
                problems += 1
    return lines, problems


# ── the CloudTAK routes each plugin calls (ops #1414) ────────────────────────────
#
# Why this exists: a menu entry in the bundle proves the plugin loaded, not that its main action
# works. CloudTAK 14.0.0 removed routes, changed chat and location, and a plugin that calls a route
# that is gone shows its menu and then fails when the user clicks. So: for every plugin, read every
# CloudTAK API call its browser code makes (std('/api/...', {method})), and check that CloudTAK's own
# source (plus the routes the plugin ships in server/) still defines that route with that method.
# It needs no TAK Server and no login, so it runs in the nightly with the rest.

HTTP_VERBS = ('get', 'post', 'put', 'patch', 'delete')
# A call to CloudTAK's own fetch helper. `std` is what plugins use (plain fetch gives 401 No Auth Present).
CALL_RE = re.compile(r'(?<![\w.$])(?:std|stdurl|server\s*\.\s*(?:GET|POST|PUT|PATCH|DELETE))\s*\(\s*(?=[`\'"A-Za-z_])')
ROUTE_RE = re.compile(r'\bschema\s*\.\s*(' + '|'.join(HTTP_VERBS) + r')\s*\(\s*(?:\'([^\'\n]+)\'|"([^"\n]+)"|`([^`\n]+)`)')
ROUTE_DIR_RE = re.compile(r'^(?:api|tasks)(?:/[^/]+)*/routes$')


def _read_arg(text, i):
    """(kind, value, end) for the first argument of a call that starts at text[i].
    kind 'str' = a string or template literal with `${...}` parts left in; 'other' = anything else."""
    q = text[i]
    if q not in '\'"`':
        return 'other', '', i
    j, out = i + 1, []
    while j < len(text):
        c = text[j]
        if c == '\\' and j + 1 < len(text):
            out.append(text[j:j + 2])
            j += 2
            continue
        if q == '`' and c == '$' and text[j + 1:j + 2] == '{':
            depth, k, inq = 1, j + 2, None
            while k < len(text) and depth:
                d = text[k]
                if inq:
                    if d == '\\':
                        k += 1
                    elif d == inq:
                        inq = None
                elif d in '\'"`':
                    inq = d
                elif d == '{':
                    depth += 1
                elif d == '}':
                    depth -= 1
                k += 1
            out.append(text[j:k])
            j = k
            continue
        if c == q:
            return 'str', ''.join(out), j + 1
        if c == '\n' and q != '`':
            break
        out.append(c)
        j += 1
    return 'other', '', j


def _call_end(text, i):
    """Index of the ')' that closes the call whose '(' was just before text[i] (string-aware)."""
    depth, quote, j = 1, None, i
    while j < len(text):
        c = text[j]
        if quote:
            if c == '\\':
                j += 1
            elif c == quote:
                quote = None
        elif c in '\'"`':
            quote = c
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return len(text)


def _fill(template, consts):
    """(path, open_tail) for a call path with every ${...} resolved: a known string constant becomes
    its text, a value in a path position becomes ':p'. A '?query' built on the fly is dropped. A value
    glued onto the end of a path (`${BASE}${path}`) cannot be read: open_tail is then True and the
    caller only checks that CloudTAK has routes under that prefix."""
    out, i, open_tail = '', 0, False
    while i < len(template):
        if template.startswith('${', i):
            depth, k = 1, i + 2
            while k < len(template) and depth:
                depth += (template[k] == '{') - (template[k] == '}')
                k += 1
            expr = template[i + 2:k - 1].strip()
            if expr in consts:
                out += consts[expr]
            elif out == '' or out.endswith('/'):
                out += ':p'
            elif '?' not in out and not re.search(r'[\'"`]\?', expr):
                open_tail = True
            i = k
        else:
            out += template[i]
            i += 1
    return out, open_tail


def _literals(text):
    """(start, end, value) of every string and template literal outside comments."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '/' and text.startswith('//', i):
            j = text.find('\n', i)
            i = n if j < 0 else j
        elif c == '/' and text.startswith('/*', i):
            j = text.find('*/', i + 2)
            i = n if j < 0 else j + 2
        elif c in '\'"`':
            kind, value, end = _read_arg(text, i)
            if kind == 'str':
                yield i, end, value
                i = end
            else:
                i += 1
        else:
            i += 1


_STD_CTX = re.compile(r'(?<![\w.$])std\s*\(\s*$')      # stdurl() only builds an address: the method is chosen later
_SERVER_CTX = re.compile(r'\bserver\s*\.\s*(GET|POST|PUT|PATCH|DELETE)\s*\(\s*$')
_CONST_CTX = re.compile(r'\bconst\s+(\w+)\s*(?::\s*string\s*)?=\s*$')


def derive_calls(plugin_dir):
    """([{method, path, prefix, file, line}], [{file, line}]) from the plugin's browser code.

    Three kinds of call are read: std('/api/...', {method}) (CloudTAK's fetch helper), the typed
    client server.GET('/api/...') and any other string that holds an /api/ path (a plain fetch built
    on serverUrl). std() and the typed client know their method; every other string (stdurl() builds an address that a later fetch or sendBeacon uses) matches any method. `path` has no query
    and ':p' where the plugin puts a value. prefix=True: only the start of the path can be read (a
    constant such as BASE, a path that ends in '/', or a tail added at run time), so the check is
    that CloudTAK has routes under it. The second list is calls to std()/server.* whose first
    argument is not a literal: they are reported, never silently skipped."""
    calls, unread = [], []
    for root, dirs, files in os.walk(plugin_dir):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(files):
            if not n.endswith(SRC_SUFFIXES) or n.endswith('.d.ts'):
                continue
            rel = os.path.relpath(Path(root, n), plugin_dir).replace(os.sep, '/')
            try:
                text = Path(root, n).read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            consts = _consts(text)
            for m in CALL_RE.finditer(text):
                if _read_arg(text, m.end())[0] != 'str':
                    unread.append({'file': rel, 'line': text.count('\n', 0, m.start()) + 1})
            for start, end, value in _literals(text):
                path, open_tail = _fill(value, consts)
                k = path.find('/api/')
                # Nothing, or a value (the server address), before /api/. A fixed host name is another site.
                if k < 0 or path[:k] not in ('', ':p'):
                    continue
                path = re.sub(r'\{[^}]*\}', ':p', path[k:]).split('?')[0]
                before = text[max(0, start - 80):start]
                sm = _SERVER_CTX.search(before)
                method = '*'
                if sm:
                    method = sm.group(1).lower()
                elif _STD_CTX.search(before):
                    mm = re.search(r'\bmethod\s*:\s*[\'"`]([A-Za-z]+)[\'"`]', text[end:_call_end(text, end)])
                    method = (mm.group(1) if mm else 'get').lower()
                cm = _CONST_CTX.search(before) if '${' not in value else None
                if cm and re.search(r'\$\{\s*' + re.escape(cm.group(1)) + r'\b', text):
                    continue            # a constant the calls below use as ${NAME}: they are checked, not the constant
                prefix = open_tail or path.endswith('/') or bool(cm)
                call = {'method': method, 'path': path.rstrip('/') or '/', 'prefix': prefix,
                        'file': rel, 'line': text.count('\n', 0, start) + 1}
                if not any(c['method'] == call['method'] and c['path'] == call['path'] and c['prefix'] == call['prefix']
                           for c in calls):
                    calls.append(call)
    return calls, unread


def cloudtak_routes(ct):
    """{(method, '/api/...')} that this CloudTAK checkout defines. Routes are `schema.get('/x', ...)`
    in api/*/routes/*.ts (and tasks/*/routes) and are mounted under /api."""
    ct, routes = Path(ct), set()
    for root, _dirs, files in os.walk(ct):
        rel = os.path.relpath(root, ct).replace(os.sep, '/')
        if 'node_modules' in rel.split('/') or not ROUTE_DIR_RE.match(rel):
            continue
        for n in sorted(files):
            if not n.endswith('.ts'):
                continue
            text = Path(root, n).read_text(encoding='utf-8', errors='replace')
            for m in ROUTE_RE.finditer(text):
                path = m.group(2) or m.group(3) or m.group(4)
                if path.startswith('/'):
                    routes.add((m.group(1), ('/api' + path).rstrip('/') or '/api'))
    return routes


def _seg_match(call_seg, route_seg):
    return call_seg == route_seg or route_seg.startswith(':') or call_seg == ':p'


def route_exists(routes, method, path, prefix=False):
    """Is there a route for this call? method '*' = any method. prefix = only the start of the
    path is known, so any route under it counts."""
    segs = path.strip('/').split('/')
    for m, r in routes:
        rs = r.strip('/').split('/')
        if method != '*' and m != method:
            continue
        if (len(rs) >= len(segs) if prefix else len(rs) == len(segs)) \
                and all(_seg_match(a, b) for a, b in zip(segs, rs)):
            return True
    return False


def other_method(routes, method, path):
    """The methods CloudTAK does have for this path, when `method` is not one of them."""
    return sorted({m.upper() for m in HTTP_VERBS if m != method and route_exists(routes, m, path)})


def _says(c):
    return f"{c['method'].upper() if c['method'] != '*' else 'any method'} {c['path']}{'/...' if c.get('prefix') else ''}"


def verify_routes(expect, routes):
    """(report lines, number of problems). One line per plugin, then one per call that has no route.
    A plugin may list `allow_missing` calls it copes with (each needs a `why`): they are shown as
    `known`, not counted, so a NEW missing route is still red."""
    lines, problems = [], 0
    if not routes:
        return ['FAIL  no routes found in this CloudTAK checkout: the route scan cannot read it'], 1
    for p in expect['plugins']:
        label = f"{p['name']} ({p['key']})"
        if p.get('skipped'):
            lines.append(f"skip  {label}: {p['skipped']}")
            continue
        calls = p.get('calls', [])
        if not calls:
            if p.get('unread'):
                lines.append(f"note  {label}: no CloudTAK API call with a literal path ({len(p['unread'])} call(s) pass a variable); nothing this check can compare")
            else:
                lines.append(f"ok    {label}: the plugin makes no CloudTAK API call of its own, nothing to compare")
            continue
        allowed = {(a['method'].lower(), a['path']): a['why'] for a in p.get('allow_missing', [])}
        missing, known = [], []
        for c in calls:
            if route_exists(routes, c['method'], c['path'], c.get('prefix', False)):
                continue
            (known if (c['method'], c['path']) in allowed else missing).append(c)
        for c in missing:
            alt = other_method(routes, c['method'], c['path']) if c['method'] != '*' and not c.get('prefix') else []
            why = (f"CloudTAK has {', '.join(alt)} for this path but not {c['method'].upper()}" if alt
                   else 'CloudTAK has no route for this')
            lines.append(f"FAIL  {label}: {_says(c)} ({c['file']}:{c['line']}): {why}")
            problems += 1
        for c in known:
            lines.append(f"known {label}: {_says(c)} ({c['file']}:{c['line']}) is not in this CloudTAK; tolerated: {allowed[(c['method'], c['path'])]}")
        if not missing:
            lines.append(f"ok    {label}: all {len(calls) - len(known)} CloudTAK API calls have a route")
        if p.get('unread'):
            lines.append(f"note  {label}: {len(p['unread'])} call(s) pass a variable, not a literal, so they were not checked "
                         f"({', '.join(sorted({u['file'] for u in p['unread']}))})")
    return lines, problems


# ── installing ───────────────────────────────────────────────────────────────────

def run(cmd, cwd=None, check=True, env=None):
    print('$ ' + ' '.join(str(c) for c in cmd), flush=True)
    r = subprocess.run([str(c) for c in cmd], cwd=cwd, env=env, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if r.stdout.strip():
        print(r.stdout.rstrip(), flush=True)
    if check and r.returncode != 0:
        raise SystemExit(f'ERROR: command failed ({r.returncode}): {" ".join(str(c) for c in cmd)}')
    return r


def fetch(repo, ref, dest):
    """Shallow copy of repo at ref (branch, tag or sha; default branch when ref is empty). Returns the sha."""
    dest = Path(dest)
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    run(['git', '-C', dest, 'init', '-q'])
    run(['git', '-C', dest, 'remote', 'add', 'origin', repo])
    run(['git', '-C', dest, 'fetch', '-q', '--depth', '1', 'origin', ref or 'HEAD'])
    run(['git', '-C', dest, 'checkout', '-q', 'FETCH_HEAD'])
    return run(['git', '-C', dest, 'rev-parse', '--short=9', 'HEAD']).stdout.strip()


def copy_dir(src, dest):
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns('.git', 'node_modules'), symlinks=False)


def plugin_expectation(p, web_src, sha=None):
    entries = derive_menu(web_src)
    calls, unread = derive_calls(web_src)
    out = {'key': p['key'], 'name': p['name'], 'install_dir': p['install_dir'], 'source': sha or 'local',
           'menu': entries, 'calls': calls, 'unread': unread}
    if p.get('allow_missing'):
        out['allow_missing'] = p['allow_missing']
    if not entries:
        out['error'] = (f'could not read a menu.add({{key, label}}) call in the plugin source ({web_src.name}/); '
                        'either the plugin no longer registers a menu entry or it does it in a way this check cannot read')
    return out


PRIVATE_NOTE = ('private repo: a GitHub-hosted run cannot read it, so it is not built or checked here. '
                'Run `bundle_check.py routes-local` on the Studio against the local checkout (see README)')


def private_expectation(p):
    return {'key': p['key'], 'name': p['name'], 'install_dir': p['install_dir'], 'source': 'private',
            'menu': [], 'calls': [], 'unread': [], 'skipped': PRIVATE_NOTE}


def cmd_install_catalog(a):
    ct, work = Path(a.ct), Path(a.work)
    plugins = load_manifest()
    web = web_dir(ct)
    routes = ct / 'api' / 'stateless' / 'routes'
    if not (ct / 'app' / 'src').is_dir():
        raise SystemExit('ERROR: this CloudTAK has no app/src: the check only covers CloudTAK 13.102.0 and newer')
    expect = []
    for p in plugins:
        if p.get('private'):
            print(f"SKIPPED {p['name']} ({p['key']}): {PRIVATE_NOTE}")
            expect.append(private_expectation(p))
            continue
        if p.get('local_path'):
            src, sha = REPO_ROOT / p['local_path'], None
            server = REPO_ROOT / p['server_path'] if p.get('server_path') else None
        else:
            clone = work / 'src' / p['key']
            sha = fetch(p['repo'], '', clone)
            src = clone / p['plugin_subpath'] if p.get('plugin_subpath') else clone
            server = clone / p['server_subpath'] if p.get('server_subpath') else None
        if not src.is_dir():
            raise SystemExit(f"ERROR: {p['name']}: {src} is not a folder")
        copy_dir(src, web / 'plugins' / p['install_dir'])
        if server and server.is_dir():
            if not routes.is_dir():
                raise SystemExit(f"ERROR: {p['name']} ships server routes but {routes} does not exist in this CloudTAK")
            for f in sorted(server.glob('*.ts')):
                shutil.copy2(f, routes / f.name)
        print(f"installed {p['name']} ({p['key']}) from {sha or 'this repo'} into {web.relative_to(ct)}/plugins/{p['install_dir']}")
        expect.append(plugin_expectation(p, src, sha))
    if a.no_shield:
        print("NOT running infra-TAK's pre-build step (--no-shield): this is the canary for a CloudTAK that leaves plugin folders out of the build")
    else:
        run_shield(ct, [p for p in plugins if p.get('in_catalog')])
    write_expect(work, expect)


def cmd_install_dispatcher(a):
    ct, work = Path(a.ct), Path(a.work)
    p = next(x for x in load_manifest() if x['key'] == 'tak-dispatcher')
    clone = work / 'src' / 'tak-dispatcher'
    sha = fetch(p['repo'], a.ref, clone)
    print(f"Dispatcher installer from {a.ref or 'the default branch'} = {sha}")
    run(['bash', clone / 'install.sh', '--no-build', ct])
    write_expect(work, [plugin_expectation(p, clone / p['plugin_subpath'], sha)])


def write_expect(work, expect):
    Path(work).mkdir(parents=True, exist_ok=True)
    (Path(work) / 'expect.json').write_text(json.dumps({'plugins': expect}, indent=2) + '\n', encoding='utf-8')


# ── infra-TAK's own pre-build step, taken from app.py as written ─────────────────

SHIELD_CONSTS = ('_CT_MARKETPLACE_TSCONFIG', '_CT_MARKETPLACE_ROUTES_RE', '_CT_IMPORT_RE',
                 '_CT_NPM_NAME_RE', '_CT_NPM_SPEC_RE', '_CT_DOCKERIGNORE_MARK', '_CT_PLUGIN_DIR_RE',
                 '_CT_DOCKERIGNORE_DISPATCHER_MARK')
SHIELD_FUNCS = ('_cloudtak_web_dir', '_cloudtak_plugins_dir', '_cloudtak_foreign_plugins',
                '_cloudtak_has_ts_nocheck', '_cloudtak_rewrite_in_place',
                '_cloudtak_plugin_missing_deps', '_ct_dockerignore_leaves_out',
                '_cloudtak_keep_plugins_in_build', '_cloudtak_shield_foreign_plugins')


def load_shield(app_py=REPO_ROOT / 'app.py', catalog=()):
    """The shield functions from app.py (the same ones the console runs before every CloudTAK
    image build), compiled on their own: app.py itself is a Flask app and is not imported."""
    src = Path(app_py).read_text(encoding='utf-8')
    tree = ast.parse(src)
    lines = src.splitlines(keepends=True)
    found = {}
    for node in tree.body:
        name = None
        if isinstance(node, ast.FunctionDef):
            name = node.name
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
        if name in SHIELD_CONSTS + SHIELD_FUNCS:
            start = min([node.lineno] + [d.lineno for d in getattr(node, 'decorator_list', [])]) - 1
            found[name] = ''.join(lines[start:node.end_lineno])
    missing = [n for n in SHIELD_CONSTS + SHIELD_FUNCS if n not in found]
    if missing:
        raise SystemExit('ERROR: app.py no longer defines ' + ', '.join(missing)
                         + ': update SHIELD_CONSTS / SHIELD_FUNCS in .github/ci/cloudtak_plugins/bundle_check.py')
    ns = {'os': os, 're': re, 'json': json, 'subprocess': subprocess,
          'CLOUDTAK_PLUGINS': [{'install_dir': p['install_dir']} for p in catalog]}
    exec(compile('\n\n'.join(found[n] for n in SHIELD_CONSTS + SHIELD_FUNCS), 'app.py', 'exec'), ns)
    return ns


def run_shield(ct, catalog):
    ns = load_shield(catalog=catalog)
    ns['_cloudtak_shield_foreign_plugins'](str(ct), lambda m: print(m, flush=True))


# ── infra-TAK's own in-container look, run against the image we just built ───────

def load_app_consts(names, app_py=REPO_ROOT / 'app.py'):
    tree = ast.parse(Path(app_py).read_text(encoding='utf-8'))
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in names:
            out[node.targets[0].id] = ast.literal_eval(node.value)
    missing = [n for n in names if n not in out]
    if missing:
        raise SystemExit('ERROR: app.py no longer defines ' + ', '.join(missing))
    return out


DIAG_SH = ('echo "js files: $(find "$3" -name "*.js" | wc -l)"; '
           'echo "files containing the key $1: $(find "$3" -name "*.js" | xargs -r grep -lF -e "$1" | wc -l)"; '
           'echo "files containing the label $2: $(find "$3" -name "*.js" | xargs -r grep -lF -e "$2" | wc -l)"')


def cmd_verify_in_image(a):
    """Run the exact shell snippet the console runs inside the api container after a rebuild
    (_CT_IN_APP_SH in app.py) in the image we built, once per menu entry. The two checks must agree."""
    c = load_app_consts(('_CT_IN_APP_SH', '_CT_APP_DIST'))
    expect = json.loads(Path(a.expect).read_text(encoding='utf-8'))
    bad = 0
    for p in expect['plugins']:
        for e in p.get('menu', []):
            r = subprocess.run(['docker', 'run', '--rm', '--entrypoint', 'sh', a.image, '-c', c['_CT_IN_APP_SH'], '_',
                                e['key'], e['label'], c['_CT_APP_DIST']],
                               text=True, capture_output=True)
            verdict = (r.stdout.strip().splitlines() or [''])[-1]
            print(f"{verdict or 'ERROR':8} {p['name']}: '{e['label']}'" + (f"  ({r.stderr.strip()[:200]})" if r.returncode else ''))
            if verdict != 'FOUND':
                bad += 1
                diag = subprocess.run(['docker', 'run', '--rm', '--entrypoint', 'sh', a.image, '-c', DIAG_SH, '_',
                                       e['key'], e['label'], c['_CT_APP_DIST']],
                                      text=True, capture_output=True)
                print('   ' + (diag.stdout + diag.stderr).strip().replace('\n', '\n   '))
    return 1 if bad else 0


# ── command line ─────────────────────────────────────────────────────────────────

def cmd_verify(a):
    expect = json.loads(Path(a.expect).read_text(encoding='utf-8'))
    lines, problems = verify_bundle(expect, a.dist)
    print('\n'.join(lines))
    skipped = sum(1 for ln in lines if ln.startswith('skip'))
    total = sum(1 for ln in lines if not ln.startswith((' ', 'skip')))
    print(f"\n{total - problems} of {total} checks passed" + (f" ({skipped} skipped: private)" if skipped else '')
          if lines else 'nothing to check')
    return 1 if problems else 0


def cmd_verify_routes(a):
    expect = json.loads(Path(a.expect).read_text(encoding='utf-8'))
    lines, problems = verify_routes(expect, cloudtak_routes(a.ct))
    print('\n'.join(lines))
    checked = sum(1 for ln in lines if ln.startswith(('ok', 'FAIL')))
    print(f"\n{checked - problems} of {checked} plugins' API calls match a CloudTAK route" if checked else 'nothing to check')
    return 1 if problems else 0


def cmd_routes_local(a):
    """Route check for plugin checkouts on this machine. Each --plugin is a repo folder with plugin/
    (browser code) and server/ (its own routes, optional)."""
    routes = cloudtak_routes(a.ct)
    plugins = []
    for repo in a.plugin:
        repo = Path(repo)
        web = repo / 'plugin' if (repo / 'plugin').is_dir() else repo
        calls, unread = derive_calls(web)
        server = repo / 'server'
        for f in sorted(server.glob('*.ts')) if server.is_dir() else []:
            for m in ROUTE_RE.finditer(f.read_text(encoding='utf-8', errors='replace')):
                path = m.group(2) or m.group(3) or m.group(4)
                if path.startswith('/'):
                    routes.add((m.group(1), ('/api' + path).rstrip('/') or '/api'))
        plugins.append({'name': repo.name, 'key': repo.name, 'calls': calls, 'unread': unread})
    lines, problems = verify_routes({'plugins': plugins}, routes)
    print('\n'.join(lines))
    return 1 if problems else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name, fn in (('install-catalog', cmd_install_catalog), ('install-dispatcher', cmd_install_dispatcher)):
        s = sub.add_parser(name)
        s.add_argument('--ct', required=True, help='CloudTAK checkout')
        s.add_argument('--work', required=True, help='scratch folder (clones go here; expect.json is written here)')
        if name == 'install-dispatcher':
            s.add_argument('--ref', default='', help='Dispatcher repo branch, tag or sha (default: its default branch)')
        else:
            s.add_argument('--no-shield', action='store_true', help="skip infra-TAK's pre-build step (canary only)")
        s.set_defaults(fn=fn)
    s = sub.add_parser('verify-in-image')
    s.add_argument('--expect', required=True)
    s.add_argument('--image', required=True)
    s.set_defaults(fn=cmd_verify_in_image)
    s = sub.add_parser('verify')
    s.add_argument('--expect', required=True)
    s.add_argument('--dist', required=True, help="the built web app (CloudTAK's app/dist)")
    s.set_defaults(fn=cmd_verify)
    s = sub.add_parser('verify-routes')
    s.add_argument('--expect', required=True)
    s.add_argument('--ct', required=True, help='CloudTAK checkout the plugins were installed into')
    s.set_defaults(fn=cmd_verify_routes)
    s = sub.add_parser('routes-local')
    s.add_argument('--ct', required=True, help='CloudTAK checkout (any tag or main)')
    s.add_argument('--plugin', action='append', required=True, help='plugin repo folder (repeat for more)')
    s.set_defaults(fn=cmd_routes_local)
    a = ap.parse_args(argv)
    return a.fn(a) or 0


if __name__ == '__main__':
    sys.exit(main())
