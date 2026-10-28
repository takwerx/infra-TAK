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


def verify_bundle(expect, dist):
    """(report lines, number of problems). One line per plugin."""
    chunks = read_chunks(dist)
    if not chunks:
        return [f'FAIL  no JavaScript found under {dist}: the web app did not build or was not copied out'], 1
    lines, problems = [], 0
    for p in expect['plugins']:
        label = f"{p['name']} ({p['key']})"
        if p.get('error'):
            lines.append(f"FAIL  {label}: {p['error']}")
            problems += 1
            continue
        for e in p['menu']:
            chunk = find_menu_entry(chunks, e)
            if chunk:
                lines.append(f"ok    {label}: menu entry '{e['label']}' (key {e['key']}) is in {chunk}")
            else:
                lines.append(f"FAIL  {label}: menu entry '{e['label']}' (key {e['key']}) is NOT in the built app "
                             f"({len(chunks)} JS files searched). The plugin was installed but did not make it into the build.")
                problems += 1
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
    out = {'key': p['key'], 'name': p['name'], 'install_dir': p['install_dir'], 'source': sha or 'local', 'menu': entries}
    if not entries:
        out['error'] = (f'could not read a menu.add({{key, label}}) call in the plugin source ({web_src.name}/); '
                        'either the plugin no longer registers a menu entry or it does it in a way this check cannot read')
    return out


def cmd_install_catalog(a):
    ct, work = Path(a.ct), Path(a.work)
    plugins = load_manifest()
    web = web_dir(ct)
    routes = ct / 'api' / 'stateless' / 'routes'
    if not (ct / 'app' / 'src').is_dir():
        raise SystemExit('ERROR: this CloudTAK has no app/src: the check only covers CloudTAK 13.102.0 and newer')
    expect = []
    for p in plugins:
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
                 '_CT_NPM_NAME_RE', '_CT_NPM_SPEC_RE', '_CT_DOCKERIGNORE_MARK', '_CT_PLUGIN_DIR_RE')
SHIELD_FUNCS = ('_cloudtak_web_dir', '_cloudtak_plugins_dir', '_cloudtak_foreign_plugins',
                '_cloudtak_has_ts_nocheck', '_cloudtak_rewrite_in_place',
                '_cloudtak_plugin_missing_deps', '_cloudtak_keep_plugins_in_build',
                '_cloudtak_shield_foreign_plugins')


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


# ── command line ─────────────────────────────────────────────────────────────────

def cmd_verify(a):
    expect = json.loads(Path(a.expect).read_text(encoding='utf-8'))
    lines, problems = verify_bundle(expect, a.dist)
    print('\n'.join(lines))
    print(f"\n{len(lines) - problems} of {len(lines)} checks passed" if lines else 'nothing to check')
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
        s.set_defaults(fn=fn)
    s = sub.add_parser('verify')
    s.add_argument('--expect', required=True)
    s.add_argument('--dist', required=True, help="the built web app (CloudTAK's app/dist)")
    s.set_defaults(fn=cmd_verify)
    a = ap.parse_args(argv)
    return a.fn(a) or 0


if __name__ == '__main__':
    sys.exit(main())
