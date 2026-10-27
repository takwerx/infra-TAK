#!/usr/bin/env python3
"""Compile every tracked Python file without writing .pyc files.

Run with the oldest Python we support (RHEL/Rocky 9 ships 3.9) so a newer-only
construct fails here instead of on a customer box. Run it from the repo root:

    python3 -I .github/ci/compile_check.py                  # everything except simulator/
    python3 -I .github/ci/compile_check.py --only simulator/  # the container's own Python

simulator/ runs in its own python:3.12 container (simulator/Dockerfile), not on the
host, so it is checked with 3.12 and is skipped by the host-floor run.
"""
import subprocess
import sys


def tracked_python_files():
    out = subprocess.run(['git', 'ls-files', '-z'], check=True,
                         capture_output=True).stdout.decode('utf-8')
    files = []
    for path in filter(None, out.split('\0')):
        if path.endswith('.py'):
            files.append(path)
            continue
        # Extensionless scripts (e.g. scripts/ufw-firewalld-shim) are found by shebang.
        try:
            with open(path, 'rb') as fh:
                first = fh.readline(200)
        except OSError:
            continue
        if first.startswith(b'#!') and b'python' in first:
            files.append(path)
    return files


CONTAINER_DIRS = ('simulator/',)


def main(argv):
    only = argv[argv.index('--only') + 1] if '--only' in argv else None
    files = tracked_python_files()
    if only:
        files = [f for f in files if f.startswith(only)]
    else:
        files = [f for f in files if not f.startswith(CONTAINER_DIRS)]
    bad = 0
    for path in files:
        try:
            with open(path, 'rb') as fh:
                source = fh.read()
            compile(source, path, 'exec', dont_inherit=True)
        except (SyntaxError, ValueError) as exc:
            bad += 1
            line = getattr(exc, 'lineno', None) or 1
            # GitHub turns this into an inline annotation on the PR.
            print('::error file=%s,line=%s::%s: %s' % (path, line, type(exc).__name__, exc))
    print('compiled %d file(s) with Python %s: %d failed' %
          (len(files), '.'.join(map(str, sys.version_info[:3])), bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
