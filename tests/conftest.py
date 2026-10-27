# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
"""Test-session setup.

Many tests read app.py (75,000 lines) and call ast.get_source_segment() once per function.
That call re-splits the whole file into lines every time, so a module that does it for every
function is quadratic: one took over an hour to collect on Python 3.10 (the CI runner) and
over a minute on 3.15. Use a version that splits each distinct source string once. It returns
the same text (padded=True still goes to the original).
"""
import ast
import functools
import re

_original_get_source_segment = ast.get_source_segment
_LINE = re.compile(r'[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+')


@functools.lru_cache(maxsize=4)
def _split_lines(source):
    return _LINE.findall(source)


def _get_source_segment(source, node, *, padded=False):
    if padded:
        return _original_get_source_segment(source, node, padded=True)
    try:
        if node.end_lineno is None or node.end_col_offset is None:
            return None
        lineno = node.lineno - 1
        end_lineno = node.end_lineno - 1
        col_offset = node.col_offset
        end_col_offset = node.end_col_offset
    except AttributeError:
        return None
    lines = _split_lines(source)
    if end_lineno == lineno:
        return lines[lineno].encode()[col_offset:end_col_offset].decode()
    first = lines[lineno].encode()[col_offset:].decode()
    last = lines[end_lineno].encode()[:end_col_offset].decode()
    return ''.join([first] + lines[lineno + 1:end_lineno] + [last])


ast.get_source_segment = _get_source_segment

# The same goes for parsing: 80 test modules each ast.parse() the same 75,000-line app.py and
# some keep the tree, which is ~100 MB apiece. Collecting the suite peaked at ~10 GB in one
# process (the 16 GB CI runner could not run it in parallel). Parse each big source once and
# hand every caller the same read-only tree. No test edits a tree in place (the grep for that
# is in the PR).
_original_parse = ast.parse
_parse_cache = {}


def _parse(source, filename='<unknown>', mode='exec', **kwargs):
    if (isinstance(source, str) and len(source) > 500_000 and mode == 'exec'
            and filename == '<unknown>' and not kwargs):
        tree = _parse_cache.get(source)
        if tree is None:
            _parse_cache.clear()
            tree = _parse_cache[source] = _original_parse(source)
        return tree
    return _original_parse(source, filename, mode, **kwargs)


ast.parse = _parse
