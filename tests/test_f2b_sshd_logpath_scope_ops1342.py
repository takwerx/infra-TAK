"""ops #1342 point 2: the dead-logpath self-heal changes the [sshd] jail only.

The shipped helper `_f2b_sshd_section_logpath_to_journal` is exec'd from app.py. Before the
fix, a file that held `[sshd]` plus another jail lost the other jail's `logpath` too
(every missing `logpath` in the file was rewritten, every `backend` line dropped)."""
import ast
import os
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = (REPO / 'app.py').read_text(encoding='utf-8')


def _helper():
    for n in ast.parse(APP).body:
        if isinstance(n, ast.FunctionDef) and n.name == '_f2b_sshd_section_logpath_to_journal':
            ns = {'os': os, 're': re}
            exec(ast.get_source_segment(APP, n), ns)
            return ns['_f2b_sshd_section_logpath_to_journal']
    raise AssertionError('_f2b_sshd_section_logpath_to_journal was renamed or removed')


FN = _helper()
NONE_EXIST = lambda p: False  # noqa: E731


def test_only_the_sshd_section_is_rewritten():
    text = ('[sshd]\nenabled = true\nlogpath = /var/log/auth.log\nbackend = auto\n'
            '[infratak-authentik]\nenabled = true\nlogpath = /var/log/authentik/x.log\nbackend = auto\n')
    out, hit = FN(text, NONE_EXIST)
    assert hit
    assert out == ('[sshd]\nenabled = true\nbackend  = systemd\n'
                   '[infratak-authentik]\nenabled = true\nlogpath = /var/log/authentik/x.log\nbackend = auto\n')


def test_a_logpath_in_another_jail_alone_changes_nothing():
    text = '[sshd]\nenabled = true\nbackend = systemd\n[other]\nlogpath = /var/log/gone.log\nbackend = auto\n'
    out, hit = FN(text, NONE_EXIST)
    assert not hit and out == text


def test_a_present_logpath_in_sshd_is_kept():
    text = '[sshd]\nlogpath = /var/log/auth.log\nbackend = auto\n'
    out, hit = FN(text, lambda p: True)
    assert not hit and out == text


def test_backend_after_the_logpath_and_two_dead_logpaths_give_one_backend_line():
    text = '[sshd]\nlogpath = /a\nlogpath = /b\nbackend = auto\n[x]\nbackend = auto\n'
    out, hit = FN(text, NONE_EXIST)
    assert hit
    assert out == '[sshd]\nbackend  = systemd\n[x]\nbackend = auto\n'


def test_default_section_before_sshd_is_untouched():
    text = '[DEFAULT]\nlogpath = /var/log/none.log\nbackend = auto\n[sshd]\nlogpath = /var/log/auth.log\n'
    out, hit = FN(text, NONE_EXIST)
    assert hit
    assert out == '[DEFAULT]\nlogpath = /var/log/none.log\nbackend = auto\n[sshd]\nbackend  = systemd\n'


def test_the_selfheal_uses_the_section_helper():
    body = APP[APP.index('def _f2b_selfheal_sshd_backend('):]
    body = body[:body.index('\ndef ')]
    assert '_f2b_sshd_section_logpath_to_journal(text)' in body
