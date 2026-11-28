"""MediaMTX editor overlay: the one-time 24 hour end must not cap a never-ending link made on purpose (ops #1363).

The overlay carries its own copy of the editor's `cap_never_ending_share_links` (mediamtx-installer
PR 84, ops #1323). The overlay copy had none of the fixes: it capped a link an admin made on purpose
(after a first start that could not read the links file), ignored the `limits_version` stamp, wrote
nothing to the log, and wrote into entries that are not links.

Run with: python3 -m pytest tests/test_mediamtx_overlay_cap_ops1363.py -q
"""
import importlib.util
import json
import pathlib

import pytest

flask = pytest.importorskip('flask')

REPO = pathlib.Path(__file__).resolve().parent.parent
NOW = 1700000000


def _overlay_in(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('overlay_cap_1363_under_test', REPO / 'mediamtx_ldap_overlay.py')
    ov = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ov)
    monkeypatch.setattr(ov, 'SHARE_LINKS_FILE', str(tmp_path / 'share_links.json'))
    monkeypatch.setattr(ov, 'SHARE_LINKS_CAP_MARKER_FILE', str(tmp_path / 'share_links_capped.json'))
    return ov


def _links(tmp_path):
    return json.loads((tmp_path / 'share_links.json').read_text())


def _write(tmp_path, data):
    (tmp_path / 'share_links.json').write_text(json.dumps(data))


# -- The reported steps: a damaged file at the first start, then a link made on purpose ----

@pytest.mark.parametrize('first_start_file', [b'', b'  \n'])
def test_empty_file_at_first_start_does_not_cap_a_link_made_later(tmp_path, monkeypatch, capsys, first_start_file):
    """Empty file, start, admin makes a never-ending link, restart: the link has no end time.
    No stamp here (editor v2.1.17, the pin in infra-TAK 10.4.9 does not stamp)."""
    ov = _overlay_in(tmp_path, monkeypatch)
    (tmp_path / 'share_links.json').write_bytes(first_start_file)
    ov.cap_never_ending_share_links(now=NOW)              # first start: nothing old in the file
    assert 'is empty' in capsys.readouterr().out
    _write(tmp_path, {'madeOnPurpose': {'stream': 'cam1', 'expires': None, 'ttl_label': 'Until revoked'}})
    assert ov.cap_never_ending_share_links(now=NOW + 60) == 0   # restart
    link = _links(tmp_path)['madeOnPurpose']
    assert link['expires'] is None
    assert link['ttl_label'] == 'Until revoked'


def test_marker_deleted_by_hand_does_not_cap_a_stamped_link(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    _write(tmp_path, {'stamped': {'stream': 'cam1', 'expires': None, 'ttl_label': 'Until revoked',
                                   'limits_version': 1}})
    assert ov.cap_never_ending_share_links(now=NOW) == 0
    assert _links(tmp_path)['stamped']['expires'] is None
    assert (tmp_path / 'share_links_capped.json').exists()


def test_stamp_is_skipped_but_an_old_link_next_to_it_is_still_capped(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    _write(tmp_path, {
        'stamped': {'stream': 'cam1', 'expires': None, 'limits_version': 1},
        'old': {'stream': 'cam2', 'expires': None, 'ttl_label': 'Until revoked'},
    })
    assert ov.cap_never_ending_share_links(now=NOW) == 1
    links = _links(tmp_path)
    assert links['stamped']['expires'] is None
    assert links['old']['expires'] == NOW + 86400
    assert links['old']['ttl_label'] == '24 hours (set by the update)'


# -- Entries that are not links (a newer version may keep other data in this file) ---------

def test_entries_that_are_not_links_are_left_alone(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    data = {
        '_future': {'schema': 3},
        'a number': 7,
        'a list': [1, 2],
        'empty stream': {'stream': '', 'expires': None},
        'stream not text': {'stream': 5, 'expires': None},
        'old': {'stream': 'cam1', 'expires': None},
    }
    _write(tmp_path, data)
    assert ov.cap_never_ending_share_links(now=NOW) == 1
    links = _links(tmp_path)
    for name in ('_future', 'a number', 'a list', 'empty stream', 'stream not text'):
        assert links[name] == data[name]
    assert links['old']['expires'] == NOW + 86400


# -- A file the cap cannot read: say why, change nothing, try again at the next start ------

@pytest.mark.parametrize('raw, why', [
    (b'{"a": {"stream": "cam1", "expi', 'cut off or not valid JSON'),
    (b'[1, 2]', 'top level is not an object'),
])
def test_a_damaged_file_is_logged_and_left_as_it_is(tmp_path, monkeypatch, capsys, raw, why):
    ov = _overlay_in(tmp_path, monkeypatch)
    (tmp_path / 'share_links.json').write_bytes(raw)
    assert ov.cap_never_ending_share_links(now=NOW) is None
    assert (tmp_path / 'share_links.json').read_bytes() == raw
    assert not (tmp_path / 'share_links_capped.json').exists()
    out = capsys.readouterr().out
    assert 'old share links not capped' in out
    assert why in out
    assert 'tries again at the next start' in out


def test_a_damaged_file_that_is_repaired_is_capped_at_the_next_start(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    (tmp_path / 'share_links.json').write_bytes(b'{not json')
    assert ov.cap_never_ending_share_links(now=NOW) is None
    _write(tmp_path, {'old': {'stream': 'cam1', 'expires': None}})
    assert ov.cap_never_ending_share_links(now=NOW + 30) == 1
    assert _links(tmp_path)['old']['expires'] == NOW + 30 + 86400


def test_an_unreadable_file_is_logged_and_tried_again(tmp_path, monkeypatch, capsys):
    ov = _overlay_in(tmp_path, monkeypatch)
    _write(tmp_path, {'old': {'stream': 'cam1', 'expires': None}})
    real_open = open

    def refuse(path, *a, **kw):
        if str(path) == str(tmp_path / 'share_links.json'):
            raise PermissionError(13, 'Permission denied')
        return real_open(path, *a, **kw)

    monkeypatch.setattr('builtins.open', refuse)
    assert ov.cap_never_ending_share_links(now=NOW) is None
    monkeypatch.undo()
    assert not (tmp_path / 'share_links_capped.json').exists()
    assert 'cannot be read' in capsys.readouterr().out


def test_a_write_that_fails_is_logged_and_tried_again(tmp_path, monkeypatch, capsys):
    ov = _overlay_in(tmp_path, monkeypatch)
    _write(tmp_path, {'old': {'stream': 'cam1', 'expires': None}})
    monkeypatch.setattr(ov, 'SHARE_LINKS_CAP_MARKER_FILE', str(tmp_path / 'no-such-dir' / 'marker.json'))
    assert ov.cap_never_ending_share_links(now=NOW) is None
    assert 'could not write' in capsys.readouterr().out


def test_a_log_line_that_cannot_be_printed_never_stops_the_cap(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    (tmp_path / 'share_links.json').write_bytes(b'{not json')

    def broken_print(*a, **kw):
        raise ValueError('I/O operation on closed file')

    monkeypatch.setattr('builtins.print', broken_print)
    assert ov.cap_never_ending_share_links(now=NOW) is None


# -- What already worked must still work ---------------------------------------------------

def test_old_never_ending_links_still_end_24_hours_after_the_update(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    _write(tmp_path, {
        'oldA': {'stream': 'cam1', 'expires': None, 'ttl_label': 'Until revoked'},
        'oldB': {'stream': 'cam2', 'ttl_label': 'Until revoked'},
        'timed': {'stream': 'cam3', 'expires': 2000000000, 'ttl_label': '4 hours'},
    })
    assert ov.cap_never_ending_share_links(now=NOW) == 2
    links = _links(tmp_path)
    assert links['oldA']['expires'] == links['oldB']['expires'] == NOW + 86400
    assert links['timed']['expires'] == 2000000000
    marker = json.loads((tmp_path / 'share_links_capped.json').read_text())
    assert marker['capped'] == 2


def test_the_cap_runs_once(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    _write(tmp_path, {'old': {'stream': 'cam1', 'expires': None}})
    assert ov.cap_never_ending_share_links(now=NOW) == 1
    links = _links(tmp_path)
    links['later'] = {'stream': 'cam1', 'expires': None}
    _write(tmp_path, links)
    assert ov.cap_never_ending_share_links(now=NOW + 5) == 0
    assert _links(tmp_path)['later']['expires'] is None


def test_no_file_at_all_still_makes_the_marker(tmp_path, monkeypatch):
    ov = _overlay_in(tmp_path, monkeypatch)
    assert ov.cap_never_ending_share_links(now=NOW) == 0
    assert (tmp_path / 'share_links_capped.json').exists()


def test_starting_the_overlay_with_a_damaged_file_still_starts_the_editor(tmp_path, monkeypatch):
    cfg = tmp_path / 'mediamtx.yml'
    cfg.write_text('authInternalUsers:\n- user: any\n  ips: [127.0.0.1]\n')
    monkeypatch.setenv('MEDIAMTX_CONFIG', str(cfg))
    ov = _overlay_in(tmp_path, monkeypatch)
    (tmp_path / 'share_links.json').write_bytes(b'{cut off')
    app = flask.Flask('overlay-cap-1363-start-test')
    app.secret_key = 'test'
    ov.apply_ldap_overlay(app)
    assert (tmp_path / 'share_links.json').read_bytes() == b'{cut off'
