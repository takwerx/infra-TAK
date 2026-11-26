"""ops #1266 part A: the ATLAS tile on a box flipped from root to non-root.

CORAZ (prod, 10.4.7-alpha) showed ATLAS "Stopped" while its three containers had
been up for 26 hours. The deployment sits under /root/atlas, which the non-root
console cannot enter, so `instance_is_built` (a filesystem question) said False
and `detect` kept only built deployments. Its list was empty, so `running` was
False.

`instance_is_stranded` (a Docker question) already said True for that box. The
tile just never used it.
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402


class Probe:
    def __init__(self, stdout=''):
        self.stdout = stdout
        self.stderr = ''
        self.returncode = 0


def stranded_box(monkeypatch, tmp_path, instances, projects, running):
    """A console that cannot see any checkout: the home holds no `atlas/`.

    `projects` are the compose projects Docker lists; `running` are the ones
    whose API container is up.
    """
    monkeypatch.setattr(atlas, 'install_base',
                        lambda ctx=None: str(tmp_path).replace(chr(92), '/'))
    monkeypatch.setattr(atlas, 'compose_projects_present',
                        lambda ctx=None: set(projects))
    monkeypatch.setattr(atlas, 'access_state', lambda c, s=None: True)
    monkeypatch.setattr(atlas, 'unrestricted_deployments', lambda c, s=None: [])
    monkeypatch.setattr(atlas, '_installed_version', lambda c, i=None: None)

    def probe_run(argv, **kwargs):
        alive = any(argv[-1] == '%s-api-1' % p for p in running)
        return Probe('true' if alive else 'false')

    settings = {'atlas_enabled': True, ai.INSTANCES_KEY: list(instances)}
    return {'load_settings': lambda: dict(settings), 'probe_run': probe_run}


PLAIN = ai.make(None, ai.MODE_FIXED, 100, 8760)
CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)


def test_a_stranded_deployment_that_is_serving_reads_running(monkeypatch,
                                                              tmp_path):
    """⚠️ **The CORAZ bug.** Containers up, files out of reach: the tile said
    Stopped."""
    ctx = stranded_box(monkeypatch, tmp_path, [PLAIN],
                       projects=['takmdm'], running=['takmdm'])

    assert atlas.detect(ctx)['running'] is True


def test_a_stranded_deployment_that_is_down_reads_stopped(monkeypatch, tmp_path):
    """The fix must not turn the tile green for everything it cannot see."""
    ctx = stranded_box(monkeypatch, tmp_path, [PLAIN],
                       projects=['takmdm'], running=[])

    assert atlas.detect(ctx)['running'] is False


def test_the_row_of_a_stranded_deployment_says_it_is_running(monkeypatch,
                                                              tmp_path):
    ctx = stranded_box(monkeypatch, tmp_path, [PLAIN],
                       projects=['takmdm'], running=['takmdm'])

    row = atlas.instance_status(ctx, PLAIN)

    assert row['stranded'] is True
    assert row['running'] is True
    # Still not built: the page must offer no Update, Restart or Deploy for it.
    assert row['built'] is False


def test_a_stopped_stranded_row_says_stopped(monkeypatch, tmp_path):
    ctx = stranded_box(monkeypatch, tmp_path, [PLAIN],
                       projects=['takmdm'], running=[])

    row = atlas.instance_status(ctx, PLAIN)

    assert row['stranded'] is True
    assert row['running'] is False


def test_one_stranded_deployment_that_is_down_holds_the_tile_down(monkeypatch,
                                                                    tmp_path):
    """⚠️ All of them, as before. A stopped agency must not hide behind a
    running one just because the console cannot see its files."""
    ctx = stranded_box(monkeypatch, tmp_path, [PLAIN, CORONA],
                       projects=['takmdm', 'takmdm-corona'],
                       running=['takmdm'])

    assert atlas.detect(ctx)['running'] is False


def test_two_stranded_deployments_that_are_up_read_running(monkeypatch,
                                                            tmp_path):
    ctx = stranded_box(monkeypatch, tmp_path, [PLAIN, CORONA],
                       projects=['takmdm', 'takmdm-corona'],
                       running=['takmdm', 'takmdm-corona'])

    assert atlas.detect(ctx)['running'] is True


def test_a_recorded_deployment_with_no_containers_is_still_ignored(monkeypatch,
                                                                    tmp_path):
    """Unfinished (no files, no containers) is not stranded, and still must not
    hold the tile down or up."""
    ctx = stranded_box(monkeypatch, tmp_path, [PLAIN, CORONA],
                       projects=['takmdm'], running=['takmdm'])

    assert atlas.detect(ctx)['running'] is True


def test_a_box_with_nothing_at_all_is_not_running(monkeypatch, tmp_path):
    """`all()` over an empty list is True; the guard against that must hold for
    the widened list too."""
    ctx = stranded_box(monkeypatch, tmp_path, [PLAIN],
                       projects=[], running=[])

    assert atlas.detect(ctx)['running'] is False


def test_detect_asks_docker_for_the_project_list_once(monkeypatch, tmp_path):
    """⚠️ The tile runs on every dashboard poll from several threads and must
    answer in under a second. One `docker ps` per recorded deployment made it
    slower the more agencies a box had."""
    ctx = stranded_box(monkeypatch, tmp_path, [PLAIN, CORONA],
                       projects=['takmdm', 'takmdm-corona'],
                       running=['takmdm', 'takmdm-corona'])
    calls = []
    monkeypatch.setattr(atlas, 'compose_projects_present',
                        lambda ctx=None: calls.append(1) or
                        {'takmdm', 'takmdm-corona'})

    atlas.detect(ctx)

    assert len(calls) == 1


def test_the_page_never_calls_a_stranded_deployment_unfinished():
    """The deployments list printed "(not finished)" for a stranded row, and the
    only control that reading offers is the one that builds a second copy."""
    html = (ROOT / 'templates' / 'atlas.html').read_text(encoding='utf-8')
    rows = html[html.index('const state = i.stranded'):]
    rows = rows[:rows.index('\n', rows.index("'  (not finished)'"))]
    assert 'i.stranded' in rows and 'stateLabel(i)' in rows
    assert "(i.running ? 'running' : 'stopped') +" in html
    # And the finish button stays off a stranded deployment.
    assert '!i.built && !i.stranded' in html
