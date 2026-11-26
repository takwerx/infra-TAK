"""An update keeps the admin groups an operator added (ATLAS issue #14).

`_arm_admin_gates` used to write exactly the groups infra-TAK manages, so
`TAKMDM_ADMIN_GROUP=ATLAS-Admins` became `authentik Admins` on every update.
Authentik's policy still admitted ATLAS-Admins (``atlas_access`` merges), and
ATLAS answered 403: "admin access denied: in none of authentik Admins".
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import modules.atlas as atlas  # noqa: E402
from modules import atlas_instances as ai  # noqa: E402
from modules import atlas_renewal  # noqa: E402


CORONA = ai.make('corona', ai.MODE_DYNAMIC, 50, 8761)


def _arm(tmp_path, monkeypatch, text, **kw):
    monkeypatch.setattr(atlas, '_proxy_auth_secret', lambda ctx=None: '')
    env = tmp_path / '.env'
    env.write_text(text, encoding='utf-8')
    said = []
    changed = atlas._arm_admin_gates(None, str(tmp_path), said.append, **kw)
    return changed, env.read_text(encoding='utf-8'), said


def _line(body):
    return [l for l in body.splitlines() if l.startswith('TAKMDM_ADMIN_GROUP=')]


# --------------------------------------------------------------------------- #
# The rule
# --------------------------------------------------------------------------- #


def test_managed_first_then_the_operator_s():
    assert atlas.merged_admin_groups(
        ['ATLAS-Admins'], ['authentik Admins']) == ['authentik Admins', 'ATLAS-Admins']


def test_a_previously_managed_name_is_not_kept():
    """A renamed superuser group: the old name must go, not be kept as custom."""
    assert atlas.merged_admin_groups(
        ['authentik Admins', 'ATLAS-Admins'], ['Platform Owners'],
        previously_managed={'authentik Admins'}) == ['Platform Owners', 'ATLAS-Admins']


def test_a_never_name_is_dropped_and_duplicates_collapse():
    assert atlas.merged_admin_groups(
        ['authentik Admins', 'X', 'X', 'ATLAS certificate renewal'], ['authentik Admins'],
        never={'ATLAS certificate renewal'}) == ['authentik Admins', 'X']


# --------------------------------------------------------------------------- #
# The `.env` an update leaves
# --------------------------------------------------------------------------- #


def test_the_issue_14_line_keeps_the_operator_s_group(tmp_path, monkeypatch):
    changed, body, said = _arm(tmp_path, monkeypatch, 'TAKMDM_ADMIN_GROUP=ATLAS-Admins\n')

    assert changed is True
    assert _line(body) == ['TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins']
    assert any('kept your "ATLAS-Admins"' in s for s in said), said


def test_a_second_update_changes_nothing(tmp_path, monkeypatch):
    """No rewrite means no api restart the operator did not ask for."""
    _, first, _ = _arm(tmp_path, monkeypatch, 'TAKMDM_ADMIN_GROUP=ATLAS-Admins\n')
    changed, second, _ = _arm(tmp_path, monkeypatch, first)

    assert changed is False
    assert second == first
    assert second.count('# SEC_AUDIT (ATLAS) H-1.') == 1


def test_an_agency_keeps_the_operator_s_group_too(tmp_path, monkeypatch):
    _, body, _ = _arm(tmp_path, monkeypatch,
                      'TAKMDM_ADMIN_GROUP=authentik Admins,Night shift\n', inst=CORONA)

    assert _line(body) == [
        'TAKMDM_ADMIN_GROUP=atlas-corona-admins,authentik Admins,Night shift']


def test_a_renamed_superuser_group_drops_the_old_name(tmp_path, monkeypatch):
    _, first, _ = _arm(tmp_path, monkeypatch, 'TAKMDM_ADMIN_GROUP=ATLAS-Admins\n')
    _, body, _ = _arm(tmp_path, monkeypatch, first, global_group='Platform Owners')

    assert _line(body) == ['TAKMDM_ADMIN_GROUP=Platform Owners,ATLAS-Admins']


def test_the_renewal_group_is_still_removed(tmp_path, monkeypatch):
    """ops #510: only the renewal service account is in it."""
    _, body, _ = _arm(tmp_path, monkeypatch,
                      'TAKMDM_ADMIN_GROUP=%s,ATLAS-Admins\n' % atlas_renewal.GROUP_NAME)

    assert _line(body) == ['TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins']


def test_the_standard_admin_group_is_removed(tmp_path, monkeypatch):
    """Listed as an admin group, its members would be full administrators."""
    _, body, _ = _arm(tmp_path, monkeypatch,
                      'TAKMDM_STANDARD_ADMIN_GROUP=Helpdesk\n'
                      'TAKMDM_ADMIN_GROUP=authentik Admins,Helpdesk,ATLAS-Admins\n')

    assert _line(body) == ['TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins']


def test_a_quoted_value_and_spaces_are_read(tmp_path, monkeypatch):
    _, body, _ = _arm(tmp_path, monkeypatch,
                      'TAKMDM_ADMIN_GROUP="ATLAS-Admins , authentik Admins"\n')

    assert _line(body) == ['TAKMDM_ADMIN_GROUP=authentik Admins,ATLAS-Admins']
