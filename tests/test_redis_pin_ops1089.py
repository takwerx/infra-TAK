"""Redis 8.10.2 -> 8.10.3 (ops #1089): both pins move together, and the WebODM broker follows on restart.

Redis is pinned in two places: AUTHENTIK_REDIS_IMAGE (fresh Authentik deploys, and boxes whose
compose has no redis service) and WEBODM_IMAGES['wo_broker'] (every WebODM box, moved in place by the
startup migration and by WebODM's Update). They must name the same tested release.
"""
import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = (ROOT / 'app.py').read_text(encoding='utf-8')
TREE = ast.parse(APP)

REDIS_RELEASE = '8.10.3'


def _assign(name):
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == name for t in node.targets):
            return ast.get_source_segment(APP, node)
    raise AssertionError(f'{name} not found at module level in app.py')


def _const(name):
    """Evaluate a module-level constant (WEBODM_IMAGES builds a name from WEBODM_VERSION)."""
    ns = {}
    exec(_assign('WEBODM_VERSION'), ns)
    exec(_assign(name), ns)
    return ns[name]


def _pin_function():
    """`_webodm_pin_images` and WEBODM_IMAGES, taken out of app.py (importing app.py starts a server)."""
    ns = {'re': re, 'WEBODM_IMAGES': _const('WEBODM_IMAGES')}
    # the direction check it calls (ops #1307) is cut out with it
    for n in TREE.body:
        if (isinstance(n, ast.FunctionDef) and n.name in ('_webodm_pin_images', '_image_ref_parts',
                                                          '_image_exact_version', '_image_ahead_of_pin')) or (
                isinstance(n, ast.Assign) and any(getattr(t, 'id', None) == '_IMAGE_EXACT_TAG_RE' for t in n.targets)):
            exec(compile(ast.Module([n], []), 'app.py', 'exec'), ns)
    return ns['_webodm_pin_images']


def test_both_redis_pins_name_the_same_release():
    authentik = _const('AUTHENTIK_REDIS_IMAGE')
    broker = _const('WEBODM_IMAGES')['wo_broker']
    assert authentik == f'docker.io/library/redis:{REDIS_RELEASE}-alpine', authentik
    assert broker == f'redis:{REDIS_RELEASE}-alpine', broker


def test_no_other_redis_pin_is_left_in_app():
    tags = set(re.findall(r'redis:(\d+\.\d+\.\d+(?:-alpine)?)', APP))
    # 7.0.10 stays in the comments and migration notes that explain the old EOL broker
    assert tags - {'7.0.10'} == {f'{REDIS_RELEASE}-alpine'}, tags


def test_webodm_broker_on_the_old_pin_moves_to_the_new_one():
    pin = _pin_function()
    old = (
        "services:\n"
        "  wo_broker:\n"
        "    image: redis:8.10.2-alpine\n"
        "    container_name: wo_broker\n"
        "  wo_webapp:\n"
        "    image: webodm/webodm_webapp:4.0.1\n"
    )
    new = pin(old, services=('wo_broker',))
    assert f'    image: redis:{REDIS_RELEASE}-alpine\n' in new
    assert '8.10.2' not in new
    assert 'webodm/webodm_webapp:4.0.1' in new           # only the broker moved
    assert pin(new, services=('wo_broker',)) == new      # a second run changes nothing
