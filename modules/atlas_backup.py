"""ATLAS database backup before an Update (ops #864).

ATLAS 2.x migrates its database forward only. The 1.x code cannot open it: the
api restart-loops with "Can't locate revision identified by ..." until the
newer release is put back. Before this module the ATLAS Update button took no
backup, so an operator who updated and then hit a problem had no way back.

What this does, and no more:

* `take` writes one plain-SQL dump of the deployment's database to a folder
  next to (not inside) the deployment, mode 0600, keeps the newest `KEEP` per
  deployment, and checks the file is a complete dump before it says it worked.
* `restore_steps` writes the exact commands that put a dump back and return the
  deployment to the release it was on, for the page and the update log.

⚠️ **Pure on purpose.** Nothing here runs Docker. The caller passes the dump
in as a function, so a test can fail the dump, truncate it or lose the folder
without a box. The module imports nothing from `app.py`.

⚠️ **Plain SQL, not `-Fc`.** The console reaches Docker through the broker,
which hands back text. A plain dump is text all the way through (bytea values
are written as hex), and it ends in a fixed line, which is how a truncated
copy is told from a whole one.
"""

import os
import posixpath
import re
import time

#: Folder name, under the same base as the deployments (`<base>/atlas-backups`).
#: ⚠️ A sibling of `<base>/atlas`, never inside it: removing a deployment or
#: running the uninstall deletes that tree, and a backup that goes with it is
#: no backup.
BACKUP_DIRNAME = 'atlas-backups'

#: Newest dumps kept per deployment. Older ones are deleted after a new one is
#: verified, never before.
KEEP = 3

#: The database and role the ATLAS compose file creates (`POSTGRES_USER`,
#: `POSTGRES_DB`). Verified against upstream docker-compose.yml.
DB_USER = 'takmdm'
DB_NAME = 'takmdm'

#: The last line of a finished `pg_dump` plain file.
COMPLETE_MARK = 'PostgreSQL database dump complete'

_NAME_RE = re.compile(r'^takmdm-v[0-9A-Za-z._-]{1,40}-\d{8}-\d{6}\.sql$')
_VER_RE = re.compile(r'[^0-9A-Za-z._-]')


class BackupError(RuntimeError):
    """The backup was not made. The update must not go on."""


def backup_dir(base, name):
    """Folder holding one deployment's dumps. `name` is the deployment name
    (`atlas`, `atlas-<slug>`), already a safe path part."""
    if not name or '/' in name or name in ('.', '..'):
        raise BackupError('bad deployment name for a backup folder: %r' % (name,))
    return posixpath.join(base, BACKUP_DIRNAME, name)


def dump_argv(container):
    """The command inside the database container that writes the dump to stdout."""
    return ['docker', 'exec', container, 'pg_dump', '-U', DB_USER,
            '-d', DB_NAME, '--no-owner']


def backup_name(version, now=None):
    """`takmdm-v<installed version>-<UTC date>-<UTC time>.sql`. The version in
    the name is the release the dump was taken FROM, so it is also the one to go
    back to."""
    ver = _VER_RE.sub('', str(version or 'unknown'))[:40] or 'unknown'
    stamp = time.strftime('%Y%m%d-%H%M%S', time.gmtime(now))
    return 'takmdm-v%s-%s.sql' % (ver, stamp)


def list_backups(directory):
    """Dumps in `directory`, newest first: [{'path','name','version','size','mtime'}]."""
    out = []
    try:
        names = os.listdir(directory)
    except OSError:
        return out
    for n in names:
        if not _NAME_RE.match(n):
            continue
        p = os.path.join(directory, n)
        try:
            st = os.stat(p)
        except OSError:
            continue
        out.append({'path': p, 'name': n, 'size': st.st_size, 'mtime': st.st_mtime,
                    'version': n[len('takmdm-v'):].rsplit('-', 2)[0]})
    out.sort(key=lambda b: (b['mtime'], b['name']), reverse=True)
    return out


def prune(directory, keep=KEEP):
    """Delete all but the newest `keep` dumps. Returns the names deleted."""
    gone = []
    for b in list_backups(directory)[max(keep, 1):]:
        try:
            os.unlink(b['path'])
            gone.append(b['name'])
        except OSError:
            pass
    return gone


def _complete(data):
    """True when `data` (bytes) is a whole pg_dump plain file."""
    if not data or len(data) < 200:
        return False
    return COMPLETE_MARK.encode() in data[-400:]


def take(directory, version, dump, plog, now=None):
    """Write a verified dump and return its path. Raises BackupError otherwise.

    `dump` is a function returning `(returncode, stdout_bytes, error_text)`.
    The file is written under a temporary name and renamed only once it ends
    with the pg_dump completion line, so a half-written file never looks like a
    backup. Older dumps are pruned after the new one is in place.
    """
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
    except OSError as exc:
        raise BackupError('cannot create the backup folder %s: %s' % (directory, exc))
    rc, data, err = dump()
    if rc != 0:
        raise BackupError('pg_dump failed (exit %s): %s' % (rc, (err or '').strip()[-300:]))
    if isinstance(data, str):
        data = data.encode('utf-8')
    if not _complete(data):
        raise BackupError('pg_dump output is not a complete dump (%d bytes)' % len(data or b''))
    final = os.path.join(directory, backup_name(version, now))
    tmp = final + '.part'
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if os.path.getsize(tmp) != len(data):
            raise BackupError('the backup file is %d bytes, expected %d'
                              % (os.path.getsize(tmp), len(data)))
        os.replace(tmp, final)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise BackupError('cannot write the backup file: %s' % exc)
    removed = prune(directory)
    if removed:
        plog('  removed older backups (keeping the newest %d): %s' % (KEEP, ', '.join(removed)))
    return final


def _q(text):
    """Single-quote one shell word."""
    return "'" + str(text).replace("'", "'\"'\"'") + "'"


def restore_steps(dirpath, project_flag, tag, backup_path):
    """The commands that put `backup_path` back and return to release `tag`.

    `project_flag` is '' for the plain deployment and `-p <project>` for an
    agency (the same flag `_compose` adds). Run them as the user that owns the
    deployment folder, from any directory. They drop the deployment's database
    and create it again from the dump, so run them only when you want to go
    back.
    """
    compose = ('docker compose --project-directory %s %s' % (_q(dirpath), project_flag)).replace('  ', ' ').strip()
    steps = [
        '%s stop api' % compose,
        '%s exec -T db psql -U %s -d postgres -c "DROP DATABASE %s WITH (FORCE)" '
        '-c "CREATE DATABASE %s OWNER %s" < /dev/null' % (compose, DB_USER, DB_NAME, DB_NAME, DB_USER),
        '%s exec -T db psql -U %s -d %s -q -v ON_ERROR_STOP=1 < %s'
        % (compose, DB_USER, DB_NAME, _q(backup_path)),
    ]
    if tag:
        ref = 'refs/tags/' + tag
        steps += [
            'git -c safe.directory=%s -C %s fetch --no-tags --depth=1 origin +%s:%s'
            % (_q(dirpath), _q(dirpath), ref, ref),
            'git -c safe.directory=%s -C %s checkout -f %s' % (_q(dirpath), _q(dirpath), tag),
        ]
    steps.append('%s up -d --build api' % compose)
    return steps


def describe(dirpath, project_flag, backup_path, version):
    """Lines for the update log and the page: where the backup is and how to use it.

    `version` is the release the dump was taken from, or '' when it was not
    known (the git steps are then left out and the log says so)."""
    tag = ('v' + str(version)) if version else ''
    lines = ['Backup of the database: %s' % backup_path,
             ('To go back to v%s, run these commands on the server, in order:' % version)
             if version else
             ('The release before this update is not known. Run these commands on the '
              'server, in order, then check out that release yourself:')]
    lines += ['  ' + s for s in restore_steps(dirpath, project_flag, tag, backup_path)]
    lines.append('Going back replaces the database with this backup. Anything '
                 'devices wrote after the backup is lost.')
    return lines
