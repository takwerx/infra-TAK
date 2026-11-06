# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Michael Leckliter
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""The TAK Server's CA certificates, handed to ATLAS (ATLAS W460).

A device can hold TAK connections the user added to other TAK Servers. ATLAS's
TAK Server CAs page, its Retire step and its certificate renewal should look
only at the CAs of the TAK Server on this box, and the device cannot say which
server a connection belongs to: an address can be a domain, a custom domain, an
IP or a proxy in front of 8089. A certificate always chains to the TAK Server's
root, so ATLAS matches by CA, and this module gives it the CAs.

What is written: every CA certificate (`CA:TRUE`) found in a `.pem` file in the
TAK Server's certificate folder, the root first, as one bundle at
`<deployment>/tak-ca/tak-cas.pem`. Old intermediates stay in that folder after a
rotation, so a CA being retired is in the bundle too. ATLAS keeps only the CAs
that chain to a self-signed root in it, so a stray certificate claims nothing.

⚠️ **Certificate blocks only.** The folder also holds private keys (`.key`,
`.p12`, `.jks`). Only `.pem` files are read, and from them only
`BEGIN CERTIFICATE` blocks are copied: a key in a `.pem` is never written.

⚠️ **The folder may be root's.** An InfraTAK without this module, updating an
ATLAS release that mounts `./tak-ca`, leaves Docker to create it, as root. The
console owns the deployment folder, so an empty root-owned `tak-ca` is removed
and made again, and the caller restarts `api` so its mount sees the new one.

Refreshed on deploy, on update and after InfraTAK's TAK CA rotation. ATLAS reads
the file at each page load, so a refresh needs no restart otherwise.
"""

import os
import re
import subprocess

#: The TAK Server's certificate folder on an InfraTAK box (as `atlas_renewal`).
TAK_CERT_DIR = '/opt/tak/certs/files'
ROOT_FILE = 'root-ca.pem'

#: Relative to the deployment folder; mounted read-only into ATLAS's `api` at
#: `/run/tak-ca`. Untracked (ATLAS ignores `/tak-ca/`), so the updater's
#: `git checkout` never touches it.
DIR = 'tak-ca'
FILE = 'tak-cas.pem'

#: A TAK certificate file is a few KB; anything this size is not one.
MAX_FILE_BYTES = 1024 * 1024

_BLOCK = re.compile(
    r'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+?-----END CERTIFICATE-----')


def openssl_is_ca(pem):
    """Whether one PEM certificate says `CA:TRUE`. The console's Python has no
    `cryptography`; `openssl` is on every InfraTAK box."""
    try:
        r = subprocess.run(['openssl', 'x509', '-noout', '-ext', 'basicConstraints'],
                           input=pem, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and 'CA:TRUE' in r.stdout


def _read(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return ''
        with open(path, encoding='ascii', errors='replace') as fh:
            return fh.read()
    except OSError:
        return ''


def collect(cert_dir=TAK_CERT_DIR, is_ca=openssl_is_ca):
    """The bundle to write, or None when this box has no TAK Server root."""
    root = os.path.join(cert_dir, ROOT_FILE)
    if not os.path.isfile(root):
        return None
    try:
        names = sorted(n for n in os.listdir(cert_dir) if n.endswith('.pem') and n != ROOT_FILE)
    except OSError:
        return None
    seen, blocks = set(), []
    for name in [ROOT_FILE] + names:
        for block in _BLOCK.findall(_read(os.path.join(cert_dir, name))):
            block = block.replace('\r\n', '\n')
            if block in seen:
                continue
            seen.add(block)
            if is_ca(block + '\n'):
                blocks.append(block)
    return '\n'.join(blocks) + '\n' if blocks else None


def write(dirpath, bundle):
    """Write the bundle if it changed. `{'changed', 'recreated'}`; raises
    OSError when the folder is not ours and not empty."""
    folder = os.path.join(dirpath, DIR)
    recreated = False
    if os.path.isdir(folder) and not os.access(folder, os.W_OK | os.X_OK):
        if os.listdir(folder):
            raise PermissionError(folder + ' is not writable by the console and is not empty')
        os.rmdir(folder)
        recreated = True
    os.makedirs(folder, mode=0o755, exist_ok=True)
    path = os.path.join(folder, FILE)
    if _read(path) == bundle:
        return {'changed': False, 'recreated': recreated}
    tmp = path + '.tmp'
    if os.path.exists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.write(fd, bundle.encode('ascii'))
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return {'changed': True, 'recreated': recreated}


def refresh(dirpath, plog, cert_dir=TAK_CERT_DIR, is_ca=openssl_is_ca):
    """Collect and write, logging the outcome. Never raises: a failure leaves
    ATLAS listing every CA, which is what it did before this existed."""
    result = {'changed': False, 'recreated': False}
    try:
        bundle = collect(cert_dir, is_ca)
        if bundle is None:
            plog('  ⚠ No TAK Server CA certificates in ' + cert_dir +
                 ': ATLAS lists every TAK Server CA its devices report')
            return result
        result = write(dirpath, bundle)
        count = bundle.count('BEGIN CERTIFICATE')
        plog('  ✓ TAK Server CAs for ATLAS: %d certificate(s)%s'
             % (count, ', updated' if result['changed'] else ', unchanged'))
    except Exception as exc:  # noqa: BLE001 - logged, and ATLAS falls back
        plog('  ⚠ Could not give ATLAS the TAK Server CAs: ' + str(exc)[:160])
    return result
