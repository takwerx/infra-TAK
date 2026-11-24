# SPDX-License-Identifier: AGPL-3.0-or-later
# infra-TAK — TAK Infrastructure Platform
# Copyright (C) 2026 Andreas Johansson (TAKWERX)
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
"""A fresh native TAK install keeps its Step-8 CoreConfig edits (ops #1118).

TAK Server loads CoreConfig.xml at its first start (Step 5, stock) and writes that in-memory
copy back to disk when it shuts down. The native deploy edited the file in Step 8 and again
for LDAP while TAK was still running, so the LDAP restart's shutdown put the stock config
back: no truststore-INTERMEDIATE-CA, no certificateSigning block, CloudTAK setup died with
UND_ERR_SOCKET (fresh Ubuntu 22.04, v10.4.4, ops #1117).

The fix stops TAK before Step 8 touches the file, and re-checks the file once more with TAK
stopped before the final start. These tests read the deploy source (the deploy itself needs
a box) and run the Step-8 text transform on a stock CoreConfig.
"""

import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(REPO, 'app.py'), encoding='utf-8') as _f:
    APP = _f.read()

INT_CA = 'INTERMEDIATE-CA-01'
CA_LINE = ('<TAKServerCAConfig keystore="JKS" keystoreFile="certs/files/INTERMEDIATE-CA-01-signing.jks" '
           'keystorePass="atakatak" validityDays="728" signatureAlg="SHA256WithRSA" />')
CERT_BLOCK = ('<certificateSigning CA="TAKServer"><certificateConfig>\n'
              '<nameEntries>\n<nameEntry name="O" value="TAKWERX"/>\n<nameEntry name="OU" value="DEV-CI"/>\n'
              '</nameEntries>\n</certificateConfig>\n' + CA_LINE + '\n</certificateSigning>\n<vbm enabled="false"/>')

# What TAK 5.8 writes back from memory: stock truststore, no enrollment block, no x509 attr.
STOCK = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Configuration xmlns="http://bbn.com/marti/xml/config">
    <network multicastTTL="5" serverId="1e76bb0fbff24cdf85456f056eda22a3" version="5.8-RELEASE-104-HEAD">
        <input _name="stdssl" protocol="tls" port="8089" coreVersion="2"/>
        <connector port="8446" clientAuth="false" _name="cert_https"/>
    </network>
    <auth>
        <File location="UserAuthenticationFile.xml"/>
    </auth>
    <security>
        <tls keystore="JKS" keystoreFile="certs/files/takserver.jks" keystorePass="X" truststore="JKS" truststoreFile="certs/files/truststore-root.jks" truststorePass="X" context="TLSv1.2" keymanager="SunX509"/>
    </security>
    <vbm enabled="false"/>
</Configuration>
'''


def _fn(name):
    m = re.search(r'^def %s\(.*?(?=^def |\Z)' % name, APP, re.S | re.M)
    assert m, name
    ns = {}
    exec(m.group(0), ns)
    return ns[name]


def _native_step8_slice():
    a = APP.index('Step 8/9: Configuring CoreConfig.xml')
    b = APP.index('Step 9/9: Promoting Admin', a)
    return APP[a:b]


# ── the transform ────────────────────────────────────────────────────────────────

def test_stock_config_is_missing_all_three_step8_edits():
    missing = _fn('_coreconfig_step8_missing')(STOCK, INT_CA, CA_LINE)
    assert len(missing) == 3


def test_step8_apply_restores_every_edit_and_is_idempotent():
    apply_ = _fn('_coreconfig_step8_apply')
    missing = _fn('_coreconfig_step8_missing')
    once = apply_(STOCK, INT_CA, CA_LINE, CERT_BLOCK)
    assert missing(once, INT_CA, CA_LINE) == []
    assert 'truststore-root.jks' not in once
    assert '<auth x509useGroupCache="true">' in once
    assert apply_(once, INT_CA, CA_LINE, CERT_BLOCK) == once      # no second enrollment block
    assert once.count('<certificateSigning') == 1


def test_step8_apply_sets_webtak_flags_only_when_asked():
    apply_ = _fn('_coreconfig_step8_apply')
    assert 'enableAdminUI' not in apply_(STOCK, INT_CA, CA_LINE, CERT_BLOCK)
    on = apply_(STOCK, INT_CA, CA_LINE, CERT_BLOCK, admin_ui='true', webtak='false')
    assert '"cert_https" enableAdminUI="true" enableWebtak="false" enableNonAdminUI="false"/' in on


# ── the order: nothing may rewrite the file after Step 8 edits it ────────────────

def test_tak_is_stopped_before_step8_reads_the_file():
    s = _native_step8_slice()
    read = s.index("_read_priv('/opt/tak/CoreConfig.xml')")
    stop = s.find("systemctl stop takserver")
    assert stop != -1 and stop < read, 'TAK must be stopped before Step 8 reads CoreConfig.xml'
    kill = s.find("pkill -9 -f takserver")
    assert kill != -1 and kill < read, 'TAK must be killed (not just asked to stop) before Step 8 reads it'


def test_step8_is_rechecked_with_tak_stopped_before_the_final_start():
    s = _native_step8_slice()
    final_stop = s.index("Final restart...")
    recheck = s.find('_coreconfig_step8_missing(_cc_s8', final_stop)
    start = s.index("run_cmd('systemctl start takserver')", final_stop)
    assert recheck != -1, 'no Step-8 re-check after the final stop'
    assert final_stop < recheck < start


def test_deploy_uses_the_shared_helpers_not_a_second_copy_of_the_edits():
    s = _native_step8_slice()
    assert '_coreconfig_step8_apply(' in s
    assert '_coreconfig_step8_missing(' in s
    # the replaces live in the helper now; a copy inside the deploy would drift
    assert "replace('truststoreFile=\"certs/files/truststore-root.jks'" not in s
