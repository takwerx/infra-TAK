#!/bin/bash
# LDAP bind diagnostic and fix script — run on the TAK host as root.
set -e
cd ~/authentik || { echo "~/authentik not found"; exit 1; }

TOKEN=$(grep AUTHENTIK_BOOTSTRAP_TOKEN .env | cut -d= -f2)
LDAP_PASS=$(grep AUTHENTIK_BOOTSTRAP_LDAPSERVICE_PASSWORD .env | cut -d= -f2-)

echo "=== 1. LDAP flow (get pk for bindings query) ==="
FLOW_JSON=$(curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9090/api/v3/flows/instances/?slug=ldap-authentication-flow")
FLOW_PK=$(echo "$FLOW_JSON" | python3 -c "import sys,json; r=json.load(sys.stdin); res=r.get('results',[]); print(res[0]['pk'] if res else '')" 2>/dev/null)
echo "Flow pk: $FLOW_PK"

echo ""
echo "=== 2. Flow bindings (should show 3 stages: order 10, 15, 20) ==="
if [ -n "$FLOW_PK" ]; then
  # Fetch all bindings and filter by target (API filter varies by version)
  curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9090/api/v3/flows/bindings/?ordering=order&page_size=500" | \
    python3 -c "
import sys,json
data=json.loads(sys.stdin.read())
all_bindings=data.get('results',[])
ldap_bindings=[b for b in all_bindings if str(b.get('target'))==str('$FLOW_PK')]
if not ldap_bindings:
  print('  EMPTY — NO BINDINGS! This causes Access denied (50).')
  print('  Fix: Run \"Connect TAK Server to LDAP\" in infra-TAK, or restart worker and reconcile blueprint.')
else:
  for b in sorted(ldap_bindings, key=lambda x: x.get('order',0)):
    name=b.get('stage_obj',{}).get('name','?')
    print(f'  order={b[\"order\"]} stage={name}')
" 2>/dev/null || echo "  (parse error)"
else
  echo "  No flow found"
fi

echo ""
echo "=== 3. LDAP application + provider ==="
curl -s -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:9090/api/v3/core/applications/?search=LDAP' | \
  python3 -c "import sys,json; r=json.loads(sys.stdin.read())['results']; [print(f'  name={a[\"name\"]} provider={a.get(\"provider\")} slug={a[\"slug\"]}') for a in r]" 2>/dev/null || true

echo ""
echo "=== 4. LDAP provider details ==="
curl -s -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:9090/api/v3/providers/ldap/?search=LDAP' | \
  python3 -c "import sys,json; r=json.loads(sys.stdin.read())['results']; [print(f'  pk={p[\"pk\"]} name={p[\"name\"]} auth_flow={p.get(\"authorization_flow\")} bind_mode={p.get(\"bind_mode\")}') for p in r]" 2>/dev/null || true

echo ""
echo "=== 5. User adm_ldapservice (pk=54) ==="
curl -s -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:9090/api/v3/core/users/54/' | \
  python3 -c "import sys,json; u=json.loads(sys.stdin.read()); print(f'  pk={u[\"pk\"]} username={u[\"username\"]} active={u[\"is_active\"]} groups={[g[\"name\"] for g in u.get(\"groups_obj\",[])]}')" 2>/dev/null || echo "  User 54 not found"

echo ""
echo "=== 6. Recent LDAP outpost logs ==="
docker compose logs ldap --tail=15 --no-log-prefix 2>/dev/null || true

echo ""
echo "=== 7. Bind test ==="
ldapsearch -x -H ldap://127.0.0.1:389 -D 'cn=adm_ldapservice,ou=users,dc=takldap' -w "$LDAP_PASS" -b 'dc=takldap' -s base '(objectClass=*)' 2>&1 | head -15

echo ""
echo "=== FIX: If bindings are empty, run blueprint reconciliation ==="
echo "  cd ~/authentik && docker compose restart worker && sleep 45"
echo "  Then re-run this script. Or use infra-TAK: Connect TAK Server to LDAP (auto-fixes bindings)."
