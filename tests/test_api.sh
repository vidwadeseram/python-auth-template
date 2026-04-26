#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8001/api/v1}"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  ✅ PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  ❌ FAIL: $1 — $2"; }

echo "============================================"
echo "  Python Auth Template — Curl Test Suite"
echo "  Base URL: $BASE_URL"
echo "============================================"

# --- Health ---
echo ""
echo "--- Health ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/../health")
[ "$STATUS" = "200" ] && pass "GET /health → 200" || fail "GET /health → 200" "got $STATUS"

# --- Auth: Register ---
echo ""
echo "--- Auth: Register ---"
REGISTER=$(curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@example.com","password":"SecurePass123!","first_name":"Test","last_name":"User"}')
echo "$REGISTER" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'user' in d['data'], 'no user key'; assert d['data']['user']['email']=='testuser@example.com'" && pass "POST /auth/register → user created" || fail "POST /auth/register" "response: $REGISTER"

# --- Auth: Login ---
echo ""
echo "--- Auth: Login ---"
LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@example.com","password":"SecurePass123!"}')
TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['access_token'])")
REFRESH=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['refresh_token'])")
[ -n "$TOKEN" ] && pass "POST /auth/login → access token" || fail "POST /auth/login" "no token"
[ -n "$REFRESH" ] && pass "POST /auth/login → refresh token" || fail "POST /auth/login" "no refresh token"

# --- Auth: Me ---
echo ""
echo "--- Auth: Me ---"
ME=$(curl -s "$BASE_URL/auth/me" -H "Authorization: Bearer $TOKEN")
echo "$ME" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['data']['email']=='testuser@example.com'" && pass "GET /auth/me → correct user" || fail "GET /auth/me" "response: $ME"

# --- Auth: Refresh ---
echo ""
echo "--- Auth: Refresh ---"
REFRESHED=$(curl -s -X POST "$BASE_URL/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\"}")
NEW_TOKEN=$(echo "$REFRESHED" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['access_token'])")
[ -n "$NEW_TOKEN" ] && pass "POST /auth/refresh → new access token" || fail "POST /auth/refresh" "response: $REFRESHED"
TOKEN="$NEW_TOKEN"

# --- Auth: Forgot Password ---
echo ""
echo "--- Auth: Forgot Password ---"
FORGOT=$(curl -s -X POST "$BASE_URL/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@example.com"}')
echo "$FORGOT" | python3 -c "import sys,json; assert 'message' in json.load(sys.stdin)['data']" && pass "POST /auth/forgot-password → message sent" || fail "POST /auth/forgot-password" "response: $FORGOT"

# --- Auth: Logout ---
echo ""
echo "--- Auth: Logout ---"
LOGOUT=$(curl -s -X POST "$BASE_URL/auth/logout" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\"}")
echo "$LOGOUT" | python3 -c "import sys,json; assert 'message' in json.load(sys.stdin)['data']" && pass "POST /auth/logout → success" || fail "POST /auth/logout" "response: $LOGOUT"

# --- Auth: Me after logout (refresh token revoked, access still valid until expiry) ---
echo ""
echo "--- Auth: Register admin for RBAC tests ---"
ADMIN_REG=$(curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"AdminPass123!","first_name":"Admin","last_name":"User"}')
ADMIN_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"AdminPass123!"}')
ADMIN_TOKEN=$(echo "$ADMIN_LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['access_token'])")

# --- RBAC: Test without role (should 403) ---
echo ""
echo "--- RBAC: Admin endpoints without role ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/admin/roles" -H "Authorization: Bearer $ADMIN_TOKEN")
[ "$STATUS" = "403" ] && pass "GET /admin/roles without role → 403" || fail "GET /admin/roles without role → 403" "got $STATUS"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/admin/users" -H "Authorization: Bearer $ADMIN_TOKEN")
[ "$STATUS" = "403" ] && pass "GET /admin/users without role → 403" || fail "GET /admin/users without role → 403" "got $STATUS"

echo ""
echo "--- RBAC: Assign super_admin role via DB ---"
CONTAINER=$(docker ps --filter "publish=8001" --format "{{.Names}}" | head -1)
if [ -n "$CONTAINER" ]; then
  ADMIN_USER_ID=$(echo "$ADMIN_LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['user']['id'])")
  docker exec "$CONTAINER" psql -U postgres -d authdb -c "INSERT INTO user_roles (user_id, role_id) SELECT '$ADMIN_USER_ID', id FROM roles WHERE name='super_admin' ON CONFLICT DO NOTHING;" 2>/dev/null || true
fi

echo ""
echo "--- RBAC: Admin endpoints with super_admin ---"
ROLES=$(curl -s "$BASE_URL/admin/roles" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$ROLES" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d['data']) > 0" && pass "GET /admin/roles → roles listed" || fail "GET /admin/roles" "response: $ROLES"

PERMS=$(curl -s "$BASE_URL/admin/permissions" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$PERMS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d['data']) > 0" && pass "GET /admin/permissions → permissions listed" || fail "GET /admin/permissions" "response: $PERMS"

USERS=$(curl -s "$BASE_URL/admin/users" -H "Authorization: Bearer $ADMIN_TOKEN")
echo "$USERS" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d['data']) >= 2" && pass "GET /admin/users → users listed" || fail "GET /admin/users" "response: $USERS"

echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
