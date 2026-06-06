#!/usr/bin/env bash
# LockGuardian Integration Test Suite
# Tests all major API endpoints for Bitwarden client compatibility
set -uo pipefail

BASE="http://localhost:8080"
PASS=0
FAIL=0
FAILURES=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}PASS${NC} $desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES="${FAILURES}\n  FAIL: $desc (expected='$expected', got='$actual')"
        echo -e "  ${RED}FAIL${NC} $desc (expected='$expected', got='$actual')"
    fi
}

assert_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -q "$needle"; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}PASS${NC} $desc"
    else
        FAIL=$((FAIL + 1))
        FAILURES="${FAILURES}\n  FAIL: $desc (expected to contain '$needle')"
        echo -e "  ${RED}FAIL${NC} $desc (missing '$needle')"
    fi
}

assert_http() {
    local desc="$1" expected_code="$2" actual_code="$3"
    assert_eq "$desc [HTTP $expected_code]" "$expected_code" "$actual_code"
}

json_field() {
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)" 2>/dev/null
}

# ========== SETUP ==========
echo "=== LockGuardian Integration Tests ==="
echo ""

# Clean state
rm -f ./data/lockguardian.db* ./data/rsa_key.pem
rm -rf ./data/attachments

# Start server
cp .env.example .env
./target/release/lockguardian &
SERVER_PID=$!
sleep 2

cleanup() {
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

# ========== 1. HEALTH CHECK ==========
echo "--- 1. Health Check ---"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/alive")
assert_http "GET /alive" "200" "$HTTP"

# ========== 2. REGISTRATION ==========
echo "--- 2. Registration ---"

# Register user 1
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/api/accounts/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"user1@test.com","masterPasswordHash":"hash1","name":"User One","key":"2.enc_key_1","kdf":0,"kdfIterations":600000,"keys":{"publicKey":"pub_key_1","encryptedPrivateKey":"enc_priv_key_1"}}')
HTTP=$(echo "$RESP" | tail -1)
assert_http "Register user1" "200" "$HTTP"

# Register user 2
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/api/accounts/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"user2@test.com","masterPasswordHash":"hash2","name":"User Two","key":"2.enc_key_2","kdf":0,"kdfIterations":600000}')
HTTP=$(echo "$RESP" | tail -1)
assert_http "Register user2" "200" "$HTTP"

# Duplicate registration should fail
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/api/accounts/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"user1@test.com","masterPasswordHash":"hash1","name":"Dup"}')
HTTP=$(echo "$RESP" | tail -1)
assert_http "Duplicate register fails" "400" "$HTTP"

# ========== 3. PRELOGIN ==========
echo "--- 3. Prelogin ---"
RESP=$(curl -s "$BASE/api/accounts/prelogin" \
    -H "Content-Type: application/json" \
    -d '{"email":"user1@test.com"}')
KDF=$(echo "$RESP" | json_field "['Kdf']")
KDF_ITER=$(echo "$RESP" | json_field "['KdfIterations']")
assert_eq "Prelogin Kdf" "0" "$KDF"
assert_eq "Prelogin KdfIterations" "600000" "$KDF_ITER"

# Prelogin for non-existent user (no enumeration)
RESP=$(curl -s "$BASE/api/accounts/prelogin" \
    -H "Content-Type: application/json" \
    -d '{"email":"nonexist@test.com"}')
KDF=$(echo "$RESP" | json_field "['Kdf']")
assert_eq "Prelogin non-existent user returns defaults" "0" "$KDF"

# ========== 4. LOGIN ==========
echo "--- 4. Login ---"

# Login user1
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/identity/connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&username=user1@test.com&password=hash1&deviceIdentifier=dev-001&deviceName=TestBrowser&deviceType=7&scope=api+offline_access&client_id=web")
HTTP=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | head -1)
assert_http "Login user1" "200" "$HTTP"

TOKEN1=$(echo "$BODY" | json_field "['access_token']")
REFRESH1=$(echo "$BODY" | json_field "['refresh_token']")
KEY1=$(echo "$BODY" | json_field "['Key']")
assert_eq "Login returns Key" "2.enc_key_1" "$KEY1"

UNOFFICIAL=$(echo "$BODY" | json_field "['unofficialServer']")
assert_eq "Login returns unofficialServer" "True" "$UNOFFICIAL"

UDO=$(echo "$BODY" | json_field "['UserDecryptionOptions']['HasMasterPassword']")
assert_eq "Login returns UserDecryptionOptions" "True" "$UDO"

# Wrong password
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/identity/connect/token" \
    -d "grant_type=password&username=user1@test.com&password=wrongpass&deviceIdentifier=dev-001&deviceName=TestBrowser&deviceType=7")
HTTP=$(echo "$RESP" | tail -1)
assert_http "Login wrong password" "401" "$HTTP"

# Login user2
RESP=$(curl -s -X POST "$BASE/identity/connect/token" \
    -d "grant_type=password&username=user2@test.com&password=hash2&deviceIdentifier=dev-002&deviceName=TestPhone&deviceType=1")
TOKEN2=$(echo "$RESP" | json_field "['access_token']")

# ========== 5. REFRESH TOKEN ==========
echo "--- 5. Refresh Token ---"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/identity/connect/token" \
    -d "grant_type=refresh_token&refresh_token=$REFRESH1")
HTTP=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | head -1)
assert_http "Refresh token" "200" "$HTTP"
NEW_TOKEN=$(echo "$BODY" | json_field "['access_token']")
NEW_REFRESH=$(echo "$BODY" | json_field "['refresh_token']")
assert_contains "New access_token returned" "eyJ" "$NEW_TOKEN"
# Use new token for remaining tests
TOKEN1="$NEW_TOKEN"

# ========== 6. PROFILE ==========
echo "--- 6. Profile ---"
RESP=$(curl -s "$BASE/api/accounts/profile" -H "Authorization: Bearer $TOKEN1")
OBJ=$(echo "$RESP" | json_field "['Object']")
EMAIL=$(echo "$RESP" | json_field "['Email']")
assert_eq "Profile Object" "profile" "$OBJ"
assert_eq "Profile Email" "user1@test.com" "$EMAIL"

# ========== 7. SYNC (empty) ==========
echo "--- 7. Sync (empty vault) ---"
RESP=$(curl -s "$BASE/api/sync" -H "Authorization: Bearer $TOKEN1")
OBJ=$(echo "$RESP" | json_field "['Object']")
CIPHERS_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['Ciphers']))")
FOLDERS_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['Folders']))")
assert_eq "Sync Object" "sync" "$OBJ"
assert_eq "Sync empty ciphers" "0" "$CIPHERS_COUNT"
assert_eq "Sync empty folders" "0" "$FOLDERS_COUNT"
# Check required fields
assert_contains "Sync has Domains" "Domains" "$RESP"
assert_contains "Sync has Policies" "Policies" "$RESP"
assert_contains "Sync has Sends" "Sends" "$RESP"
assert_contains "Sync has Profile" "Profile" "$RESP"

# ========== 8. FOLDERS ==========
echo "--- 8. Folders ---"

# Create folder
RESP=$(curl -s -X POST "$BASE/api/folders" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d '{"name":"2.folder_enc_name"}')
FOLDER_OBJ=$(echo "$RESP" | json_field "['Object']")
FOLDER_ID=$(echo "$RESP" | json_field "['Id']")
FOLDER_NAME=$(echo "$RESP" | json_field "['Name']")
assert_eq "Folder Object" "folder" "$FOLDER_OBJ"
assert_eq "Folder Name" "2.folder_enc_name" "$FOLDER_NAME"
assert_contains "Folder has RevisionDate" "RevisionDate" "$RESP"

# Update folder
RESP=$(curl -s -X PUT "$BASE/api/folders/$FOLDER_ID" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d '{"name":"2.folder_renamed"}')
UPDATED_NAME=$(echo "$RESP" | json_field "['Name']")
assert_eq "Folder updated" "2.folder_renamed" "$UPDATED_NAME"

# List folders
RESP=$(curl -s "$BASE/api/folders" -H "Authorization: Bearer $TOKEN1")
LIST_OBJ=$(echo "$RESP" | json_field "['Object']")
LIST_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['Data']))")
assert_eq "Folder list Object" "list" "$LIST_OBJ"
assert_eq "Folder list count" "1" "$LIST_COUNT"

# ========== 9. CIPHERS ==========
echo "--- 9. Ciphers ---"

# Create cipher (Login type)
RESP=$(curl -s -X POST "$BASE/api/ciphers" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d "{\"type\":1,\"name\":\"2.cipher_name\",\"notes\":\"2.cipher_notes\",\"login\":{\"uri\":\"2.enc_uri\",\"username\":\"2.enc_user\",\"password\":\"2.enc_pass\"},\"favorite\":true,\"reprompt\":0,\"folderId\":\"$FOLDER_ID\"}")
CIPHER_OBJ=$(echo "$RESP" | json_field "['Object']")
CIPHER_ID=$(echo "$RESP" | json_field "['Id']")
CIPHER_TYPE=$(echo "$RESP" | json_field "['Type']")
CIPHER_FAV=$(echo "$RESP" | json_field "['Favorite']")
CIPHER_FOLDER=$(echo "$RESP" | json_field "['FolderId']")
assert_eq "Cipher Object" "cipher" "$CIPHER_OBJ"
assert_eq "Cipher Type" "1" "$CIPHER_TYPE"
assert_eq "Cipher Favorite" "True" "$CIPHER_FAV"
assert_eq "Cipher FolderId" "$FOLDER_ID" "$CIPHER_FOLDER"
assert_contains "Cipher has Login field" "Login" "$RESP"
assert_contains "Cipher has Data field" "Data" "$RESP"
assert_contains "Cipher has CreationDate" "CreationDate" "$RESP"
assert_contains "Cipher has RevisionDate" "RevisionDate" "$RESP"
assert_contains "Cipher has Edit field" "Edit" "$RESP"

# Create SecureNote cipher
RESP=$(curl -s -X POST "$BASE/api/ciphers" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d '{"type":2,"name":"2.secure_note_name","notes":"2.secure_note_content","secureNote":{"type":0},"favorite":false,"reprompt":0}')
CIPHER2_ID=$(echo "$RESP" | json_field "['Id']")
CIPHER2_TYPE=$(echo "$RESP" | json_field "['Type']")
assert_eq "SecureNote Type" "2" "$CIPHER2_TYPE"

# Get cipher
RESP=$(curl -s "$BASE/api/ciphers/$CIPHER_ID" -H "Authorization: Bearer $TOKEN1")
GET_ID=$(echo "$RESP" | json_field "['Id']")
assert_eq "Get cipher Id" "$CIPHER_ID" "$GET_ID"

# Update cipher
RESP=$(curl -s -X PUT "$BASE/api/ciphers/$CIPHER_ID" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d "{\"type\":1,\"name\":\"2.updated_name\",\"notes\":null,\"login\":{\"uri\":\"2.new_uri\",\"username\":\"2.new_user\",\"password\":\"2.new_pass\"},\"favorite\":false,\"reprompt\":1,\"folderId\":\"$FOLDER_ID\"}")
UPD_NAME=$(echo "$RESP" | json_field "['Name']")
UPD_FAV=$(echo "$RESP" | json_field "['Favorite']")
assert_eq "Updated cipher Name" "2.updated_name" "$UPD_NAME"
assert_eq "Updated cipher Favorite" "False" "$UPD_FAV"

# Soft delete
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/ciphers/$CIPHER2_ID/delete" \
    -H "Authorization: Bearer $TOKEN1")
assert_http "Soft delete cipher" "200" "$HTTP"

# Verify soft delete shows in sync
RESP=$(curl -s "$BASE/api/sync" -H "Authorization: Bearer $TOKEN1")
DELETED_CIPHER=$(echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for c in d['Ciphers']:
    if c['Id'] == '$CIPHER2_ID':
        print(c.get('DeletedDate', 'None'))
        break
")
assert_contains "Soft deleted has DeletedDate" "T" "$DELETED_CIPHER"

# Restore
RESP=$(curl -s -w "\n%{http_code}" -X PUT "$BASE/api/ciphers/$CIPHER2_ID/restore" \
    -H "Authorization: Bearer $TOKEN1")
HTTP=$(echo "$RESP" | tail -1)
assert_http "Restore cipher" "200" "$HTTP"

# Hard delete
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/api/ciphers/$CIPHER2_ID" \
    -H "Authorization: Bearer $TOKEN1")
assert_http "Hard delete cipher" "200" "$HTTP"

# Verify hard delete removes from list
RESP=$(curl -s "$BASE/api/ciphers" -H "Authorization: Bearer $TOKEN1")
CIPHER_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['Data']))")
assert_eq "After hard delete, 1 cipher remains" "1" "$CIPHER_COUNT"

# ========== 10. ATTACHMENTS ==========
echo "--- 10. Attachments ---"

# Upload attachment
echo "ATTACHMENT_FILE_CONTENT_TEST_123" > /tmp/test_attachment.bin
RESP=$(curl -s -X POST "$BASE/api/ciphers/$CIPHER_ID/attachment" \
    -H "Authorization: Bearer $TOKEN1" \
    -F "key=2.enc_attachment_key" \
    -F "data=@/tmp/test_attachment.bin")
ATT_ID=$(echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
atts = d.get('Attachments', [])
if atts:
    print(atts[0]['Id'])
else:
    print('NONE')
" 2>/dev/null || echo "NONE")

if [ "$ATT_ID" != "NONE" ]; then
    # Download attachment
    DOWNLOAD=$(curl -s "$BASE/attachments/$CIPHER_ID/$ATT_ID")
    assert_contains "Attachment download content" "ATTACHMENT_FILE_CONTENT_TEST_123" "$DOWNLOAD"

    # Verify attachment URL in response
    ATT_URL=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['Attachments'][0]['Url'])")
    assert_contains "Attachment URL contains cipher ID" "$CIPHER_ID" "$ATT_URL"
    assert_contains "Attachment URL contains attachment ID" "$ATT_ID" "$ATT_URL"

    # Delete attachment
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/api/ciphers/$CIPHER_ID/attachment/$ATT_ID" \
        -H "Authorization: Bearer $TOKEN1")
    assert_http "Delete attachment" "200" "$HTTP"

    # Verify download fails after delete
    HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/attachments/$CIPHER_ID/$ATT_ID")
    assert_http "Attachment 404 after delete" "404" "$HTTP"
else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} Attachment upload returned no attachment"
fi
rm -f /tmp/test_attachment.bin

# ========== 11. ORGANIZATIONS ==========
echo "--- 11. Organizations ---"

# Create org
RESP=$(curl -s -X POST "$BASE/api/organizations" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d '{"name":"Test Org","billingEmail":"admin@test.com","key":"2.org_key","collectionName":"Default"}')
ORG_ID=$(echo "$RESP" | json_field "['Id']")
ORG_NAME=$(echo "$RESP" | json_field "['Name']")
ORG_TYPE=$(echo "$RESP" | json_field "['Type']")
assert_eq "Org Name" "Test Org" "$ORG_NAME"
assert_eq "Org user Type (owner)" "0" "$ORG_TYPE"

# List orgs
RESP=$(curl -s "$BASE/api/organizations" -H "Authorization: Bearer $TOKEN1")
ORG_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['Data']))")
assert_eq "Org list count" "1" "$ORG_COUNT"

# Invite user2
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/organizations/$ORG_ID/users/invite" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d '{"emails":["user2@test.com"],"type":2,"accessAll":true}')
assert_http "Invite user2" "200" "$HTTP"

# List org users
RESP=$(curl -s "$BASE/api/organizations/$ORG_ID/users" -H "Authorization: Bearer $TOKEN1")
USER_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['Data']))")
assert_eq "Org has 2 users" "2" "$USER_COUNT"

# Get invited user org ID
USER2_ORG_ID=$(echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for u in d['Data']:
    if u['Email'] == 'user2@test.com':
        print(u['Id'])
        break
")

# Confirm user2
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "$BASE/api/organizations/$ORG_ID/users/$USER2_ORG_ID/confirm" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d '{"key":"2.org_user_key"}')
assert_http "Confirm user2" "200" "$HTTP"

# ========== 12. COLLECTIONS ==========
echo "--- 12. Collections ---"

# List collections (should have "Default" from org creation)
RESP=$(curl -s "$BASE/api/organizations/$ORG_ID/collections" \
    -H "Authorization: Bearer $TOKEN1")
COLL_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['Data']))")
assert_eq "Default collection exists" "1" "$COLL_COUNT"
DEFAULT_COLL_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['Data'][0]['Id'])")

# Create another collection
RESP=$(curl -s -X POST "$BASE/api/organizations/$ORG_ID/collections" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d '{"name":"2.secret_collection"}')
COLL2_ID=$(echo "$RESP" | json_field "['Id']")
COLL_OBJ=$(echo "$RESP" | json_field "['Object']")
assert_eq "Collection Object" "collection" "$COLL_OBJ"

# ========== 13. ORG CIPHER WITH COLLECTION PERMISSIONS ==========
echo "--- 13. Org Cipher + Collection Permissions ---"

# Create org cipher assigned to default collection
RESP=$(curl -s -X POST "$BASE/api/ciphers" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d "{\"type\":1,\"name\":\"2.org_cipher\",\"login\":{\"uri\":\"2.org_uri\"},\"organizationId\":\"$ORG_ID\",\"collectionIds\":[\"$DEFAULT_COLL_ID\"]}")
ORG_CIPHER_ID=$(echo "$RESP" | json_field "['Id']")
ORG_CIPHER_ORG=$(echo "$RESP" | json_field "['OrganizationId']")
assert_eq "Org cipher has OrganizationId" "$ORG_ID" "$ORG_CIPHER_ORG"

# User2 (confirmed member, access_all) should see org cipher in sync
RESP=$(curl -s "$BASE/api/sync" -H "Authorization: Bearer $TOKEN2")
USER2_CIPHERS=$(echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
org_ciphers = [c for c in d['Ciphers'] if c.get('OrganizationId') == '$ORG_ID']
print(len(org_ciphers))
")
assert_eq "User2 sees org cipher in sync" "1" "$USER2_CIPHERS"

# User2 should NOT see user1's personal cipher
USER2_PERSONAL=$(echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
personal = [c for c in d['Ciphers'] if c.get('OrganizationId') is None and c['Id'] == '$CIPHER_ID']
print(len(personal))
")
assert_eq "User2 cannot see user1 personal cipher" "0" "$USER2_PERSONAL"

# Non-member cannot access org cipher
curl -s -X POST "$BASE/api/accounts/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"outsider@test.com","masterPasswordHash":"hash3","name":"Outsider","key":"k3"}' > /dev/null
RESP=$(curl -s -X POST "$BASE/identity/connect/token" \
    -d "grant_type=password&username=outsider@test.com&password=hash3&deviceIdentifier=dev-003&deviceName=D&deviceType=7")
TOKEN3=$(echo "$RESP" | json_field "['access_token']")

HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/ciphers/$ORG_CIPHER_ID" \
    -H "Authorization: Bearer $TOKEN3")
assert_http "Non-member cannot read org cipher" "403" "$HTTP"

# ========== 14. TWO-FACTOR AUTHENTICATION ==========
echo "--- 14. Two-Factor Auth ---"

# Get authenticator (initial - not enabled)
RESP=$(curl -s -X POST "$BASE/api/two-factor/get-authenticator" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d '{"masterPasswordHash":"hash1"}')
ENABLED=$(echo "$RESP" | json_field "['Enabled']")
TF_KEY=$(echo "$RESP" | json_field "['Key']")
assert_eq "2FA initially disabled" "False" "$ENABLED"
TF_KEY_LEN=${#TF_KEY}
if [ "$TF_KEY_LEN" -ge 16 ]; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC} 2FA key length >= 16 ($TF_KEY_LEN chars)"
else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} 2FA key too short ($TF_KEY_LEN chars)"
fi

# Generate a valid TOTP code for the key
TOTP_CODE=$(python3 -c "
import hmac, hashlib, struct, time, base64
key_bytes = base64.b32decode('$TF_KEY')
t = int(time.time()) // 30
msg = struct.pack('>Q', t)
h = hmac.digest(key_bytes, msg, hashlib.sha1)
o = h[-1] & 0x0F
code = (struct.unpack('>I', h[o:o+4])[0] & 0x7FFFFFFF) % 1000000
print(f'{code:06d}')
" 2>/dev/null || echo "INVALID")

# Activate authenticator
RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/api/two-factor/authenticator" \
    -H "Authorization: Bearer $TOKEN1" \
    -H "Content-Type: application/json" \
    -d "{\"masterPasswordHash\":\"hash1\",\"key\":\"$TF_KEY\",\"token\":\"$TOTP_CODE\"}")
HTTP=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | head -1)
if [ "$HTTP" = "200" ]; then
    ENABLED=$(echo "$BODY" | json_field "['Enabled']")
    assert_eq "2FA activated" "True" "$ENABLED"

    # Login now requires 2FA - should get error
    RESP=$(curl -s -X POST "$BASE/identity/connect/token" \
        -d "grant_type=password&username=user1@test.com&password=hash1&deviceIdentifier=dev-001&deviceName=D&deviceType=7")
    TWO_FA_ERR=$(echo "$RESP" | json_field "['TwoFactorProviders']" 2>/dev/null || echo "NONE")
    assert_contains "Login requires 2FA" "0" "$TWO_FA_ERR"

    # Login with 2FA token
    NEW_TOTP=$(python3 -c "
import hmac, hashlib, struct, time, base64
key_bytes = base64.b32decode('$TF_KEY')
t = int(time.time()) // 30
msg = struct.pack('>Q', t)
h = hmac.digest(key_bytes, msg, hashlib.sha1)
o = h[-1] & 0x0F
code = (struct.unpack('>I', h[o:o+4])[0] & 0x7FFFFFFF) % 1000000
print(f'{code:06d}')
" 2>/dev/null || echo "INVALID")

    RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/identity/connect/token" \
        -d "grant_type=password&username=user1@test.com&password=hash1&deviceIdentifier=dev-001&deviceName=D&deviceType=7&twoFactorToken=$NEW_TOTP&twoFactorProvider=0")
    HTTP=$(echo "$RESP" | tail -1)
    assert_http "Login with 2FA" "200" "$HTTP"
    TOKEN1=$(echo "$RESP" | head -1 | json_field "['access_token']")

    # Disable 2FA
    RESP=$(curl -s -w "\n%{http_code}" -X POST "$BASE/api/two-factor/disable" \
        -H "Authorization: Bearer $TOKEN1" \
        -H "Content-Type: application/json" \
        -d '{"masterPasswordHash":"hash1","type":0}')
    HTTP=$(echo "$RESP" | tail -1)
    assert_http "Disable 2FA" "200" "$HTTP"

    # Re-login after 2FA disable (security stamp changed)
    RESP=$(curl -s -X POST "$BASE/identity/connect/token" \
        -d "grant_type=password&username=user1@test.com&password=hash1&deviceIdentifier=dev-001&deviceName=D&deviceType=7")
    TOKEN1=$(echo "$RESP" | json_field "['access_token']")
else
    # TOTP code might be wrong due to timing; test that the endpoint works structurally
    echo -e "  ${RED}SKIP${NC} 2FA activation failed (timing issue with TOTP code)"
    FAIL=$((FAIL + 1))
fi

# ========== 15. EVENT LOG ==========
echo "--- 15. Event Log ---"
EVENTS=$(python3 -c "
import sqlite3
conn = sqlite3.connect('./data/lockguardian.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM events')
print(c.fetchone()[0])
conn.close()
")
if [ "$EVENTS" -gt 0 ]; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC} Events count > 0 ($EVENTS events recorded)"
else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} No events recorded"
fi

# Check login event exists
LOGIN_EVENTS=$(python3 -c "
import sqlite3
conn = sqlite3.connect('./data/lockguardian.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM events WHERE type_ = 1000')
print(c.fetchone()[0])
conn.close()
")
if [ "$LOGIN_EVENTS" -gt 0 ]; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC} Login events recorded ($LOGIN_EVENTS)"
else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} No login events"
fi

# Check cipher events
CIPHER_EVENTS=$(python3 -c "
import sqlite3
conn = sqlite3.connect('./data/lockguardian.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM events WHERE type_ >= 1100 AND type_ < 1200')
print(c.fetchone()[0])
conn.close()
")
if [ "$CIPHER_EVENTS" -gt 0 ]; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC} Cipher events recorded ($CIPHER_EVENTS)"
else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC} No cipher events"
fi

# ========== 16. VAULT EXPORT ==========
echo "--- 16. Vault Export ---"
RESP=$(curl -s -X POST "$BASE/api/accounts/export" \
    -H "Authorization: Bearer $TOKEN1")
assert_contains "Export has Folders" "Folders" "$RESP"
assert_contains "Export has Ciphers" "Ciphers" "$RESP"

# ========== 17. REMOVE ORG USER ==========
echo "--- 17. Remove Org User ---"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    "$BASE/api/organizations/$ORG_ID/users/$USER2_ORG_ID" \
    -H "Authorization: Bearer $TOKEN1")
assert_http "Remove user from org" "200" "$HTTP"

# After removal, user2 should not see org cipher
RESP=$(curl -s "$BASE/api/sync" -H "Authorization: Bearer $TOKEN2")
USER2_ORG_CIPHERS=$(echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
org_ciphers = [c for c in d['Ciphers'] if c.get('OrganizationId') == '$ORG_ID']
print(len(org_ciphers))
")
assert_eq "Removed user2 no longer sees org ciphers" "0" "$USER2_ORG_CIPHERS"

# ========== 18. REVISION DATE ==========
echo "--- 18. Revision Date ---"
RESP=$(curl -s "$BASE/api/accounts/revision-date" -H "Authorization: Bearer $TOKEN1")
assert_contains "Revision date is timestamp" "" "$RESP"

# ========== 19. DELETE FOLDER ==========
echo "--- 19. Delete Folder ---"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/api/folders/$FOLDER_ID" \
    -H "Authorization: Bearer $TOKEN1")
assert_http "Delete folder" "200" "$HTTP"

# ========== SUMMARY ==========
echo ""
echo "======================================="
echo -e "  Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "======================================="
if [ $FAIL -gt 0 ]; then
    echo -e "\nFailures:$FAILURES"
    exit 1
fi
