#!/bin/bash

BASE_URL="http://127.0.0.1:5000"

echo "=================================================="
echo "      AICTE-PRAMAAN END-TO-END TEST SUITE        "
echo "=================================================="

# 1. Health Check
echo -e "\n[1/6] Checking API Health..."
curl -s "$BASE_URL/health"
echo ""

# 2. Authenticate Users
echo -e "\n[2/6] Authenticating Users (JWT + 2FA)..."
INST_TOKEN=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"INST001","password":"password123","totp_code":"123456"}' \
  | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

ADMIN_TOKEN=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"AICTE_ADMIN","password":"admin123","totp_code":"123456"}' \
  | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -z "$INST_TOKEN" ] || [ -z "$ADMIN_TOKEN" ]; then
  echo "Authentication Failed!"
  exit 1
fi
echo "INST001 Token: ${INST_TOKEN:0:20}..."
echo "AICTE_ADMIN Token: ${ADMIN_TOKEN:0:20}..."

# 3. Ingest Records (Primary & Fuzzy Duplicate)
echo -e "\n[3/6] Ingesting Student Records into Merkle Tree..."
APAAR_1="100020003000"
APAAR_2="400050006000"

curl -s -X POST "$BASE_URL/api/records/ingest" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INST_TOKEN" \
  -d "{
    \"apaar_id\": \"$APAAR_1\",
    \"student_id\": \"REG_101\",
    \"name\": \"Aarav Ramesh Sharma\",
    \"institution_id\": \"INST001\",
    \"branch\": \"CSE\",
    \"admission_year\": 2026,
    \"has_consent\": true
  }"
echo ""

# Ingest fuzzy duplicate under INST002
curl -s -X POST "$BASE_URL/api/records/ingest" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $INST_TOKEN" \
  -d "{
    \"apaar_id\": \"$APAAR_2\",
    \"student_id\": \"REG_102\",
    \"name\": \"Aarav R Sharma\",
    \"institution_id\": \"INST002\",
    \"branch\": \"ECE\",
    \"admission_year\": 2026,
    \"has_consent\": true
  }"
echo ""

# 4. Generate Verifiable QR & Test Consent Revocation
echo -e "\n[4/6] Testing QR Verification & DPDP Consent Revocation..."
echo "Fetching QR Payload prior to revocation:"
curl -s "$BASE_URL/api/records/generate-qr/$APAAR_1"
echo ""

echo "Revoking DPDP Consent for APAAR ID $APAAR_1:"
curl -s -X POST "$BASE_URL/api/records/student/revoke-consent" \
  -H "Content-Type: application/json" \
  -d "{\"apaar_id\": \"$APAAR_1\"}"
echo ""

echo "Fetching QR Payload after revocation (Expect 403):"
curl -s "$BASE_URL/api/records/generate-qr/$APAAR_1"
echo ""

# 5. ML Vigilance Sweep
echo -e "\n[5/6] Executing ML Vigilance Sweep (Duplicate & Anomaly Detection)..."
curl -s -X POST "$BASE_URL/api/vigilance/run-ml-sweep" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
echo ""

# 6. Verify SHA-256 Audit Log Block Chain
echo -e "\n[6/6] Verifying Audit Log Chain Integrity..."
curl -s "$BASE_URL/api/audit/verify-chain" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
echo ""

echo -e "\n=================================================="
echo "          ALL VERIFICATION TESTS COMPLETE         "
echo "=================================================="