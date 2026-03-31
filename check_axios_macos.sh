#!/bin/bash
# check_axios_macos.sh
# Scans the entire macOS system for malicious axios versions (1.14.1 / 0.30.4)
# Usage: chmod +x check_axios_macos.sh && sudo ./check_axios_macos.sh

BAD_VERSIONS=("1.14.1" "0.30.4")
FOUND=0
MALICIOUS=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================================"
echo " Axios Supply Chain Attack — macOS Scanner"
echo " Bad versions: 1.14.1 / 0.30.4"
echo " Safe versions: 1.14.0 / 0.30.3"
echo "======================================================"
echo "Scanning filesystem for axios installations..."
echo "(Run with sudo for full coverage)"
echo ""

while IFS= read -r pkg_file; do
    name=$(python3 -c "
import json
try:
    d = json.load(open('$pkg_file'))
    print(d.get('name',''))
except:
    pass
" 2>/dev/null)

    version=$(python3 -c "
import json
try:
    d = json.load(open('$pkg_file'))
    print(d.get('version',''))
except:
    pass
" 2>/dev/null)

    if [[ "$name" == "axios" ]]; then
        FOUND=$((FOUND + 1))
        if [[ " ${BAD_VERSIONS[*]} " =~ " $version " ]]; then
            echo -e "${RED}[*** MALICIOUS ***]${NC} $pkg_file --> v$version"
            MALICIOUS=$((MALICIOUS + 1))
        else
            echo -e "${GREEN}[OK]${NC} $pkg_file --> v$version"
        fi
    fi
done < <(find / -name "package.json" -path "*/axios/*" 2>/dev/null)

echo ""
echo "======================================================"
echo " SCAN COMPLETE"
echo " Total axios installs found: $FOUND"

if [[ $MALICIOUS -gt 0 ]]; then
    echo -e " ${RED}!! MALICIOUS VERSIONS FOUND: $MALICIOUS !!${NC}"
    echo ""
    echo " NEXT STEPS:"
    echo "  1. Disconnect from the internet NOW"
    echo "  2. Check for RAT artifact (see below)"
    echo "  3. Rotate ALL credentials (SSH keys, AWS, npm tokens, .env files)"
    echo "  4. Run: rm -rf node_modules/plain-crypto-js"
    echo "  5. Downgrade: npm install axios@1.14.0 --ignore-scripts"
    echo "  6. Block C2:  echo '0.0.0.0 sfrclak.com' | sudo tee -a /etc/hosts"
    echo "  7. See axios-supply-chain-attack.md for full remediation steps"
else
    echo -e " ${GREEN}No malicious axios versions detected.${NC}"
fi

echo ""
echo " --- Checking for RAT artifact (/Library/Caches/com.apple.act.mond) ---"
RAT_PATH="/Library/Caches/com.apple.act.mond"
if [[ -f "$RAT_PATH" ]]; then
    echo -e "${RED}RAT ARTIFACT FOUND: $RAT_PATH${NC}"
    ls -la "$RAT_PATH"
    echo ""
    echo -e "${RED}YOUR SYSTEM IS COMPROMISED. Isolate immediately and rotate all credentials.${NC}"
else
    echo -e "${GREEN}Clean — RAT artifact not present.${NC}"
fi

echo ""
echo " --- Checking for active C2 connections (sfrclak.com / 142.11.206.73) ---"
CONN=$(netstat -an 2>/dev/null | grep "142.11.206.73")
if [[ -n "$CONN" ]]; then
    echo -e "${RED}ACTIVE C2 CONNECTION DETECTED:${NC}"
    echo "$CONN"
else
    echo -e "${GREEN}No active connections to C2 server detected.${NC}"
fi

echo ""
echo " --- Checking launchd for persistence entries ---"
PERSIST=$(launchctl list 2>/dev/null | grep -i "act.mond\|sfrclak\|plain-crypto")
if [[ -n "$PERSIST" ]]; then
    echo -e "${RED}SUSPICIOUS LAUNCHD ENTRY FOUND:${NC}"
    echo "$PERSIST"
else
    echo -e "${GREEN}No suspicious launchd persistence entries found.${NC}"
fi

echo "======================================================"
