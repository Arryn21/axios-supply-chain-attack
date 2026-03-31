# Axios npm Supply Chain Attack — Detection & Remediation

On **March 30–31, 2026**, two malicious versions of the `axios` npm package were published by an attacker who compromised the primary maintainer's account. The malicious versions dropped a cross-platform Remote Access Trojan (RAT) on any machine that ran `npm install` during the ~3 hour exposure window.

**Affected versions:** `axios@1.14.1` and `axios@0.30.4`
**Safe versions:** `axios@1.14.0` and `axios@0.30.3`

---

## Quick Check

```bash
npm list axios
npm list -g axios
```

If you see `1.14.1` or `0.30.4` — your system is compromised. See the full article for remediation steps.

---

## Detection Scripts

Run the script for your platform to scan your entire system:

| Platform | Script | Usage |
|---|---|---|
| Windows | `check_axios_windows.ps1` | `powershell.exe -ExecutionPolicy Bypass -File check_axios_windows.ps1` |
| macOS | `check_axios_macos.sh` | `chmod +x check_axios_macos.sh && sudo ./check_axios_macos.sh` |
| Linux | `check_axios_linux.sh` | `chmod +x check_axios_linux.sh && sudo ./check_axios_linux.sh` |

Each script:
- Scans the full filesystem for axios installations
- Flags malicious versions in red
- Checks for RAT artifacts on disk
- Checks for active connections to the C2 server

---

## Full Article

See **[axios-supply-chain-attack.md](./axios-supply-chain-attack.md)** for:
- Full timeline of the attack
- What the RAT does on each platform
- Indicators of Compromise (IOCs) — hashes, C2 domain/IP, file artifacts
- Step-by-step remediation
- Prevention going forward

---

## Prevention (set this now)

```bash
npm config set min-release-age 3
```

Delays installs of newly published packages by 3 days — would have blocked this attack entirely.
