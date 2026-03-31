# Axios npm Supply Chain Attack — Are You Compromised?

> **Severity: CRITICAL**
> **Date of Attack: March 30–31, 2026 (UTC)**
> **Affected Versions: `axios@1.14.1` and `axios@0.30.4`**
> **Safe Versions: `axios@1.14.0` and `axios@0.30.3`**

---

## What Happened

On March 30, 2026, attackers compromised the npm account of **jasonsaayman** — the primary maintainer of `axios`, one of the most downloaded JavaScript libraries on the planet (100+ million weekly downloads). The attacker changed the account's registered email to an attacker-controlled ProtonMail address (`ifstap@proton.me`) and published two malicious versions of the package.

Rather than modifying axios source code directly (which would have been more obvious), the attacker took a subtler approach: they injected a pre-staged malicious dependency, `plain-crypto-js@4.2.1`, into the new axios releases. This package contained a `postinstall` script that silently deployed a **cross-platform Remote Access Trojan (RAT)** — targeting macOS, Windows, and Linux — the moment any developer ran `npm install`.

**Socket.dev flagged the malicious dependency just 6 minutes after it was published.** The npm security team removed both malicious axios versions approximately 3 hours after they went live. But in those 3 hours, the blast radius across 100 million weekly downloads was enormous.

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 2026-03-30 23:59 | `plain-crypto-js@4.2.1` (malicious) published to npm |
| 2026-03-31 00:05 | Socket.dev flags package as malware (6 min after publish) |
| 2026-03-31 00:21 | `axios@1.14.1` published and tagged `latest` |
| 2026-03-31 00:23 | **First observed infection** — macOS endpoint executes RAT, 89 seconds after publish |
| 2026-03-31 00:58 | First Windows infection observed via `wt.exe` |
| 2026-03-31 01:00 | `axios@0.30.4` published and tagged `legacy` |
| 2026-03-31 03:25 | npm places security hold on `plain-crypto-js` |
| 2026-03-31 03:29 | Both malicious axios versions removed from npm |

---

## What the Malware Does

The malicious `postinstall` script (`setup.js`, 4,209 bytes) used reversed Base64 and XOR encryption (key: `OrDeR_7077`) to obfuscate its payload. Once decrypted and executed, it dropped a platform-specific RAT:

| Platform | Dropper Method | RAT Location |
|---|---|---|
| **macOS** | AppleScript → curl download | `/Library/Caches/com.apple.act.mond` |
| **Windows** | VBScript + PowerShell | `%PROGRAMDATA%\wt.exe` |
| **Linux** | Python script | `/tmp/ld.py` |

Each platform sent a distinct POST body to the same C2 server, which responded with a platform-appropriate binary:
- macOS → `product0`
- Windows → `product1`
- Linux → `product2`

The macOS RAT (a compiled C++ binary) **beaconed to the C2 server every 60 seconds**, capable of:
- Running additional payloads
- Executing arbitrary shell commands
- Enumerating the file system
- Terminating itself on command

**After execution, the malware deleted itself and replaced its own `package.json` with a clean stub** (reporting version `4.2.0`) to evade forensic detection.

### What Data Was at Risk

The RAT targeted developer machines specifically. Credentials accessible at install time included:
- npm tokens
- AWS / GCP / Azure credentials and config files
- SSH private keys (`~/.ssh/`)
- CI/CD secrets and environment variables
- Any credentials stored in shell environment at time of `npm install`

> Huntress observed **at least 135 endpoints across all operating systems** contacting attacker infrastructure during the exposure window.

---

## Indicators of Compromise (IOCs)

### Malicious Package Hashes

| Package | SHA |
|---|---|
| `axios@1.14.1` | `2553649f232204966871cea80a5d0d6adc700ca` |
| `axios@0.30.4` | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| `plain-crypto-js@4.2.1` | `07d889e2dadce6f3910dcbc253317d28ca61c766` |

### Network Indicators

| Indicator | Value |
|---|---|
| C2 Domain | `sfrclak.com` |
| C2 IP | `142.11.206.73` |
| C2 Port | `8000` |
| C2 URL | `http://sfrclak.com:8000/6202033` |

### File Artifacts

| Platform | Path |
|---|---|
| macOS | `/Library/Caches/com.apple.act.mond` |
| Windows | `%PROGRAMDATA%\wt.exe` |
| Linux | `/tmp/ld.py` |

### Attacker npm Accounts

- `nrwise@proton.me` — created `plain-crypto-js`
- `ifstap@proton.me` — attacker-controlled email used to hijack `jasonsaayman`

---

## Detection Scripts

> Standalone scripts are included in this repo:
> - Windows → **`check_axios_windows.ps1`**
> - macOS   → **`check_axios_macos.sh`**
> - Linux   → **`check_axios_linux.sh`**
>
> **Tested:** The Linux script was run on a real system that had executed `npm install` the day after the attack window. No malicious versions or RAT artifacts were detected.

### Quick Check (any platform)

```bash
# Check local project
npm list axios

# Check global installs
npm list -g axios

# BAD:  1.14.1 or 0.30.4
# SAFE: 1.14.0 or 0.30.3
```

### Full System Scan — Windows (PowerShell)

Run it with:
```powershell
powershell.exe -ExecutionPolicy Bypass -File check_axios_windows.ps1
```

### Full System Scan — macOS

```bash
chmod +x check_axios_macos.sh && sudo ./check_axios_macos.sh
```

### Full System Scan — Linux

```bash
chmod +x check_axios_linux.sh && sudo ./check_axios_linux.sh
```

Both scripts scan the full filesystem, check for the RAT artifact on disk, and check for active C2 connections.

### Check for RAT Artifacts (Post-Infection)

```bash
# macOS
ls -la /Library/Caches/com.apple.act.mond 2>/dev/null && echo "RAT FOUND on macOS" || echo "macOS: clean"

# Linux
ls -la /tmp/ld.py 2>/dev/null && echo "RAT FOUND on Linux" || echo "Linux: clean"

# Check C2 network connections (macOS/Linux)
netstat -an | grep "142.11.206.73"
```

```powershell
# Windows — check for wt.exe RAT artifact
$ratPath = "$env:PROGRAMDATA\wt.exe"
if (Test-Path $ratPath) {
    Write-Host "RAT ARTIFACT FOUND: $ratPath" -ForegroundColor Red
    Get-Item $ratPath | Select-Object Name, Length, CreationTime, LastWriteTime
} else {
    Write-Host "Windows: clean (wt.exe not found in ProgramData)" -ForegroundColor Green
}
```

---

## Remediation Steps

### If `npm list` shows a SAFE version (1.14.0 / 0.30.3)

You're clean. Set a preventive measure for future installs:

```bash
npm config set min-release-age 3
```

This delays installation of newly published packages by 3 days — blocking the attack window of versions like these that were live for only ~3 hours.

---

### If `npm list` shows a BAD version (1.14.1 / 0.30.4)

**Treat your system as fully compromised.** Follow these steps in order:

#### Step 1 — Isolate

Disconnect the machine from the internet and your internal network immediately. Do not run anything else on it until you've completed the steps below.

#### Step 2 — Check for RAT Artifacts

Run the artifact checks above for your platform. Document what you find before removing anything.

#### Step 3 — Rotate ALL Credentials

Assume every credential accessible on this machine at the time of `npm install` has been stolen. Rotate immediately:

- [ ] npm tokens (`npm token list`, revoke all, generate new)
- [ ] AWS IAM keys / `~/.aws/credentials`
- [ ] GCP service account keys
- [ ] Azure credentials
- [ ] SSH private keys (`~/.ssh/id_*`) — generate new keypairs, update authorized_keys on all servers
- [ ] GitHub / GitLab tokens
- [ ] `.env` files with secrets
- [ ] CI/CD secrets (GitHub Actions, GitLab CI, Jenkins, etc.)
- [ ] Any API keys in environment variables at install time

#### Step 4 — Remove Malicious Packages

```bash
# Remove RAT artifacts
rm -rf node_modules/plain-crypto-js

# macOS
rm -f /Library/Caches/com.apple.act.mond

# Linux
rm -f /tmp/ld.py
```

```powershell
# Windows
Remove-Item "$env:PROGRAMDATA\wt.exe" -Force -ErrorAction SilentlyContinue
```

#### Step 5 — Downgrade and Reinstall

```bash
# Downgrade to safe version
npm install axios@1.14.0   # modern projects
# OR
npm install axios@0.30.3   # legacy projects

# Reinstall all packages with scripts disabled
rm -rf node_modules
npm install --ignore-scripts
```

#### Step 6 — Audit CI/CD Pipeline Logs

Review all pipeline runs between **2026-03-31 00:21 UTC** and **2026-03-31 03:29 UTC**. Any pipeline that ran `npm install` during this window may have installed the malicious version. Rotate all secrets injected into those pipelines.

#### Step 7 — Block C2 at Network Level

```bash
# macOS/Linux
echo "0.0.0.0 sfrclak.com" | sudo tee -a /etc/hosts
```

```powershell
# Windows
Add-Content "C:\Windows\System32\drivers\etc\hosts" "0.0.0.0 sfrclak.com"
```

#### Step 8 — Consider Full Rebuild

If any secrets were rotated and you found RAT artifacts, **the safest option is a full OS rebuild** from a known-good image. The RAT supported arbitrary command execution — you cannot be certain of the full extent of compromise through forensics alone.

---

## Why This Attack Was So Dangerous

1. **Axios is everywhere.** 100M+ weekly downloads. It ships inside React apps, Node.js backends, CLIs, CI/CD tools, Docker containers — if you write JavaScript, you almost certainly depend on it.

2. **Trusted package, trusted account.** The attack used the real axios maintainer's compromised credentials. No fork, no typosquat — it was the official package at the official npm registry.

3. **Instant propagation.** 89 seconds after `axios@1.14.1` was published, the first machine was infected. CI/CD pipelines with no version pinning auto-update on every run.

4. **Self-deleting.** The malware removed itself after execution and spoofed its own `package.json` — making post-infection forensics significantly harder.

5. **Targets developers specifically.** Developer machines hold the keys to everything: source code, cloud infrastructure, CI/CD pipelines, production deployments. One compromised dev machine can cascade into a full organizational breach.

---

## Prevention Going Forward

```bash
# Delay installs of newly published packages by 3 days
npm config set min-release-age 3

# Always use --ignore-scripts in CI/CD
npm ci --ignore-scripts

# Pin exact versions in package.json (no ^ or ~ ranges)
# Use package-lock.json and commit it

# Consider using Socket.dev to monitor your dependencies
# https://socket.dev
```

---

## Sources

- [StepSecurity: axios Compromised on npm — Malicious Versions Drop Remote Access Trojan](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Huntress: Supply-Chain Compromise of axios npm Package](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package)
- [Socket.dev: Supply Chain Attack on Axios](https://socket.dev/blog/axios-npm-package-compromised)
- [Snyk: Axios npm Package Compromised — Supply Chain Attack Delivers Cross-Platform RAT](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [The Hacker News: Axios Supply Chain Attack Pushes Cross-Platform RAT via Compromised npm Account](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)
- [Wiz: Axios NPM Distribution Compromised in Supply Chain Attack](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack)
- [SANS Institute: Axios NPM Supply Chain Compromise](https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan)
- [GitHub Issue #10604: axios@1.14.1 and axios@0.30.4 are compromised](https://github.com/axios/axios/issues/10604)
- [Vercel: Axios package compromise and remediation steps](https://vercel.com/changelog/axios-package-compromise-and-remediation-steps)
