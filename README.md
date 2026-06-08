# 🛡️ Incident Report: XMR Cryptomining Trojan — Detection, Analysis & Remediation

> **Type:** Real-World Malware Incident Response  
> **Platform:** Windows 11 (ASUS Vivobook)  
> **Malware Family:** `Trojan.MalPack.Generic` (XMR Miner)  
> **Status:** ✅ Fully Remediated

---

## 📋 Table of Contents

- [Executive Summary](#executive-summary)
- [Timeline](#timeline)
- [Initial Detection](#initial-detection)
- [Investigation](#investigation)
- [Malware Behavior](#malware-behavior)
- [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
- [Remediation](#remediation)
- [Lessons Learned](#lessons-learned)
- [Prevention Tips](#prevention-tips)

---

## 🔍 Executive Summary

A Windows 11 laptop was found to be infected with a **Monero (XMR) cryptocurrency mining trojan** that had been active for approximately **21 months** (since August 2024). The malware disguised itself as a legitimate Windows process (`dialer.exe`) and used a dropper (`nugxeveofufy.exe`) stored in a randomly named folder under `C:\ProgramData\` to maintain persistence.

The infection caused **severe overheating**, repeated **Blue Screen of Death (BSOD)** events, and significant **performance degradation** — all of which went undiagnosed until Malwarebytes flagged an outbound connection to `pool.hashvault.pro`, a known Monero mining pool.

The malware was fully quarantined by Malwarebytes during the investigation, and a **Windows Cloud Reset** was performed to completely eradicate all remnants.

---

## ⏱️ Timeline

| Date | Event |
|------|-------|
| ~August 2024 | Malware first installed — `idle.exe` dropper created |
| January 2026 | User notices unusual overheating during winter months |
| June 22, 2025 | Malware reinstalls itself — second `idle.exe` created |
| June 7, 2026 | Malwarebytes flags outbound connection to `pool.hashvault.pro` |
| June 7, 2026 | Investigation begins — malicious files identified and deleted |
| June 7, 2026 | Dropper `nugxeveofufy.exe` detected and quarantined (201 times) |
| June 7–8, 2026 | Windows Cloud Reset performed |
| June 8, 2026 | System verified clean — zero threats detected |

---

## 🚨 Initial Detection

The investigation began when **Malwarebytes Real-Time Protection** displayed the following alert:

```
We blocked a connection to a potentially risky site

Domain : pool.hashvault.pro
App    : Microsoft® Windows® Operating System — dialer.exe
```

`pool.hashvault.pro` is a publicly known **Monero mining pool**. No legitimate Windows process has any reason to connect to this domain, making this an immediate red flag.

A search for `dialer.exe` in Task Manager showed **no active process** — indicating the malware had already executed and terminated, or was hiding itself from standard process enumeration.

---

## 🔬 Investigation

### Step 1 — AppData Scan

A scan of `%appdata%` for executable files revealed two suspicious entries:

```
C:\Users\[User]\AppData\Roaming\Microsoft\Installer\{1BA18593-41AB-434B-B31F-EEC8BBA9612A}\idle.exe
C:\Users\[User]\AppData\Roaming\Microsoft\Installer\{AC3F660A-8ABD-4E2A-9C2E-D9C1F734D7C9}\idle.exe
```

**Red flags:**
- Both files named `idle.exe` — mimicking Python's IDLE editor icon file
- Stored inside randomly named GUID folders under `Microsoft\Installer`
- Both identical in size: **57,746 bytes**
- First created: **August 31, 2024** (21 months prior)
- Second created: **June 22, 2025** (malware reinstalled itself)

### Step 2 — VirusTotal Analysis

The file was uploaded to VirusTotal. The hash matched `idle.ico` — a legitimate Python Software Foundation icon file (0/61 detections). However, the **Relations tab** revealed files distributed alongside it scoring **64–70/72 detections**, confirming the sample was part of a malicious bundle.

FileScan.IO verdict: **SUSPICIOUS — Confidence 100/100 — Tag: masquerade**

### Step 3 — Dropper Discovery

Malwarebytes Real-Time Protection began quarantining a new file repeatedly:

```
Trojan.MalPack.Generic
C:\ProgramData\xzdawqyqqvdn\nugxeveofufy.exe
```

The file was being **regenerated every 60 seconds**, indicating an active parent process maintaining persistence.

### Step 4 — Network Analysis

Malwarebytes web protection logs showed repeated outbound connections:

```
Domain  : pool.hashvault.pro
IPs     : 107.155.109.94, 144.168.36.74, 185.84.98.5, 185.84.98.85
Port    : 443 (HTTPS)
Process : C:\Windows\System32\dialer.exe
Type    : Outbound
```

All connections were **successfully blocked** by Malwarebytes — meaning no actual mining was accomplished during the protection window.

### Step 5 — Admin Command Interference

Standard admin CMD commands were returning **"Access is denied"** errors, including:

```
schtasks /query    → Access is denied
reg query HKCU\... → Access is denied
tasklist /v        → Access is denied
sc query           → Access is denied
```

This indicated the malware had **kernel-level or elevated privileges**, actively interfering with system administration commands.

### Step 6 — Malwarebytes Full Scan Results

```
Scan Type        : Threat Scan (Rootkits Enabled)
Objects Scanned  : 252,663
Threats Detected : 0
```

The rootkit scan returned clean — the malware was successfully hiding from the scanner while simultaneously blocking admin tools. This confirmed the infection was beyond manual remediation.

---

## 🦠 Malware Behavior

### What it did:

| Behavior | Detail |
|----------|--------|
| **Persistence** | Dropper in `C:\ProgramData\[random]\` regenerated every 60 seconds |
| **Masquerading** | Used `dialer.exe` name (legitimate Windows process) as cover |
| **Mimicry** | `idle.exe` mimicked Python IDLE icon file |
| **Mining** | Connected to `pool.hashvault.pro` to mine Monero (XMR) |
| **Privilege escalation** | Blocked admin CMD commands, interfered with system tools |
| **Self-healing** | Reinstalled itself at least once (June 2025) |
| **Evasion** | Hid from rootkit scans and Task Manager |

### Impact on system:

- **Overheating** — CPU/GPU running at near 100% continuously for 21 months
- **BSODs** — `CRITICAL_PROCESS_DIED`, `WIN32K_POWER_WATCHDOG_TIMEOUT` caused by kernel-level interference and thermal issues
- **Performance degradation** — system resources constantly consumed by miner
- **Battery drain** — accelerated battery discharge due to constant high load
- **Thermal paste degradation** — prolonged extreme heat accelerated wear

### What it did NOT do:

- ❌ No credential theft detected
- ❌ No unauthorized account access (Gmail, GitHub, Discord all verified clean)
- ❌ No ransomware behavior
- ❌ No data exfiltration observed

---

## 🔴 Indicators of Compromise (IOCs)

### Files

| File | Path | SHA-256 | MD5 |
|------|------|---------|-----|
| `nugxeveofufy.exe` | `C:\ProgramData\xzdawqyqqvdn\` | `5A1B76C76FFC916698A8AC41DE94849D7152DBE58302049BD923C22ADBAC7D27` | — |
| `idle.exe` (instance 1) | `%AppData%\Microsoft\Installer\{1BA18593-41AB-434B-B31F-EEC8BBA9612A}\` | — | `18fe30f810364bd33c396c9ee428f4b4` |
| `idle.exe` (instance 2) | `%AppData%\Microsoft\Installer\{AC3F660A-8ABD-4E2A-9C2E-D9C1F734D7C9}\` | — | `18fe30f810364bd33c396c9ee428f4b4` |

### Network

| Indicator | Type | Description |
|-----------|------|-------------|
| `pool.hashvault.pro` | Domain | Monero mining pool |
| `107.155.109.94` | IP | Mining pool endpoint |
| `144.168.36.74` | IP | Mining pool endpoint |
| `185.84.98.5` | IP | Mining pool endpoint |
| `185.84.98.85` | IP | Mining pool endpoint |
| Port `443` | Port | Outbound HTTPS used to blend with normal traffic |

### File System

| Indicator | Description |
|-----------|-------------|
| `C:\ProgramData\xzdawqyqqvdn\` | Randomly named dropper folder |
| `%AppData%\Microsoft\Installer\{GUID}\idle.exe` | Miner disguised as Python IDLE icon |

### Registry / Process

| Indicator | Description |
|-----------|-------------|
| `dialer.exe` (non-Microsoft) | Malicious process masquerading as Windows Phone Dialer |
| Admin CMD commands returning "Access is denied" | Sign of elevated malware privileges |

---

## 🛠️ Remediation

### What was tried first:

1. Manual deletion of `idle.exe` files ✅
2. Manual deletion of `xzdawqyqqvdn` folder ✅ (kept recreating)
3. Malwarebytes Threat Scan (rootkits disabled) — 1 threat found, quarantined
4. Malwarebytes Threat Scan (rootkits enabled) — false clean result
5. Admin CMD cleanup commands — blocked by malware

### Final solution — Windows Cloud Reset:

Since the malware had kernel-level access and was actively blocking remediation:

```
Settings → System → Recovery → Reset this PC
→ Keep my files
→ Cloud Download (fresh Windows from Microsoft servers)
```

**Why Cloud Reset specifically:**
- Downloads a **verified fresh copy of Windows** directly from Microsoft
- Completely replaces `C:\Windows\System32\` — overwrites the malicious `dialer.exe`
- Wipes `C:\ProgramData\` — removes dropper folder
- Clears all scheduled tasks and services
- Malware cannot interfere with the recovery environment

### Post-reset verification:

```cmd
# Check 1 — ProgramData clean
dir C:\ProgramData\  → No xzdawqyqqvdn folder ✅

# Check 2 — dialer.exe legitimate
Properties → Publisher: Microsoft Corporation ✅
            Version: 10.0.26100.5074 ✅

# Check 3 — No mining connections
netstat -b | findstr /i "hash|pool|xzda" → No results ✅
```

**Result: 100% clean system confirmed ✅**

---

## 📚 Lessons Learned

1. **Unexplained overheating is a serious signal** — especially during low-load tasks or in cold weather. Don't ignore it.

2. **Malwarebytes web protection was the hero** — it blocked 231 outbound mining connections before the infection was even noticed.

3. **"Access is denied" in Admin CMD is a red flag** — legitimate Windows processes don't block administrator commands.

4. **Rootkit scans can return false negatives** — a clean rootkit scan result doesn't always mean the system is clean.

5. **Cloud Reset is the nuclear option that always works** — when malware has kernel-level access, no manual removal is reliable. Reset wins.

6. **Cracked software is never free** — the real cost is your CPU, your privacy, and your system's integrity.

---

## 🔒 Prevention Tips

| Practice | Why it matters |
|----------|---------------|
| Only download from official sources | Cracked software is the #1 infection vector |
| Keep Windows Defender ON always | Catches most threats before they execute |
| Use Malwarebytes for monthly manual scans | Second-opinion scanner catches what Defender misses |
| Never install two real-time AVs simultaneously | They conflict and create system instability |
| Monitor CPU usage regularly | Sudden high CPU at idle = possible miner |
| Check Task Manager if device overheats unexpectedly | Identify rogue processes early |
| Enable 2FA on all important accounts | Reduces impact if credentials are ever stolen |
| Use a password manager (Bitwarden) | Avoids reusing passwords across services |

---

## 🧰 Tools Used

| Tool | Purpose |
|------|---------|
| Malwarebytes | Real-time protection, threat detection, quarantine |
| VirusTotal | File hash analysis and malware family identification |
| Windows Task Manager | Process enumeration |
| Task Scheduler (`taskschd.msc`) | Persistence mechanism analysis |
| Admin CMD | File system forensics, network analysis |
| `netstat -b` | Active network connection monitoring |
| `dir /s /b` | Recursive file system scanning |
| Windows Security | Defender Offline Scan attempt |
| FileScan.IO | Behavioral analysis — verdict: masquerade |

---

## 📎 References

- [Malwarebytes — Trojan.MalPack.Generic](https://www.malwarebytes.com)
- [HashVault Mining Pool](https://hashvault.pro) — confirmed Monero mining pool
- [VirusTotal Report](https://www.virustotal.com/gui/file/7f13eeb5dca39d05e24b9eb069c6dcb2748633822d67288a8bf8b7e21cdddf55)
- [Free Download Manager Supply Chain Attack — Kaspersky Research](https://securelist.com)

---

*This report documents a real incident response case. All IOCs are published for educational and defensive purposes only.*

