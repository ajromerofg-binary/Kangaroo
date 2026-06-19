[README.md](https://github.com/user-attachments/files/29124620/README.md)
# 🦘 Kangaroo

> **Automated network pivoting via Metasploit/Meterpreter — recon, route, SOCKS, done.**

![Bash](https://img.shields.io/badge/language-Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![Version](https://img.shields.io/badge/version-2.0-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square)

Kangaroo automates the full pivoting workflow once you have a Meterpreter session on a compromised host. It scans the internal network through the session, lets you pick a target interactively, then sets up Autoroute + a SOCKS proxy and generates a ready-to-run Metasploit resource script — all in one command.

---

## How it works

```
Phase 0 — RECON    Temporary Autoroute → TCP portscan of internal subnet
                   → Interactive host/target selection
Phase 1 — PIVOT    Permanent Autoroute through the compromised session
Phase 2 — SOCKS    SOCKS4a/5 server on localhost (for proxychains)
Phase 3 — OUTPUT   .rc resource script + /etc/proxychains4.conf updated
```

### Workflow diagram

```
Attacker machine
      │
      │  Meterpreter session (e.g. EternalBlue / WinRM / RCE)
      ▼
 [Pivot host]  ──────────────────────────────────► Internal network
 192.168.1.50                                      192.168.112.0/24
      │                         Autoroute          ┌──────────────┐
      │◄── kangaroo.sh ────────────────────────────│ 192.168.112.4│
      │    + SOCKS5 :1080                          │  (target)    │
      │                                            └──────────────┘
      │
 proxychains nmap / curl / sqlmap / ssh ...
```

---

## Requirements

| Dependency | Purpose |
|---|---|
| `bash` ≥ 4.0 | Associative arrays (`declare -A`) |
| `metasploit-framework` | `msfconsole`, Autoroute, SOCKS proxy, TCP scanner |
| `proxychains4` | Tunnelling traffic through the SOCKS proxy |
| `python3` | Updating `/etc/proxychains4.conf` |

> Kangaroo is designed for **Kali Linux** and **Parrot OS**. All dependencies come pre-installed.

---

## Installation

```bash
git clone https://github.com/ajromerofg-binary/kangaroo.git
cd kangaroo
chmod +x kangaroo.sh
```

---

## Usage

```
./kangaroo.sh -s SESSION_ID -n PIVOT_NETWORK [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-s SESSION_ID` | Meterpreter session ID **(required)** | — |
| `-n PIVOT_NETWORK` | Internal network in CIDR notation **(required)** | — |
| `-p SOCKS_PORT` | Local SOCKS proxy port | `1080` |
| `-v SOCKS_VERSION` | SOCKS version: `4a` or `5` | `5` |
| `-o OUTPUT_RC` | Output resource script path | `kangaroo_<date>.rc` |
| `-P PROXYCHAINS_CFG` | Path to proxychains config | `/etc/proxychains4.conf` |
| `-t TARGET_PORTS` | Comma-separated ports to scan | `21,22,23,25,80,443,445,`<br>`3306,3389,5432,5900,6379,8080,8443` |
| `-T SCAN_THREADS` | Portscan threads (1–50) | `20` |
| `-S` | Skip recon phase, pivot directly | — |
| `-x` | Launch `msfconsole` with the `.rc` automatically | — |
| `-h` | Show help | — |

---

## Examples

### Full flow — recon + pivot + launch msfconsole
```bash
./kangaroo.sh -s 1 -n 192.168.112.0/24 -x
```

### Custom ports and threads, SOCKS4a
```bash
./kangaroo.sh -s 1 -n 10.10.10.0/24 -t 22,80,443,8080 -T 30 -v 4a -x
```

### Skip recon (you already know the target network)
```bash
./kangaroo.sh -s 2 -n 172.16.0.0/24 -S -p 9050
msfconsole -r kangaroo_20250619_143200.rc
```

### Custom proxychains config path
```bash
./kangaroo.sh -s 1 -n 192.168.50.0/24 -P /etc/proxychains.conf -x
```

---

## Interactive recon output

During Phase 0, Kangaroo scans the internal subnet and displays discovered hosts:

```
[*] FASE 0 — Reconocimiento de red interna
[+] Lanzando recon...

  Hosts descubiertos en 192.168.112.0/24:
  ─────────────────────────────────────────
[>] [1] 192.168.112.4   →  puertos: 22, 80, 443
[>] [2] 192.168.112.10  →  puertos: 3389
[>] [3] 192.168.112.25  →  puertos: 21, 22
  ─────────────────────────────────────────

  Selecciona el target para el pivoting:
  [0] Todos los hosts

  Opción [0-3]: 1

[+] Target seleccionado: 192.168.112.4
```

The selected target is embedded in the generated `.rc` with ready-to-use examples.

---

## Generated resource script

Kangaroo produces a `kangaroo_<date>.rc` that you can inspect, modify, or run directly:

```
# Kangaroo v2.0 — Resource Script
# Session : 1  |  Network : 192.168.112.0/24  |  SOCKS5 : 1080
# Target  : 192.168.112.4

use post/multi/manage/autoroute    → adds the internal route
use post/multi/manage/autoroute    → prints active routes
use auxiliary/server/socks_proxy   → starts SOCKS5 on 127.0.0.1:1080
jobs -l                            → confirms the proxy job is running
```

---

## Post-pivot usage

Once the pivot is active, route all traffic through proxychains:

```bash
# Network scan
proxychains nmap -sT -Pn -p 22,80,443 192.168.112.4

# Web enumeration
proxychains curl -v http://192.168.112.4
proxychains gobuster dir -u http://192.168.112.4 -w /usr/share/wordlists/dirb/common.txt

# Exploitation
proxychains ssh user@192.168.112.4
proxychains sqlmap -u "http://192.168.112.4/login.php"

# Direct port forward (no proxychains needed)
# Inside msfconsole:
sessions -i 1
portfwd add -l 8080 -p 80 -r 192.168.112.4
# Then locally:
curl http://127.0.0.1:8080
```

---

## Cleanup

```bash
# Inside msfconsole after you're done:
msf > route flush
msf > jobs -k <JOB_ID>
```

---

## Input validation

Kangaroo validates all inputs before doing anything:

| Check | Rule |
|-------|------|
| `SESSION_ID` | Must be a positive integer |
| `PIVOT_NETWORK` | Valid CIDR — octets 0–255, mask 1–32 |
| `SOCKS_PORT` | Integer between 1–65535 |
| `SOCKS_VERSION` | Must be `4a` or `5` |
| `SCAN_THREADS` | Integer between 1–50 |
| `OUTPUT_RC` directory | Must exist and be writable |

---

## Legal disclaimer

Kangaroo is intended for **authorised penetration testing and educational purposes only**. Use it exclusively on systems and networks you own or have explicit written permission to test. The author is not responsible for any misuse or damage caused by this tool.

---

## Author

**Tony_ZeroD** · [ajromerofg-binary](https://github.com/ajromerofg-binary) · [Portfolio](https://ajromerofg-binary.github.io)

*Full-stack developer & cybersecurity professional — Zaragoza, Spain*
