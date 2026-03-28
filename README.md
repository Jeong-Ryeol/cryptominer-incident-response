# Cryptominer Incident Response Report

> **XMR Cryptominer Intrusion via Unauthenticated Redis - Detection, Containment & Remediation**

**Date:** 2026-03-18
**Responder:** Jeong-Ryeol
**Environment:** Ubuntu 24.04 Home Server (Docker-based microservices)
**Severity:** High
**Status:** Resolved

> **See also: [Incident #2 (2026-03-28)](./INCIDENT-2026-03-28.md)** - Same attacker returned via Next.js Server Action RCE

---

## Executive Summary

On March 18, 2026, a Monero (XMR) cryptominer was detected on a personal Ubuntu home server running multiple Docker-based services. The malware was consuming **384% CPU** across cores and had raised CPU temperatures to **95 degrees celsius**, causing audible fan noise that prompted the investigation.

The attack vector was identified as an **unauthenticated Redis instance** exposed to the public internet on port 6379. The attacker exploited Redis to pivot into the Docker network and deploy a cryptominer binary disguised as `/tmp/npm_update` within a container.

The incident was detected, contained, and remediated within **30 minutes**. No data was exfiltrated, no host credentials were compromised, and all services were restored to normal operation.

---

## Table of Contents

1. [Timeline](#1-timeline)
2. [Detection](#2-detection)
3. [Analysis](#3-analysis)
4. [Attack Vector](#4-attack-vector)
5. [Impact Assessment](#5-impact-assessment)
6. [Containment & Eradication](#6-containment--eradication)
7. [Hardening & Remediation](#7-hardening--remediation)
8. [Post-Incident Verification](#8-post-incident-verification)
9. [Lessons Learned](#9-lessons-learned)
10. [Appendix](#appendix)

---

## 1. Timeline

| Time (KST) | Event |
|-------------|-------|
| Mar 17, ~unknown | Attacker exploits unauthenticated Redis (port 6379) to deploy cryptominer |
| Mar 18, 17:26 | Abnormal fan noise detected; investigation begins |
| Mar 18, 17:26 | `ps aux --sort=-%cpu` reveals `/tmp/npm_update` consuming 384% CPU |
| Mar 18, 17:27 | Process identified as XMR miner connecting to mining pool `31.220.80.26:3333` |
| Mar 18, 17:27 | CPU temperature confirmed at **95 degrees celsius** (critical threshold) |
| Mar 18, 17:28 | Malicious process killed (`kill -9 2247817`) |
| Mar 18, 17:28 | Binary removed (`rm -f /tmp/npm_update`) |
| Mar 18, 17:29 | Attack vector identified: unauthenticated Redis exposed on 0.0.0.0:6379 |
| Mar 18, 17:30 | iptables rules applied to block external access to Redis, MySQL, PostgreSQL, Portainer |
| Mar 18, 17:31 | Parent process traced to arkmarket Docker container (`next-server`, PID 1660432) |
| Mar 18, 17:33 | Container restarted to clear zombie processes |
| Mar 18, 17:34 | Redis reconfigured with password authentication + localhost binding |
| Mar 18, 17:35 | iptables rules persisted with `iptables-persistent` |
| Mar 18, 17:40 | Full security audit completed; server declared clean |
| Mar 18, 17:40 | CPU temperature dropped to **74 degrees celsius** (normal) |

---

## 2. Detection

### Initial Indicator
Abnormal fan noise from the home server prompted a system resource check.

### Discovery Command
```bash
ps aux --sort=-%cpu | head -12
```

### Finding
```
USER   PID     %CPU %MEM  COMMAND
1001   2247817 384  15.0  /tmp/npm_update -a rx/0 -o 31.220.80.26:3333
                          -u 46RS6nKCGwRhndfpksLJomXuo4dZ7N9Afj3P1vHZxnwoQhHLw4yEzcocy
                          1XseBdAvvb3Avx2o5PDKND8hdcRumi63ix8Ers.3000_ORDU_XMR -p x --background
```

### Key Indicators of Compromise (IOC)

| Indicator | Value |
|-----------|-------|
| **Malware Path** | `/tmp/npm_update` |
| **Process Type** | XMR (Monero) cryptominer |
| **Mining Pool** | `31.220.80.26:3333` |
| **Mining Algorithm** | RandomX (`rx/0`) |
| **Wallet Address** | `46RS6nKCGwRhndfpksLJomXuo4dZ7N9Afj3P1vHZxnwoQhHLw4yEzcocy1XseBdAvvb3Avx2o5PDKND8hdcRumi63ix8Ers` |
| **Worker ID** | `3000_ORDU_XMR` |
| **Running As** | UID 1001 (container user `nextjs`) |
| **CPU Usage** | 384% (multi-core) |
| **CPU Temperature** | 95 degrees C (critical) |

---

## 3. Analysis

### Process Hierarchy
```
PID 1660432 (next-server - arkmarket container)
  └── PID 2247815 (/tmp/npm_update)
      └── PID 2247817 (/tmp/npm_update - main miner process)
```

The miner's parent process was the Next.js server running inside the `arkmarket` Docker container, confirming the attack was **container-scoped**.

### Attack Chain
```
Internet
  → Port 6379 (Redis, no auth, bound to 0.0.0.0)
  → Docker bridge network (shared with arkmarket container)
  → Redis SLAVEOF / MODULE LOAD or container-level exploit
  → Binary dropped as /tmp/npm_update
  → Cryptominer executed, connecting to external mining pool
```

---

## 4. Attack Vector

### Root Cause: Unauthenticated Redis Exposed to Internet

The Redis container was configured with:
```yaml
# VULNERABLE configuration
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"          # Bound to 0.0.0.0 (all interfaces)
    command: redis-server --appendonly yes  # NO password
```

This is a **well-known attack vector** (CVE references: Redis unauthorized access). Attackers continuously scan the internet for open Redis instances and exploit them to:
1. Write crontab entries via `CONFIG SET dir/dbfilename`
2. Write SSH authorized_keys
3. Load malicious Redis modules
4. Pivot through Docker networks to compromise containers

### Other Exposed Services Found

| Service | Port | Binding | Risk |
|---------|------|---------|------|
| **Redis** | 6379 | 0.0.0.0 | **CRITICAL** - No authentication |
| MySQL | 3306 | 0.0.0.0 | HIGH - Password protected but exposed |
| PostgreSQL | 5432 | 0.0.0.0 | HIGH - Password protected but exposed |
| Portainer | 9000 | 0.0.0.0 | MEDIUM - Web UI exposed |

---

## 5. Impact Assessment

### What Was Compromised
| Asset | Status | Details |
|-------|--------|---------|
| arkmarket container | Compromised | Miner running inside container |
| CPU resources | Abused | 384% CPU for ~24 hours |
| Electricity | Wasted | Extended high-power operation |

### What Was NOT Compromised
| Asset | Status | Evidence |
|-------|--------|----------|
| Host filesystem | Safe | Container mount limited to `/app/data` only |
| SSH credentials | Safe | No `Accepted password` entries in auth.log |
| Database passwords | Safe | Stored on host, not in container |
| Server sudo password | Safe | Not accessible from container |
| Other containers | Safe | No lateral movement detected |
| User data | Safe | No data exfiltration observed |
| Credential files | Safe | `credentials.md` on host filesystem, inaccessible from container |

### Verification of No Host Compromise
```bash
# SSH login check - only legitimate logins from local IP
$ grep "Accepted" /var/log/auth.log | tail -5
Accepted publickey for wonryeol5336-server from 192.168.50.165  # Local machine only

# No password-based SSH logins
$ grep "Accepted password" /var/log/auth.log
(empty - password auth is disabled)

# Crontab clean
$ crontab -l
0 * * * * ~/backup.sh                    # Legitimate
0 * * * * .../cron_update.sh              # Legitimate

# No suspicious files in temp directories
$ find /tmp /var/tmp /dev/shm -type f -executable
(empty)

# No unauthorized SUID binaries
$ find / -perm -4000 -type f
(all standard system binaries)
```

---

## 6. Containment & Eradication

### Step 1: Kill Malicious Process
```bash
sudo kill -9 2247817
```

### Step 2: Remove Malware Binary
```bash
sudo rm -f /tmp/npm_update
```

### Step 3: Identify Parent Process
```bash
cat /proc/2247815/status | grep PPid
# PPid: 1660432

ps aux | grep 1660432
# next-server (arkmarket container)
```

### Step 4: Clear Zombie Processes
```bash
cd ~/docker/arkmarket && docker compose restart
# Confirmed: npm_update processes gone
```

---

## 7. Hardening & Remediation

### 7.1 Network-Level Firewall (iptables)

Applied rules to restrict database and management ports to local network only:

```bash
# Redis - internal only
sudo iptables -A INPUT -p tcp --dport 6379 -s 192.168.50.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 6379 -j DROP

# MySQL - internal only
sudo iptables -A INPUT -p tcp --dport 3306 -s 192.168.50.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 3306 -j DROP

# PostgreSQL - internal only
sudo iptables -A INPUT -p tcp --dport 5432 -s 192.168.50.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5432 -j DROP

# Portainer - internal only
sudo iptables -A INPUT -p tcp --dport 9000 -s 192.168.50.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9000 -j DROP

# Persist rules across reboots
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

### 7.2 Redis Authentication & Localhost Binding

```yaml
# HARDENED configuration
services:
  redis:
    image: redis:7-alpine
    ports:
      - "127.0.0.1:6379:6379"    # Localhost only
    command: redis-server --appendonly yes --requirepass <password>
```

### 7.3 Security Posture Before vs After

| Control | Before | After |
|---------|--------|-------|
| Redis authentication | None | Password required |
| Redis binding | 0.0.0.0 (all) | 127.0.0.1 (localhost) |
| Redis firewall | None | iptables DROP from external |
| MySQL firewall | None | iptables DROP from external |
| PostgreSQL firewall | None | iptables DROP from external |
| Portainer firewall | None | iptables DROP from external |
| Firewall persistence | N/A | iptables-persistent installed |

---

## 8. Post-Incident Verification

### Full Security Audit Results (Post-Remediation)

```
Suspicious processes:          CLEAN - No unauthorized processes
Crontab (all users):           CLEAN - Only legitimate jobs
Temp directory executables:    CLEAN - No files found
Recently modified system bins: CLEAN - Only snap updates
SUID binaries:                 CLEAN - All standard
Docker host networking:        CLEAN - No containers use host network
SSH authorized_keys:           CLEAN - Only owner's key
User accounts:                 CLEAN - Only wonryeol5336-server (UID 1000)
Systemd services:              CLEAN - Only pm2 service (legitimate)
Redis keys:                    CLEAN - Only backup keys
```

### System Health After Remediation

| Metric | During Attack | After Remediation |
|--------|--------------|-------------------|
| CPU Usage | 384% (miner) | <2% (normal) |
| CPU Temperature | 95 degrees C | 74 degrees C |
| Load Average | 6.55 | 0.11 |
| Memory Usage | 6.1 GB | Normal |
| Fan Noise | Loud | Normal |

---

## 9. Lessons Learned

### What Went Wrong
1. **Redis was deployed without authentication** - Default Redis has no password, and the Docker port mapping exposed it to the internet
2. **Multiple database ports were publicly accessible** - MySQL (3306) and PostgreSQL (5432) were also bound to 0.0.0.0
3. **No network-level firewall was configured** - iptables had no rules to restrict incoming traffic

### What Went Right
1. **SSH was properly secured** - Key-only authentication prevented SSH-based intrusion
2. **Docker containerization limited blast radius** - The attacker was confined to the container and could not access host credentials or filesystem
3. **Quick detection** - Physical indicator (fan noise) led to immediate investigation
4. **Systematic response** - Methodical process: detect, identify, kill, trace, contain, harden, verify
5. **No sensitive data exposure** - Credentials stored on host filesystem were inaccessible from the compromised container

### Recommendations for Future Prevention
1. **Never expose database ports to 0.0.0.0** - Always bind to `127.0.0.1` or use Docker internal networks
2. **Always require authentication** - Even for "internal" services
3. **Implement default-deny firewall policy** - Only allow explicitly needed ports (22, 80, 443)
4. **Regular security audits** - Monthly check for open ports and running processes
5. **Docker network isolation** - Use separate Docker networks per service group instead of exposing ports on the host
6. **Monitoring & alerting** - Set up CPU/temperature alerts (e.g., via Grafana) to detect anomalies faster

---

## Appendix

### A. Infrastructure Overview

```
Ubuntu 24.04 Home Server
├── Docker Services
│   ├── arkmarket (Next.js marketplace)       Port 3003
│   ├── ainote (Note application)             Port 3100
│   ├── raid-together (Discord bot)           Port 3000
│   ├── bitcoin-prediction (Streamlit)        Port 8501
│   ├── jenkins (CI/CD)                       Internal
│   ├── mumuk (Backend + Monitoring stack)    Internal
│   ├── redis                                 Port 6379 [EXPLOITED]
│   ├── mysql                                 Port 3306
│   ├── postgresql                            Port 5432
│   └── portainer                             Port 9000
├── Nginx Reverse Proxy (SSL termination)
│   ├── wonryeol-ai-note.kro.kr → :3100
│   └── clotizen-mart.kro.kr → :3003
└── ASUS TUF-AX6000 Router (DDNS: wonryeol.asuscomm.com)
```

### B. Attacker Information

| Field | Value |
|-------|-------|
| Mining Pool IP | 31.220.80.26 |
| Mining Pool Port | 3333 |
| Cryptocurrency | Monero (XMR) |
| Algorithm | RandomX (rx/0) |
| Wallet | `46RS6nKCGwRhndfpksLJomXuo4dZ7N9Afj3P1vHZxnwoQhHLw4yEzcocy1XseBdAvvb3Avx2o5PDKND8hdcRumi63ix8Ers` |
| Worker ID | `3000_ORDU_XMR` |
| Binary Name | `/tmp/npm_update` (disguised as npm) |

### C. Tools Used in Response

| Tool | Purpose |
|------|---------|
| `ps aux` | Process identification |
| `kill -9` | Process termination |
| `/proc/[pid]/status` | Parent process tracing |
| `docker inspect` | Container analysis |
| `docker stats` | Resource monitoring |
| `ss -tlnp` | Open port enumeration |
| `iptables` | Firewall configuration |
| `auth.log` | SSH audit trail |
| `find` | Filesystem scan for malware |
| `thermal_zone` | CPU temperature monitoring |

---

**Report prepared by:** Jeong-Ryeol
**Date:** 2026-03-18
**Classification:** Public (sanitized - credentials redacted)
