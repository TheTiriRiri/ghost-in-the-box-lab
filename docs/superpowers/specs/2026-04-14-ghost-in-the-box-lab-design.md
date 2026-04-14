# Ghost-in-the-Box Lab — Design Spec

**Date:** 2026-04-14  
**Status:** Approved  
**Audience:** Advanced university students (cybersecurity)  
**Language:** Polish (participant materials), English (technical names)

---

## Overview

Educational lab teaching how spyware works and how to detect/remove it. Students follow one fictional attacker whose spyware evolves across 3 rounds of escalating OPSEC. Each round has a red team phase (analyze the sample) and a blue team phase (detect, respond, harden).

Everything runs in an isolated Docker network — no outbound connections to the real internet.

---

## Architecture

```
ghost-in-the-box-lab/
  core/
    scenario/              ← briefing.md, attacker-profile.md
    spyware-samples/       ← real spyware source code per round
      round-1/spyware.py
      round-2/spyware.py
      round-3/             ← C code for LD_PRELOAD + Python orchestrator
      shared/              ← exfil_http.py, exfil_dns.py, collector.py
    evidence-data/         ← generated artifacts (pcaps, logs, files)
  generators/
    data/scenario_facts.py ← single source of truth (C2 IP, process names, etc.)
    generate_logs.py
    generate_pcap.py
    generate_artifacts.py
  module-techlab/
    docker-compose.yml
    victim/                ← Ubuntu 24, spyware pre-installed per ROUND
    c2-server/             ← receives exfiltrated data (HTTP/HTTPS/DNS)
    analyst-ws/            ← forensics tools
    dns-server/            ← authoritative DNS for Round 3 tunneling
    rounds/
      round-1-naive/       ← zadania.md + answer key
      round-2-hidden/
      round-3-advanced/
  module-casefile/         ← pre-generated artifacts for classroom analysis
    round-1/
    round-2/
    round-3/
  tests/
  CLAUDE.md
```

---

## Docker Environment

**Services:**

| Service | Profile | Description |
|---------|---------|-------------|
| `victim` | `full` | Ubuntu 24, spyware installed (build arg `ROUND`) |
| `c2-server` | `full` | Receives exfiltrated data |
| `analyst-ws` | `full` | Forensics workstation |
| `dns-server` | `round3` | Authoritative DNS for tunneling (Round 3 only) |

**Usage:**
```bash
ROUND=1 docker compose --profile full up -d
ROUND=2 docker compose --profile full up -d
ROUND=3 docker compose --profile full --profile round3 up -d
```

**Isolated network:** all inter-container traffic stays on `ghost-net` bridge network. No external DNS, no internet access.

---

## Spyware Samples

All samples are real techniques running inside the isolated `victim` container. No host devices are exposed.

### Round 1 — Naïve (`round-1/spyware.py`)

- **Keylogger:** `LD_PRELOAD` hook intercepting `read()` syscalls (no `/dev/input` needed)
- **File harvester:** collects `~/.bash_history`, `~/.ssh/`, recent files from `~/Documents`
- **Screenshot:** `scrot` + `Xvfb` (virtual framebuffer, no physical display)
- **Exfiltration:** HTTP POST to `c2-server:8080` every 60s, plaintext JSON
- **Persistence:** none
- **Evasion:** none — process visible as `python3 spyware.py`

### Round 2 — Hidden (`round-2/spyware.py`)

Same collection logic, plus:
- **Process name:** renamed to `[kworker/u4:2]` via `prctl(PR_SET_NAME)`
- **Exfiltration:** HTTPS to `c2-server:443` (self-signed cert, provided in casefile as "court order" artifact)
- **Persistence:** entry in user `crontab` (`@reboot`)
- **Evasion:** binary stripped, process name mimics kernel thread

### Round 3 — Advanced (`round-3/`)

- **Keylogger + harvester:** same as R2
- **Exfiltration:** DNS tunneling via `dnscat2` — data encoded in subdomains of queries to `dns-server`
- **Process hiding:** `LD_PRELOAD` library (`libhide.so`) that filters own PID from `/proc` directory listings
- **Log wiping:** clears entries from `/var/log/syslog` and `/var/log/auth.log` after each session
- **Persistence:** hook in `~/.bashrc`
- **Anti-forensics:** timestamps modified with `touch -t`

All sample files carry the header:
```python
# GHOST-IN-THE-BOX LAB — EDUCATIONAL SAMPLE
# Round: X | Isolated Docker environment only
# For use in university cybersecurity courses
```

---

## Rounds and Tasks

### Round 1 — Naïve

**Red team phase:**
1. Identify suspicious process (`ps aux`, `top`, `lsof -i`)
2. Trace syscalls (`strace -p <pid>`) — find what it reads and writes
3. Capture HTTP traffic (`tcpdump -A port 8080`) — read exfiltrated data in plaintext
4. Map the sample: what data is collected, how often, where sent

**Blue team phase:**
5. Document IOCs: process name, path, C2 IP and port, data types stolen
6. Kill the process, verify traffic stops
7. Write a one-page incident report

---

### Round 2 — Hidden

**Red team phase:**
1. Find the anomaly: why does a `[kworker]` thread have an open TCP socket? (`ss -tp`, `lsof -i`)
2. Identify the real binary behind the fake process name (`/proc/<pid>/exe`)
3. Decrypt HTTPS traffic using C2 cert from casefile (`ssldump` / Wireshark with cert)
4. Find the persistence mechanism (`crontab -l`, `/etc/cron*`)

**Blue team phase:**
5. Remove persistence (crontab entry)
6. Write a detection script: alert when a non-system process opens port 443
7. Compare with Round 1 — what changed in attacker OPSEC?

---

### Round 3 — Advanced

**Red team phase:**
1. Notice spyware is not visible in `ps` — find it via `/proc` traversal or `auditd`
2. Analyse DNS traffic (`tcpdump port 53`) — detect anomalous subdomain patterns
3. Decode DNS-tunneled data (provided decoder script in analyst-ws tools)
4. Reconstruct what was stolen and when

**Blue team phase:**
5. Incident response: timeline of the attack (when installed, how long active, what stolen)
6. Detect log tampering: compare `syslog` with `auditd` logs
7. Hardening recommendations: DNS firewall rules, `auditd` policy, immutable logs (`chattr +a`)
8. Write a full incident response report

---

## Scenario Constants (single source of truth)

`generators/data/scenario_facts.py`:

```python
RANDOM_SEED = 42

C2_IP = "10.13.37.1"                  # HTTP (R1) and HTTPS (R2) — same container, different ports
DNS_C2_DOMAIN = "update.ghost-pkg.net"  # Round 3 tunneling domain

VICTIM_USERNAME = "analyst"
VICTIM_HOSTNAME = "workstation-042"

EXFIL_INTERVAL_SECONDS = 60
STOLEN_FILES = [".bash_history", ".ssh/id_rsa", "Documents/report-draft.txt"]

ATTACKER_ALIAS = "ghost"
```

---

## Analyst Workstation Tools

Pre-installed in `analyst-ws`:

- `strace`, `ltrace`
- `lsof`, `ss`, `netstat`
- `tcpdump`, Wireshark (CLI: `tshark`)
- `strings`, `file`, `xxd`
- `auditd` + `ausearch`
- `Volatility 3` (memory forensics)
- `dnscat2` client (for decoding Round 3 traffic)
- Jupyter Lab (for report writing)
- Custom tools: `dns-decoder.py`, `timeline-builder.py`

---

## Casefile (module-casefile)

Pre-generated artifacts for classroom analysis (without Docker):

```
module-casefile/
  round-1/
    network-capture.pcap
    process-list.txt
    stolen-data-sample.json
    zadania.md
  round-2/
    network-capture.pcap
    c2-certificate.pem       ← "court order" artifact
    crontab-dump.txt
    zadania.md
  round-3/
    dns-capture.pcap
    auditd-log.txt
    syslog-tampered.txt
    syslog-original.txt      ← for comparison
    zadania.md
```

---

## Testing

`pytest tests/` — deterministic, no Docker required for unit tests:

- `test_scenario_facts.py` — constants defined and consistent
- `test_spyware_samples.py` — samples parse without error, headers present
- `test_casefile_structure.py` — all expected casefile files exist
- `test_techlab_integration.py` — Docker stack tests (skipped if Docker unavailable)
  - Round 1: C2 server receives data within 90s of stack start
  - Round 2: process not visible in standard `ps` output
  - Round 3: DNS queries to tunneling domain detected in capture

---

## Conventions

- Lab materials language: Polish; technical names in English
- Deterministic generation: `RANDOM_SEED = 42`
- All scenario constants in `generators/data/scenario_facts.py`
- Tests: `pytest`, files `test_*.py`
- Docker build arg `ROUND` controls which spyware is installed (1, 2, or 3)
