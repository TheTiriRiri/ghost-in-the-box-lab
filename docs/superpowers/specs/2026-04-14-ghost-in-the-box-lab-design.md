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

- **Keylogger:** pure-Python loop reading X11 events via `Xlib` (from `Xvfb`); fallback branch using `pynput` — no LD_PRELOAD, no syscall hooks
- **File harvester:** collects `~/.bash_history`, `~/.ssh/`, recent files from `~/Documents` using plain `open()`/`shutil` — no obfuscation
- **Screenshot:** `scrot` + `Xvfb` (virtual framebuffer, no physical display)
- **Exfiltration:** HTTP POST to `c2-server:8080` every 60s, plaintext JSON, hardcoded URL in source
- **Persistence:** none
- **Evasion:** none — process visible as `python3 spyware.py`, strings readable, no packing

> Rationale: R1 must be genuinely naïve so the OPSEC gradient across rounds is monotonic. LD_PRELOAD first appears in R3 (process hiding), never earlier.

**MITRE ATT&CK:** T1056.001 (Keylogging), T1005 (Data from Local System), T1113 (Screen Capture), T1071.001 (Web Protocols), T1041 (Exfiltration Over C2 Channel)

### Round 2 — Masquerading (`round-2/spyware.py`)

Same collection logic, plus:
- **Process name:** renamed to `[kworker/u4:2]` via `prctl(PR_SET_NAME)` + `argv[0]` overwrite — visible in `ps` as a kernel-thread lookalike, but `/proc/<pid>/exe`, `ss -tp`, `lsof -i` still expose it (this IS the detection pivot)
- **Exfiltration:** HTTPS to `c2-server:443`, self-signed cert pinned in client
- **Persistence:** entry in user `crontab` (`@reboot`)
- **Evasion:** binary stripped, process name mimics kernel thread

> Renamed from "Hidden" to "Masquerading" — the process is *disguised*, not hidden. True hiding only appears in R3.

**TLS decryption in casefile/lab:**
Decrypting HTTPS requires the **server private key**, not just the cert. Two paths are provided so students see both:
1. **Casefile (module-casefile/round-2):** ships `c2-server-key.pem` (private key) framed as "seized under court order after C2 takedown" — students load it into Wireshark (`Edit → Preferences → Protocols → TLS → RSA keys list`) to decrypt the pcap. Only works because the cipher suite is pinned to RSA key exchange (no PFS) — an intentional attacker OPSEC mistake.
2. **Techlab (module-techlab, live):** students run the C2 process with `SSLKEYLOGFILE=/shared/sslkeys.log` and decrypt live traffic via `tshark -o tls.keylog_file:/shared/sslkeys.log` — the real-world technique when PFS prevents RSA-key decryption.

**MITRE ATT&CK:** T1036.005 (Match Legitimate Name — Masquerading), T1053.003 (Scheduled Task: Cron), T1071.001 (Web Protocols), T1573.002 (Asymmetric Cryptography), T1027.002 (Software Packing — stripping)

### Round 3 — Advanced (`round-3/`)

- **Keylogger + harvester:** same as R2
- **Exfiltration:** custom DNS tunneling (`exfil_dns.py`) — base32-encoded payload chunks in subdomains of queries to `dns-server`, TXT responses for command channel. Built in-house (not `dnscat2`) so students see protocol mechanics; `dnscat2` client remains in `analyst-ws` as decoder reference
- **Process hiding:** `LD_PRELOAD` library (`libhide.so`) filtering own PID from `readdir()` on `/proc`
- **Log wiping:** selectively removes entries from `/var/log/syslog` and `/var/log/auth.log` after each session
- **Persistence:** hook in `~/.bashrc`
- **Anti-forensics:** mtime/atime modified with `touch -t` (ctime is untouched — see OPSEC mistakes below)

**MITRE ATT&CK:** T1574.006 (Hijack Execution Flow: LD_PRELOAD), T1014 (Rootkit), T1071.004 (Application Layer Protocol: DNS), T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol), T1070.002 (Clear Linux or Mac System Logs), T1070.006 (Timestomp), T1546.004 (Event Triggered Execution: Unix Shell Configuration Modification)

#### Intentional OPSEC mistakes (R3)

The attacker is sophisticated but imperfect. These are the planted detection pivots — **visible to instructors, hidden from students** (moved to `rounds/round-3-advanced/instructor-notes.md`, never shipped in casefile):

1. **ctime leak** — `touch -t` modifies mtime/atime but not ctime. `stat` on tampered files shows ctime later than mtime, revealing forgery.
2. **auditd survives log wipe** — attacker clears `/var/log/syslog` and `auditd`'s syslog forwarding, but the kernel audit buffer and `/var/log/audit/audit.log` (separate subsystem, different ACL) are untouched. `ausearch -k exec-trace` reconstructs the timeline.
3. **Volatility `psscan` beats LD_PRELOAD** — `libhide.so` filters `/proc` userland reads, but memory forensics walks kernel `task_struct` directly. `psscan` shows the hidden PID that `pslist` does not.
4. **DNS query-rate baseline anomaly** — exfil client does not rotate cadence; subdomain query rate to `update.ghost-pkg.net` is ~3× host baseline over 60s windows. Trivially detected with entropy + rate analysis.
5. **.bashrc hook leaves provenance** — persistence line is appended without matching comment style, and git-tracked dotfiles (if any) show a diff.
6. **Private key pinned in binary** — R3 C2 client ships a private X25519 key baked into the stripped ELF. `strings` + known-format scanning (key header magic) recovers it from memory via Volatility `yarascan`.

All sample files carry the header:
```python
# GHOST-IN-THE-BOX LAB — EDUCATIONAL SAMPLE
# Round: X | Isolated Docker environment only
# For use in university cybersecurity courses
# MITRE ATT&CK: T1056.001, T1005, T1071.001, ...   (per-round allowlist, enforced by tests)
```

---

## MITRE ATT&CK Mapping (master table)

| Technique ID | Name | R1 | R2 | R3 |
|---|---|:-:|:-:|:-:|
| T1056.001 | Input Capture: Keylogging | ✓ | ✓ | ✓ |
| T1113 | Screen Capture | ✓ | ✓ | ✓ |
| T1005 | Data from Local System | ✓ | ✓ | ✓ |
| T1071.001 | Application Layer Protocol: Web | ✓ | ✓ |   |
| T1071.004 | Application Layer Protocol: DNS |   |   | ✓ |
| T1041 | Exfiltration Over C2 Channel | ✓ | ✓ |   |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 |   |   | ✓ |
| T1573.002 | Encrypted Channel: Asymmetric Crypto |   | ✓ |   |
| T1036.005 | Masquerading: Match Legitimate Name |   | ✓ | ✓ |
| T1053.003 | Scheduled Task/Job: Cron |   | ✓ |   |
| T1546.004 | Event Triggered: Shell Config Mod |   |   | ✓ |
| T1574.006 | Hijack Execution Flow: LD_PRELOAD |   |   | ✓ |
| T1014 | Rootkit |   |   | ✓ |
| T1070.002 | Clear Linux/Mac System Logs |   |   | ✓ |
| T1070.006 | Timestomp |   |   | ✓ |
| T1027.002 | Obfuscated Files: Software Packing |   | ✓ | ✓ |

Students are required to produce this same table, populated from *their own observations*, in each round's incident report. Instructor copy is the ground truth for grading.

---

## Rounds and Tasks

### Round 1 — Naïve

**Red team phase:**
1. Identify suspicious process (`ps aux`, `top`, `lsof -i`)
2. Trace syscalls (`strace -p <pid>`) — find what it reads and writes
3. Capture HTTP traffic (`tcpdump -A port 8080`) — read exfiltrated data in plaintext
4. Map the sample: what data is collected, how often, where sent

**Blue team phase:**
5. Document IOCs: process name, path, C2 IP and port, data types stolen; map each to MITRE ATT&CK
6. Kill the process, verify traffic stops
7. **Detection engineering deliverable:** write a YARA rule matching the R1 sample (hardcoded C2 URL, plaintext JSON field names) — auto-graded against positive/negative corpus
8. Write a one-page incident report following NIST SP 800-61r2 phases (Detection → Containment → Eradication → Recovery)

---

### Round 2 — Masquerading

**Red team phase:**
1. Find the anomaly: why does a `[kworker]` thread have an open TCP socket? (`ss -tp`, `lsof -i`)
2. Identify the real binary behind the fake process name (`/proc/<pid>/exe`, `/proc/<pid>/maps`, `/proc/<pid>/cmdline` vs `comm`)
3. **Memory forensics:** dump victim memory (`avml`), load in Volatility 3, extract the TLS server private key from the C2 process memory using `yarascan` with a PEM-header rule. Use the key to decrypt the pcap in Wireshark.
4. Find the persistence mechanism (`crontab -l`, `/etc/cron*`)

**Blue team phase:**
5. Remove persistence (crontab entry)
6. **Detection engineering deliverables (all required, auto-graded):**
   - **YARA rule** matching the R2 sample (strings, section entropy, stripped-ELF heuristic) — must hit R2 sample, miss R1 and benign `/bin/*`
   - **Sigma rule** (Linux auditd source) alerting when a process whose `comm` starts with `[kworker` opens a non-loopback TCP socket — must trigger on R2 telemetry, not on real kernel threads
   - **Suricata/Zeek rule** flagging TLS connections with self-signed certs to non-allowlisted IPs on the lab network
7. Compare with Round 1 — what changed in attacker OPSEC? Map all observed behaviors to MITRE ATT&CK tactics/techniques in the report.

---

### Round 3 — Advanced

**Red team phase:**
1. Notice spyware is not visible in `ps` — find it via `/proc` traversal, `auditd`, or Volatility `psscan` (compare `pslist` vs `psscan` — the delta IS the hidden PID)
2. **Memory forensics:** use Volatility 3 on a memory dump to (a) extract the hidden process, (b) recover the X25519 private key via `yarascan`, (c) list open handles and mapped libraries including `libhide.so`
3. **Quantitative DNS analysis:** compute per-domain Shannon entropy, subdomain-length histogram, and query-rate baseline over 60s windows from `dns-capture.pcap`. Deliverable: Jupyter notebook with plots + threshold justification (ROC curve on labeled positive/negative windows shipped in casefile)
4. Decode DNS-tunneled data with provided `dns-decoder.py` and reconstruct stolen-data timeline
5. **Detect timestomping:** compare `stat` mtime vs ctime on suspect files — the ctime leak exposes `touch -t` forgery

**Blue team phase:**
6. Incident response: full timeline (installation, dwell time, data exfiltrated) reconciled from `auditd`, memory, and DNS pcap
7. Detect log tampering: `auditd` logs (separate subsystem) survive the attacker's syslog wipe — use them to prove tampering occurred
8. **Detection engineering deliverables (all required, auto-graded):**
   - **YARA rule** matching `libhide.so` (function export names, PEM-in-binary heuristic)
   - **Sigma rule** for LD_PRELOAD abuse (auditd `execve` with non-standard `LD_PRELOAD` env) and for log-file truncation events
   - **Suricata/Zeek rule or Python detector** for DNS tunneling using entropy + rate thresholds derived in step 3; graded on precision/recall against labeled pcap corpus
9. Hardening recommendations: DNS sinkhole + allowlist, `auditd` policy (`-a exit,always -F arch=b64 -S execve -k exec-trace`), append-only logs (`chattr +a` — append-only, not fully immutable; state this precisely), disable unused `LD_PRELOAD` via `/etc/ld.so.preload` monitoring
10. Write a full incident response report following NIST SP 800-61r2, with MITRE ATT&CK mapping table as appendix

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
- `Volatility 3` with pinned Ubuntu 24 symbol pack (shipped with image; required for R2/R3 memory forensics tasks)
- `avml` (memory acquisition tool)
- `yara` + `yarac` (rule compiler, for auto-grading deliverables)
- `sigma-cli` + `sigmac` backends (auditd, Zeek) for Sigma rule testing
- `suricata` (for rule validation against pcap corpus)
- `dnscat2` client (reference decoder for Round 3 traffic)
- Jupyter Lab (for quantitative DNS analysis and report writing; scipy/numpy/pandas/matplotlib preinstalled)
- Custom tools: `dns-decoder.py`, `timeline-builder.py`, `dns-entropy.py`, `rule-grader.py`

---

## Casefile (module-casefile)

Pre-generated artifacts for classroom analysis (without Docker):

```
module-casefile/
  round-1/
    network-capture.pcap
    process-list.txt
    stolen-data-sample.json
    yara-corpus/             ← positive + negative samples for rule auto-grading
    zadania.md
  round-2/
    network-capture.pcap
    c2-server-cert.pem       ← public cert (for pinning verification)
    c2-server-key.pem        ← private key, "seized under court order" — required for TLS decryption
    memory-dump.lime         ← victim RAM dump for Volatility (key recovery exercise)
    crontab-dump.txt
    yara-corpus/
    sigma-test-events/       ← auditd JSON events (positive + negative) for Sigma rule grading
    zadania.md
  round-3/
    dns-capture.pcap
    dns-labeled-windows.csv  ← labeled 60s windows for ROC/threshold tuning
    memory-dump.lime         ← includes hidden process visible to psscan
    auditd-log.txt           ← survived the attacker's wipe
    syslog-tampered.txt
    syslog-original.txt      ← for comparison (instructor ground truth)
    suspect-files-stat.txt   ← output of `stat` showing ctime vs mtime mismatch
    yara-corpus/
    sigma-test-events/
    suricata-test-pcaps/
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
  - Round 2: process `comm` matches `[kworker*` pattern while `/proc/<pid>/exe` points to the spyware binary
  - Round 3: DNS queries to tunneling domain detected in capture; `pslist` vs `psscan` delta reveals hidden PID
- `test_detection_rules.py` — auto-grader for student deliverables against shipped YARA/Sigma/Suricata corpora (measures precision/recall; used both for instructor baseline reference rules and optional self-check by students)
- `test_mitre_mapping.py` — verifies every sample file declares its MITRE ATT&CK TTP IDs in its header block, and that declared TTPs match an allowlist per round

---

## Conventions

- Lab materials language: Polish; technical names in English
- Deterministic generation: `RANDOM_SEED = 42`
- All scenario constants in `generators/data/scenario_facts.py`
- Tests: `pytest`, files `test_*.py`
- Docker build arg `ROUND` controls which spyware is installed (1, 2, or 3)
