# Ghost-in-the-Box Lab

An educational cybersecurity lab for advanced university students. Students play both attacker and defender across three escalating rounds of spyware OPSEC — from a naïve plaintext keylogger to a process-hiding DNS tunneler.

Everything runs in an isolated Docker network with no outbound internet access. Student-facing materials (`zadania.md`, briefings) are written in Polish. All code and configuration is in English.

> **Status:** Round 1 fully implemented. Rounds 2 and 3 are planned.

---

## Rounds

| Round | Spyware behaviour | Exfil channel | Evasion |
|-------|------------------|---------------|---------|
| **1 — Naïve** | `python3 spyware.py` visible in `ps` | HTTP POST :8080 plaintext | None |
| **2 — Masquerading** | Process renamed to `[kworker/u4:2]` via `prctl` | HTTPS :443 (RSA, no PFS — intentional flaw) | Name mimicry, `@reboot` crontab |
| **3 — Advanced** | Hidden via `libhide.so` (`LD_PRELOAD`) | DNS tunneling to `update.ghost-pkg.net` | `/proc` hiding, log wiping, timestomping |

---

## Two Ways to Use the Lab

### Option A — Casefile (offline, no Docker required)

Pre-generated artifacts for classroom use. Students analyse real pcaps, logs, and process snapshots without running any containers.

```
module-casefile/round-1/
  network-capture.pcap
  auth.log
  syslog
  process-list.txt
  stolen-data-sample.json
  zadania.md                       ← student task sheet (Polish)
  yara-corpus/
    positive/spyware-r1.py
    negative/                      ← benign decoys for YARA testing
```

Student workflow:
```bash
cd module-casefile/round-1/
cat zadania.md

# Inspect traffic
tshark -r network-capture.pcap -Y http -T fields \
  -e ip.src -e ip.dst -e tcp.dstport -e http.request.uri

# Self-check YARA rule
python -m tests.test_detection_rules --rule my-rule.yar --round 1
```

### Option B — Techlab (live Docker environment)

Full live environment: spyware runs on the victim container and exfiltrates data to the C2 server in real time. Students investigate from the analyst workstation.

```bash
cd module-techlab/
cp .env.example .env

# Start Round 1
ROUND=1 docker compose --profile full up -d --build

# Open analyst workstation shell
docker exec -it ghost-analyst bash
```

Inside the analyst container the full forensics toolchain is available: `tshark`, `tcpdump`, `strace`, `ltrace`, `lsof`, `ss`, `auditd`, `yara`, `sigma-cli`, `suricata`, Volatility 3, Jupyter Lab.

---

## Repository Layout

```
ghost-in-the-box-lab/
  core/
    scenario/              ← briefing.md, attacker-profile.md (Polish)
    spyware-samples/
      round-1/spyware.py   ← naïve keylogger + file harvester
      shared/              ← collector.py, exfil_http.py
  generators/
    data/scenario_facts.py ← single source of truth for all constants
    generate_pcap.py
    generate_logs.py
    generate_artifacts.py
  module-techlab/
    docker-compose.yml
    victim/  c2-server/  analyst-ws/
    rounds/round-1-naive/
      zadania.md           ← live-env student task sheet (Polish)
      instructor-notes.md  ← answer key, MITRE GT, reference YARA (never shipped to students)
  module-casefile/
    round-1/               ← pre-generated artifacts + offline zadania.md
  tests/
```

---

## Running Tests

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r core/spyware-samples/requirements.txt yara-python scapy pytest flask pyyaml

pytest tests/                                  # all tests (Docker tests skipped if unavailable)
pytest tests/test_scenario_facts.py            # constants only, no Docker
pytest tests/test_detection_rules.py           # grade YARA deliverables
pytest tests/test_mitre_mapping.py             # verify MITRE TTP declarations
```

---

## MITRE ATT&CK Coverage (Round 1)

| Technique | ID | Observable |
|-----------|-----|-----------|
| Keylogging | T1056.001 | `keys` field in POST body |
| Screen capture | T1113 | `screenshot_bytes` field in POST body |
| Local data collection | T1005 | `files` field in POST body |
| Application layer protocol | T1071.001 | HTTP POST to `10.13.37.1:8080/collect` |
| Exfiltration over C2 channel | T1041 | Same HTTP channel used for C2 and exfil |

---

## Design Principles

- **`generators/data/scenario_facts.py` is the single source of truth** — every IP, port, username, and interval is imported from there, never hardcoded.
- **All artifact generation is deterministic** — RNG seeded with `RANDOM_SEED = 42`.
- **Instructor content never ships to students** — `instructor-notes.md` lives only under `module-techlab/`; a leak-guard test enforces this.
- **Incident reports follow NIST SP 800-61r2** with a MITRE ATT&CK mapping appendix.
