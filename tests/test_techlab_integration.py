"""Docker-gated integration tests. Skipped when Docker is unavailable."""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import time

import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent
COMPOSE_DIR = REPO_ROOT / "module-techlab"

pytestmark = pytest.mark.docker


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "compose", "version"],
                           capture_output=True, timeout=10)
    except Exception:
        return False
    return r.returncode == 0


if not _docker_available():
    pytest.skip("docker or docker compose not available", allow_module_level=True)


def _compose(*args, env=None, check=True, timeout=180):
    base = ["docker", "compose", "-f", str(COMPOSE_DIR / "docker-compose.yml")]
    return subprocess.run(base + list(args), env=env, check=check,
                          capture_output=True, text=True, timeout=timeout,
                          cwd=COMPOSE_DIR)


@pytest.fixture(scope="module")
def stack():
    import os
    env = {**os.environ, "ROUND": "1"}
    _compose("down", "-v", "--remove-orphans", check=False)
    _compose("build", "--build-arg", "ROUND=1", env=env, timeout=900)
    _compose("--profile", "full", "up", "-d", env=env)
    try:
        yield env
    finally:
        _compose("logs", "--no-color", check=False)
        _compose("down", "-v", "--remove-orphans", check=False)


def test_round_1_c2_receives_payload_within_90_seconds(stack):
    """Victim must POST to c2-server within one exfil interval + buffer."""
    deadline = time.time() + 120
    last_output = ""
    while time.time() < deadline:
        r = _compose("exec", "-T", "c2-server",
                     "sh", "-c",
                     "test -s /data/received.jsonl && cat /data/received.jsonl || true",
                     check=False, timeout=15)
        last_output = (r.stdout or "").strip()
        if last_output:
            break
        time.sleep(3)

    assert last_output, f"no payloads after 120s. stdout={last_output!r}"

    first_line = last_output.splitlines()[0]
    record = json.loads(first_line)
    assert record["host"] == "workstation-042"
    assert record["user"] == "analyst"
    assert "received_at" in record


def test_round_1_stolen_bash_history_present_in_payload(stack):
    r = _compose("exec", "-T", "c2-server",
                 "sh", "-c", "cat /data/received.jsonl",
                 check=False, timeout=15)
    records = [json.loads(line) for line in r.stdout.strip().splitlines() if line]
    assert records, "no payloads collected"
    with_files = [rec for rec in records if rec.get("files")]
    assert with_files, "no record with harvested files within the window"
    bash_hist = with_files[0]["files"].get(".bash_history", "")
    assert "ls -la" in bash_hist, f"bash_history content unexpected: {bash_hist!r}"
