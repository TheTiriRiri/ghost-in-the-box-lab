"""Benign example: periodic metric uploader. Shares HTTP-exfil surface with the
spyware but is clearly legitimate (documented, no keystroke capture, no file
harvest). A YARA rule that hits this file is too broad."""
import json
import time
import requests

METRICS_URL = "https://metrics.example.org/ingest"
DEVICE = "workstation-042"


def collect_metrics() -> dict:
    return {
        "host": DEVICE,
        "cpu_load": 0.12,
        "mem_used_mb": 4096,
        "uptime_s": int(time.monotonic()),
    }


def main():
    while True:
        r = requests.post(METRICS_URL, json=collect_metrics(), timeout=5)
        r.raise_for_status()
        time.sleep(60)


if __name__ == "__main__":
    main()
