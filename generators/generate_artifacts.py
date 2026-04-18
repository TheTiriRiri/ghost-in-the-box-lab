"""Deterministic text-artifact generator — process list and stolen-data JSONL."""
from __future__ import annotations

import argparse
import json
import pathlib
import random
from typing import Iterable

from generators.data import scenario_facts as sf


PROC_LIST_HEADER = "UID        PID  PPID   PRI  NI      VSZ      RSS WCHAN  STAT START  TIME CMD"


def _r1_process_list(rng: random.Random) -> str:
    rows = [
        ("root",        1,      0, 19,  0, 167300,  11244, "-",    "Ss",  "08:00", "0:02", "/sbin/init"),
        ("root",      128,      1, 19,  0,  42780,   5220, "-",    "Ss",  "08:00", "0:00", "/lib/systemd/systemd-journald"),
        ("root",      412,      1, 19,  0,  13460,   3120, "-",    "Ss",  "08:00", "0:00", "/usr/sbin/cron -f"),
        ("root",      843,      1, 19,  0,  15584,   2212, "-",    "Ss",  "08:00", "0:00", "/usr/sbin/sshd -D"),
        (sf.VICTIM_USERNAME, 1032, 843, 19,  0,  21440,   4880, "wait", "Ss+", "08:12", "0:00", "-bash"),
        (sf.VICTIM_USERNAME, 2104, 1032, 19,  0, 104300,  29884, "-",    "S",   "08:42", "0:15",
         "python3 /opt/spyware/spyware.py"),
        (sf.VICTIM_USERNAME, 2110, 2104, 19,  0,  18740,   2112, "poll_s", "S",   "08:42", "0:01", "Xvfb :99 -screen 0 1024x768x24"),
    ]
    rng.shuffle(rows[1:5])
    lines = [PROC_LIST_HEADER]
    for uid, pid, ppid, pri, ni, vsz, rss, wchan, stat, start, time_, cmd in rows:
        lines.append(
            f"{uid:<8} {pid:>6} {ppid:>5}  {pri:>4} {ni:>2} {vsz:>8} {rss:>8} {wchan:<6} {stat:<4} {start:<6} {time_:<6} {cmd}"
        )
    return "\n".join(lines) + "\n"


def _r1_stolen_data(rng: random.Random) -> list[dict]:
    base_epoch = 1712332800
    records = []
    for i in range(3):
        key_count = rng.randint(3, 8)
        records.append({
            "received_at": base_epoch + i * sf.EXFIL_INTERVAL_SECONDS + 0.0,
            "host": sf.VICTIM_HOSTNAME,
            "user": sf.VICTIM_USERNAME,
            "ts_epoch": base_epoch + i * sf.EXFIL_INTERVAL_SECONDS,
            "keys": list("password123"[:key_count]),
            "files": {
                ".bash_history": "ls -la\ncat Documents/report-draft.txt\nssh analyst@prod-01\n",
                ".ssh/id_rsa": (
                    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    "MOCK-RSA-PRIVATE-KEY-DO-NOT-USE-FOR-ANYTHING\n"
                    "-----END OPENSSH PRIVATE KEY-----\n"
                ),
                "Documents/report-draft.txt": "Q4 report draft — internal only. Revenue figures redacted.\n",
            },
            "screenshot_bytes": 8192 + i * 512,
        })
    return records


def generate(output_dir: pathlib.Path, round_num: int) -> None:
    if round_num != 1:
        raise ValueError(f"unknown round: {round_num} (this generator only handles R1)")
    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(sf.RANDOM_SEED)

    (output_dir / "process-list.txt").write_text(_r1_process_list(rng), encoding="utf-8")

    records = _r1_stolen_data(rng)
    (output_dir / "stolen-data-sample.json").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )


def main(argv: Iterable[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = ap.parse_args(argv)
    generate(args.output_dir, args.round)


if __name__ == "__main__":
    main()
