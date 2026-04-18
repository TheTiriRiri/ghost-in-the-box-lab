"""Deterministic syslog/auth.log generator for R1 casefile."""
from __future__ import annotations

import argparse
import datetime
import pathlib
import random
from typing import Iterable

from generators.data import scenario_facts as sf


BASE_EPOCH = datetime.datetime(2026, 3, 14, 8, 0, 0, tzinfo=datetime.timezone.utc)


def _fmt(ts: datetime.datetime, host: str, program: str, msg: str) -> str:
    return f"{ts.strftime('%b %d %H:%M:%S')} {host} {program}: {msg}"


def _r1_auth_lines(rng: random.Random) -> list[str]:
    host = sf.VICTIM_HOSTNAME
    user = sf.VICTIM_USERNAME
    ts = BASE_EPOCH
    lines = [
        _fmt(ts, host, "systemd-logind[841]",
             f"New session 3 of user {user}."),
        _fmt(ts + datetime.timedelta(seconds=2), host, "login[1032]",
             f"pam_unix(login:session): session opened for user {user}(uid=1000) by LOGIN(uid=0)"),
        _fmt(ts + datetime.timedelta(seconds=12), host, f"su[{1100 + rng.randint(0, 50)}]",
             f"pam_unix(su:session): session opened for user {user} by {user}(uid=1000)"),
    ]
    return lines


def _r1_syslog_lines(rng: random.Random) -> list[str]:
    host = sf.VICTIM_HOSTNAME
    ts = BASE_EPOCH + datetime.timedelta(minutes=5)
    lines: list[str] = []
    for i in range(10):
        t = ts + datetime.timedelta(seconds=i * 60 + rng.randint(0, 5))
        lines.append(
            _fmt(t, host, "CRON[12345]",
                 "(analyst) CMD (command_not_found spyware.py)")
        )
        lines.append(
            _fmt(t + datetime.timedelta(seconds=2), host,
                 "systemd[1]",
                 "Started Session " + str(4 + i) + " of user analyst.")
        )
    for i in range(3):
        t = ts + datetime.timedelta(seconds=30 + i * sf.EXFIL_INTERVAL_SECONDS)
        lines.append(
            _fmt(t, host, "kernel",
                 f"[  {150 + i * 60}.{rng.randint(100000, 999999)}] "
                 f"IN=eth0 OUT= SRC=10.13.37.50 DST={sf.C2_IP} LEN=512 "
                 f"PROTO=TCP SPT={40000 + i} DPT={sf.C2_HTTP_PORT} WINDOW=64240")
        )
    return lines


def generate(output_dir: pathlib.Path, round_num: int) -> None:
    if round_num != 1:
        raise ValueError(f"unknown round: {round_num} (this generator only handles R1)")
    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(sf.RANDOM_SEED)
    auth = _r1_auth_lines(rng)
    syslog = _r1_syslog_lines(rng)
    (output_dir / "auth.log").write_text("\n".join(auth) + "\n", encoding="utf-8")
    (output_dir / "syslog").write_text("\n".join(syslog) + "\n", encoding="utf-8")


def main(argv: Iterable[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = ap.parse_args(argv)
    generate(args.output_dir, args.round)


if __name__ == "__main__":
    main()
