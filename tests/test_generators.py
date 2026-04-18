"""Unit tests for generators/. Keep scapy optional; skip if missing."""
import pathlib

import pytest

scapy_all = pytest.importorskip("scapy.all")


def test_generate_pcap_is_deterministic(tmp_path):
    from generators import generate_pcap

    p1 = tmp_path / "a.pcap"
    p2 = tmp_path / "b.pcap"

    generate_pcap.generate(output_path=p1, round_num=1)
    generate_pcap.generate(output_path=p2, round_num=1)

    assert p1.read_bytes() == p2.read_bytes(), "pcap generation is not deterministic"


def test_generate_pcap_contains_c2_ip(tmp_path):
    from generators import generate_pcap
    from generators.data import scenario_facts as sf

    out = tmp_path / "r1.pcap"
    generate_pcap.generate(output_path=out, round_num=1)

    packets = scapy_all.rdpcap(str(out))
    assert len(packets) > 0
    c2 = sf.C2_IP
    assert any(
        (scapy_all.IP in pkt and (pkt[scapy_all.IP].dst == c2 or pkt[scapy_all.IP].src == c2))
        for pkt in packets
    )


def test_generate_pcap_contains_plaintext_json_payload(tmp_path):
    from generators import generate_pcap

    out = tmp_path / "r1.pcap"
    generate_pcap.generate(output_path=out, round_num=1)
    raw = out.read_bytes()
    assert b"POST /collect" in raw
    assert b"workstation-042" in raw
    assert b'"keys"' in raw


def test_generate_pcap_rejects_unknown_round(tmp_path):
    from generators import generate_pcap
    with pytest.raises(ValueError, match="round"):
        generate_pcap.generate(output_path=tmp_path / "x.pcap", round_num=7)
