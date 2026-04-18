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


# --- generate_logs ---------------------------------------------------------

def test_generate_logs_is_deterministic(tmp_path):
    from generators import generate_logs

    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir(); b.mkdir()

    generate_logs.generate(output_dir=a, round_num=1)
    generate_logs.generate(output_dir=b, round_num=1)

    assert (a / "auth.log").read_text() == (b / "auth.log").read_text()
    assert (a / "syslog").read_text() == (b / "syslog").read_text()


def test_generate_logs_produces_expected_files(tmp_path):
    from generators import generate_logs

    generate_logs.generate(output_dir=tmp_path, round_num=1)
    assert (tmp_path / "auth.log").is_file()
    assert (tmp_path / "syslog").is_file()


def test_generate_logs_auth_log_mentions_victim_user(tmp_path):
    from generators import generate_logs
    from generators.data import scenario_facts as sf

    generate_logs.generate(output_dir=tmp_path, round_num=1)
    text = (tmp_path / "auth.log").read_text()
    assert sf.VICTIM_USERNAME in text
    assert sf.VICTIM_HOSTNAME in text


# --- generate_artifacts ----------------------------------------------------

def test_generate_artifacts_is_deterministic(tmp_path):
    from generators import generate_artifacts

    a = tmp_path / "a"; b = tmp_path / "b"
    a.mkdir(); b.mkdir()
    generate_artifacts.generate(output_dir=a, round_num=1)
    generate_artifacts.generate(output_dir=b, round_num=1)

    for fname in ("process-list.txt", "stolen-data-sample.json"):
        assert (a / fname).read_bytes() == (b / fname).read_bytes()


def test_generate_artifacts_process_list_shows_spyware(tmp_path):
    from generators import generate_artifacts
    from generators.data import scenario_facts as sf

    generate_artifacts.generate(output_dir=tmp_path, round_num=1)
    text = (tmp_path / "process-list.txt").read_text()
    assert "python3 /opt/spyware/spyware.py" in text
    assert sf.VICTIM_USERNAME in text


def test_generate_artifacts_stolen_data_contains_required_fields(tmp_path):
    import json
    from generators import generate_artifacts
    from generators.data import scenario_facts as sf

    generate_artifacts.generate(output_dir=tmp_path, round_num=1)
    records = [json.loads(line) for line in
               (tmp_path / "stolen-data-sample.json").read_text().splitlines() if line.strip()]
    assert records, "stolen-data-sample.json empty"
    for rec in records:
        assert rec["host"] == sf.VICTIM_HOSTNAME
        assert rec["user"] == sf.VICTIM_USERNAME
        assert "keys" in rec
        assert "files" in rec
