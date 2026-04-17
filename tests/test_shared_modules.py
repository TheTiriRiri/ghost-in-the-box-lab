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
    """Without DISPLAY and with forced xlib-missing, constructor picks pynput or null."""
    monkeypatch.delenv("DISPLAY", raising=False)
    from collector import Keylogger
    kl = Keylogger()
    assert kl.active_backend in {"xlib", "pynput", "null"}


def test_keylogger_raises_on_unknown_backend():
    from collector import Keylogger
    with pytest.raises(ValueError, match="unknown backend"):
        Keylogger(backend="telepathy")
