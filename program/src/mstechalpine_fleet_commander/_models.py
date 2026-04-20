from __future__ import annotations

import datetime as dt
import os
import sys
import threading
from dataclasses import dataclass
from typing import Any


FIPS_140_2_SUNSET = dt.date(2026, 9, 21)


class _Spinner:
    """Animated CLI spinner for long-running commands. No external deps required."""

    _CHARS = "|/-\\"

    def __init__(self, message: str) -> None:
        self._msg = message
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "_Spinner":
        self._thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self._stop.set()
        self._thread.join()
        # Clear the spinner line
        sys.stdout.write("\r" + " " * (len(self._msg) + 6) + "\r")
        sys.stdout.flush()

    def update(self, message: str) -> None:
        self._msg = message

    def _run(self) -> None:
        i = 0
        while not self._stop.wait(0.12):
            sys.stdout.write(f"\r  {self._CHARS[i % 4]}  {self._msg}")
            sys.stdout.flush()
            i += 1


def _fix_sudo_ownership(*paths: str) -> None:
    """When running as sudo, chown written files back to the real user so they stay readable.
    No-op on Windows (sudo does not exist; icacls handles permissions natively).
    """
    if not hasattr(os, "chown"):
        return  # Windows — chown does not exist
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if not sudo_uid:
        return
    try:
        uid = int(sudo_uid)
        gid = int(sudo_gid) if sudo_gid else -1
        for p in paths:
            if p and os.path.exists(p):
                os.chown(p, uid, gid)  # type: ignore[attr-defined]
    except Exception:
        pass


SHADOW_REMOTE_TOOL_PATTERNS = [
    "anydesk",
    "rustdesk",
    "atera",
    "teamviewer",
    "screenconnect",
    "connectwisecontrol",
    "splashtop",
    "logmein",
    "gotoassist",
    "ultravnc",
    "realvnc",
    "tightvnc",
    "dwservice",
]


@dataclass
class CheckResult:
    name: str
    status: str  # green | yellow | red
    detail: str
