from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
from typing import Dict, List, Optional, Tuple

from ._models import FIPS_140_2_SUNSET


def fips_sunset_suffix() -> str:
    today = dt.date.today()
    if today <= FIPS_140_2_SUNSET:
        days_left = (FIPS_140_2_SUNSET - today).days
        return (
            f" Sunset approaching: migrate to FIPS 140-3 validated modules before Sept 21, 2026 "
            f"({days_left} day(s) remaining)."
        )
    return " FIPS 140-2 sunset date has passed (2026-09-21). 140-3 evidence is now expected for new CUI acquisitions."


def _linux_fips_140_3_signal() -> Tuple[bool, str]:
    # Best effort only: indicates likely 140-3 readiness track, not a formal CMVP certification proof.
    if not os.path.exists("/proc/sys/crypto/fips_enabled"):
        return False, "Linux FIPS mode file not found."

    try:
        with open("/proc/sys/crypto/fips_enabled", "r", encoding="utf-8") as fh:
            enabled = fh.read().strip() == "1"
    except Exception:
        return False, "Could not read Linux FIPS mode status."

    if not enabled:
        return False, "Linux FIPS mode is not enabled."

    distro_hint = ""
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as fh:
                distro_hint = fh.read().lower()
        except Exception:
            distro_hint = ""

    rc, out, _ = run_cmd(["openssl", "version", "-a"]) if shutil.which("openssl") else (1, "", "")
    openssl_text = out.lower() if rc == 0 else ""
    on_modern_track = (
        "ubuntu" in distro_hint and "24.04" in distro_hint
    ) or (
        "rhel" in distro_hint and "9" in distro_hint
    ) or (
        "red hat" in distro_hint and "9" in distro_hint
    )
    openssl3 = "openssl 3" in openssl_text

    if on_modern_track and openssl3:
        return True, "Linux FIPS mode enabled on a modern distro/OpenSSL 3 track (likely 140-3 path)."

    return False, "Linux FIPS mode enabled, but 140-3 readiness could not be confirmed from distro/OpenSSL signals."


def find_likely_shared_accounts(usernames: List[str]) -> List[str]:
    # Heuristic only: catches common generic/shared naming patterns.
    patterns = [
        r"^admin$",
        r"^administrator$",
        r"^shared",
        r"^shop",
        r"^office",
        r"^frontdesk$",
        r"^reception$",
        r"^accounting$",
        r"^operator$",
        r"^user\d+$",
        r"^test",
        r"^temp",
        r"^kiosk",
        r"^guest$",
    ]
    hits: List[str] = []
    for user in usernames:
        normalized = user.strip().lower()
        for pat in patterns:
            if re.search(pat, normalized):
                hits.append(user)
                break
    return sorted(set(hits), key=lambda x: x.lower())


def run_cmd(cmd: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def detect_os() -> str:
    return platform.system().lower()


def detect_local_subnet() -> Optional[str]:
    """Auto-detect the local network subnet in CIDR notation (e.g. 10.0.0.0/24).

    Uses a UDP connect to 8.8.8.8 (no packet is sent) to find the outbound
    interface IP, then reads the prefix length from ifconfig/ip addr/ipconfig.
    Returns None if detection fails — caller should prompt the user.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except Exception:
        return None

    sys_name = platform.system().lower()
    try:
        if sys_name == "darwin":
            rc, out, _ = run_cmd(["ifconfig"], timeout=5)
            if rc == 0 and out:
                m = re.search(
                    rf"inet {re.escape(local_ip)} netmask (0x[0-9a-f]+)", out
                )
                if m:
                    prefix = bin(int(m.group(1), 16)).count("1")
                    return str(ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False))
        elif sys_name == "linux":
            rc, out, _ = run_cmd(["ip", "addr"], timeout=5)
            if rc == 0 and out:
                m = re.search(rf"inet ({re.escape(local_ip)}/\d+)", out)
                if m:
                    return str(ipaddress.ip_network(m.group(1), strict=False))
        elif sys_name == "windows":
            rc, out, _ = run_cmd(["ipconfig"], timeout=5)
            if rc == 0 and out:
                lines = out.splitlines()
                for i, ln in enumerate(lines):
                    if local_ip in ln:
                        for j in range(max(0, i - 5), min(len(lines), i + 5)):
                            if "Subnet Mask" in lines[j]:
                                mask_str = lines[j].split(":")[-1].strip()
                                prefix = sum(
                                    bin(int(o)).count("1") for o in mask_str.split(".")
                                )
                                return str(
                                    ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)
                                )
    except Exception:
        pass
    return None


def load_asset_tags(path: Optional[str]) -> Dict[str, str]:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            # Expected: {"192.168.1.10": "CUI Asset", "host1": "Security Protection Asset"}
            return {str(k).strip().lower(): str(v).strip() for k, v in data.items()}
    except Exception:
        pass
    return {}


def append_hash_ledger(artifact_path: str, ledger_path: str) -> Optional[str]:
    try:
        with open(artifact_path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()

        abs_ledger = os.path.abspath(ledger_path)
        os.makedirs(os.path.dirname(abs_ledger), exist_ok=True)

        # Read the last line of the ledger to build a hash chain.
        # Each entry's "prev_sha256" field is the SHA-256 of the previous
        # entry's raw JSON line, making retroactive insertion detectable:
        # an auditor can re-hash any line and verify it matches the next
        # entry's prev_sha256 field.
        prev_sha256 = "genesis"
        try:
            with open(abs_ledger, "r", encoding="utf-8") as fh:
                last_line = ""
                for line in fh:
                    if line.strip():
                        last_line = line.strip()
            if last_line:
                prev_sha256 = hashlib.sha256(last_line.encode()).hexdigest()
        except FileNotFoundError:
            pass

        record = {
            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "artifact_path": os.path.abspath(artifact_path),
            "sha256": digest,
            "prev_sha256": prev_sha256,
        }

        with open(abs_ledger, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

        if detect_os() in {"linux", "darwin"}:
            try:
                os.chmod(abs_ledger, 0o600)
            except Exception:
                pass

        return digest
    except Exception:
        return None
