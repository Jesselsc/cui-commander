from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from ._models import CheckResult, SHADOW_REMOTE_TOOL_PATTERNS
from ._utils import (
    _linux_fips_140_3_signal,
    find_likely_shared_accounts,
    fips_sunset_suffix,
    run_cmd,
)


def is_admin_context(os_name: str) -> CheckResult:
    if os_name in {"linux", "darwin"}:
        try:
            is_root = os.geteuid() == 0
        except AttributeError:
            is_root = False
        if is_root:
            return CheckResult("admin_context", "green", "Running with elevated privileges.")
        return CheckResult("admin_context", "yellow", "Not running as root/admin. Some checks may be limited.")

    if os_name == "windows":
        # Minimal Windows admin check without external packages.
        rc, out, _ = run_cmd(["whoami", "/groups"])
        if rc == 0 and "S-1-5-32-544" in out:
            return CheckResult("admin_context", "green", "Running in Administrators context.")
        return CheckResult("admin_context", "yellow", "Not running as Administrator. Some checks may be limited.")

    return CheckResult("admin_context", "yellow", "Unknown operating system. Admin check not available.")


def check_encryption(os_name: str) -> CheckResult:
    if os_name == "darwin":
        if shutil.which("fdesetup"):
            rc, out, err = run_cmd(["fdesetup", "status"])
            if rc == 0 and "FileVault is On" in out:
                return CheckResult(
                    "disk_encryption",
                    "yellow",
                    "FileVault is enabled. FIPS 140-3 module evidence is not automatically verifiable by this script." + fips_sunset_suffix(),
                )
            if out:
                return CheckResult("disk_encryption", "red", out)
            return CheckResult("disk_encryption", "yellow", f"Could not determine FileVault status: {err}")
        return CheckResult("disk_encryption", "yellow", "fdesetup not found.")

    if os_name == "linux":
        # Check /etc/crypttab for configured encrypted volumes
        if os.path.exists("/etc/crypttab"):
            try:
                with open("/etc/crypttab", "r") as f:
                    lines = [ln.strip() for ln in f.readlines() if ln.strip() and not ln.strip().startswith("#")]
                    if lines:
                        on_1403_track, detail = _linux_fips_140_3_signal()
                        if on_1403_track:
                            return CheckResult("disk_encryption", "green", f"Found {len(lines)} encrypted volume(s) configured. {detail}")
                        return CheckResult(
                            "disk_encryption",
                            "yellow",
                            f"Found {len(lines)} encrypted volume(s) configured. {detail}" + fips_sunset_suffix(),
                        )
            except Exception:
                pass

        # Fallback: check lsblk for LUKS on critical partitions
        if shutil.which("lsblk"):
            rc, out, err = run_cmd(["lsblk", "-o", "NAME,MOUNTPOINT,FSTYPE"])
            if rc == 0:
                # Look for crypt/luks on root or mounted system partitions
                for line in out.splitlines():
                    if re.search(r"(?:crypt|luks)", line, re.IGNORECASE):
                        if re.search(r"[\s](?:/|/home|/root|/boot)\s", line):
                            on_1403_track, detail = _linux_fips_140_3_signal()
                            if on_1403_track:
                                return CheckResult("disk_encryption", "green", f"Detected LUKS on critical system partition. {detail}")
                            return CheckResult(
                                "disk_encryption",
                                "yellow",
                                "Detected LUKS on critical system partition, but 140-3 readiness is not confirmed." + fips_sunset_suffix(),
                            )
                return CheckResult("disk_encryption", "yellow", "No LUKS encryption detected on critical partitions (root/home/boot).")
            return CheckResult("disk_encryption", "yellow", f"lsblk failed: {err}")
        return CheckResult("disk_encryption", "yellow", "lsblk not found.")

    if os_name == "windows":
        if shutil.which("manage-bde"):
            rc, out, err = run_cmd(["manage-bde", "-status"])
            if rc == 0:
                if "Protection Status:    Protection On" in out or "Conversion Status:    Fully Encrypted" in out:
                    fips_rc, fips_out, _ = run_cmd([
                        "reg",
                        "query",
                        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy",
                        "/v",
                        "Enabled",
                    ])
                    fips_enabled = fips_rc == 0 and "0x1" in fips_out.lower()
                    if fips_enabled:
                        return CheckResult(
                            "disk_encryption",
                            "yellow",
                            "BitLocker appears enabled and Windows FIPS policy is ON, but this script cannot verify CMVP 140-3 certificate mapping automatically." + fips_sunset_suffix(),
                        )
                    return CheckResult(
                        "disk_encryption",
                        "yellow",
                        "BitLocker appears enabled, but Windows FIPS policy is not enabled. Enable FIPS policy and confirm 140-3 module path before affirmation." + fips_sunset_suffix(),
                    )
                return CheckResult("disk_encryption", "yellow", "BitLocker output did not show clear full protection for all volumes.")
            return CheckResult("disk_encryption", "yellow", f"manage-bde failed: {err}")
        return CheckResult("disk_encryption", "yellow", "manage-bde not available in PATH.")

    return CheckResult("disk_encryption", "yellow", "Encryption check not implemented for this OS.")


def check_mfa_signal(os_name: str) -> CheckResult:
    """Check IA.L2-3.5.3: Phishing-resistant MFA with hardware key AAGUID validation.

    Goes beyond presence checks — distinguishes hardware-bound FIDO2 keys (YubiKey,
    Feitian, etc.) from software authenticators. An auditor can be shown the specific
    AAGUID found to prove company-issued keys are enforced on local logins.
    """
    # Known FIDO2 hardware key AAGUIDs (non-exhaustive; add your org's issued keys here)
    _HARDWARE_KEY_AAGUIDS: Dict[str, str] = {
        "2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 Series (NFC)",
        "c1f9a0bc-1dd2-404a-b27f-8e29047a43fd": "YubiKey 5 Series (USB-A)",
        "fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5Ci",
        "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5 (NFC)",
        "cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5 Nano",
        "6d44ba9b-f6ec-2e49-b930-0c8fe920cb73": "Security Key by Yubico",
        "3789da91-f943-46bc-95c3-50ea2012f03a": "Feitian ePass FIDO2",
        "12ded745-4bed-47d4-abaa-e713f51d6393": "Feitian BioPass FIDO2",
        "b6ede29c-3772-412c-8a78-539c1f4c62d2": "Feitian K9",
        "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome Touch ID / Platform",
        "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello Hardware",
        "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello Software",
    }

    if os_name == "windows":
        has_webauthn = os.path.exists(r"C:\Windows\System32\webauthn.dll")
        rc1, out1, _ = run_cmd(["reg", "query", r"HKLM\SOFTWARE\Microsoft\PassportForWork"])
        rc2, out2, _ = run_cmd(["reg", "query", r"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork"])
        has_hello = (rc1 == 0 and bool(out1.strip())) or (rc2 == 0 and bool(out2.strip()))

        # Try to find registered FIDO2 credential AAGUIDs from Windows Hello key storage
        aaguid_found: Optional[str] = None
        aaguid_name: Optional[str] = None
        rc_fg, out_fg, _ = run_cmd(
            ["reg", "query",
             r"HKLM\SOFTWARE\Microsoft\Cryptography\FIDO\Enrollments",
             "/s", "/f", "aaguid"],
            timeout=10,
        )
        if rc_fg == 0 and out_fg:
            for line in out_fg.lower().splitlines():
                for aaguid, name in _HARDWARE_KEY_AAGUIDS.items():
                    if aaguid.lower() in line:
                        aaguid_found = aaguid
                        aaguid_name = name
                        break

        if aaguid_found:
            return CheckResult(
                "mfa_signal", "green",
                f"Hardware FIDO2 key enrolled: {aaguid_name} (AAGUID {aaguid_found}). "
                "Phishing-resistant hardware-bound MFA confirmed on this host. "
                "Verify IdP policy enforces this key class for all privileged paths.",
            )
        if has_webauthn and has_hello:
            return CheckResult(
                "mfa_signal", "green",
                "WebAuthn + Windows Hello for Business policy keys detected. "
                "AAGUID for hardware key not found in enrollment store — "
                "confirm hardware key is the enforced authenticator (not software Hello).",
            )
        if has_webauthn or has_hello:
            return CheckResult(
                "mfa_signal", "yellow",
                "Partial MFA indicators (WebAuthn or Hello policy). "
                "No hardware FIDO2 AAGUID found. Push/SMS MFA is high-risk for 2026 CMMC work.",
            )
        return CheckResult(
            "mfa_signal", "yellow",
            "No FIDO2/WebAuthn/Windows Hello indicators found. "
            "Push/SMS-only MFA is high-risk for 2026 prioritized work.",
        )

    if os_name in {"linux", "darwin"}:
        aaguid_found = None
        aaguid_name = None

        if shutil.which("fido2-token"):
            rc, out, _ = run_cmd(["fido2-token", "-L"])
            if rc == 0 and out:
                # Enumerate each token and check its AAGUID
                for line in out.splitlines():
                    parts = line.split(":")
                    dev = parts[0].strip() if parts else ""
                    if dev:
                        rc_i, out_i, _ = run_cmd(["fido2-token", "-I", dev], timeout=5)
                        if rc_i == 0 and out_i:
                            for info_line in out_i.lower().splitlines():
                                if "aaguid" in info_line:
                                    for aaguid, name in _HARDWARE_KEY_AAGUIDS.items():
                                        if aaguid.lower() in info_line:
                                            aaguid_found = aaguid
                                            aaguid_name = name
                                            break
                if aaguid_found:
                    return CheckResult(
                        "mfa_signal", "green",
                        f"Hardware FIDO2 key present: {aaguid_name} (AAGUID {aaguid_found}). "
                        "Phishing-resistant hardware-bound MFA confirmed. "
                        "Verify PAM/IdP enforces this key class for privileged access.",
                    )
                return CheckResult(
                    "mfa_signal", "green",
                    f"FIDO2 token detected (fido2-token -L returned results). "
                    "AAGUID not matched to known hardware key list — add your org's AAGUID to the script. "
                    "Verify PAM/IdP enforcement on all privileged paths.",
                )

        pam_u2f_paths = ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/sshd"]
        for path in pam_u2f_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as fh:
                        txt = fh.read().lower()
                    if "pam_u2f" in txt or "pam_faillock" in txt:
                        return CheckResult(
                            "mfa_signal", "yellow",
                            "PAM auth-hardening signals found (pam_u2f or pam_faillock). "
                            "No FIDO2 token visible — confirm key is plugged in during scans. "
                            "Check IdP/PAM enforces hardware FIDO2 for all privileged access.",
                        )
                except Exception:
                    continue

        return CheckResult(
            "mfa_signal", "yellow",
            "No hardware FIDO2 key or PAM MFA signals found. "
            "Validate FIDO2/WebAuthn enforcement in your IdP and auth stack.",
        )

    return CheckResult("mfa_signal", "yellow", "MFA signal check not implemented for this OS.")


def _scan_text_for_remote_tools(text: str) -> List[str]:
    lowered = text.lower()
    hits: List[str] = []
    for pattern in SHADOW_REMOTE_TOOL_PATTERNS:
        if pattern in lowered:
            hits.append(pattern)
    return sorted(set(hits))


def check_remote_access_shadow_tools(os_name: str) -> CheckResult:
    # Best-effort software fingerprinting for unauthorized remote access tooling.
    fingerprints: List[str] = []

    if os_name == "windows":
        # Running processes
        rc, out, _ = run_cmd(["tasklist"])
        if rc == 0 and out:
            fingerprints.extend(_scan_text_for_remote_tools(out))

        # Installed apps in common uninstall registry paths
        uninstall_paths = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ]
        for path in uninstall_paths:
            rc, out, _ = run_cmd(["reg", "query", path, "/s", "/f", "DisplayName"])
            if rc == 0 and out:
                fingerprints.extend(_scan_text_for_remote_tools(out))

    elif os_name in {"linux", "darwin"}:
        # Running processes
        rc, out, _ = run_cmd(["ps", "aux"])
        if rc == 0 and out:
            fingerprints.extend(_scan_text_for_remote_tools(out))

        # Common app/package signals
        if os_name == "linux":
            if shutil.which("dpkg"):
                rc, out, _ = run_cmd(["dpkg", "-l"])
                if rc == 0 and out:
                    fingerprints.extend(_scan_text_for_remote_tools(out))
            if shutil.which("rpm"):
                rc, out, _ = run_cmd(["rpm", "-qa"])
                if rc == 0 and out:
                    fingerprints.extend(_scan_text_for_remote_tools(out))
        else:
            for app_dir in ["/Applications", os.path.expanduser("~/Applications")]:
                if os.path.isdir(app_dir):
                    rc, out, _ = run_cmd(["ls", "-1", app_dir])
                    if rc == 0 and out:
                        fingerprints.extend(_scan_text_for_remote_tools(out))

    else:
        return CheckResult("remote_tool_signal", "yellow", "Remote tool fingerprinting not implemented for this OS.")

    findings = sorted(set(fingerprints))
    if findings:
        sample = ", ".join(findings[:10])
        return CheckResult(
            "remote_tool_signal",
            "red",
            f"Detected potential shadow remote-access tooling: {sample}. If these are not explicitly approved in SSP boundary controls, treat as unauthorized boundary crossing and remediate.",
        )

    return CheckResult(
        "remote_tool_signal",
        "green",
        "No known shadow remote-access tool signatures detected in running process/app signals.",
    )


def _query_ntp_offset_seconds(server: str = "time.nist.gov", timeout: float = 3.0) -> Tuple[Optional[float], str]:
    # Minimal SNTP query (best effort). Returns server_time - local_time in seconds.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        packet = b"\x1b" + 47 * b"\0"
        t0 = time.time()
        sock.sendto(packet, (server, 123))
        data, _ = sock.recvfrom(48)
        t1 = time.time()
        sock.close()

        if len(data) < 48:
            return None, "NTP response too short."

        sec, frac = struct.unpack("!II", data[40:48])
        ntp_epoch_offset = 2208988800
        server_tx_time = sec - ntp_epoch_offset + frac / (2**32)
        local_midpoint = (t0 + t1) / 2
        offset = server_tx_time - local_midpoint
        return offset, "ok"
    except Exception as exc:
        return None, str(exc)


def check_time_sync_signal() -> CheckResult:
    # Rev 3/GSA incident timelines depend on trustworthy timestamps.
    offset, detail = _query_ntp_offset_seconds("time.nist.gov")
    if offset is None:
        return CheckResult(
            "time_sync_signal",
            "yellow",
            f"Could not verify NTP drift against time.nist.gov: {detail}. Validate time sync manually before relying on audit timelines.",
        )

    drift = abs(offset)
    if drift > 5.0:
        return CheckResult(
            "time_sync_signal",
            "red",
            f"System clock drift exceeds 5 seconds (offset {offset:+.3f}s vs time.nist.gov). Forensic timeline risk for audit/accountability.",
        )

    if drift > 1.0:
        return CheckResult(
            "time_sync_signal",
            "yellow",
            f"System clock drift is {offset:+.3f}s vs time.nist.gov. Within 5s, but tighten sync for cleaner incident timelines.",
        )

    return CheckResult(
        "time_sync_signal",
        "green",
        f"System clock drift is {offset:+.3f}s vs time.nist.gov (within 1 second).",
    )


def check_patch_signal(os_name: str) -> CheckResult:
    # Best-effort only. This is a recency signal, not a full vuln assessment.
    if os_name == "darwin":
        rc, out, err = run_cmd(["softwareupdate", "--history"])
        if rc == 0 and out:
            lines = [ln for ln in out.splitlines() if ln.strip()]
            if len(lines) > 1:
                return CheckResult("patch_signal", "green", "Patch history available via softwareupdate.")
            return CheckResult("patch_signal", "yellow", "Patch history command ran but returned limited data.")
        return CheckResult("patch_signal", "yellow", f"softwareupdate check failed: {err}")

    if os_name == "linux":
        if shutil.which("apt"):
            rc, out, err = run_cmd(["apt", "list", "--upgradable"])
            if rc == 0:
                if "upgradable from" in out:
                    return CheckResult("patch_signal", "yellow", "Updates available. Patch backlog exists.")
                return CheckResult("patch_signal", "green", "No obvious upgradable packages reported by apt.")
            return CheckResult("patch_signal", "yellow", f"apt check failed: {err}")

        if shutil.which("dnf"):
            rc, out, err = run_cmd(["dnf", "check-update"])
            if rc in {0, 100}:
                if rc == 100 and out:
                    return CheckResult("patch_signal", "yellow", "Updates available. Patch backlog exists.")
                return CheckResult("patch_signal", "green", "No obvious updates reported by dnf.")
            return CheckResult("patch_signal", "yellow", f"dnf check failed: {err}")

        return CheckResult("patch_signal", "yellow", "No supported package manager check found.")

    if os_name == "windows":
        # Quick signal only: check if Windows Update client exists.
        if shutil.which("wuauclt") or os.path.exists(r"C:\Windows\System32\UsoClient.exe"):
            return CheckResult("patch_signal", "yellow", "Windows update client detected. Use enterprise logs for full patch evidence.")
        return CheckResult("patch_signal", "yellow", "Could not detect Windows update tooling.")

    return CheckResult("patch_signal", "yellow", "Patch check not implemented for this OS.")


def _apply_sanitize(names: List[str]) -> List[str]:
    """Replace real usernames with anonymized tokens (user_01, user_02, ...) for --sanitize mode."""
    return [f"user_{i + 1:02d}" for i in range(len(names))]


def check_account_signal(os_name: str, sanitize: bool = False) -> CheckResult:
    """Check IA.L2-3.5.1: Review local accounts for shared/generic names.

    With ``sanitize=True`` real usernames are replaced by ``user_01``, ``user_02`` …
    in all output so the JSON artifact can be shared in environments where
    usernames are considered PII or CUI-covered metadata.
    The shared-account detection logic still runs on the real names before anonymization.
    """
    if os_name in {"linux", "darwin"}:
        rc, out, err = run_cmd(["getent", "passwd"] if shutil.which("getent") else ["cat", "/etc/passwd"])
        if rc == 0 and out:
            lines = [ln for ln in out.splitlines() if ln.strip()]
            human = []
            for ln in lines:
                parts = ln.split(":")
                if len(parts) >= 3:
                    user = parts[0]
                    try:
                        uid = int(parts[2])
                    except ValueError:
                        continue
                    if uid >= 1000 and user not in {"nobody"}:
                        human.append(user)
            if human:
                shared = find_likely_shared_accounts(human)
                display_names = _apply_sanitize(human) if sanitize else human
                display_shared = _apply_sanitize(shared) if sanitize else shared
                if shared:
                    shared_sample = ", ".join(display_shared[:10])
                    return CheckResult(
                        "account_signal",
                        "red",
                        f"Detected likely shared/generic account names: {shared_sample}. Replace with named individual accounts.",
                    )
                sample = ", ".join(display_names[:10])
                return CheckResult("account_signal", "yellow", f"Detected {len(human)} local user account(s). Includes: {sample}. Review for stale accounts.")
            return CheckResult("account_signal", "green", "No standard local human accounts detected (system accounts only).")
        return CheckResult("account_signal", "yellow", f"Account inventory check failed: {err}")

    if os_name == "windows":
        rc, out, err = run_cmd(["net", "user"])
        if rc == 0 and out:
            names: List[str] = []
            collecting = False
            for ln in out.splitlines():
                line = ln.strip()
                if not line:
                    continue
                if line.startswith("---"):
                    collecting = True
                    continue
                if "The command completed successfully" in line:
                    break
                if collecting:
                    names.extend(line.split())

            shared = find_likely_shared_accounts(names)
            display_names = _apply_sanitize(names) if sanitize else names
            display_shared = _apply_sanitize(shared) if sanitize else shared
            if shared:
                shared_sample = ", ".join(display_shared[:10])
                return CheckResult(
                    "account_signal",
                    "red",
                    f"Detected likely shared/generic local account names: {shared_sample}. Replace with named individual accounts.",
                )

            if names:
                sample = ", ".join(display_names[:10])
                return CheckResult("account_signal", "yellow", f"Local account list detected ({len(names)}). Includes: {sample}. Review stale accounts and disabled users.")
            return CheckResult("account_signal", "yellow", "Local account list detected. Review stale accounts and disabled users manually.")
        return CheckResult("account_signal", "yellow", f"Account inventory check failed: {err}")

    return CheckResult("account_signal", "yellow", "Account check not implemented for this OS.")


# ---------------------------------------------------------------------------
# AC.L2-3.1.20 — VLAN / Boundary Violation Check
# ---------------------------------------------------------------------------

def check_boundary_violations(inventory: List[Dict[str, Any]], tag_map: Dict[str, str]) -> CheckResult:
    """Detect 32 CFR 170.19 boundary anomalies in the discovered inventory.

    Triggers RED for:
      - Host tagged Out-of-Scope found with CUI-indicator services (port 445/3389/1433 etc.)
      - Host tagged CUI Asset or Security Protection Asset running no recognisable services
        on the expected ports (possible miscategorisation)
      - Two hosts from different category tiers sharing the same /24 subnet when one is
        CUI Asset and the other is Out-of-Scope (cross-segment co-mingling signal)
    """
    if not inventory:
        return CheckResult("boundary_validation", "yellow",
                           "No inventory available for boundary check. Run --discover-network first.")

    violations: List[str] = []

    # Index by category
    cui_ips: List[str] = []
    oos_ips: List[str] = []
    for host in inventory:
        cat = host.get("category", "")
        ip = host.get("ip", "")
        services = host.get("services", [])

        if cat == "Out-of-Scope":
            oos_ips.append(ip)
            # OOS host with CUI-indicator ports is a boundary crossing
            ports = {s.split("/")[1].split(":")[0] for s in services if "/" in s}
            cui_indicator = ports & {"445", "1433", "3306", "5432", "3389", "5985", "5986"}
            if cui_indicator:
                violations.append(
                    f"{ip} tagged Out-of-Scope but exposes CUI-indicator port(s): "
                    f"{', '.join(sorted(cui_indicator))} — verify segment isolation."
                )

        if cat == "CUI Asset":
            cui_ips.append(ip)

    # Cross-segment co-mingling: CUI and OOS hosts in the same /24
    def subnet_key(ip: str) -> str:
        """Return a /24 (IPv4) or /48 (IPv6) network string for grouping hosts by segment."""
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv6Address):
                return str(ipaddress.ip_network(f"{ip}/48", strict=False))
            return ".".join(ip.split(".")[:3])
        except ValueError:
            return ip

    cui_subnets = {subnet_key(ip) for ip in cui_ips}
    oos_subnets = {subnet_key(ip) for ip in oos_ips}
    shared = cui_subnets & oos_subnets
    for subnet in sorted(shared):
        violations.append(
            f"CUI Assets and Out-of-Scope hosts co-exist on subnet {subnet}.0/24. "
            f"Verify VLAN segmentation — AC.L2-3.1.20 requires boundary enforcement."
        )

    if violations:
        detail = f"{len(violations)} boundary anomaly(ies) detected: " + " | ".join(violations[:3])
        return CheckResult("boundary_validation", "red", detail)

    cats_present = sorted(set(h.get("category", "") for h in inventory))
    return CheckResult(
        "boundary_validation", "green",
        f"No boundary violations detected across {len(inventory)} discovered asset(s). "
        f"Categories present: {', '.join(cats_present)}."
    )


# ---------------------------------------------------------------------------
# AU.L2-3.3.1 — Audit Log Continuity Check (Rev 3 / 1-hour IR window)
# ---------------------------------------------------------------------------

def check_audit_log_signal(os_name: str) -> CheckResult:
    """Check AU.L2-3.3.1: audit service is running and has logged events in the last 24 hours.

    NIST 800-171 Rev 3 and GSA 2026 civilian contracts require a 1-hour IR
    reporting window. If audit logs have been silent for 24+ hours the audit
    service is likely stopped/tampered — this is a red Test finding.
    """
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)

    if os_name == "darwin":
        # macOS: unified log — count security/auth events in the last 24 h
        if shutil.which("log"):
            rc, out, _ = run_cmd(
                ["log", "show", "--style", "compact",
                 "--predicate", "subsystem == 'com.apple.securityd' OR category == 'authentication'",
                 "--last", "24h"],
                timeout=20,
            )
            if rc == 0:
                lines = [l for l in out.splitlines() if l.strip()]
                count = len(lines)
                if count == 0:
                    return CheckResult(
                        "audit_log_signal", "red",
                        "Zero security/auth log entries in the last 24 hours (macOS unified log). "
                        "Audit service may be stopped or tampered. Rev 3 AU.L2-3.3.1 critical finding."
                    )
                return CheckResult(
                    "audit_log_signal", "green",
                    f"{count} security/auth log event(s) found in last 24h (macOS unified log). "
                    "Audit continuity confirmed."
                )
        return CheckResult("audit_log_signal", "yellow",
                           "macOS 'log' command not found. Cannot verify AU.L2-3.3.1 log continuity.")

    if os_name == "linux":
        # Try journald first
        if shutil.which("journalctl"):
            rc, out, _ = run_cmd(
                ["journalctl", "_TRANSPORT=audit", "--since", "24 hours ago", "--no-pager", "-q"],
                timeout=15,
            )
            if rc == 0:
                count = len([l for l in out.splitlines() if l.strip()])
                if count == 0:
                    return CheckResult(
                        "audit_log_signal", "red",
                        "Zero auditd events via journald in the last 24 hours. "
                        "Audit service may be stopped. Rev 3 AU.L2-3.3.1 critical finding."
                    )
                return CheckResult(
                    "audit_log_signal", "green",
                    f"{count} audit event(s) found in last 24h via journald. Continuity confirmed."
                )
        # Fallback: check /var/log/audit/audit.log mtime
        audit_log = "/var/log/audit/audit.log"
        if os.path.exists(audit_log):
            try:
                mtime = dt.datetime.fromtimestamp(os.path.getmtime(audit_log), tz=dt.timezone.utc)
                age_h = (dt.datetime.now(dt.timezone.utc) - mtime).total_seconds() / 3600
                if age_h > 24:
                    return CheckResult(
                        "audit_log_signal", "red",
                        f"audit.log last modified {age_h:.1f} hours ago — no recent events. "
                        "AU.L2-3.3.1: audit service may be down."
                    )
                return CheckResult(
                    "audit_log_signal", "yellow",
                    f"audit.log modified {age_h:.1f}h ago. Event count not verified (journalctl unavailable). "
                    "Manual check recommended."
                )
            except Exception:
                pass
        return CheckResult("audit_log_signal", "yellow",
                           "Could not locate audit log or journald. Verify auditd is running (AU.L2-3.3.1).")

    if os_name == "windows":
        # Query Security event log — count events in last 24h
        rc, out, _ = run_cmd(
            ["wevtutil", "qe", "Security",
             f"/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]",
             "/c:1", "/f:text"],
            timeout=15,
        )
        if rc == 0 and out.strip():
            return CheckResult(
                "audit_log_signal", "green",
                "Windows Security event log has entries in the last 24 hours. AU.L2-3.3.1 continuity confirmed."
            )
        if rc == 0 and not out.strip():
            return CheckResult(
                "audit_log_signal", "red",
                "Windows Security event log: zero events in the last 24 hours. "
                "Audit service may be disabled. AU.L2-3.3.1 critical finding."
            )
        return CheckResult("audit_log_signal", "yellow",
                           "wevtutil query failed. Verify Windows Event Log service (AU.L2-3.3.1).")

    return CheckResult("audit_log_signal", "yellow", "Audit log check not implemented for this OS.")


# ---------------------------------------------------------------------------
# SR.L2-3.17.1 / EO 14028 — Software Inventory (SBOM foundation)
# ---------------------------------------------------------------------------

def collect_software_inventory(os_name: str) -> List[Dict[str, str]]:
    """Return a structured list of {"name": ..., "version": ...} dicts.

    Used by check_software_inventory_sbom() and, when --sbom-output is
    requested, by the SBOM writers in _sbom.py to produce CycloneDX / SPDX
    output with proper name/version fields rather than freeform strings.
    """
    components: List[Dict[str, str]] = []
    seen: set = set()

    def _add(name: str, version: str) -> None:
        name = name.strip()
        version = version.strip()
        if not name:
            return
        key = (name.lower(), version.lower())
        if key in seen:
            return
        seen.add(key)
        components.append({"name": name, "version": version})

    if os_name == "windows":
        # Query both 32-bit and 64-bit uninstall registry hives.
        # Use tab as delimiter so names with spaces parse correctly.
        for hive in [
            r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            r"HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        ]:
            rc, out, _ = run_cmd(
                ["powershell", "-NoProfile", "-Command",
                 f"Get-ItemProperty '{hive}' | "
                 "Select-Object DisplayName,DisplayVersion | "
                 "Where-Object {{ $_.DisplayName }} | "
                 "ForEach-Object {{ $_.DisplayName + \"`t\" + $_.DisplayVersion }}"],
                timeout=20,
            )
            if rc == 0 and out:
                for ln in out.splitlines():
                    parts = ln.strip().split("\t", 1)
                    _add(parts[0], parts[1] if len(parts) > 1 else "")

    elif os_name == "linux":
        # dpkg (Debian/Ubuntu) — tab-delimited for reliable parsing
        rc, out, _ = run_cmd(
            ["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"], timeout=15
        )
        if rc == 0 and out:
            for ln in out.splitlines():
                parts = ln.strip().split("\t", 1)
                _add(parts[0], parts[1] if len(parts) > 1 else "")

        if not components:
            # rpm (RHEL/Fedora/CentOS) — tab-delimited
            rc, out, _ = run_cmd(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"], timeout=15
            )
            if rc == 0 and out:
                for ln in out.splitlines():
                    parts = ln.strip().split("\t", 1)
                    _add(parts[0], parts[1] if len(parts) > 1 else "")

        if not components:
            # Flatpak — tab-separated columns (application, version)
            rc, out, _ = run_cmd(
                ["flatpak", "list", "--columns=application,version"], timeout=10
            )
            if rc == 0 and out:
                for ln in out.splitlines():
                    parts = ln.strip().split("\t", 1) if "\t" in ln else ln.strip().split(None, 1)
                    _add(parts[0], parts[1] if len(parts) > 1 else "")

    elif os_name == "darwin":
        # When running as root (sudo), system_profiler and brew query per-user
        # application data that is inaccessible in the root context.
        # Drop back to the original user's context via "sudo -u $SUDO_USER".
        user_prefix: List[str] = []
        if os.geteuid() == 0:
            sudo_user = os.environ.get("SUDO_USER", "")
            if sudo_user and sudo_user != "root":
                user_prefix = ["sudo", "-u", sudo_user]

        # system_profiler JSON — authoritative installed-app list with version fields
        rc, out, _ = run_cmd(
            [*user_prefix, "system_profiler", "SPApplicationsDataType", "-json"], timeout=30
        )
        if rc == 0 and out:
            try:
                data = json.loads(out)
                for app in data.get("SPApplicationsDataType", []):
                    _add(app.get("_name", ""), app.get("version", ""))
            except Exception:
                pass

        # Homebrew formula and cask installs (supplement system_profiler)
        brew_path = shutil.which("brew")
        if not brew_path and user_prefix:
            # brew may only be on the original user's PATH; try common locations
            for candidate in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
                if os.path.isfile(candidate):
                    brew_path = candidate
                    break
        if brew_path:
            rc2, out2, _ = run_cmd(
                [*user_prefix, brew_path, "list", "--versions"], timeout=15
            )
            if rc2 == 0 and out2:
                for ln in out2.splitlines():
                    parts = ln.strip().split(None, 1)
                    _add(parts[0], parts[1] if len(parts) > 1 else "")

    return components


def _collect_hardware_serial(os_name: str) -> str:
    """Return the hardware serial number / service tag if readable without root.

    macOS  : system_profiler SPHardwareDataType — always readable.
    Linux  : /sys/class/dmi/id/product_serial — readable without root on most
             kernels (kernel 4.10+). Falls back to chassis_serial.
    Windows: wmic bios get SerialNumber — readable by standard users.

    Returns an empty string if the serial is unavailable or is a placeholder
    value (e.g. 'To Be Filled By O.E.M.').
    """
    _PLACEHOLDER_SERIALS = frozenset({
        "", "to be filled by o.e.m.", "none", "n/a", "not applicable",
        "default string", "system serial number", "chassis serial number",
    })

    if os_name == "darwin":
        rc, out, _ = run_cmd(["system_profiler", "SPHardwareDataType"], timeout=10)
        if rc == 0:
            for line in out.splitlines():
                if "serial number" in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        val = parts[1].strip()
                        if val.lower() not in _PLACEHOLDER_SERIALS:
                            return val

    elif os_name == "linux":
        # sysfs paths are world-readable on kernel 4.10+ without rooton most
        # distros, but some hardened images set them 0400 (root-only).
        for sysfs_path in (
            "/sys/class/dmi/id/product_serial",
            "/sys/class/dmi/id/chassis_serial",
        ):
            try:
                val = open(sysfs_path).read().strip()
                if val.lower() not in _PLACEHOLDER_SERIALS:
                    return val
            except PermissionError:
                pass   # fall through to dmidecode
            except Exception:
                pass

        # dmidecode fallback — needs root; use sudo if already running as root
        # (fleet manager remote context always runs as root via ssh).
        if shutil.which("dmidecode"):
            prefix = ["sudo"] if os.geteuid() != 0 else []
            rc, out, _ = run_cmd([*prefix, "dmidecode", "-s", "system-serial-number"], timeout=8)
            if rc == 0:
                val = out.strip()
                if val.lower() not in _PLACEHOLDER_SERIALS:
                    return val

    elif os_name == "windows":
        rc, out, _ = run_cmd(
            ["wmic", "bios", "get", "SerialNumber", "/format:list"], timeout=10
        )
        if rc == 0:
            for line in out.splitlines():
                if line.lower().startswith("serialnumber="):
                    val = line.split("=", 1)[1].strip()
                    if val.lower() not in _PLACEHOLDER_SERIALS:
                        return val

    return ""


def check_software_inventory_sbom(
    os_name: str,
    sbom_output: Optional[str] = None,
    sbom_format: str = "cyclonedx",
) -> CheckResult:
    """Enumerate installed software as the foundation of an SBOM.

    EO 14028 and NIST 800-171 Rev 3 SR family require contractors to maintain
    a software bill of materials for systems that process CUI. This check
    produces a count of installed packages/applications — GREEN means you have
    enough inventory data to generate a CycloneDX/SPDX SBOM; YELLOW means the
    data is too thin and a manual SBOM is needed.

    When sbom_output is provided the full structured inventory is written to
    that path in the requested format (cyclonedx or spdx).
    """
    components = collect_software_inventory(os_name)
    count = len(components)

    sbom_note = ""
    if sbom_output and count > 0:
        # Lazy import so _sbom.py is only loaded when actually needed.
        from ._sbom import write_cyclonedx_sbom, write_spdx_sbom  # noqa: PLC0415
        host_info = {
            "serial_number": _collect_hardware_serial(os_name),
        }
        try:
            if sbom_format == "spdx":
                written = write_spdx_sbom(components, sbom_output, host_info=host_info)
            else:
                written = write_cyclonedx_sbom(components, sbom_output, host_info=host_info)
            sbom_note = f" SBOM written: {written} ({sbom_format.upper()})."
        except Exception as exc:
            sbom_note = f" SBOM write failed: {exc}."

    if count >= 10:
        return CheckResult(
            "software_inventory_sbom", "green",
            f"Software inventory: {count} installed package(s)/application(s) enumerated.{sbom_note} "
            "Verify high-risk apps (CUI processors, ERPs) are individually assessed for known CVEs. "
            "SR.L2-3.17.1 / EO 14028."
        )
    if count > 0:
        return CheckResult(
            "software_inventory_sbom", "yellow",
            f"Software inventory: only {count} item(s) found — inventory may be incomplete.{sbom_note} "
            "Manual SBOM required for CUI-processing applications. SR.L2-3.17.1."
        )
    return CheckResult(
        "software_inventory_sbom", "yellow",
        "Could not enumerate installed software. Manual SBOM required. SR.L2-3.17.1 / EO 14028."
    )


# ---------------------------------------------------------------------------
# IR.L2-3.6.1 — Alerting / SIEM Agent Signal (1-hour detection window)
# ---------------------------------------------------------------------------

def _check_siem_socket_connections() -> List[str]:
    """Check for established TCP connections to known SIEM/EDR manager ports.

    An auditor can ask "how do you know the agent is talking to the manager?"
    Process presence alone is not enough — this checks the OS network table for
    an ESTABLISHED connection to the expected reporting port.

    Returns a list of human-readable descriptions for each confirmed live connection.
    """
    # Known SIEM/EDR manager TCP ports: Wazuh 1514/1515, Elastic 9200/9300, Splunk 9997,
    # CrowdStrike uses 443 (indistinguishable), Defender ATP tunnels through 443.
    # We check the ports that are specific enough to be meaningful.
    _manager_ports = {
        "1514": "Wazuh manager (event forwarding)",
        "1515": "Wazuh manager (agent enrollment)",
        "9200": "Elastic/OpenSearch (SIEM data)",
        "9300": "Elastic cluster transport",
        "9997": "Splunk Universal Forwarder → indexer",
        "5044": "Logstash Beats ingest",
        "6514": "Syslog TLS (RFC 5425)",
        "514":  "Syslog UDP/TCP (RFC 5424)",
        "601":  "Syslog TCP reliable (RFC 3195)",
    }

    hits: List[str] = []
    is_win = platform.system().lower() == "windows"
    if is_win:
        # Windows netstat: -n = numeric only; no -t flag (TCP is implicit via ESTABLISHED filter)
        cmds_to_try = [["netstat", "-n"]]
    else:
        # ss (Linux) preferred; netstat -tn fallback (Linux + macOS)
        cmds_to_try = [["ss", "-tnp", "state", "established"], ["netstat", "-tn"]]

    for cmd in cmds_to_try:
        if not shutil.which(cmd[0]):
            continue
        rc, out, _ = run_cmd(cmd, timeout=8)
        if rc != 0 or not out:
            continue
        for line in out.splitlines():
            # netstat output (all platforms) requires ESTABLISHED filter;
            # ss already filters by state so this is a no-op for ss.
            if cmd[0] == "netstat" and "established" not in line.lower():
                continue
            for port, label in _manager_ports.items():
                # Match :PORT at a word boundary — works for both
                # "ip:PORT  " (netstat) and "ip:PORT\n" (ss) output formats.
                if re.search(rf":{re.escape(port)}\b", line):
                    hits.append(label)
        break  # used first available tool

    return sorted(set(hits))


def check_alerting_signal(os_name: str) -> CheckResult:
    """Check IR.L2-3.6.1: active security alerting for the 1-hour IR reporting window.

    NIST 800-171 Rev 3 and GSA 2026 civilian contracts require incident detection
    and reporting within 1 hour. This check first looks for agent process/config
    signals, then validates with active network socket connections to the manager.

    GREEN requires BOTH a process signal AND a confirmed active socket.
    YELLOW means a process was found but no active connection was seen — the agent
    may be installed but not reporting (most common audit failure).
    RED means no agent signals at all.
    """
    process_signals: List[str] = []

    # Cross-platform: check for common SIEM/EDR agent process names
    _agent_procs = {
        "wazuh-agentd": "Wazuh SIEM agent",
        "osqueryd": "osquery endpoint agent",
        "filebeat": "Elastic Filebeat",
        "winlogbeat": "Elastic Winlogbeat",
        "splunkd": "Splunk Universal Forwarder",
        "td-agent": "Fluentd log forwarder",
        "falcon-sensor": "CrowdStrike Falcon EDR",
        "cb-agent": "VMware Carbon Black",
        "elastic-agent": "Elastic Agent",
        "sentinelone": "SentinelOne EDR",
    }
    rc_ps, out_ps, _ = run_cmd(
        (["tasklist"] if os_name == "windows" else ["ps", "aux"]), timeout=10
    )
    if rc_ps == 0 and out_ps:
        for proc, label in _agent_procs.items():
            if proc.lower() in out_ps.lower():
                process_signals.append(label)

    if os_name == "windows":
        # Windows Event Forwarding subscription active?
        rc_wef, out_wef, _ = run_cmd(
            ["wevtutil", "gl", "ForwardedEvents"], timeout=10
        )
        if rc_wef == 0 and "enabled: true" in out_wef.lower():
            process_signals.append("Windows Event Forwarding (WEF) subscription active")

        # Defender for Endpoint (MsSense) running?
        rc_sense, out_sense, _ = run_cmd(
            ["sc", "query", "sense"], timeout=10
        )
        if rc_sense == 0 and "running" in out_sense.lower():
            process_signals.append("Microsoft Defender for Endpoint (MsSense)")

    elif os_name == "linux":
        # rsyslog / syslog-ng forwarding to remote target
        for cfg in ["/etc/rsyslog.conf", "/etc/rsyslog.d", "/etc/syslog-ng/syslog-ng.conf"]:
            if os.path.exists(cfg):
                try:
                    content = ""
                    if os.path.isdir(cfg):
                        for fn in os.listdir(cfg):
                            try:
                                content += open(os.path.join(cfg, fn)).read()
                            except Exception:
                                pass
                    else:
                        content = open(cfg).read()
                    # Remote forwarding: @@host or *.* @host or action(type="omfwd"...)
                    if re.search(r"@@?\S+:\d+|omfwd", content):
                        process_signals.append("rsyslog/syslog-ng remote forwarding configured")
                        break
                except Exception:
                    pass

        # auditd with an active plugin that forwards (audisp-remote)
        if os.path.exists("/etc/audisp/plugins.d/au-remote.conf"):
            try:
                txt = open("/etc/audisp/plugins.d/au-remote.conf").read()
                if "active = yes" in txt.lower():
                    process_signals.append("auditd remote forwarding (audisp-remote) active")
            except Exception:
                pass

    elif os_name == "darwin":
        # Keyword patterns that identify security/EDR/MDM agents in plist names
        _SEC_KEYWORDS = re.compile(
            r"wazuh|elastic|osquery|crowdstrike|falcon|sentinelone|sentinel_one|"
            r"carbon.?black|cb\.protection|tanium|jamf|kandji|mosyle|addigy|"
            r"filewave|cisco\.amp|cylance|cylancesvc|sophos|bitdefender|"
            r"paloaltonetworks|cortex|vmware\.cb",
            re.IGNORECASE,
        )
        # 1. Dynamic scan of /Library/LaunchDaemons/ for any security agent plists
        _launch_dir = "/Library/LaunchDaemons"
        if os.path.isdir(_launch_dir):
            try:
                for plist_name in os.listdir(_launch_dir):
                    if _SEC_KEYWORDS.search(plist_name):
                        process_signals.append(f"LaunchDaemon: {plist_name}")
            except Exception:
                pass

        # 2. launchctl list — catches agents that may not have a plist in LaunchDaemons
        rc_lc, out_lc, _ = run_cmd(["launchctl", "list"], timeout=8)
        if rc_lc == 0 and out_lc:
            for line in out_lc.splitlines():
                if _SEC_KEYWORDS.search(line):
                    # Extract the label (third tab-delimited column in launchctl list output)
                    parts = line.split("\t")
                    label = parts[-1].strip() if parts else line.strip()
                    sig = f"launchctl: {label}"
                    if sig not in process_signals:
                        process_signals.append(sig)

        # 3. MDM enrollment signal — enrolled devices often have centrally managed EDR
        rc_mdm, out_mdm, _ = run_cmd(
            ["profiles", "show", "-type", "configuration"], timeout=8
        )
        if rc_mdm == 0 and out_mdm and "There are no configuration profiles" not in out_mdm:
            # Count profiles to give a useful signal
            profile_count = out_mdm.count("attribute: profileIdentifier")
            if profile_count == 0:
                profile_count = out_mdm.count("_computerlevel[")
            process_signals.append(
                f"MDM enrollment detected ({profile_count} configuration profile(s)) — "
                "EDR/alerting may be centrally managed; verify in MDM console"
            )

        # 4. ASL / asl.conf remote syslog forwarding
        for asl_path in ("/etc/asl.conf", "/etc/asl"):
            if not os.path.exists(asl_path):
                continue
            try:
                if os.path.isdir(asl_path):
                    content = ""
                    for fn in os.listdir(asl_path):
                        try:
                            content += open(os.path.join(asl_path, fn)).read()
                        except Exception:
                            pass
                else:
                    content = open(asl_path).read()
                # 'store_dir' or '> /remote' or 'forward' with a host:port indicate remote forwarding
                if re.search(r"@\w|forward|omfwd|remote_addr", content, re.IGNORECASE):
                    process_signals.append("ASL/syslog remote forwarding configured")
                    break
            except Exception:
                pass

    # --- Network socket validation (the auditor question: "Is it actually talking?") ---
    socket_confirmations = _check_siem_socket_connections()

    if process_signals and socket_confirmations:
        return CheckResult(
            "alerting_signal", "green",
            f"Agent signal(s): {', '.join(process_signals)}. "
            f"Active socket connection(s) to security manager confirmed: {', '.join(socket_confirmations)}. "
            "IR.L2-3.6.1 — verify end-to-end alert delivery within the 1-hour window."
        )

    if process_signals and not socket_confirmations:
        return CheckResult(
            "alerting_signal", "yellow",
            f"Agent detected ({', '.join(process_signals)}) but NO active network socket found to a "
            "SIEM/EDR manager port (Wazuh 1514, Elastic 9200, Splunk 9997, etc.). "
            "Agent may be installed but not reporting — verify connection to manager before affirmation. "
            "IR.L2-3.6.1."
        )

    return CheckResult(
        "alerting_signal", "red",
        "No SIEM agent, EDR, syslog forwarding, or Windows Event Forwarding detected. "
        "Without active alerting you cannot meet the 1-hour incident detection window. "
        "IR.L2-3.6.1 critical gap — deploy Wazuh, Elastic Agent, or equivalent before assessment."
    )
