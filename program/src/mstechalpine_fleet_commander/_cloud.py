from __future__ import annotations

"""_cloud.py — FedRAMP / Cloud / ESP scoping checks.

NIST 800-171 Rev 3 and 32 CFR Part 170 require contractors to account for the
Shared Responsibility Model (SRM) when CUI is processed in cloud-hosted systems.
Without an SRM, endpoint checks cover only half of the required control evidence.

Two checks are provided:

1. check_cloud_srm(srm_path)
   Verifies a Shared Responsibility Matrix document exists and was recently
   reviewed. Raises RED if no SRM is present (instant FCA exposure for orgs
   using GCC High, Azure Government, or AWS GovCloud for CUI).

2. check_esp_scoping(inventory)
   Scans the network inventory for active connections to known MSP/ESP
   remote-management IP ranges and ports. External Service Providers must be
   scoped into the SSP — undocumented MSP tunnels are an AC.L2-3.1.20
   boundary violation in 2026 assessments.
"""

import datetime as dt
import os
import re
import socket
from typing import Any, Dict, List, Optional

from ._models import CheckResult
from ._utils import run_cmd


# ---------------------------------------------------------------------------
# Known MSP / ESP remote-management ports used by common RMM platforms.
# An ESTABLISHED outbound connection on these ports that is NOT documented in
# the SSP is a boundary violation (AC.L2-3.1.20) and a scoping gap.
# ---------------------------------------------------------------------------
_ESP_RMM_PORTS = {
    "443":   "HTTPS (generic — may be MSP/EDR cloud)",
    "4116":  "ConnectWise Automate (LabTech) agent",
    "4343":  "Kaseya VSA agent",
    "5721":  "Windows SCCM / Endpoint Manager",
    "8044":  "Atera agent",
    "9955":  "NinjaRMM / NinjaOne agent",
    "11001": "Datto RMM (CagService)",
    "12000": "AutoTask / Datto older port",
    "20010": "Level.io agent",
    "50000": "TeamViewer fallback",
}

# Cloud provider / CSP FedRAMP metadata endpoint prefixes (IPv4 link-local)
_CLOUD_METADATA_IPS = {
    "169.254.169.254": "AWS / Azure / GCP instance metadata service",
    "169.254.170.2":   "AWS ECS task metadata",
}


def check_cloud_srm(srm_path: Optional[str]) -> CheckResult:
    """Verify a Shared Responsibility Matrix (SRM) document exists and is current.

    FedRAMP Moderate Equivalency and 32 CFR Part 170 require the contractor to
    define which controls are inherited from the CSP and which they own.
    Without an SRM the endpoint checks in this tool cover only the 'Endpoint'
    half of the CMMC Level 2 requirement.

    Args:
        srm_path: Path to the SRM file (any format: PDF, XLSX, JSON, DOCX).
                  Pass None or empty string to trigger a RED finding.
    """
    if not srm_path:
        # Auto-detect common SRM file names in evidence/ or cwd
        candidates = [
            "evidence/shared-responsibility-matrix.xlsx",
            "evidence/shared-responsibility-matrix.pdf",
            "evidence/srm.xlsx",
            "evidence/srm.pdf",
            "evidence/cloud-srm.json",
            "shared-responsibility-matrix.xlsx",
            "srm.xlsx",
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                srm_path = candidate
                break

    if not srm_path or not os.path.exists(srm_path):
        return CheckResult(
            "cloud_srm",
            "red",
            "No Shared Responsibility Matrix (SRM) document found. "
            "FedRAMP Moderate Equivalency and 32 CFR Part 170 require an SRM that maps inherited CSP "
            "controls vs. contractor-owned controls. Without it, this tool only covers the endpoint half "
            "of CMMC Level 2. Create an SRM and pass --srm <path> to resolve. "
            "Scoping gap: GCC High / Azure Government / AWS GovCloud users are at highest FCA risk.",
        )

    if os.path.getsize(srm_path) == 0:
        return CheckResult(
            "cloud_srm",
            "red",
            f"SRM file exists but is empty (0 bytes): {os.path.abspath(srm_path)}. "
            "Populate it with your Shared Responsibility Matrix before affirming CMMC readiness.",
        )

    # Check file age — SRM older than 365 days is a yellow flag (annual review expected)
    try:
        mtime = dt.datetime.fromtimestamp(os.path.getmtime(srm_path), tz=dt.timezone.utc)
        age_days = (dt.datetime.now(dt.timezone.utc) - mtime).days
    except Exception:
        age_days = 0

    if age_days > 365:
        return CheckResult(
            "cloud_srm",
            "yellow",
            f"SRM found: {os.path.abspath(srm_path)} — but it was last modified {age_days} day(s) ago. "
            "Annual SRM review is expected for FedRAMP Moderate Equivalency. "
            "Update before Senior Official affirmation.",
        )

    # Check for GCC High indicators (environment variables / registry) and note if found
    gcc_hint = _detect_gcc_high_environment()
    gcc_note = f" GCC High environment indicators detected: {gcc_hint}." if gcc_hint else ""

    return CheckResult(
        "cloud_srm",
        "green",
        f"SRM document present: {os.path.abspath(srm_path)} (modified {age_days}d ago).{gcc_note} "
        "Ensure SRM maps all CUI-processing cloud services and is included in SSP Appendix.",
    )


def _detect_gcc_high_environment() -> Optional[str]:
    """Return a short description if GCC High / cloud-tenant indicators are found, else None."""
    hints: List[str] = []

    # Azure / M365 tenant config files
    azure_cfg_paths = [
        os.path.expanduser("~/.azure/clouds.config"),
        os.path.expanduser("~/.azure/azureProfile.json"),
        "/etc/azure",
    ]
    for p in azure_cfg_paths:
        if os.path.exists(p):
            try:
                content = open(p).read() if os.path.isfile(p) else ""
                if "usgov" in content.lower() or "gcc" in content.lower() or "high" in content.lower():
                    hints.append("Azure GCC High / USGov tenant config")
                    break
            except Exception:
                pass

    # AWS GovCloud region in credentials or config
    aws_cfg_paths = [
        os.path.expanduser("~/.aws/config"),
        os.path.expanduser("~/.aws/credentials"),
    ]
    for p in aws_cfg_paths:
        if os.path.exists(p):
            try:
                content = open(p).read()
                if "us-gov-" in content.lower():
                    hints.append("AWS GovCloud region in ~/.aws/config")
                    break
            except Exception:
                pass

    # Cloud metadata endpoint reachable (indicates running inside a cloud VM)
    for ip, label in _CLOUD_METADATA_IPS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, 80))
            sock.close()
            if result == 0:
                hints.append(f"Cloud metadata endpoint reachable ({ip} — {label})")
                break
        except Exception:
            pass

    return "; ".join(hints) if hints else None


def check_esp_scoping(inventory: Optional[List[Dict[str, Any]]] = None) -> CheckResult:
    """Detect active connections to External Service Provider (ESP/MSP) management ports.

    Undocumented MSP remote-management tunnels are an AC.L2-3.1.20 boundary
    violation and a common C3PAO finding in 2026 assessments. This check:
    1. Reads active ESTABLISHED connections from the OS network table.
    2. Flags connections to well-known RMM ports that are NOT expected to be
       present on a self-managed CUI endpoint.
    3. Cross-references the nmap inventory (if provided) for hosts presenting
       RMM ports from inside the assessed boundary.
    """
    esp_connections: List[str] = []

    # --- Live socket scan ---
    import platform as _platform
    _is_win = _platform.system().lower() == "windows"
    _sock_cmds = (
        [["netstat", "-n"]] if _is_win
        else [["ss", "-tnp", "state", "established"], ["netstat", "-tn"]]
    )
    for cmd in _sock_cmds:
        import shutil as _sh
        if not _sh.which(cmd[0]):
            continue
        rc, out, _ = run_cmd(cmd, timeout=8)
        if rc != 0 or not out:
            continue
        for line in out.splitlines():
            if cmd[0] == "netstat" and "established" not in line.lower():
                continue
            for port, label in _ESP_RMM_PORTS.items():
                if port == "443":
                    continue  # Too noisy — skip generic HTTPS
                if re.search(rf":{re.escape(port)}\b", line):
                    esp_connections.append(f"Port {port} ({label})")
        break

    # --- Inventory scan: hosts inside boundary with RMM ports open ---
    boundary_rmm: List[str] = []
    if inventory:
        for host in inventory:
            services = host.get("services", [])
            ip = host.get("ip", "")
            for svc in services:
                for port, label in _ESP_RMM_PORTS.items():
                    if port == "443":
                        continue
                    if f"/{port}:" in svc or f"/{port}" == svc:
                        boundary_rmm.append(f"{ip} port {port} ({label})")

    all_findings = sorted(set(esp_connections + boundary_rmm))

    if all_findings:
        sample = "; ".join(all_findings[:5])
        return CheckResult(
            "esp_scoping",
            "yellow",
            f"Potential ESP/MSP remote-management port(s) detected: {sample}. "
            "If an MSP manages this environment, their remote access MUST be documented in the SSP "
            "boundary and they must carry their own CMMC Level 2 certification (32 CFR 170.19(c)). "
            "Undocumented ESP access is an AC.L2-3.1.20 finding.",
        )

    return CheckResult(
        "esp_scoping",
        "green",
        "No undocumented ESP/MSP remote-management port connections detected. "
        "Confirm with your SSP that any managed service providers are explicitly scoped. "
        "32 CFR 170.19(c).",
    )
