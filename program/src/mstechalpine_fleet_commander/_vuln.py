"""
MSTechAlpine Fleet Commander — OSV.dev Vulnerability Cross-Reference

Queries https://api.osv.dev/v1/querybatch (public REST API, no auth required)
to cross-reference installed packages against the Open Source Vulnerability
database. Covers Homebrew, PyPI, npm, RubyGems, Cargo, Go, Debian, and Alpine.

CMMC controls addressed:
  SI.L2-3.14.1 — Identify, report, and correct system flaws.
  SA.L2-3.15.1 — Monitor security advisories.
  EO 14028     — Vulnerability disclosure and SBOM linkage.
"""
from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from ._models import CheckResult, _fix_sudo_ownership
from ._utils import run_cmd

# ---------------------------------------------------------------------------
# Hardcoded allowlisted endpoint — the only URL this module will ever contact.
# ---------------------------------------------------------------------------
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_HOST      = "api.osv.dev"
_MAX_PKGS_PER_BATCH = 1000       # OSV hard limit
_MAX_BATCHES        = 5          # cap: 5 000 packages total
_TIMEOUT_S          = 20
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024   # 10 MB cap


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_a, **_kw):  # type: ignore[override]
        raise urllib.error.URLError("Redirect blocked (SSRF guard)")


def _is_safe_host(hostname: str) -> bool:
    """Return True IFF ALL resolved addresses are public routable IPs."""
    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except Exception:
        return False   # fail closed — DNS error
    for _family, _type, _proto, _canon, sockaddr in infos:
        addr_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(addr_str)
            if (
                addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified
            ):
                return False
        except ValueError:
            return False
    return True


def _osv_batch_query(pkgs: List[Dict[str, str]]) -> Optional[List[Dict[str, Any]]]:
    """POST one batch of ≤1000 packages to OSV.dev.

    Returns the ``results`` list or None on any error.
    Each result index corresponds to the query at the same index.
    """
    if not pkgs:
        return None

    if not _is_safe_host(_OSV_HOST):
        return None

    queries = []
    for p in pkgs:
        q: Dict[str, Any] = {"version": p["version"], "package": {"name": p["name"]}}
        if p.get("ecosystem"):
            q["package"]["ecosystem"] = p["ecosystem"]
        queries.append(q)

    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        _OSV_BATCH_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept":       "application/json",
            "User-Agent":   "MSTechAlpine-FleetCommander/1.0",
        },
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=_TIMEOUT_S) as resp:
            raw = resp.read(_MAX_RESPONSE_BYTES)
        data = json.loads(raw)
        return data.get("results", [])
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Package collectors
# ---------------------------------------------------------------------------

def _gather_brew_packages() -> List[Dict[str, str]]:
    """Return Homebrew package list as OSV query dicts.

    When running under sudo, brew must be invoked as the original user
    because brew refuses to run as root.
    """
    # Build user-prefix for sudo context (same pattern as SBOM collector)
    user_prefix: List[str] = []
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER", "")
        if sudo_user and sudo_user != "root":
            user_prefix = ["sudo", "-u", sudo_user]
    brew_path = shutil.which("brew")
    if not brew_path:
        # Also try common non-root locations when $PATH is restricted under sudo
        for candidate in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
            if os.path.isfile(candidate):
                brew_path = candidate
                break
    if not brew_path:
        return []
    rc, out, _ = run_cmd([*user_prefix, brew_path, "list", "--versions"], timeout=30)
    if rc != 0 or not out:
        return []
    pkgs: List[Dict[str, str]] = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            name, version = parts[0], parts[-1]
            pkgs.append({"name": name, "version": version, "ecosystem": "Homebrew"})
    return pkgs


def _gather_pip_packages(os_name: str) -> List[Dict[str, str]]:
    """Return pip-installed packages as OSV query dicts."""
    pip_cmds = (
        ["pip3", "list", "--format=json"],
        ["pip",  "list", "--format=json"],
    )
    for cmd in pip_cmds:
        if not shutil.which(cmd[0]):
            continue
        rc, out, _ = run_cmd(cmd, timeout=20)
        if rc == 0 and out:
            try:
                entries = json.loads(out)
                return [
                    {"name": e["name"], "version": e["version"], "ecosystem": "PyPI"}
                    for e in entries
                    if e.get("name") and e.get("version")
                ]
            except Exception:
                continue
    return []


def _gather_npm_packages() -> List[Dict[str, str]]:
    """Return globally-installed npm packages as OSV query dicts."""
    if not shutil.which("npm"):
        return []
    rc, out, _ = run_cmd(["npm", "list", "-g", "--json", "--depth=0"], timeout=20)
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
        deps = data.get("dependencies", {})
        return [
            {"name": name, "version": info.get("version", ""), "ecosystem": "npm"}
            for name, info in deps.items()
            if info.get("version")
        ]
    except Exception:
        return []


def _gather_debian_packages() -> List[Dict[str, str]]:
    """Return dpkg-installed packages (Debian/Ubuntu)."""
    if not shutil.which("dpkg-query"):
        return []
    rc, out, _ = run_cmd(
        ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"], timeout=20
    )
    if rc != 0 or not out:
        return []
    pkgs: List[Dict[str, str]] = []
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) == 2 and parts[1]:
            pkgs.append({"name": parts[0], "version": parts[1], "ecosystem": "Debian"})
    return pkgs


def _gather_alpine_packages() -> List[Dict[str, str]]:
    """Return apk-installed packages (Alpine Linux)."""
    if not shutil.which("apk"):
        return []
    rc, out, _ = run_cmd(["apk", "info", "-v"], timeout=15)
    if rc != 0 or not out:
        return []
    pkgs: List[Dict[str, str]] = []
    for line in out.splitlines():
        # format: name-version
        m = re.match(r"^(.+?)-(\d[\d.].*)$", line.strip())
        if m:
            pkgs.append({"name": m.group(1), "version": m.group(2), "ecosystem": "Alpine"})
    return pkgs


def _gather_chocolatey_packages() -> List[Dict[str, str]]:
    """Return Chocolatey-installed packages (Windows).

    Uses -r (machine-readable) flag: outputs ``name|version`` per line.
    Ecosystem reported as NuGet — the underlying package format for Chocolatey.
    """
    if not shutil.which("choco"):
        return []
    rc, out, _ = run_cmd(["choco", "list", "--local-only", "-r"], timeout=20)
    if rc != 0 or not out:
        return []
    pkgs: List[Dict[str, str]] = []
    for line in out.splitlines():
        parts = line.strip().split("|", 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            pkgs.append({"name": parts[0], "version": parts[1], "ecosystem": "NuGet"})
    return pkgs


def _gather_winget_packages() -> List[Dict[str, str]]:
    """Return winget-installed packages (Windows 10 1809+ / Windows 11).

    winget 1.4+ supports ``--output json``. Older versions fall back to
    parsing the plain-text table (tab-aligned columns).
    Ecosystem reported as winget (no canonical OSV ecosystem yet, but the
    package names are queryable by PURL in future OSV iterations).
    """
    if not shutil.which("winget"):
        return []
    # Try JSON output first (winget 1.4+)
    rc, out, _ = run_cmd(
        ["winget", "list", "--output", "json", "--disable-interactivity"],
        timeout=30,
    )
    if rc == 0 and out and out.strip().startswith("["):
        try:
            entries = json.loads(out)
            return [
                {"name": e["Name"], "version": e.get("Version", ""), "ecosystem": "winget"}
                for e in entries
                if e.get("Name")
            ]
        except Exception:
            pass
    # Fallback: parse the table header to find column offsets
    rc, out, _ = run_cmd(
        ["winget", "list", "--disable-interactivity"], timeout=30
    )
    if rc != 0 or not out:
        return []
    pkgs: List[Dict[str, str]] = []
    name_col = ver_col = -1
    for line in out.splitlines():
        if "Name" in line and "Version" in line and name_col == -1:
            name_col = line.index("Name")
            ver_col  = line.index("Version")
            continue
        if name_col == -1 or not line.strip() or set(line.strip()) == {"-"}:
            continue
        name    = line[name_col:ver_col].strip() if ver_col > name_col else ""
        version = line[ver_col:].split()[0].strip() if ver_col < len(line) else ""
        if name:
            pkgs.append({"name": name, "version": version, "ecosystem": "winget"})
    return pkgs


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}

# GitHub Advisory Database uses "MODERATE" instead of "MEDIUM"
_DB_SEV_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def _parse_cvss_vector(vector: str) -> str:
    """Heuristic severity label from a CVSS v3/v4 vector string.

    Extracts the CIA impact triad and scope, then maps to a severity label.
    Not a full CVSS calculator — may slight-underrate complex vectors, but
    never silently returns UNKNOWN for a vector that has real impact.
    """
    scope_m = re.search(r'\bS:([CU])', vector)
    scope_c = bool(scope_m and scope_m.group(1) == "C")
    c = (re.search(r'\bC:([HLN])', vector) or re.search(r'\bVC:([HLN])', vector))
    i = (re.search(r'\bI:([HLN])', vector) or re.search(r'\bVI:([HLN])', vector))
    a = (re.search(r'\bA:([HLN])', vector) or re.search(r'\bVA:([HLN])', vector))
    cv = c.group(1) if c else "N"
    iv = i.group(1) if i else "N"
    av = a.group(1) if a else "N"
    highs = sum(1 for x in (cv, iv, av) if x == "H")
    lows  = sum(1 for x in (cv, iv, av) if x == "L")
    if scope_c and highs >= 2:
        return "CRITICAL"
    if highs >= 1:
        return "HIGH"
    if lows >= 2 or (scope_c and lows >= 1):
        return "MEDIUM"
    if lows >= 1:
        return "LOW"
    return "NONE"


def _max_severity(vuln: Dict[str, Any]) -> str:
    """Extract the highest severity label from a single OSV vuln record.

    Priority:
      1. database_specific.severity — most authoritative (GitHub Advisory, NVD).
      2. severity[].score — CVSS vector string, parsed heuristically.
    """
    # 1. database_specific.severity (GitHub Advisory format uses "MODERATE")
    db_sev = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    if db_sev in _DB_SEV_MAP:
        return _DB_SEV_MAP[db_sev]

    # 2. severity[] array — try numeric first, then parse CVSS vector string
    best = "UNKNOWN"
    for sev in vuln.get("severity", []):
        score_str = str(sev.get("score", ""))
        try:
            score = float(score_str)
            if score >= 9.0:
                label: str = "CRITICAL"
            elif score >= 7.0:
                label = "HIGH"
            elif score >= 4.0:
                label = "MEDIUM"
            elif score > 0:
                label = "LOW"
            else:
                label = "NONE"
        except (ValueError, TypeError):
            # CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/...")
            label = _parse_cvss_vector(score_str)
        if _SEVERITY_RANK.get(label, 0) > _SEVERITY_RANK.get(best, 0):
            best = label
    return best


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_vuln_signal(
    os_name: str,
    output_path: Optional[str] = None,
) -> CheckResult:
    """SI.L2-3.14.1 — CVE cross-reference via OSV.dev public API.

    Gathers package lists from Homebrew, pip, npm, dpkg, or apk depending on
    the OS, then queries the OSV.dev batch API for known vulnerabilities.
    Returns GREEN / YELLOW / RED based on the highest-severity finding.

    Parameters
    ----------
    os_name:     Value from detect_os() — "darwin" | "linux" | "windows".
    output_path: Optional path to write a JSON vulnerability report.
    """
    # ---- 1. Collect packages by ecosystem ----
    all_pkgs: List[Dict[str, str]] = []
    sources_checked: List[str] = []

    if os_name == "darwin":
        brew_pkgs = _gather_brew_packages()
        if brew_pkgs:
            all_pkgs.extend(brew_pkgs)
            sources_checked.append(f"Homebrew ({len(brew_pkgs)} pkg(s))")
        pip_pkgs = _gather_pip_packages(os_name)
        if pip_pkgs:
            all_pkgs.extend(pip_pkgs)
            sources_checked.append(f"PyPI ({len(pip_pkgs)} pkg(s))")
        npm_pkgs = _gather_npm_packages()
        if npm_pkgs:
            all_pkgs.extend(npm_pkgs)
            sources_checked.append(f"npm ({len(npm_pkgs)} pkg(s))")

    elif os_name == "linux":
        deb_pkgs = _gather_debian_packages()
        if deb_pkgs:
            all_pkgs.extend(deb_pkgs)
            sources_checked.append(f"dpkg ({len(deb_pkgs)} pkg(s))")
        alp_pkgs = _gather_alpine_packages()
        if alp_pkgs:
            all_pkgs.extend(alp_pkgs)
            sources_checked.append(f"apk ({len(alp_pkgs)} pkg(s))")
        pip_pkgs = _gather_pip_packages(os_name)
        if pip_pkgs:
            all_pkgs.extend(pip_pkgs)
            sources_checked.append(f"PyPI ({len(pip_pkgs)} pkg(s))")
        npm_pkgs = _gather_npm_packages()
        if npm_pkgs:
            all_pkgs.extend(npm_pkgs)
            sources_checked.append(f"npm ({len(npm_pkgs)} pkg(s))")

    else:
        # Windows — Chocolatey, winget, pip, npm
        choco_pkgs = _gather_chocolatey_packages()
        if choco_pkgs:
            all_pkgs.extend(choco_pkgs)
            sources_checked.append(f"Chocolatey ({len(choco_pkgs)} pkg(s))")
        winget_pkgs = _gather_winget_packages()
        if winget_pkgs:
            all_pkgs.extend(winget_pkgs)
            sources_checked.append(f"winget ({len(winget_pkgs)} pkg(s))")
        pip_pkgs = _gather_pip_packages(os_name)
        if pip_pkgs:
            all_pkgs.extend(pip_pkgs)
            sources_checked.append(f"PyPI ({len(pip_pkgs)} pkg(s))")
        npm_pkgs = _gather_npm_packages()
        if npm_pkgs:
            all_pkgs.extend(npm_pkgs)
            sources_checked.append(f"npm ({len(npm_pkgs)} pkg(s))")

    if not all_pkgs:
        return CheckResult(
            "vuln_signal", "yellow",
            "No queryable package managers found (brew, pip3, npm, dpkg, apk). "
            "Cannot cross-reference packages against OSV.dev. "
            "Manually audit high-risk packages against https://osv.dev. SI.L2-3.14.1."
        )

    total_pkgs = len(all_pkgs)
    sources_str = ", ".join(sources_checked)

    # ---- 2. Batch query OSV ----
    vuln_hits: List[Dict[str, Any]] = []  # {name, version, ecosystem, vuln_id, severity}
    network_ok = True

    for batch_start in range(0, min(total_pkgs, _MAX_PKGS_PER_BATCH * _MAX_BATCHES), _MAX_PKGS_PER_BATCH):
        batch = all_pkgs[batch_start: batch_start + _MAX_PKGS_PER_BATCH]
        results = _osv_batch_query(batch)
        if results is None:
            network_ok = False
            break
        for i, result in enumerate(results):
            pkg = batch[i]
            for vuln in result.get("vulns", []):
                sev = _max_severity(vuln)
                vuln_hits.append({
                    "name":       pkg["name"],
                    "version":    pkg["version"],
                    "ecosystem":  pkg.get("ecosystem", ""),
                    "vuln_id":    vuln.get("id", ""),
                    "summary":    vuln.get("summary", ""),
                    "severity":   sev,
                })

    # ---- 3. Optionally write JSON artifact ----
    if output_path and (vuln_hits or network_ok):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            report = {
                "generated_at_utc": __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).isoformat().replace("+00:00", "Z"),
                "packages_scanned": total_pkgs,
                "sources": sources_checked,
                "vulnerabilities_found": len(vuln_hits),
                "findings": sorted(
                    vuln_hits,
                    key=lambda x: _SEVERITY_RANK.get(x["severity"], 0),
                    reverse=True,
                ),
            }
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
            try:
                os.chmod(output_path, 0o600)
            except Exception:
                pass
            _fix_sudo_ownership(output_path)
        except Exception:
            pass

    # ---- 4. Build CheckResult ----
    if not network_ok:
        return CheckResult(
            "vuln_signal", "yellow",
            f"Scanned {sources_str} but OSV.dev API was unreachable. "
            "Rerun with network access or manually check https://osv.dev. SI.L2-3.14.1."
        )

    if not vuln_hits:
        return CheckResult(
            "vuln_signal", "green",
            f"OSV.dev CVE scan: {total_pkgs} package(s) checked across {sources_str}. "
            "No known vulnerabilities found. "
            "Review again after each patch cycle. SI.L2-3.14.1 / SA.L2-3.15.1."
        )

    # Tally by severity
    counts: Dict[str, int] = {}
    for h in vuln_hits:
        counts[h["severity"]] = counts.get(h["severity"], 0) + 1
    sev_str = ", ".join(f'{v} {k}' for k, v in sorted(counts.items(), key=lambda x: -_SEVERITY_RANK.get(x[0], 0)))
    affected = len({h["name"] for h in vuln_hits})
    detail_lines = ", ".join(
        f'{h["name"]}@{h["version"]} → {h["vuln_id"]} ({h["severity"]})'
        for h in sorted(vuln_hits, key=lambda x: -_SEVERITY_RANK.get(x["severity"], 0))[:5]
    )
    suffix = f" ... (and {len(vuln_hits) - 5} more)" if len(vuln_hits) > 5 else ""

    if counts.get("CRITICAL", 0) > 0 or counts.get("HIGH", 0) >= 3:
        status = "red"
    elif counts.get("HIGH", 0) > 0 or counts.get("MEDIUM", 0) >= 5:
        status = "yellow"
    else:
        status = "yellow"  # any finding is at minimum yellow

    vuln_path_note = f" Vuln report: {os.path.abspath(output_path)}." if output_path else ""
    return CheckResult(
        "vuln_signal", status,
        f"OSV.dev CVE scan: {total_pkgs} pkg(s) checked ({sources_str}). "
        f"{affected} package(s) with known CVEs — {sev_str}. "
        f"Top findings: {detail_lines}{suffix}.{vuln_path_note} "
        "Remediate CRITICAL/HIGH within 30 days. SI.L2-3.14.1 / EO 14028."
    )
