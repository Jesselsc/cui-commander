from __future__ import annotations

"""_sbom.py — Machine-readable SBOM generation (CycloneDX 1.5 / SPDX 2.3).

EO 14028 and NIST 800-171 Rev 3 SR family require contractors to maintain a
Software Bill of Materials for systems that process CUI. Federal agencies have
discretion to demand an SBOM for any software used to process CUI, and
C3PAO auditors may ask for machine-readable evidence for high-risk
applications (custom ERPs, shop management tools, etc.).

Two standard formats are supported:

  CycloneDX 1.5 JSON  — preferred by DoD/SBOM tooling (CycloneDX.org)
  SPDX 2.3 JSON       — Linux Foundation standard, accepted by NTIA/CISA

Both are pure-stdlib, no third-party dependencies.

Public API:
  write_cyclonedx_sbom(components, output_path, host_info) -> str
  write_spdx_sbom(components, output_path, host_info)      -> str
"""

import datetime as dt
import hashlib
import json
import os
import platform
import re
import socket
import uuid
from typing import Dict, List, Optional

from ._models import _fix_sudo_ownership

# Tool metadata embedded in every SBOM we emit.
_TOOL_VENDOR = "MSTechAlpine"
_TOOL_NAME = "Fleet Commander"
_TOOL_VERSION = "2.0"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sanitize_bom_ref(name: str, version: str) -> str:
    """Return a filesystem/JSON-safe bom-ref string for a component."""
    slug = re.sub(r"[^A-Za-z0-9.\-_@]", "_", f"{name}@{version}")
    return slug[:128]  # cap length to stay sane in deeply nested reports


def _short_hash(name: str, version: str) -> str:
    """Return a 6-char hex digest to disambiguate duplicate names."""
    return hashlib.sha256(f"{name}:{version}".encode()).hexdigest()[:6]


def _timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


def _deterministic_serial_number(hostname: str) -> str:
    """Return a UUID5 (namespace=DNS, name=hostname) formatted as a URN.

    UUID5 is deterministic: the same hostname always produces the same UUID,
    so repeat runs on the same host produce a consistent serialNumber. Combined
    with an incrementing version counter this enables continuous-monitoring
    diff tracking (e.g. CycloneDX BOM-diff tooling) without storing external
    state — the identity key is the host itself.
    """
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_DNS, hostname)}"


def _get_previous_version(output_path: str) -> int:
    """Return the CycloneDX 'version' integer from an existing SBOM, or 0.

    Used to increment the version counter on each new run so auditors can
    track SBOM generations for the same host over time.
    """
    abs_path = os.path.abspath(output_path)
    if not os.path.exists(abs_path):
        return 0
    try:
        with open(abs_path, "r", encoding="utf-8") as fh:
            existing = json.load(fh)
        v = existing.get("version")
        if isinstance(v, int) and v > 0:
            return v
    except Exception:
        pass
    return 0


# ---------------------------------------------------------------------------
# CycloneDX 1.5 JSON
# ---------------------------------------------------------------------------

def write_cyclonedx_sbom(
    components: List[Dict[str, str]],
    output_path: str,
    host_info: Optional[Dict[str, str]] = None,
) -> str:
    """Write a CycloneDX 1.5 JSON SBOM to *output_path*.

    Args:
        components: List of {"name": "...", "version": "..."} dicts from
                    collect_software_inventory().
        output_path: Destination file path. Parent directories are created.
        host_info:   Optional dict with "hostname" and "os_version" keys.
                     Defaults to live system values.

    Returns:
        The absolute path to the written file.

    The file is written mode 0o600 (owner read/write only) because an SBOM
    enumerates the exact attack surface of the host — it must not be left
    world-readable.
    """
    if host_info is None:
        host_info = {}

    hostname = host_info.get("hostname") or _hostname()
    os_version = host_info.get("os_version") or platform.platform()
    hw_serial = (host_info.get("serial_number") or "").strip()

    cdx_components = []
    seen_refs: dict = {}

    for comp in components:
        name = (comp.get("name") or "").strip()
        version = (comp.get("version") or "").strip()
        if not name:
            continue

        raw_ref = _sanitize_bom_ref(name, version)
        # Deduplicate bom-ref — CycloneDX requires uniqueness within the BOM.
        if raw_ref in seen_refs:
            raw_ref = f"{raw_ref}-{_short_hash(name, version)}"
        seen_refs[raw_ref] = True

        entry: Dict = {
            "type": "application",
            "bom-ref": raw_ref,
            "name": name,
        }
        if version:
            entry["version"] = version

        cdx_components.append(entry)

    # Consistent per-host serialNumber: UUID5(DNS, hostname) is stable across
    # runs on the same machine. version increments on each write so BOM-diff
    # tooling can track generations without an external state file.
    serial_number = _deterministic_serial_number(hostname)
    version_num = _get_previous_version(output_path) + 1

    component_meta: Dict = {
        "type": "device",
        "name": hostname,
        "version": os_version,
    }
    if hw_serial:
        component_meta["properties"] = [
            {"name": "hardware:serialNumber", "value": hw_serial}
        ]

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": version_num,
        "serialNumber": serial_number,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": [
                {
                    "vendor": _TOOL_VENDOR,
                    "name": _TOOL_NAME,
                    "version": _TOOL_VERSION,
                }
            ],
            "component": component_meta,
        },
        "components": cdx_components,
    }

    _write_sbom_file(output_path, bom)
    return os.path.abspath(output_path)


# ---------------------------------------------------------------------------
# SPDX 2.3 JSON
# ---------------------------------------------------------------------------

def write_spdx_sbom(
    components: List[Dict[str, str]],
    output_path: str,
    host_info: Optional[Dict[str, str]] = None,
) -> str:
    """Write an SPDX 2.3 JSON SBOM to *output_path*.

    Args:
        components: List of {"name": "...", "version": "..."} dicts from
                    collect_software_inventory().
        output_path: Destination file path. Parent directories are created.
        host_info:   Optional dict with "hostname" and "os_version" keys.

    Returns:
        The absolute path to the written file.

    The file is written mode 0o600 (owner read/write only).
    """
    if host_info is None:
        host_info = {}

    hostname = host_info.get("hostname") or _hostname()
    hw_serial = (host_info.get("serial_number") or "").strip()
    ts = _timestamp()
    # documentNamespace must be globally unique per run — uuid4 here is correct
    # per SPDX 2.3 §3.5: "Each document must have a unique namespace."
    doc_ns = f"https://mstechalpine.com/sbom/{hostname}/{uuid.uuid4()}"

    packages = []
    for idx, comp in enumerate(components):
        name = (comp.get("name") or "").strip()
        version = (comp.get("version") or "").strip()
        if not name:
            continue

        pkg: Dict = {
            "SPDXID": f"SPDXRef-Package-{idx}",
            "name": name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }
        if version:
            pkg["versionInfo"] = version

        packages.append(pkg)

    creators = [
        f"Tool: {_TOOL_VENDOR} {_TOOL_NAME} {_TOOL_VERSION}",
        f"Device: {hostname}",
    ]
    if hw_serial:
        # SPDX 2.3 §6.8 allows free-form creator strings for supplemental info.
        creators.append(f"Device-Serial: {hw_serial}")

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{hostname}-sbom",
        "documentNamespace": doc_ns,
        "creationInfo": {
            "created": ts,
            "creators": creators,
            "licenseListVersion": "3.21",
        },
        "documentDescribes": ["SPDXRef-DOCUMENT"],
        "packages": packages,
    }

    _write_sbom_file(output_path, spdx_doc)
    return os.path.abspath(output_path)


# ---------------------------------------------------------------------------
# Shared file writer
# ---------------------------------------------------------------------------

def _write_sbom_file(output_path: str, payload: dict) -> None:
    abs_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    # SBOM exposes full software attack surface — restrict to owner only.
    try:
        os.chmod(abs_path, 0o600)
    except Exception:
        pass
    _fix_sudo_ownership(abs_path)
