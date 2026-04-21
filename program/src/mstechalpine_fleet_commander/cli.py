#!/usr/bin/env python3
"""
MSTechAlpine Diagnostic Script

This script provides a local, non-intrusive baseline check for:
- Host encryption status (best effort by OS)
- FIPS transition signal (140-2 sunset vs 140-3 readiness, best effort)
- Administrative execution context
- Phishing-resistant MFA signal (best effort by OS)
- Basic patch recency signal (best effort by OS)
- Local account inventory signal (best effort by OS)

Output:
- Human-readable console summary
- Optional JSON artifact for evidence tracking

IMPORTANT DISCLAIMERS:
1. This is NOT a compliance certification or legal determination.
2. Readiness score is a BASELINE SIGNAL ONLY, not proof of CMMC/NIST 800-171 compliance.
   Green/yellow results mean tools exist, not that policies are enforced or effective.
3. PRIVACY: This script captures local usernames and system details.
   - Keep JSON output private; do not commit to version control or share publicly.
   - Remove username data before sharing with non-IT personnel.
4. This script detects presence of controls, not their effectiveness.
   Requires manual verification: policy review, testing, auditor assessment.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import sys
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from ._checks import (
    check_account_signal,
    check_alerting_signal,
    check_audit_log_signal,
    check_boundary_violations,
    check_encryption,
    check_mfa_signal,
    check_patch_signal,
    check_remote_access_shadow_tools,
    check_software_inventory_sbom,
    check_time_sync_signal,
    collect_software_inventory,
    is_admin_context,
)
from ._cloud import check_cloud_srm, check_esp_scoping
from ._cloud_api import (
    check_azure_conditional_access,
    check_fedramp_authorization,
    check_google_workspace_bac,
    check_intune_device_compliance,
)
from ._discovery import generate_network_diagram_svg, run_nmap_discovery
from ._fleet import load_discovery_inventory, run_fleet_manager
from ._models import CheckResult, _fix_sudo_ownership
from ._report import get_remediation_guidance, write_html_report
from ._utils import append_hash_ledger, detect_local_subnet, detect_os, load_asset_tags
from ._vuln import check_vuln_signal


def _print_banner() -> None:
    banner = r"""
    __  ______________          __    ___    __      _
   /  |/  / ___/_  __/__  _____/ /_  /   |  / /___  (_)___  ___
  / /|_/ /\__ \ / / / _ \/ ___/ __ \/ /| | / / __ \/ / __ \/ _ \
 / /  / /___/ // / /  __/ /__/ / / / ___ |/ / /_/ / / / / /  __/
/_/  /_//____//_/  \___/\___/_/ /_/_/  |_/_/ .___/_/_/ /_/\___/
                                          /_/
  Fleet Commander  ·  FY2026 CMMC Edition
  CMMC Level 2 / NIST 800-171 Rev 3 Diagnostic Tool
  Copyright (c) 2026 Jesse Edwards / MSTechAlpine Ventures LLC
  ---------------------------------------------------------------
  FREE for internal use by defense contractors and small business.
  Commercial use by consulting firms, C3PAOs, or MSSPs requires
  a paid license — https://mstechalpine.com/contact
  ---------------------------------------------------------------"""
    print(banner)


def summarize(results: List[CheckResult]) -> Dict[str, int]:
    summary = {"green": 0, "yellow": 0, "red": 0}
    for r in results:
        if r.status not in summary:
            summary["yellow"] += 1
        else:
            summary[r.status] += 1
    return summary


def readiness(summary: Dict[str, int]) -> int:
    total = summary["green"] + summary["yellow"] + summary["red"]
    if total == 0:
        return 0
    score = int(round((summary["green"] + 0.5 * summary["yellow"]) / total * 100))
    return score


def main() -> int:
    _print_banner()
    parser = argparse.ArgumentParser(description="MSTechAlpine Fleet Commander — CMMC Level 2 / NIST 800-171 diagnostic tool")
    parser.add_argument("--json-output", help="Write JSON results to this path")
    parser.add_argument(
        "--discover-network",
        nargs="?",
        const="auto",
        metavar="CIDR",
        help="Run nmap discovery on this subnet (e.g. 192.168.1.0/24). "
             "Omit the value to auto-detect your local subnet.",
    )
    parser.add_argument("--fleet-run", action="store_true", help="Run diagnostic orchestration across in-scope assets via SSH/SCP")
    parser.add_argument("--fleet-inventory", help="Path to discovery JSON (uses assets list) when not running --discover-network in same command")
    parser.add_argument("--fleet-user", help="SSH username for fleet orchestration")
    parser.add_argument("--fleet-ssh-key", help="Path to SSH private key for fleet orchestration")
    parser.add_argument("--fleet-ssh-port", type=int, default=22, help="SSH port for fleet orchestration")
    parser.add_argument("--fleet-output-dir", default="evidence/fleet-results", help="Output directory for per-host fleet artifacts")
    parser.add_argument(
        "--fleet-categories",
        default="CUI Asset,Security Protection Asset,Contractor Risk Managed Asset",
        help="Comma-separated category filter for fleet run",
    )
    parser.add_argument("--fleet-max-hosts", type=int, default=0, help="Optional cap for number of hosts to process (0 = all)")
    parser.add_argument("--asset-tags", help="Optional JSON map for asset categorization by IP or hostname")
    parser.add_argument("--auto-tag", action="store_true", help="After discovery, write auto-classified IP→category map to --asset-tags file (merges with existing)")
    parser.add_argument("--discovery-full-scan", action="store_true", help="Scan all 65535 ports instead of top 200 (slower, more thorough)")
    parser.add_argument("--sanitize", action="store_true", help="Anonymize usernames in output (user_01, user_02, …). Use when sharing artifacts that may expose PII/CUI metadata.")
    parser.add_argument("--discovery-output", default="evidence/fleet-discovery.json", help="Path for fleet discovery JSON output")
    parser.add_argument("--diagram-output", default="evidence/network-architecture.svg", help="Path for generated network diagram (SVG)")
    parser.add_argument("--hash-ledger", default="evidence/hash-ledger.jsonl", help="Append-only ledger path for SHA-256 artifact hashes")
    parser.add_argument("--srm", metavar="PATH", help="Path to Shared Responsibility Matrix document (PDF/XLSX/JSON). Required for cloud/FedRAMP environments.")
    parser.add_argument(
        "--sbom-output",
        metavar="PATH",
        help="Write a machine-readable SBOM to this path (e.g. evidence/sbom.json). "
             "Format set by --sbom-format. File is written mode 0600.",
    )
    parser.add_argument(
        "--sbom-format",
        choices=["cyclonedx", "spdx"],
        default="cyclonedx",
        metavar="FORMAT",
        help="SBOM output format: cyclonedx (default, CycloneDX 1.5 JSON) or spdx (SPDX 2.3 JSON).",
    )
    parser.add_argument(
        "--html-output",
        metavar="PATH",
        help="Write a self-contained HTML diagnostic report to this path (e.g. evidence/report.html). "
             "Includes findings table, remediation guidance, embedded network diagram, and hash audit trail.",
    )
    parser.add_argument(
        "--vuln-scan",
        action="store_true",
        help=(
            "Cross-reference installed packages against the OSV.dev public vulnerability database "
            "(Homebrew, PyPI, npm, dpkg, apk). Makes outbound HTTPS calls to api.osv.dev. "
            "SI.L2-3.14.1 / EO 14028 evidence."
        ),
    )
    parser.add_argument(
        "--vuln-output",
        metavar="PATH",
        help="Write a JSON vulnerability report to this path when --vuln-scan is active (e.g. evidence/vulns.json).",
    )
    parser.add_argument(
        "--cloud-api",
        action="store_true",
        help=(
            "Enable live cloud portal API checks (FedRAMP Marketplace, Azure Conditional Access, "
            "Intune device compliance, Google BeyondCorp). "
            "Requires az CLI / gcloud CLI to be installed and authenticated. "
            "Makes outbound HTTPS calls to cloud management APIs."
        ),
    )
    parser.add_argument(
        "--strict-exit-codes",
        action="store_true",
        help=(
            "Return a non-zero exit code when red findings are present. "
            "Recommended for CI pipelines and scripted gating, not interactive use."
        ),
    )
    args = parser.parse_args()

    os_name = detect_os()
    now = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")

    sanitize = getattr(args, "sanitize", False)

    def _run_check(fn, *a, label: str = "", **kw) -> CheckResult:
        """Run a single check, printing a live status line while it executes."""
        msg = label or fn.__name__
        sys.stdout.write(f"  ...  {msg:<48}\r")
        sys.stdout.flush()
        result = fn(*a, **kw)
        # Clear the status line — the final table is printed later
        sys.stdout.write(" " * (len(msg) + 10) + "\r")
        sys.stdout.flush()
        return result

    print("Running endpoint checks...")
    checks = [
        _run_check(is_admin_context, os_name,          label="admin context"),
        _run_check(check_encryption, os_name,           label="disk encryption"),
        _run_check(check_mfa_signal, os_name,           label="MFA signal"),
        _run_check(check_remote_access_shadow_tools, os_name, label="shadow remote tools"),
        _run_check(check_time_sync_signal,              label="time sync"),
        _run_check(check_patch_signal, os_name,         label="patch signal"),
        _run_check(check_account_signal, os_name, sanitize=sanitize, label="account signal"),
        _run_check(check_audit_log_signal, os_name,     label="audit log signal"),
        _run_check(check_alerting_signal, os_name,      label="alerting / SIEM signal"),
        _run_check(check_software_inventory_sbom, os_name,
                   sbom_output=getattr(args, "sbom_output", None),
                   sbom_format=getattr(args, "sbom_format", "cyclonedx"),
                   label="software inventory / SBOM"),
        _run_check(check_cloud_srm, getattr(args, "srm", None), label="cloud SRM"),
        _run_check(check_esp_scoping,                   label="ESP / MSP scoping"),
    ]

    # Vulnerability scan — opt-in because it makes outbound calls to api.osv.dev
    if getattr(args, "vuln_scan", False):
        if os.environ.get("FLEET_COMMANDER_REMOTE"):
            print(
                "NOTE: --vuln-scan skipped on remote fleet endpoint "
                "(runs on hub only to avoid per-host API calls)."
            )
        else:
            print("Running OSV.dev vulnerability scan...")
            checks.append(
                _run_check(
                    check_vuln_signal,
                    os_name,
                    getattr(args, "vuln_output", None),
                    label="OSV.dev CVE cross-reference",
                )
            )

    # Cloud portal API checks — opt-in because they make outbound HTTPS calls
    # to cloud management APIs and require authenticated CLI credentials.
    # Guard: skip entirely on remote fleet endpoints to prevent rate-limiting
    # the FedRAMP Marketplace and Microsoft Graph APIs across a fleet of hosts.
    if getattr(args, "cloud_api", False):
        if os.environ.get("FLEET_COMMANDER_REMOTE"):
            print(
                "NOTE: --cloud-api skipped — running as a remote fleet endpoint. "
                "Cloud API checks (FedRAMP Marketplace, Azure CA, Intune, BeyondCorp) "
                "run on the hub only to avoid multi-host API rate-limiting."
            )
        else:
            print("Running cloud portal API checks...")
            checks.extend([
                _run_check(check_fedramp_authorization,        label="FedRAMP Marketplace authorization"),
                _run_check(check_azure_conditional_access,     label="Azure Conditional Access policies"),
                _run_check(check_intune_device_compliance,     label="Intune device compliance"),
                _run_check(check_google_workspace_bac,         label="Google Workspace BeyondCorp"),
            ])

    fleet_inventory: List[Dict[str, Any]] = []
    discovery_check: Optional[CheckResult] = None
    effective_target: Optional[str] = None  # set when discovery actually runs
    if args.discover_network is not None:
        target_cidr = args.discover_network
        if target_cidr == "auto":
            target_cidr = detect_local_subnet()
            if target_cidr is None:
                print("WARNING: Could not auto-detect local subnet. "
                      "Pass --discover-network CIDR explicitly (e.g. 192.168.1.0/24).")
                target_cidr = ""
            else:
                print(f"Auto-detected local subnet: {target_cidr}")
        if target_cidr:
            effective_target = target_cidr
            tag_map = load_asset_tags(args.asset_tags)
            discovery_check, fleet_inventory, raw_xml = run_nmap_discovery(
                target_cidr, tag_map, full_scan=args.discovery_full_scan
            )
            checks.insert(0, discovery_check)

            discovery_payload = {
                "generated_at_utc": now,
                "target": target_cidr,
                "asset_count": len(fleet_inventory),
                "assets": fleet_inventory,
            }

            disc_path = os.path.abspath(args.discovery_output)
            os.makedirs(os.path.dirname(disc_path), exist_ok=True)
            with open(disc_path, "w", encoding="utf-8") as fh:
                json.dump(discovery_payload, fh, indent=2)
            _fix_sudo_ownership(disc_path)

            if fleet_inventory:
                generate_network_diagram_svg(fleet_inventory, args.diagram_output)
                _fix_sudo_ownership(os.path.abspath(args.diagram_output))

            # AC.L2-3.1.20 boundary violation check — runs after discovery so inventory is populated
            boundary_check = check_boundary_violations(fleet_inventory, tag_map)
            checks.append(boundary_check)

            # Update ESP scoping check with the now-available inventory
            # Replace the placeholder result added before discovery ran
            checks = [c for c in checks if c.name != "esp_scoping"]
            checks.append(check_esp_scoping(fleet_inventory))

            if getattr(args, "auto_tag", False) and fleet_inventory:
                tags_path = args.asset_tags or "evidence/asset-tags.json"
                # Load existing manual tags first so they are not overwritten
                existing: Dict[str, str] = {}
                try:
                    with open(tags_path, "r", encoding="utf-8") as _fh:
                        existing = json.load(_fh)
                except Exception:
                    pass
                # Merge: existing manual tags win; new discovered IPs get auto category
                merged = {item["ip"]: item["category"] for item in fleet_inventory}
                merged.update(existing)  # manual overrides sit on top
                os.makedirs(os.path.dirname(os.path.abspath(tags_path)), exist_ok=True)
                with open(tags_path, "w", encoding="utf-8") as _fh:
                    json.dump(merged, _fh, indent=2)
                _fix_sudo_ownership(os.path.abspath(tags_path))
                print(f"Asset tags written to: {os.path.abspath(tags_path)} ({len(merged)} entries)")

    fleet_summary: Optional[Dict[str, Any]] = None
    if args.fleet_run:
        source_assets = fleet_inventory
        if not source_assets and args.fleet_inventory:
            source_assets = load_discovery_inventory(args.fleet_inventory)

        categories = [x.strip() for x in str(args.fleet_categories).split(",")]
        fleet_check, fleet_summary = run_fleet_manager(
            assets=source_assets,
            fleet_user=args.fleet_user or "",
            ssh_key=args.fleet_ssh_key,
            ssh_port=args.fleet_ssh_port,
            output_dir=args.fleet_output_dir,
            include_categories=categories,
            max_hosts=args.fleet_max_hosts,
            ledger_path=args.hash_ledger,
        )
        checks.append(fleet_check)

    summary = summarize(checks)
    score = readiness(summary)

    print("Fleet Commander — MSTechAlpine CMMC Diagnostic")
    print(f"Timestamp (UTC): {now}")
    print(f"Host OS: {platform.platform()}")
    print("-" * 60)
    print("[Status Legend]")
    print("  GREEN  = Tool/signal detected. Verify enforcement & policy. NOT proof of compliance.")
    print("  YELLOW = Tool not found, no clear signal, or requires manual verification.")
    print("  RED    = Critical gap found. Immediate remediation needed.")
    print("-" * 60)
    for c in checks:
        print(f"[{c.status.upper():6}] {c.name}: {c.detail}")
    print("-" * 60)
    print(f"Summary: green={summary['green']} yellow={summary['yellow']} red={summary['red']}")
    print(f"\nReadiness Estimate: {score}%")
    print("FY2026 Annual Affirmation Prep: Use this output as technical fact input for the Senior Official annual affirmation (32 CFR Part 170).")
    print("\nDISCLAIMER: This score is a BASELINE SIGNAL ONLY.")
    print("  - Does NOT prove CMMC/NIST 800-171 compliance.")
    print("  - Green results mean tools exist, not that controls are effective.")
    print("  - Requires: written SSP, policy enforcement tests, auditor assessment.")
    print("  - Keep JSON output private; contains system details & usernames.")
    print("  - Script truth and executive affirmation must match. Documented red findings left unresolved are legal landmines in the current whistleblower era.")
    print("  - By default, completed interactive runs return success even when red findings are present.")
    print("  - Use --strict-exit-codes if you want non-zero exit codes for CI or scripted gating.")

    if summary["red"] > 0:
        print("\nWARNING: Red findings detected. Remediate before proceeding.")

    remediation_items = []
    for check in checks:
        guidance = get_remediation_guidance(check.name, plain_text=True)
        if guidance and check.status != "green":
            remediation_items.append(
                {
                    "name": check.name,
                    "status": check.status,
                    "guidance": guidance,
                }
            )

    if remediation_items:
        print("\nRecommended remediation steps:")
        for item in remediation_items:
            print(f"- [{item['status'].upper()}] {item['name']}")
            for line in item["guidance"].splitlines():
                print(f"    {line}")

    payload = {
        "generated_at_utc": now,
        "os": platform.platform(),
        "checks": [asdict(c) for c in checks],
        "summary": summary,
        "readiness_estimate_percent": score,
    }
    if remediation_items:
        payload["remediation"] = remediation_items
    if effective_target:
        payload["fleet_discovery"] = {
            "target": effective_target,
            "asset_count": len(fleet_inventory),
            "inventory_path": os.path.abspath(args.discovery_output),
            "diagram_path": os.path.abspath(args.diagram_output),
        }
    if fleet_summary is not None:
        payload["fleet_orchestration"] = {
            "summary": {
                "attempted": fleet_summary.get("attempted", 0),
                "executed": fleet_summary.get("executed", 0),
                "failed": fleet_summary.get("failed", 0),
                "manifest_path": os.path.abspath(os.path.join(args.fleet_output_dir, "fleet-manifest.json")),
            }
        }

    sbom_path_written: Optional[str] = None
    if getattr(args, "sbom_output", None):
        sbom_path_written = os.path.abspath(args.sbom_output)
        payload["sbom"] = {
            "path": sbom_path_written,
            "format": getattr(args, "sbom_format", "cyclonedx"),
        }

    vuln_path_written: Optional[str] = getattr(args, "vuln_output", None)
    if vuln_path_written:
        vuln_path_written = os.path.abspath(vuln_path_written)
        payload["vuln_scan"] = {"path": vuln_path_written}

    if args.json_output:
        out_path = os.path.abspath(args.json_output)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        # Restrict file permissions on Unix to owner only (contains sensitive data)
        if os_name in {"linux", "darwin"}:
            try:
                os.chmod(out_path, 0o600)
            except Exception:
                pass
        _fix_sudo_ownership(out_path)
        print(f"JSON written to: {out_path}")
        print(f"CAUTION: JSON file contains usernames and system details. Keep private. Do not commit to git.")

        digest = append_hash_ledger(out_path, args.hash_ledger)
        if digest:
            print(f"SHA-256 ledger updated: {os.path.abspath(args.hash_ledger)}")
            print(f"Artifact SHA-256: {digest}")
        else:
            print("WARNING: Could not update SHA-256 ledger for diagnostic artifact.")

    if effective_target:
        disc_path = os.path.abspath(args.discovery_output)
        print(f"Fleet discovery JSON: {disc_path}")
        if os.path.exists(os.path.abspath(args.diagram_output)):
            print(f"Network diagram SVG: {os.path.abspath(args.diagram_output)}")

        digest = append_hash_ledger(disc_path, args.hash_ledger)
        if digest:
            print(f"Discovery SHA-256 ledger updated: {os.path.abspath(args.hash_ledger)}")
            print(f"Discovery artifact SHA-256: {digest}")
        else:
            print("WARNING: Could not update SHA-256 ledger for discovery artifact.")

    if sbom_path_written and os.path.exists(sbom_path_written):
        fmt_label = getattr(args, "sbom_format", "cyclonedx").upper()
        print(f"SBOM ({fmt_label}) written: {sbom_path_written}")
        print("CAUTION: SBOM enumerates the full software attack surface. Keep private.")
        digest = append_hash_ledger(sbom_path_written, args.hash_ledger)
        if digest:
            print(f"SBOM SHA-256 ledger updated: {os.path.abspath(args.hash_ledger)}")
            print(f"SBOM artifact SHA-256: {digest}")

    if vuln_path_written and os.path.exists(vuln_path_written):
        print(f"Vuln report written: {vuln_path_written}")
        print("CAUTION: Vuln report lists exploitable packages. Keep private.")
        digest = append_hash_ledger(vuln_path_written, args.hash_ledger)
        if digest:
            print(f"Vuln report SHA-256: {digest}")

    html_output = getattr(args, "html_output", None)
    if html_output:
        html_path = os.path.abspath(html_output)
        diagram_path = os.path.abspath(args.diagram_output) if effective_target else None
        write_html_report(
            checks=checks,
            summary=summary,
            readiness_pct=score,
            metadata={
                "generated_at_utc": now,
                "os": platform.platform(),
                "hostname": platform.node(),
                "subnet": effective_target or "",
            },
            output_path=html_path,
            diagram_svg_path=diagram_path,
            sbom_path=sbom_path_written,
            hash_ledger_path=os.path.abspath(args.hash_ledger),
        )
        _fix_sudo_ownership(html_path)
        print(f"HTML report written: {html_path}")
        print(f"Open in browser:     file://{html_path}")
        digest = append_hash_ledger(html_path, args.hash_ledger)
        if digest:
            print(f"Report SHA-256: {digest}")

    if fleet_summary is not None:
        print(
            "Fleet Manager Summary: "
            f"attempted={fleet_summary.get('attempted', 0)} "
            f"executed={fleet_summary.get('executed', 0)} "
            f"failed={fleet_summary.get('failed', 0)}"
        )
        print(f"Fleet manifest: {os.path.abspath(os.path.join(args.fleet_output_dir, 'fleet-manifest.json'))}")

    if summary["red"] > 0:
        print("Run completed. Red findings were detected and need remediation.")
        if args.strict_exit_codes:
            print("Strict mode enabled: returning a non-zero exit code for automation.")
            return 2
        print("Interactive mode: returning success so the report can be reviewed normally.")
        return 0

    print("Run completed. No red findings were detected.")
    return 0


if __name__ == "__main__":
    # Support direct execution: python3 /path/to/cli.py
    # The relative imports (from ._checks import ...) require the package to be on sys.path.
    # When run as __main__ they are already resolved. If not (e.g. old Python path edge case),
    # fall back to inserting the src directory so the package is importable.
    import importlib
    try:
        importlib.import_module("mstechalpine_fleet_commander._checks")
    except ModuleNotFoundError:
        import pathlib
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    sys.exit(main())
