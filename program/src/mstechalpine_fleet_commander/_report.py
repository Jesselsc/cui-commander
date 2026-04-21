"""
MSTechAlpine Fleet Commander — HTML Report Generator

Produces a self-contained, single-file HTML artifact suitable for sharing
with C3PAO assessors or executive leadership. All CSS is inline; no external
network resources are required. The file is written mode 0600.
"""
from __future__ import annotations

import html
import json
import os
import re
from typing import Any, Dict, List, Optional

from ._models import CheckResult

# ---------------------------------------------------------------------------
# CMMC control cross-reference table
# ---------------------------------------------------------------------------
_CMMC_MAP: Dict[str, str] = {
    "admin_context":           "AC.L1-3.1.1",
    "disk_encryption":         "SC.L2-3.13.16",
    "mfa_signal":              "IA.L2-3.5.3",
    "remote_tool_signal":      "AC.L2-3.1.20",
    "time_sync_signal":        "AU.L2-3.3.7",
    "patch_signal":            "SI.L2-3.14.1",
    "account_signal":          "AC.L2-3.1.5",
    "audit_log_signal":        "AU.L2-3.3.1",
    "alerting_signal":         "IR.L2-3.6.1",
    "software_inventory_sbom": "SR.L2-3.17.1",
    "vuln_signal":             "SI.L2-3.14.1 / SA.L2-3.15.1 / EO 14028",
    "cloud_srm":               "CA.L2-3.12.4",
    "fedramp_authorization":   "CA.L2-3.12.4 / DFARS 252.204-7012",
    "azure_conditional_access":"IA.L2-3.5.3 / AC.L2-3.1.3",
    "intune_device_compliance":"AC.L2-3.1.3 / SC.L2-3.13.3",
    "google_workspace_bac":    "AC.L2-3.1.1 / IA.L2-3.5.3",
    "boundary_validation":     "AC.L2-3.1.20",
    "esp_scoping":             "32 CFR 170.19(c)",
    "fleet_discovery":         "CA.L2-3.12.2",
}

# Remediation guidance for non-green findings (used in the remediation section)
_REMEDIATION: Dict[str, str] = {
    "admin_context": (
        "Re-run the tool with <code>sudo</code> (macOS/Linux) or as an elevated Administrator (Windows) "
        "so all OS checks can execute with full privilege."
    ),
    "disk_encryption": (
        "<strong>macOS</strong>: <code>sudo fdesetup enable</code> — requires reboot.<br>"
        "<strong>Linux</strong>: Configure LUKS at install time (dm-crypt) or use <code>cryptsetup</code> on a new volume.<br>"
        "<strong>Windows</strong>: Enable BitLocker via Group Policy or <code>manage-bde -on C:</code>.<br>"
        "Pair with a FIPS 140-3 validated module. See NIST SP 800-111."
    ),
    "mfa_signal": (
        "Enroll all user accounts in phishing-resistant MFA (FIDO2 / PIV). "
        "<strong>macOS</strong>: enable Touch ID + SmartCard pairing or use a Passkey-capable IdP (Okta, Microsoft Entra). "
        "<strong>Windows</strong>: configure Windows Hello for Business or YubiKey via ADFS/Entra. "
        "IA.L2-3.5.3 requires hardware-bound authenticators for CUI access."
    ),
    "remote_tool_signal": (
        "Identify and remove any unapproved remote-access tools (TeamViewer, AnyDesk, ngrok, etc.). "
        "Document approved RMM tools in your SSP and restrict to named vendor IPs via firewall. "
        "AC.L2-3.1.20 prohibits uncontrolled connections to external systems."
    ),
    "time_sync_signal": (
        "<strong>macOS</strong>: <code>sudo sntp -sS time.nist.gov</code> or configure NTP via <code>systemsetup -setnetworktimeserver</code>.<br>"
        "<strong>Linux</strong>: Install chronyd (<code>dnf install chrony</code>) and set <code>server time.nist.gov iburst</code>.<br>"
        "Drift &gt;1 second invalidates log correlation and can break Kerberos."
    ),
    "patch_signal": (
        "<strong>macOS</strong>: <code>softwareupdate --install --all</code>.<br>"
        "<strong>Linux</strong>: <code>dnf upgrade -y</code> / <code>apt-get dist-upgrade -y</code>.<br>"
        "<strong>Windows</strong>: Ensure Windows Update / WSUS is active. "
        "SI.L2-3.14.1 requires patching within a defined window (≤30 days critical). "
        "Automate with an MDM or patch-management tool."
    ),
    "account_signal": (
        "Audit local accounts and disable any non-essential shared or service accounts. "
        "Name accounts uniquely (no 'admin', 'user', 'test'). "
        "AC.L2-3.1.5 requires least privilege. "
        "Use PAM (Linux) or Local Security Policy (Windows) to enforce password complexity."
    ),
    "audit_log_signal": (
        "<strong>macOS</strong>: Unified log is enabled by default — verify with <code>log show --last 1h</code>.<br>"
        "<strong>Linux</strong>: Install and configure <code>auditd</code> with STIG rules (<code>sudo apt install auditd</code>).<br>"
        "<strong>Windows</strong>: Enable Advanced Audit Policy via GPO. "
        "AU.L2-3.3.1 requires successful/failed logon, object access, and privilege use events."
    ),
    "alerting_signal": (
        "Deploy one of:<br>"
        "&bull; <strong>Wazuh</strong> (open source, FedRAMP-friendly): "
        "<a href='https://documentation.wazuh.com/current/installation-guide/' target='_blank'>installation guide</a><br>"
        "&bull; <strong>Elastic Agent</strong>: <code>brew install elastic-stack</code> → point to Elastic Cloud or on-prem.<br>"
        "&bull; <strong>Splunk Universal Forwarder</strong>: configure to forward to a Splunk indexer.<br>"
        "IR.L2-3.6.1 requires a 1-hour incident detection and escalation window. "
        "Agent must show active socket connection to its manager."
    ),
    "software_inventory_sbom": (
        "Review the generated SBOM for high-risk packages (CUI-processing apps, ERPs, custom tools). "
        "SR.L2-3.17.1 requires a formal software bill of materials. "
        "Subscribe components to a vulnerability feed (OSV, NVD) and triage CRITICAL CVEs within 30 days."
    ),
    "vuln_signal": (
        "Remediate CRITICAL CVEs immediately; HIGH within 30 days; MEDIUM within 90 days.<br>"
        "Use the generated <code>vulns.json</code> report to triage. Check each package:<br>"
        "&bull; <code>pip install --upgrade &lt;package&gt;</code> (PyPI)<br>"
        "&bull; <code>brew upgrade &lt;formula&gt;</code> (Homebrew)<br>"
        "&bull; <code>npm update -g &lt;package&gt;</code> (npm)<br>"
        "Track remediation in your POA&amp;M. SI.L2-3.14.1 / SA.L2-3.15.1 / EO 14028."
    ),
    "cloud_srm": (
        "Create a Shared Responsibility Matrix documenting which NIST 800-171 controls are met by "
        "your cloud provider vs your organization. Include the SRM as SSP Appendix D. "
        "Reference the cloud provider's FedRAMP package at marketplace.fedramp.gov."
    ),
    "fedramp_authorization": (
        "Verify your cloud service providers hold current FedRAMP authorizations at "
        "<a href='https://marketplace.fedramp.gov' target='_blank'>marketplace.fedramp.gov</a>. "
        "Link the ATO record number in your SSP. "
        "DFARS 252.204-7012 prohibits storing CUI on non-FedRAMP authorized systems."
    ),
    "azure_conditional_access": (
        "Install Azure CLI: <code>brew install azure-cli</code> (macOS) | "
        "<code>winget install Microsoft.AzureCLI</code> (Windows).<br>"
        "Then configure in Azure Portal → Entra ID → Security → Conditional Access:<br>"
        "1. MFA policy covering all users (phishing-resistant preferred).<br>"
        "2. Device compliance requirement (Intune-enrolled Compliant devices only).<br>"
        "3. Legacy auth block (Exchange ActiveSync / other legacy).<br>"
        "IA.L2-3.5.3 / AC.L2-3.1.3."
    ),
    "intune_device_compliance": (
        "Install Azure CLI and authenticate (<code>az login</code>).<br>"
        "In Intune Portal (endpoint.microsoft.com) → Devices → Monitor → Device compliance:<br>"
        "all company devices must show <em>Compliant</em>.<br>"
        "Configure compliance policies for encryption, OS version, firewall, and antivirus.<br>"
        "AC.L2-3.1.3 / SC.L2-3.13.3."
    ),
    "google_workspace_bac": (
        "Install gcloud CLI: <a href='https://cloud.google.com/sdk/docs/install' target='_blank'>cloud.google.com/sdk/docs/install</a>.<br>"
        "Configure access levels in Google Admin Console → Security → Context-Aware Access. "
        "Assign levels to Drive, Gmail, Meet, and any CUI-scoped apps.<br>"
        "AC.L2-3.1.1 / IA.L2-3.5.3."
    ),
    "boundary_validation": (
        "Review discovered assets and update your asset-tags.json to correctly classify each IP. "
        "Any CUI Asset must be documented in the SSP Boundary diagram. "
        "AC.L2-3.1.20 prohibits unauthorized connections between CUI systems and external networks."
    ),
    "esp_scoping": (
        "Audit open connections: <code>ss -tnp</code> (Linux) / <code>netstat -tn</code>.<br>"
        "Document all managed service providers in the SSP and restrict their access to named source IPs. "
        "32 CFR 170.19(c) requires ESPs to be explicitly in scope."
    ),
    "fleet_discovery": (
        "Ensure all in-scope assets are reachable via nmap. "
        "Update asset-tags.json to classify each discovered host as CUI Asset, Security Protection Asset, "
        "Out of Scope Asset, or Contractor Risk Managed Asset. "
        "CA.L2-3.12.2 requires a current network diagram."
    ),
}


def get_remediation_guidance(check_name: str, plain_text: bool = False) -> Optional[str]:
  """Return remediation guidance for a finding, optionally normalized for CLI/JSON use."""
  guidance = _REMEDIATION.get(check_name)
  if not guidance:
    return None
  if not plain_text:
    return guidance

  text = guidance.replace("<br>", "\n").replace("<br/>", "\n").replace("<br />", "\n")
  text = text.replace("&bull;", "- ")
  text = re.sub(r"<[^>]+>", "", text)
  text = html.unescape(text)
  text = re.sub(r"\n{3,}", "\n\n", text)
  return text.strip()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _badge(status: str) -> str:
    colours = {
        "green":  ("d4edda", "155724"),
        "yellow": ("fff3cd", "856404"),
        "red":    ("f8d7da", "721c24"),
    }
    bg, fg = colours.get(status.lower(), ("e2e3e5", "383d41"))
    label = status.upper()
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;'
        f'font-size:0.72rem;font-weight:700;letter-spacing:0.06em;'
        f'background:#{bg};color:#{fg}">{label}</span>'
    )


def _score_style(score: int) -> tuple[str, str]:
    """Return (bg_hex, fg_hex) for the score badge."""
    if score >= 80:
        return "d4edda", "155724"
    if score >= 60:
        return "fff3cd", "856404"
    return "f8d7da", "721c24"


def _h(text: str) -> str:
    """HTML-escape and convert newlines to <br>."""
    return html.escape(str(text)).replace("\n", "<br>")


def _embed_svg(path: str) -> str:
    """Read an SVG file and return it inline, or empty string."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
        # Strip XML declaration and DOCTYPE if present
        content = content.strip()
        if content.startswith("<?xml"):
            content = content[content.index("<svg"):]
        return content
    except Exception:
        return ""


def _findings_rows(checks: List[CheckResult]) -> str:
    _STATUS_ORDER = {"red": 0, "yellow": 1, "green": 2}
    sorted_checks = sorted(checks, key=lambda c: _STATUS_ORDER.get(c.status.lower(), 3))
    rows: List[str] = []
    for c in sorted_checks:
        ctrl = _CMMC_MAP.get(c.name, "—")
        rows.append(
            f"<tr>"
            f"<td style='white-space:nowrap'>{_badge(c.status)}</td>"
            f"<td style='font-family:monospace;font-size:0.82rem;white-space:nowrap'>{_h(c.name)}</td>"
            f"<td style='font-size:0.78rem;color:#555'>{_h(ctrl)}</td>"
            f"<td style='font-size:0.85rem'>{_h(c.detail)}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _remediation_rows(checks: List[CheckResult]) -> str:
    """Return table rows for every non-green finding that has remediation guidance."""
    rows: List[str] = []
    for c in checks:
        if c.status == "green":
            continue
        guidance = _REMEDIATION.get(c.name)
        if not guidance:
            continue
        rows.append(
            f"<tr>"
            f"<td style='white-space:nowrap'>{_badge(c.status)}</td>"
            f"<td style='font-family:monospace;font-size:0.82rem;vertical-align:top;white-space:nowrap'>{_h(c.name)}</td>"
            f"<td style='font-size:0.85rem'>{guidance}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_html_report(
    checks: List[CheckResult],
    summary: Dict[str, int],
    readiness_pct: int,
    metadata: Dict[str, Any],
    output_path: str,
    diagram_svg_path: Optional[str] = None,
    sbom_path: Optional[str] = None,
    hash_ledger_path: Optional[str] = None,
) -> None:
    """Write a self-contained HTML diagnostic report.

    Parameters
    ----------
    checks:          Ordered list of CheckResult objects (all checks, including discovery).
    summary:         Dict with keys green/yellow/red.
    readiness_pct:   Integer 0-100 readiness estimate.
    metadata:        Dict with keys: generated_at_utc, os, hostname (optional), subnet (optional).
    output_path:     Absolute path for the HTML file. Written mode 0600.
    diagram_svg_path:Optional path to network-architecture.svg — embedded inline.
    sbom_path:       Optional path to sbom.json — referenced in audit section.
    hash_ledger_path:Optional path to hash-ledger.jsonl — shows last N entries.
    """
    ts   = metadata.get("generated_at_utc", "—")
    os_s = metadata.get("os", "—")
    host = metadata.get("hostname", "")
    subnet = metadata.get("subnet", "")

    bg_score, fg_score = _score_style(readiness_pct)

    # ---------- findings table ----------
    findings_html = _findings_rows(checks)

    # ---------- remediation section ----------
    rem_rows = _remediation_rows(checks)
    if rem_rows:
        remediation_section = f"""
        <div class="card">
          <h2 style="margin-top:0">Remediation Guidance</h2>
          <p style="font-size:0.85rem;color:#666;margin:0 0 12px">
            Action items for non-green findings. Address in priority order: RED first, then YELLOW.
          </p>
          <table>
            <thead><tr>
              <th>Status</th>
              <th>Check</th>
              <th>Recommended Action</th>
            </tr></thead>
            <tbody>{rem_rows}</tbody>
          </table>
        </div>"""
    else:
        remediation_section = ""

    # ---------- network diagram ----------
    if diagram_svg_path and os.path.exists(diagram_svg_path):
        svg_content = _embed_svg(diagram_svg_path)
        if svg_content:
            diagram_section = f"""
        <div class="card">
          <h2 style="margin-top:0">Network Boundary Diagram</h2>
          <p style="font-size:0.82rem;color:#666;margin:0 0 12px">
            Discovered assets. CA.L2-3.12.2 — keep current and include in SSP Appendix.
          </p>
          <div style="overflow-x:auto;border:1px solid #dde;border-radius:4px;padding:12px;background:#fafbff">
            {svg_content}
          </div>
        </div>"""
        else:
            diagram_section = ""
    else:
        diagram_section = ""

    # ---------- audit trail ----------
    ledger_rows = ""
    if hash_ledger_path and os.path.exists(hash_ledger_path):
        try:
            with open(hash_ledger_path, "r", encoding="utf-8") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
            # Show last 10 entries
            for raw in lines[-10:]:
                try:
                    entry = json.loads(raw)
                    artifact = os.path.basename(entry.get("path", "—"))
                    digest   = entry.get("sha256", "—")
                    ts_e     = entry.get("timestamp_utc", "—")
                    ledger_rows += (
                        f"<tr><td style='font-size:0.78rem'>{_h(ts_e)}</td>"
                        f"<td style='font-family:monospace;font-size:0.78rem'>{_h(artifact)}</td>"
                        f"<td style='font-family:monospace;font-size:0.72rem;color:#555;word-break:break-all'>{_h(digest)}</td></tr>"
                    )
                except Exception:
                    pass
        except Exception:
            pass

    audit_section = ""
    if ledger_rows:
        audit_section = f"""
        <div class="card">
          <h2 style="margin-top:0">Artifact Hash Ledger (last 10)</h2>
          <p style="font-size:0.82rem;color:#666;margin:0 0 12px">
            SHA-256 of each evidence artifact. Chain-of-custody for C3PAO submission.
          </p>
          <table>
            <thead><tr><th>Timestamp (UTC)</th><th>Artifact</th><th>SHA-256</th></tr></thead>
            <tbody>{ledger_rows}</tbody>
          </table>
        </div>"""

    # ---------- SBOM reference ----------
    sbom_note = ""
    if sbom_path and os.path.exists(sbom_path):
        sbom_note = (
            f"<p style='font-size:0.82rem;color:#555;margin:4px 0 0'>"
            f"SBOM written: <code>{_h(sbom_path)}</code> — include in SSP Appendix (EO 14028 / SR.L2-3.17.1).</p>"
        )

    # ---------- host meta line ----------
    meta_parts = [f"Generated: {_h(ts)}", f"Host OS: {_h(os_s)}"]
    if host:
        meta_parts.append(f"Host: {_h(host)}")
    if subnet:
        meta_parts.append(f"Subnet scanned: {_h(subnet)}")
    meta_line = " &nbsp;|&nbsp; ".join(meta_parts)

    # ---------- assemble HTML ----------
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MSTechAlpine Fleet Commander — CMMC Diagnostic Report</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',Arial,Helvetica,sans-serif;background:#f0f4f8;color:#1a1a2e;line-height:1.5}}
    a{{color:#1a4fa0}}
    h2{{font-size:1.1rem;font-weight:600;margin:0 0 12px}}
    .header{{background:#1a2744;color:#fff;padding:20px 32px 16px}}
    .header h1{{font-size:1.5rem;font-weight:700;letter-spacing:-0.02em}}
    .header .sub{{font-size:0.82rem;opacity:.75;margin:4px 0 10px}}
    .header .meta{{font-size:0.8rem;opacity:.65}}
    .content{{max-width:1100px;margin:0 auto;padding:0 16px 32px}}
    .card{{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.09);padding:20px 24px;margin:16px 0}}
    .score-row{{display:flex;align-items:center;gap:24px;flex-wrap:wrap;margin-bottom:8px}}
    .score-badge{{padding:10px 22px;border-radius:8px;font-size:2.2rem;font-weight:800;line-height:1}}
    .counter-group{{display:flex;gap:12px;flex-wrap:wrap}}
    .counter{{text-align:center;padding:10px 18px;border-radius:6px;min-width:70px}}
    .counter .num{{font-size:1.8rem;font-weight:800;line-height:1}}
    .counter .lbl{{font-size:0.68rem;text-transform:uppercase;letter-spacing:.08em;margin-top:2px}}
    table{{width:100%;border-collapse:collapse}}
    th{{text-align:left;padding:7px 10px;background:#f0f4f8;font-size:0.72rem;text-transform:uppercase;letter-spacing:.06em;color:#556;border-bottom:2px solid #dde}}
    td{{padding:9px 10px;border-bottom:1px solid #eef;vertical-align:top}}
    tr:last-child td{{border-bottom:none}}
    code{{background:#f4f6f9;border-radius:3px;padding:1px 4px;font-size:0.85em}}
    .disclaimer{{font-size:0.78rem;color:#666;line-height:1.6}}
    footer{{margin:0 0 32px;padding:16px 0 0;border-top:1px solid #dde}}
  </style>
</head>
<body>
  <div class="header">
    <h1>MSTechAlpine Fleet Commander</h1>
    <div class="sub">CMMC Level 2 / NIST 800-171 Rev 3 Diagnostic Report</div>
    <div class="meta">{meta_line}</div>
  </div>

  <div class="content">

    <div class="card">
      <h2>Baseline Readiness Estimate</h2>
      <div class="score-row">
        <div class="score-badge" style="background:#{bg_score};color:#{fg_score}">{readiness_pct}%</div>
        <div class="counter-group">
          <div class="counter" style="background:#d4edda">
            <div class="num" style="color:#155724">{summary.get('green', 0)}</div>
            <div class="lbl" style="color:#155724">Green</div>
          </div>
          <div class="counter" style="background:#fff3cd">
            <div class="num" style="color:#856404">{summary.get('yellow', 0)}</div>
            <div class="lbl" style="color:#856404">Yellow</div>
          </div>
          <div class="counter" style="background:#f8d7da">
            <div class="num" style="color:#721c24">{summary.get('red', 0)}</div>
            <div class="lbl" style="color:#721c24">Red</div>
          </div>
        </div>
      </div>
      <p style="font-size:0.82rem;color:#777;margin-top:8px">
        Score = (green + 0.5&times;yellow) / total checks &times; 100. Weighted baseline signal only — not a compliance certification.
      </p>
      {sbom_note}
    </div>

    <div class="card">
      <h2>Findings</h2>
      <table>
        <thead><tr>
          <th>Status</th>
          <th>Check</th>
          <th>CMMC Control</th>
          <th>Detail</th>
        </tr></thead>
        <tbody>{findings_html}</tbody>
      </table>
    </div>

    {remediation_section}

    {diagram_section}

    {audit_section}

    <div class="card">
      <footer>
        <p class="disclaimer">
          <strong>DISCLAIMER — BASELINE SIGNAL ONLY:</strong>
          This report was generated by an automated script and does <em>not</em> constitute a compliance
          determination, legal opinion, or CMMC certification. Green results indicate a tool or signal was
          detected — they do not prove the control is enforced, policy-complete, or effective against an
          adversary. This document must be supplemented with a written System Security Plan (SSP), formal
          policy review, penetration testing, and an accredited C3PAO assessment before any CMMC Level 2
          affirmation or DFARS 252.204-7012 representation.
        </p>
        <p class="disclaimer" style="margin-top:8px">
          <strong>PRIVACY:</strong> This report may contain hostnames, usernames, and installed-software
          details. Treat as CUI/For Official Use Only. Do not commit to version control or share publicly.
          Restrict access to personnel with a need to know.
        </p>
        <p class="disclaimer" style="margin-top:12px;font-weight:600;border-top:2px solid #c00;padding-top:8px;color:#721c24">
          INTEGRITY NOTICE: This report was generated by
          <strong>MSTechAlpine Fleet Commander</strong>.
          The integrity of this evidence can only be verified against the MSTechAlpine original
          source code. Unauthorized modifications, commercial rebranding, or removal of attribution
          void the validity of the technical truth base and constitute a breach of the
          Polyform Non-Commercial License.
        </p>
        <p class="disclaimer" style="margin-top:8px">
          &copy; 2026 Jesse Edwards / MSTechAlpine Ventures LLC &nbsp;|&nbsp;
          Commercial licensing: <a href="https://mstechalpine.com/contact">mstechalpine.com/contact</a>
          &nbsp;|&nbsp; FY2026 CMMC Level 2 &nbsp;|&nbsp; 32 CFR Part 170 &nbsp;|&nbsp; DFARS 252.204-7012
        </p>
      </footer>
    </div>

  </div>
</body>
</html>"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    try:
        os.chmod(output_path, 0o600)
    except Exception:
        pass
