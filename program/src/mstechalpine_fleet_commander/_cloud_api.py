from __future__ import annotations

"""_cloud_api.py — Live Cloud Portal Audit Module (Phase 3).

Bridges the endpoint/cloud gap in CMMC Level 2 assessments by probing live
cloud management APIs for control drift that *cannot* be detected from the
local machine alone.

Three weaknesses in a cloud-first setup that local endpoint checks miss:

A. The FedRAMP Equivalency Trap
   Under DFARS 252.204-7012, placing CUI in a cloud that is not FedRAMP
   Moderate Authorized is a major violation. This module queries the FedRAMP
   Marketplace API to confirm your CSP holds an active ATO.

B. Configuration Drift in the Portal
   A user could log in from a non-compliant personal PC if Conditional Access
   (CA) policies are weak. The local script cannot see this. This module reads
   active CA policies via Microsoft Graph and flags missing MFA grants, missing
   device-compliance gates, and legacy-auth bypass openings.

C. The SPA (Security Protection Asset) Gap
   Entra ID and Google Workspace are Security Protection Assets in 2026. This
   module audits the identity provider directly — Intune device compliance and
   Google BeyondCorp / Context-Aware Access.

All four checks are opt-in (--cloud-api flag) because they make outbound
network calls or require authenticated cloud CLIs. They degrade gracefully:
if a CLI is absent or credentials are missing the result is YELLOW (manual
verification required), not RED, so an air-gapped machine is never penalised
incorrectly.

Checks provided:
  1. check_fedramp_authorization()    — FedRAMP Marketplace ATO verification
  2. check_azure_conditional_access() — Microsoft Graph CA policy audit
  3. check_intune_device_compliance() — Intune managed device compliance
  4. check_google_workspace_bac()     — Google BeyondCorp / Context-Aware Access
"""

import ipaddress
import json
import os
import shutil
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from ._models import CheckResult
from ._utils import run_cmd


# ---------------------------------------------------------------------------
# Trusted API endpoints — only these host prefixes are ever contacted.
# _safe_json_get() refuses to connect to any other URL.
# ---------------------------------------------------------------------------
_FEDRAMP_API_URL = "https://marketplace.fedramp.gov/api/products"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_GRAPH_RESOURCE = "https://graph.microsoft.com"

# Cap raw API responses to 4 MB to prevent memory exhaustion from unexpected payloads.
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


# ---------------------------------------------------------------------------
# Security helper — block HTTP redirects to prevent SSRF via redirect chain.
# ---------------------------------------------------------------------------
class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return None from redirect_request so OpenerDirector never follows one."""

    def redirect_request(  # type: ignore[override]
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _safe_json_get(
    url: str,
    token: Optional[str] = None,
    timeout: int = 10,
) -> Optional[Any]:
    """Fetch a trusted cloud API URL and return parsed JSON.

    Security controls (defence-in-depth, layered):
    1. URL allowlist  — URL must start with a known trusted prefix.
       Prevents fetching arbitrary or user-supplied URLs entirely.
    2. DNS pre-resolution guard  — resolves the hostname and rejects any
       address in private, loopback, link-local, or reserved space
       (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x, etc.).
       Protects against DNS rebinding and hijacked resolution that could
       redirect the script to scan cloud metadata endpoints (169.254.169.254).
       Fails closed: if DNS resolution fails entirely, the fetch is blocked.
    3. Redirect blocking  — _NoRedirectHandler prevents SSRF via redirect chain.
    4. Response size cap  — body capped at _MAX_RESPONSE_BYTES.
    5. TLS always on      — SSL certificate validation is never disabled.
    """
    # --- Layer 1: URL allowlist ---
    allowed_prefixes = (_FEDRAMP_API_URL, _GRAPH_BASE)
    if not any(url.startswith(p) for p in allowed_prefixes):
        return None

    # --- Layer 2: DNS pre-resolution / SSRF guard ---
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        if not hostname:
            return None
        # Resolve *all* returned addresses; reject if any resolve to private space.
        addr_infos = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in addr_infos:
            raw_ip = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(raw_ip)
                if (
                    ip_obj.is_private
                    or ip_obj.is_loopback
                    or ip_obj.is_link_local
                    or ip_obj.is_reserved
                    or ip_obj.is_multicast
                ):
                    return None  # Block: resolves to internal/metadata IP
            except ValueError:
                return None  # Unparseable IP — block
    except Exception:
        return None  # Fail-closed: DNS error → do not connect

    hdrs: Dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": "MSTechAlpine-FleetCommander/2.0",
    }
    if token:
        hdrs["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=hdrs)
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            raw = resp.read(_MAX_RESPONSE_BYTES)
            return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _paginated_graph_get(
    url: str,
    token: str,
    timeout: int = 10,
    max_pages: int = 50,
) -> Optional[List[Dict[str, Any]]]:
    """Follow Microsoft Graph @odata.nextLink pages and return all items.

    Returns None if the first request fails (API unreachable / no permission),
    so callers can distinguish "error" from "empty result set".

    Pagination cap: max_pages * $top items (default 50 * 200 = 10 000 devices).
    Each nextLink is validated against _GRAPH_BASE before fetching — a
    malformed or redirected nextLink that points outside Graph is silently
    dropped and pagination stops.
    """
    first = _safe_json_get(url, token=token, timeout=timeout)
    if not isinstance(first, dict):
        return None  # First-page error — caller handles

    items: List[Dict[str, Any]] = list(first.get("value") or [])
    next_link: Optional[str] = first.get("@odata.nextLink")

    for _ in range(max_pages - 1):
        if not next_link or not isinstance(next_link, str):
            break
        # Defense-in-depth: nextLink must remain within Graph API.
        # _safe_json_get enforces this too, but the explicit check here
        # makes the policy visible and stops the loop early.
        if not next_link.startswith(_GRAPH_BASE):
            break
        page = _safe_json_get(next_link, token=token, timeout=timeout)
        if not isinstance(page, dict):
            break
        items.extend(page.get("value") or [])
        next_link = page.get("@odata.nextLink")

    return items


def _detect_configured_csps() -> List[str]:
    """Return a list of CSP slugs inferred from local CLI tools and config dirs."""
    found: List[str] = []
    if shutil.which("az") or os.path.isdir(os.path.expanduser("~/.azure")):
        found.append("azure")
    if shutil.which("aws") or os.path.isdir(os.path.expanduser("~/.aws")):
        found.append("aws")
    if shutil.which("gcloud") or os.path.isdir(os.path.expanduser("~/.config/gcloud")):
        found.append("gcp")
    return found


def _get_az_graph_token() -> Tuple[Optional[str], str]:
    """Retrieve a Microsoft Graph Bearer token from the az CLI credential cache.

    Returns (token_string, error_message).
    On success: token is set as a string, error is empty.
    On failure: token is None, error describes the problem.

    The token is never written to disk — it lives in-memory only.
    """
    if not shutil.which("az"):
        return None, (
            "az CLI not installed. "
            "Install: brew install azure-cli (macOS) | "
            "winget install Microsoft.AzureCLI (Windows) | "
            "https://aka.ms/installazureclilinux (Linux)"
        )

    rc, _, _ = run_cmd(["az", "account", "show"], timeout=10)
    if rc != 0:
        return None, (
            "Not signed in to Azure CLI. "
            "Run: az login   (or: az login --use-device-code for headless environments)"
        )

    rc, out, err = run_cmd(
        [
            "az", "account", "get-access-token",
            "--resource", _GRAPH_RESOURCE,
            "--query", "accessToken",
            "--output", "tsv",
        ],
        timeout=15,
    )
    if rc != 0 or not out.strip():
        return None, f"Token acquisition failed: {(err or '').strip()[:200]}"

    token = out.strip()
    if len(token) < 30:
        return None, "Graph token response appears invalid (too short)"

    return token, ""


def _analyze_ca_policies(
    policies: List[Dict[str, Any]],
) -> Tuple[List[str], List[str]]:
    """Analyse a list of Conditional Access policy objects.

    Returns (gap_messages, passing_messages). Gaps are CMMC-relevant control
    holes; passing items are confirmed controls.

    Three controls checked per NIST 800-171 Rev 3 / CMMC Level 2:
    1. MFA or phishing-resistant authentication strength (IA.L2-3.5.3)
    2. Device compliance / Hybrid-join gate (AC.L2-3.1.3)
    3. Legacy authentication block — prevents MFA bypass via basic auth (IA.L2-3.5.3)
    """
    gaps: List[str] = []
    passing: List[str] = []

    enabled = [p for p in policies if isinstance(p, dict) and p.get("state") == "enabled"]
    if not enabled:
        gaps.append("No Conditional Access policies in 'enabled' state")
        return gaps, passing

    # --- 1. MFA / phishing-resistant auth strength ---
    mfa_names: List[str] = []
    for p in enabled:
        gc = p.get("grantControls") or {}
        controls_lower = [str(x).lower() for x in (gc.get("builtInControls") or [])]
        has_auth_strength = bool(gc.get("authenticationStrength"))
        if "mfa" in controls_lower or has_auth_strength:
            mfa_names.append(p.get("displayName") or "unnamed")

    if mfa_names:
        passing.append(f"MFA / auth-strength policies ({len(mfa_names)}): {', '.join(mfa_names[:3])}")
    else:
        gaps.append(
            "No CA policy enforces MFA or a phishing-resistant authentication strength. "
            "Users can authenticate with a password alone — IA.L2-3.5.3 gap."
        )

    # --- 2. Device compliance / Hybrid-join gate ---
    compliance_names: List[str] = []
    for p in enabled:
        gc = p.get("grantControls") or {}
        controls_lower = [str(x).lower() for x in (gc.get("builtInControls") or [])]
        if "compliantdevice" in controls_lower or "domainjoineddevice" in controls_lower:
            compliance_names.append(p.get("displayName") or "unnamed")

    if compliance_names:
        passing.append(f"Device-compliance-gating policies: {', '.join(compliance_names[:3])}")
    else:
        gaps.append(
            "No CA policy requires a compliant or Hybrid-joined device. "
            "Users can authenticate from personal unmanaged PCs — AC.L2-3.1.3 gap."
        )

    # --- 3. Legacy authentication block ---
    legacy_block_names: List[str] = []
    for p in enabled:
        conds = p.get("conditions") or {}
        client_app_types: List[str] = conds.get("clientAppTypes") or []
        gc = p.get("grantControls") or {}
        controls_lower = [str(x).lower() for x in (gc.get("builtInControls") or [])]
        targets_legacy = any(
            x in client_app_types for x in ("exchangeActiveSync", "other")
        )
        if "block" in controls_lower and targets_legacy:
            legacy_block_names.append(p.get("displayName") or "unnamed")

    if legacy_block_names:
        passing.append(f"Legacy-auth-blocking policies: {', '.join(legacy_block_names[:3])}")
    else:
        gaps.append(
            "No CA policy blocks legacy authentication (Exchange ActiveSync / basic auth). "
            "Legacy auth bypasses MFA entirely — critical IA.L2-3.5.3 gap."
        )

    return gaps, passing


# ---------------------------------------------------------------------------
# Public check functions
# ---------------------------------------------------------------------------

def check_fedramp_authorization() -> CheckResult:
    """Query the FedRAMP Marketplace to confirm your CSP holds an active ATO.

    Under DFARS 252.204-7012, CUI placed in a non-FedRAMP Moderate (or higher)
    cloud system is a reportable incident. This check:

      1. Detects which CSP(s) are configured (az, aws, gcloud CLI / config dirs).
      2. Queries the public FedRAMP Marketplace API (no auth required).
      3. Falls back to a curated known-authorized list when the API is offline.

    Returns GREEN (marketplace confirmed), YELLOW (offline fallback / no CSP
    detected), or RED (CSP not found in authorized products list).
    """
    providers = _detect_configured_csps()

    if not providers:
        return CheckResult(
            "fedramp_authorization",
            "yellow",
            "No cloud provider CLI or config directory detected "
            "(az / aws / gcloud, ~/.azure, ~/.aws, ~/.config/gcloud). "
            "If CUI is processed in any cloud environment, install the provider CLI "
            "and re-run with --cloud-api. "
            "DFARS 252.204-7012 requires FedRAMP Moderate Equivalency for all CUI cloud systems. "
            "Document your CSP's ATO reference in the SSP Appendix.",
        )

    # --- Live FedRAMP Marketplace query (public API, no credentials required) ---
    data = _safe_json_get(f"{_FEDRAMP_API_URL}?status=Authorized&sort=productName", timeout=12)
    products: Optional[List[Dict[str, Any]]] = None
    if isinstance(data, dict):
        # Marketplace API wraps results in "data", "products", or "value" depending on version
        products = data.get("data") or data.get("products") or data.get("value")
    elif isinstance(data, list):
        products = data

    if products and isinstance(products, list):
        names_lower = {str(p.get("productName", "")).lower() for p in products}

        keyword_map: Dict[str, List[str]] = {
            "azure": ["microsoft azure", "azure government", "office 365 gcc"],
            "aws":   ["amazon web services", "aws govcloud"],
            "gcp":   ["google cloud", "google workspace"],
        }
        status_lines: List[str] = []
        all_found = True

        for prov in providers:
            kws = keyword_map.get(prov, [prov])
            matches = sorted(n for n in names_lower if any(k in n for k in kws))
            if matches:
                sample = ", ".join(matches[:2])
                status_lines.append(f"{prov.upper()}: authorized ({sample})")
            else:
                status_lines.append(f"{prov.upper()}: NOT FOUND in FedRAMP Authorized list")
                all_found = False

        detail = " | ".join(status_lines)

        if all_found:
            return CheckResult(
                "fedramp_authorization",
                "green",
                f"FedRAMP Marketplace confirmed CSP authorization: {detail}. "
                "Verify your specific service offering (tier / region) is covered — "
                "not just the vendor brand name. "
                "Include the CSP ATO reference number and Body of Evidence (BoE) in SSP Appendix D. "
                "DFARS 252.204-7012.",
            )

        return CheckResult(
            "fedramp_authorization",
            "red",
            f"FedRAMP Marketplace check failed for one or more CSPs: {detail}. "
            "DFARS 252.204-7012 requires FedRAMP Moderate Equivalency for all systems handling CUI. "
            "Switch to a FedRAMP-authorized offering or obtain a written equivalency determination "
            "from your Authorizing Official. marketplace.fedramp.gov.",
        )

    # --- Offline fallback — marketplace API unreachable ---
    _KNOWN_AUTHORIZED: Dict[str, str] = {
        "azure": (
            "Microsoft Azure / GCC High — FedRAMP High "
            "(verify your specific SKU at marketplace.fedramp.gov)"
        ),
        "aws": (
            "AWS GovCloud / Commercial East-West — FedRAMP High / Moderate "
            "(verify your account type and region)"
        ),
        "gcp": (
            "Google Cloud Platform / Google Workspace — FedRAMP High / Moderate "
            "(verify the specific service tier)"
        ),
    }
    known_notes = [_KNOWN_AUTHORIZED.get(p, f"{p}: unknown status") for p in providers]

    return CheckResult(
        "fedramp_authorization",
        "yellow",
        f"FedRAMP Marketplace API unreachable (offline or network-restricted environment). "
        f"Detected CSPs: {', '.join(p.upper() for p in providers)}. "
        f"Known authorization status (curated list): {' | '.join(known_notes)}. "
        "Manually confirm at marketplace.fedramp.gov and link the ATO record in your SSP. "
        "DFARS 252.204-7012.",
    )


def check_azure_conditional_access() -> CheckResult:
    """Audit Microsoft Entra ID Conditional Access policies via Microsoft Graph.

    Looks for three CMMC-required controls that local endpoint tools cannot see:
      - MFA or phishing-resistant auth strength (IA.L2-3.5.3)
      - Device compliance / Hybrid-join gate (AC.L2-3.1.3)
      - Legacy authentication block (prevents basic-auth MFA bypass — IA.L2-3.5.3)

    Requires: az CLI installed and authenticated.
    Minimum role: Security Reader or Global Reader in Entra ID.
    The token is retrieved from the local az CLI credential cache — no
    passwords are read or written by this tool.

    Returns:
      GREEN  — all three controls confirmed active.
      YELLOW — az CLI absent / not signed in, OR one gap detected.
      RED    — zero CA policies found, OR two or more gaps detected.
    """
    token, err = _get_az_graph_token()
    if not token:
        return CheckResult(
            "azure_conditional_access",
            "yellow",
            f"Cannot probe Azure CA policies: {err}. "
            "Manual check: Azure Portal → Entra ID → Security → Conditional Access. "
            "Verify: (1) MFA policy covering all users, "
            "(2) device compliance requirement, "
            "(3) legacy auth block (Exchange ActiveSync / other). "
            "IA.L2-3.5.3 / AC.L2-3.1.3.",
        )

    data = _safe_json_get(f"{_GRAPH_BASE}/identity/conditionalAccess/policies", token=token)
    if not isinstance(data, dict):
        return CheckResult(
            "azure_conditional_access",
            "yellow",
            "Microsoft Graph returned no data for Conditional Access policies. "
            "Confirm your account has 'Security Reader' or 'Global Reader' role in Entra ID. "
            "Manual verification required: Azure Portal → Entra ID → Security → Conditional Access.",
        )

    policies: List[Dict[str, Any]] = data.get("value", [])
    if not isinstance(policies, list):
        policies = []

    if not policies:
        return CheckResult(
            "azure_conditional_access",
            "red",
            "Zero Conditional Access policies found in this tenant. "
            "Users can authenticate without MFA from any device on any network. "
            "Create three CA policies immediately: "
            "(1) require MFA for all users on all apps, "
            "(2) require device compliance for CUI workloads, "
            "(3) block legacy authentication (Exchange ActiveSync / other). "
            "IA.L2-3.5.3 / AC.L2-3.1.3 critical gap.",
        )

    enabled_count = sum(
        1 for p in policies if isinstance(p, dict) and p.get("state") == "enabled"
    )
    gaps, passing = _analyze_ca_policies(policies)

    if not gaps:
        return CheckResult(
            "azure_conditional_access",
            "green",
            f"Conditional Access policies verified ({enabled_count}/{len(policies)} enabled). "
            f"Controls confirmed: {'; '.join(passing)}. "
            "Also validate named-location exclusions, sign-in risk policies, and "
            "that no break-glass accounts are excluded from MFA. "
            "IA.L2-3.5.3 / AC.L2-3.1.3.",
        )

    status = "red" if len(gaps) >= 2 else "yellow"
    return CheckResult(
        "azure_conditional_access",
        status,
        f"Conditional Access gaps detected ({enabled_count}/{len(policies)} enabled). "
        f"Gaps: {' | '.join(gaps)}. "
        + (f"Passing: {'; '.join(passing)}. " if passing else "")
        + "Remediate in Azure Portal → Entra ID → Security → Conditional Access. "
        "IA.L2-3.5.3 / AC.L2-3.1.3.",
    )


def check_intune_device_compliance() -> CheckResult:
    """Audit Intune device enrollment and compliance via Microsoft Graph.

    Without central MDM enforcement, the local Fleet Commander check covers
    only the single host it runs on. Intune compliance policies enforce
    BitLocker / FileVault, patch level, and antivirus across the entire fleet.

    Queries company-owned managed devices and flags:
      - Devices whose complianceState is not 'compliant'.
      - Devices where isEncrypted is false.

    Requires: az CLI with 'Intune Service Administrator' or 'Global Reader'
    Azure AD role. Follows @odata.nextLink pagination so organisations with
    200+ devices are fully covered (capped at 50 pages × 200 = 10 000 devices).

    Returns:
      GREEN  — all enrolled company devices are compliant and encrypted.
      YELLOW — az CLI absent / no Intune permission / no devices enrolled.
      RED    — one or more non-compliant or unencrypted company devices found.
    """
    token, err = _get_az_graph_token()
    if not token:
        return CheckResult(
            "intune_device_compliance",
            "yellow",
            f"Cannot probe Intune: {err}. "
            "Manual check: Intune Portal (endpoint.microsoft.com) → Devices → "
            "Monitor → Device compliance. Confirm all company devices show 'Compliant'. "
            "AC.L2-3.1.3 / SC.L2-3.13.3.",
        )

    # $top=200 is the page size; _paginated_graph_get follows nextLink for the full list.
    # $select limits each record to the minimum non-PII fields needed for compliance checks.
    url = (
        f"{_GRAPH_BASE}/deviceManagement/managedDevices"
        "?$select=deviceName,complianceState,isEncrypted,operatingSystem,osVersion"
        "&$top=200"
        "&$filter=managedDeviceOwnerType eq 'company'"
    )
    devices = _paginated_graph_get(url, token=token)

    if devices is None:
        return CheckResult(
            "intune_device_compliance",
            "yellow",
            "Intune Graph API returned no response. "
            "Verify your account has the 'Intune Service Administrator' or 'Global Reader' "
            "Azure AD role. Manual compliance check required in the Intune Portal.",
        )

    if not devices:
        return CheckResult(
            "intune_device_compliance",
            "yellow",
            "No company-owned devices returned by Intune. "
            "If devices should be enrolled, check MDM authority configuration and account permissions. "
            "Unenrolled endpoints cannot be centrally monitored for compliance or encryption. "
            "CM.L2-3.4.1 / AC.L2-3.1.3 gap risk.",
        )

    total = len(devices)
    non_compliant = [
        d for d in devices
        if isinstance(d, dict) and d.get("complianceState") != "compliant"
    ]
    not_encrypted = [
        d for d in devices
        if isinstance(d, dict) and not d.get("isEncrypted", True)
    ]

    issues: List[str] = []

    if non_compliant:
        nc_names = ", ".join(
            str(d.get("deviceName", "unknown")) for d in non_compliant[:5]
        )
        extra = f" (+{len(non_compliant) - 5} more)" if len(non_compliant) > 5 else ""
        issues.append(f"{len(non_compliant)}/{total} non-compliant: {nc_names}{extra}")

    if not_encrypted:
        enc_names = ", ".join(
            str(d.get("deviceName", "unknown")) for d in not_encrypted[:3]
        )
        issues.append(f"{len(not_encrypted)} unencrypted: {enc_names}")

    if issues:
        status = "red" if non_compliant else "yellow"
        return CheckResult(
            "intune_device_compliance",
            status,
            f"Intune compliance issues ({total} managed devices): {' | '.join(issues)}. "
            "Remediate in Intune Portal → Devices → Non-compliant devices. "
            "Enable a Conditional Access policy 'Require device marked compliant' "
            "to block non-compliant access to CUI workloads. "
            "AC.L2-3.1.3 / SC.L2-3.13.3.",
        )

    return CheckResult(
        "intune_device_compliance",
        "green",
        f"Intune compliance verified: all {total} company-owned device(s) compliant and encrypted. "
        "Confirm a CA policy blocks access when compliance state is not 'compliant'. "
        "AC.L2-3.1.3 / SC.L2-3.13.3.",
    )


def check_google_workspace_bac() -> CheckResult:
    """Verify Google Workspace Context-Aware Access (BeyondCorp) is configured.

    Without Context-Aware Access (CAA), users can authenticate to Google
    Workspace from unmanaged personal devices, which is an AC.L2-3.1.1 /
    IA.L2-3.5.3 gap for orgs handling CUI in Workspace (Drive, Gmail, Meet).

    Probes the Google Access Context Manager API via gcloud CLI to verify
    that org-level access policies and access levels exist. Access levels are
    the building blocks that gate app access based on device trust — if none
    are configured, BeyondCorp is not enforcing anything.

    Requires: gcloud CLI authenticated to a Google Workspace organization
    with Organization Admin or Access Context Manager Admin role.

    Returns:
      GREEN  — Access Context Manager policies and access levels found.
      YELLOW — gcloud absent / not authenticated / insufficient permissions.
      RED    — authenticated but zero ACM policies found (BeyondCorp disabled).
    """
    if not shutil.which("gcloud"):
        return CheckResult(
            "google_workspace_bac",
            "yellow",
            "gcloud CLI not found. Cannot probe Google Workspace BeyondCorp / "
            "Context-Aware Access status. "
            "Install: https://cloud.google.com/sdk/docs/install. "
            "Manual check: Google Admin Console → Security → Context-Aware Access. "
            "Verify access levels are assigned to all CUI-scoped apps (Drive, Gmail, Meet). "
            "AC.L2-3.1.1 / IA.L2-3.5.3.",
        )

    rc, out, _ = run_cmd(
        ["gcloud", "auth", "list", "--format=json", "--filter=status=ACTIVE"],
        timeout=10,
    )
    if rc != 0:
        return CheckResult(
            "google_workspace_bac",
            "yellow",
            "gcloud CLI present but 'auth list' failed. Run 'gcloud auth login'. "
            "Manual check: Google Admin Console → Security → Context-Aware Access.",
        )

    try:
        active_accounts: List[Dict[str, Any]] = json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        active_accounts = []

    if not active_accounts:
        return CheckResult(
            "google_workspace_bac",
            "yellow",
            "No active gcloud account. Run 'gcloud auth login'. "
            "Manual check: Google Admin Console → Security → Context-Aware Access.",
        )

    active_acct = active_accounts[0].get("account", "unknown") if active_accounts else "unknown"

    # Probe Access Context Manager — org-level access policies proxy for BeyondCorp readiness.
    rc, pol_out, pol_err = run_cmd(
        ["gcloud", "access-context-manager", "policies", "list", "--format=json"],
        timeout=15,
    )

    if rc == 0 and pol_out.strip():
        try:
            acm_policies: List[Dict[str, Any]] = json.loads(pol_out)
            if not isinstance(acm_policies, list):
                acm_policies = []
        except json.JSONDecodeError:
            acm_policies = []

        if acm_policies:
            # Try to enumerate the access levels in the first policy.
            pol_name = acm_policies[0].get("name", "")
            policy_id = pol_name.split("/")[-1] if pol_name else ""
            levels: List[str] = []

            if policy_id:
                rc2, lev_out, _ = run_cmd(
                    [
                        "gcloud", "access-context-manager", "levels", "list",
                        f"--policy={policy_id}", "--format=json",
                    ],
                    timeout=15,
                )
                if rc2 == 0 and lev_out.strip():
                    try:
                        lvl_objs = json.loads(lev_out)
                        if isinstance(lvl_objs, list):
                            levels = [
                                str(lvl.get("title") or lvl.get("name", ""))
                                for lvl in lvl_objs
                            ]
                    except json.JSONDecodeError:
                        pass

            detail = (
                f"Access Context Manager: {len(acm_policies)} org access polic(ies) found. "
                + (
                    f"Access levels: {', '.join(levels[:5])}. "
                    if levels
                    else "No access levels enumerated — confirm levels are assigned to CUI apps. "
                )
                + f"Authenticated as: {active_acct}. "
                "Verify access levels are assigned to Gmail, Drive, and all CUI-scoped apps in "
                "Google Admin Console → Security → Context-Aware Access. "
                "AC.L2-3.1.1 / IA.L2-3.5.3."
            )
            return CheckResult("google_workspace_bac", "green", detail)

        # Authenticated but zero ACM policies — BeyondCorp not configured.
        return CheckResult(
            "google_workspace_bac",
            "red",
            f"No Access Context Manager policies found (account: {active_acct}). "
            "Context-Aware Access (BeyondCorp) appears unconfigured. "
            "Users can reach Google Workspace from unmanaged personal devices. "
            "Configure BeyondCorp: Google Admin Console → Security → Context-Aware Access "
            "→ create access levels → assign to CUI-scoped apps. "
            "AC.L2-3.1.1 / IA.L2-3.5.3 gap.",
        )

    # gcloud returned a non-zero exit — typically a permission or API enablement issue.
    if "PERMISSION_DENIED" in pol_err or "403" in pol_err:
        hint = " (requires Organization Admin or Access Context Manager Admin role)"
    elif "not enabled" in pol_err.lower() or "INVALID_ARGUMENT" in pol_err:
        hint = " (Access Context Manager API may not be enabled for this project)"
    else:
        hint = " (run 'gcloud access-context-manager policies list' to diagnose)"

    return CheckResult(
        "google_workspace_bac",
        "yellow",
        f"Could not read Google Access Context Manager policies{hint}. "
        f"Authenticated as: {active_acct}. "
        "Manual check: Google Admin Console → Security → Context-Aware Access. "
        "Verify access levels are applied to all Workspace apps used for CUI. "
        "AC.L2-3.1.1 / IA.L2-3.5.3.",
    )
