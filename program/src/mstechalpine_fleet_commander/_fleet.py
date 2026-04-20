from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
from typing import Any, Dict, List, Optional, Tuple

from ._models import CheckResult
from ._utils import append_hash_ledger, run_cmd


# FIPS-hardened SSH/SCP transport options.
# These restrict ciphers and MACs to FIPS 140-2/140-3 approved algorithms so that
# diagnostic data in transit is protected by a validated cryptographic path.
# An auditor asking "how is data secured in transit?" can be pointed to this spec.
_FIPS_SSH_OPTS = [
    "-o", "Ciphers=aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
    "-o", "MACs=hmac-sha2-512,hmac-sha2-256",
    "-o", "KexAlgorithms=ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
    "-o", "HostKeyAlgorithms=ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
]


def load_discovery_inventory(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        assets = data.get("assets") if isinstance(data, dict) else None
        if isinstance(assets, list):
            return [x for x in assets if isinstance(x, dict)]
    except Exception:
        pass
    return []


def _safe_host_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value.strip()) or "unknown-host"


def run_fleet_manager(
    assets: List[Dict[str, Any]],
    fleet_user: str,
    ssh_key: Optional[str],
    ssh_port: int,
    output_dir: str,
    include_categories: List[str],
    max_hosts: int,
    ledger_path: str,
) -> Tuple[CheckResult, Dict[str, Any]]:
    if not assets:
        return (
            CheckResult("fleet_orchestration", "yellow", "No assets available for fleet run. Provide --discover-network or --fleet-inventory."),
            {"attempted": 0, "executed": 0, "failed": 0, "hosts": []},
        )

    if not fleet_user:
        return (
            CheckResult("fleet_orchestration", "yellow", "--fleet-user is required for fleet orchestration."),
            {"attempted": 0, "executed": 0, "failed": 0, "hosts": []},
        )

    if not shutil.which("ssh") or not shutil.which("scp"):
        return (
            CheckResult("fleet_orchestration", "yellow", "ssh/scp not found. Install OpenSSH client tools for agentless fleet orchestration."),
            {"attempted": 0, "executed": 0, "failed": 0, "hosts": []},
        )

    include_set = {x.strip() for x in include_categories if x.strip()}
    filtered = [a for a in assets if a.get("ip") and (not include_set or a.get("category", "") in include_set)]
    if max_hosts > 0:
        filtered = filtered[:max_hosts]

    if not filtered:
        return (
            CheckResult("fleet_orchestration", "yellow", "No in-scope assets matched fleet category filters."),
            {"attempted": 0, "executed": 0, "failed": 0, "hosts": []},
        )

    local_script = os.path.abspath(__file__)
    os.makedirs(output_dir, exist_ok=True)

    hosts: List[Dict[str, Any]] = []
    executed = 0
    failed = 0

    key_args: List[str] = []
    if ssh_key:
        key_args = ["-i", os.path.abspath(ssh_key)]

    # Validate fleet_user contains only safe characters to prevent shell injection.
    # The user value is embedded in the ssh/scp destination string (user@host).
    if not re.fullmatch(r"[A-Za-z0-9._@-]+", fleet_user):
        return (
            CheckResult("fleet_orchestration", "red",
                        f"--fleet-user '{fleet_user}' contains invalid characters. Use only alphanumeric, dot, dash, or underscore."),
            {"attempted": 0, "executed": 0, "failed": 0, "hosts": []},
        )

    for asset in filtered:
        ip = str(asset.get("ip", "")).strip()
        # Validate IP is a safe dotted-decimal string before embedding in commands
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
            continue
        category = str(asset.get("category", "")).strip() or "Contractor Risk Managed Asset"
        label = _safe_host_label(ip)
        host_dir = os.path.join(output_dir, label)
        os.makedirs(host_dir, exist_ok=True)

        # Use a randomised suffix to prevent /tmp symlink collisions (CWE-377)
        rand_suffix = hashlib.sha256(f"{ip}{dt.datetime.now().isoformat()}".encode()).hexdigest()[:8]
        remote_script = f"/tmp/mstechalpine_diag_{rand_suffix}.py"
        remote_json = f"/tmp/mstechalpine-diag-{label}-{rand_suffix}.json"
        remote_log = f"/tmp/mstechalpine-diag-{label}-{rand_suffix}.log"

        host_result: Dict[str, Any] = {
            "ip": ip,
            "category": category,
            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "failed",
        }

        # 1) Push script with FIPS-hardened transport
        scp_push = ["scp", "-P", str(ssh_port), *_FIPS_SSH_OPTS, *key_args, local_script, f"{fleet_user}@{ip}:{remote_script}"]
        rc, out, err = run_cmd(scp_push, timeout=90)
        if rc != 0:
            failed += 1
            host_result["error"] = f"scp push failed: {err or out}"
            hosts.append(host_result)
            continue

        # 2) Execute remotely (rc 0 or 2 are expected from local diagnostic)
        # FLEET_COMMANDER_REMOTE=1 prevents cloud API checks (--cloud-api) from firing
        # on remote endpoints — those checks are hub-only and would rate-limit the
        # FedRAMP Marketplace and Microsoft Graph APIs across 50+ simultaneous hosts.
        # Remote paths are constructed from validated IP and sha256 suffix — no user input interpolated
        remote_cmd = f"FLEET_COMMANDER_REMOTE=1 python3 {remote_script} --json-output {remote_json} > {remote_log} 2>&1"
        ssh_exec = ["ssh", "-p", str(ssh_port), *_FIPS_SSH_OPTS, *key_args, f"{fleet_user}@{ip}", remote_cmd]
        rc, out, err = run_cmd(ssh_exec, timeout=180)
        host_result["remote_exit_code"] = rc
        if rc not in {0, 2}:
            failed += 1
            host_result["error"] = f"remote run failed: {err or out}"
            hosts.append(host_result)
            continue

        # 3) Pull artifacts back
        local_json = os.path.join(host_dir, "diagnostic.json")
        local_log = os.path.join(host_dir, "diagnostic.log")

        scp_pull_json = ["scp", "-P", str(ssh_port), *_FIPS_SSH_OPTS, *key_args, f"{fleet_user}@{ip}:{remote_json}", local_json]
        rc_json, out_json, err_json = run_cmd(scp_pull_json, timeout=90)
        if rc_json != 0:
            failed += 1
            host_result["error"] = f"scp pull diagnostic.json failed: {err_json or out_json}"
            hosts.append(host_result)
            continue

        scp_pull_log = ["scp", "-P", str(ssh_port), *_FIPS_SSH_OPTS, *key_args, f"{fleet_user}@{ip}:{remote_log}", local_log]
        run_cmd(scp_pull_log, timeout=90)

        digest = append_hash_ledger(local_json, ledger_path)
        host_result["artifact_path"] = os.path.abspath(local_json)
        host_result["log_path"] = os.path.abspath(local_log)
        host_result["sha256"] = digest
        host_result["status"] = "ok"
        executed += 1
        hosts.append(host_result)

    summary = {
        "attempted": len(filtered),
        "executed": executed,
        "failed": failed,
        "hosts": hosts,
    }

    manifest_path = os.path.join(output_dir, "fleet-manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    append_hash_ledger(manifest_path, ledger_path)

    if failed > 0:
        status = "red"
        detail = f"Fleet orchestration ran on {executed}/{len(filtered)} in-scope asset(s); {failed} failed verification hops."
    elif executed > 0:
        status = "green"
        detail = f"Fleet orchestration verified {executed}/{len(filtered)} in-scope asset(s) with per-host evidence artifacts and SHA-256 ledger records."
    else:
        status = "yellow"
        detail = "Fleet orchestration did not execute on any hosts."

    return CheckResult("fleet_orchestration", status, detail), summary
