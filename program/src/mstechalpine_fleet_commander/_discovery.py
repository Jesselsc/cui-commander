from __future__ import annotations

import ipaddress
import os
import platform
import re
import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from ._models import CheckResult, _Spinner
from ._utils import run_cmd


# Ports that suggest this host stores/processes CUI (databases, file shares, RDP)
_CUI_PORTS = {"445", "139", "1433", "3306", "5432", "27017", "1521", "3389", "5985", "5986"}
# Ports/services that suggest this host is a Security Protection Asset (IdP, network gear, SIEM)
_SPA_PORTS = {"389", "636", "88", "1812", "1813", "514", "5044", "9200", "9300"}
_SPA_OS_HINTS = ("router", "firewall", "checkpoint", "palo alto", "fortinet", "cisco", "juniper", "switch")
_SPA_HOST_HINTS = ("fw", "firewall", "router", "gw", "gateway", "ldap", "ad", "dc", "siem", "proxy", "idp", "radius")
_CUI_HOST_HINTS = ("sql", "db", "database", "file", "nas", "storage", "backup", "rdp", "desktop", "workstation", "ws")


def _auto_classify_by_signals(ip: str, hostname: str, services: List[str]) -> str:
    """Infer 32 CFR 170.19 category from nmap OS/service fingerprints when no manual tag exists."""
    host_lower = hostname.lower() if hostname else ""
    # Pull port numbers out of service strings like "tcp/445:microsoft-ds"
    ports_seen: set = set()
    for svc in services:
        parts = svc.split("/")
        if len(parts) >= 2:
            port_part = parts[1].split(":")[0]
            ports_seen.add(port_part)

    # Security Protection Asset: network infrastructure or IdP signals
    if ports_seen & _SPA_PORTS or any(h in host_lower for h in _SPA_HOST_HINTS):
        return "Security Protection Asset"

    # CUI Asset: data stores, file shares, RDP endpoints
    if ports_seen & _CUI_PORTS or any(h in host_lower for h in _CUI_HOST_HINTS):
        return "CUI Asset"

    return "Contractor Risk Managed Asset"


def classify_asset(ip: str, hostname: str, tags: Dict[str, str], services: Optional[List[str]] = None) -> str:
    # 32 CFR 170.19 oriented categories
    # Allowed labels: CUI Asset, Security Protection Asset, Contractor Risk Managed Asset, Out-of-Scope
    by_ip = tags.get(ip.lower())
    if by_ip:
        return by_ip
    by_host = tags.get(hostname.lower()) if hostname else None
    if by_host:
        return by_host
    # Fall back to nmap signal-based classification
    return _auto_classify_by_signals(ip, hostname, services or [])


def generate_network_diagram_svg(inventory: List[Dict[str, Any]], output_path: str) -> None:
    width = 1200
    row_h = 44
    pad = 20
    height = max(240, pad * 2 + row_h * (len(inventory) + 2))

    def esc(txt: str) -> str:
        return (
            txt.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    colors = {
        "CUI Asset": "#ffd6d6",
        "Security Protection Asset": "#d6ecff",
        "Contractor Risk Managed Asset": "#fff3cd",
        "Out-of-Scope": "#e2e3e5",
    }

    lines: List[str] = []
    lines.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">')
    lines.append('<rect x="0" y="0" width="100%" height="100%" fill="#ffffff"/>')
    lines.append('<text x="20" y="28" font-family="Arial" font-size="18" font-weight="bold">MSTechAlpine Fleet Discovery Diagram</text>')
    lines.append('<text x="20" y="48" font-family="Arial" font-size="12" fill="#444">Generated from nmap -O -sV discovery. Categorization follows 32 CFR 170.19-oriented labels.</text>')

    y = 70
    headers = ["IP", "Hostname", "OS Guess", "Category", "Top Services"]
    col_x = [20, 220, 400, 690, 900]
    lines.append(f'<rect x="20" y="{y}" width="1160" height="30" fill="#f2f2f2" stroke="#cccccc"/>')
    for idx, h in enumerate(headers):
        lines.append(f'<text x="{col_x[idx]}" y="{y + 20}" font-family="Arial" font-size="12" font-weight="bold">{esc(h)}</text>')

    y += 34
    for item in inventory:
        cat = item.get("category", "Contractor Risk Managed Asset")
        fill = colors.get(cat, "#fff3cd")
        lines.append(f'<rect x="20" y="{y}" width="1160" height="34" fill="{fill}" stroke="#dddddd"/>')
        vals = [
            str(item.get("ip", "")),
            str(item.get("hostname", "")),
            str(item.get("os_guess", ""))[:42],
            cat,
            ", ".join(item.get("services", [])[:3])[:50],
        ]
        for idx, v in enumerate(vals):
            lines.append(f'<text x="{col_x[idx]}" y="{y + 22}" font-family="Arial" font-size="11">{esc(v)}</text>')
        y += row_h

    lines.append("</svg>")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def _parse_live_ips(xml_out: str) -> List[str]:
    """Extract IPs of up hosts from nmap ping-sweep XML output."""
    try:
        root = ET.fromstring(xml_out)
    except Exception:
        return []
    ips: List[str] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
                if ip:
                    ips.append(ip)
                break
    return ips


def _arp_cache_ips(target_cidr: str) -> List[str]:
    """Read live IPs from the OS ARP/NDP cache that fall within target_cidr. Instant, no scanning.

    Supports both IPv4 (ARP cache) and IPv6 (NDP neighbor cache).
    """
    try:
        network = ipaddress.ip_network(target_cidr, strict=False)
    except ValueError:
        return []

    is_v6 = isinstance(network, ipaddress.IPv6Network)

    # IPv4: arp -a  |  IPv6: ip neigh (Linux) / ndp -a (macOS) / netsh (Windows)
    ips: List[str] = []
    if is_v6:
        sys_name = platform.system().lower()
        if sys_name == "darwin":
            rc, out, _ = run_cmd(["ndp", "-a"], timeout=5)
        elif sys_name == "windows":
            rc, out, _ = run_cmd(
                ["netsh", "interface", "ipv6", "show", "neighbors"], timeout=5
            )
        else:  # Linux
            rc, out, _ = run_cmd(["ip", "-6", "neigh"], timeout=5)
    else:
        rc, out, _ = run_cmd(["arp", "-a"], timeout=5)

    if rc != 0 or not out:
        return ips

    # Regex patterns that match both IPv4 dotted-decimal and IPv6 hex-colon addresses
    _ipv4_pat = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    _ipv6_pat = re.compile(r"([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})")
    pat = _ipv6_pat if is_v6 else _ipv4_pat

    seen: set = set()
    for line in out.splitlines():
        if any(x in line.lower() for x in ("incomplete", "invalid", "ff-ff-ff-ff-ff-ff",
                                            "ff:ff:ff:ff:ff:ff", "reachable 0")):
            continue
        for m in pat.finditer(line):
            raw = m.group(1)
            # Strip interface suffix from IPv6 link-local (fe80::1%en0 -> fe80::1)
            raw = raw.split("%")[0]
            try:
                addr = ipaddress.ip_address(raw)
                if addr in network:
                    seen.add(str(addr))
            except ValueError:
                continue

    return sorted(seen, key=lambda x: ipaddress.ip_address(x))


def _prewarm_subnet(target_cidr: str) -> None:
    """Ping every IP in a /24 subnet in parallel to populate the OS ARP cache.

    nmap's ARP probe window is narrow — slow devices (Raspberry Pi, embedded Linux,
    smart TVs) often miss the single-shot probe. Pre-warming forces them into the
    ARP table so nmap finds them on the first try.
    Only runs for /24 or smaller subnets (max 254 threads).
    """
    try:
        network = ipaddress.ip_network(target_cidr, strict=False)
        if network.num_addresses > 254:
            return  # too large — skip pre-warm for wide ranges
        if isinstance(network, ipaddress.IPv6Network):
            return  # ping6 is not reliable cross-platform; nmap handles IPv6 discovery directly
        # Build the host list for IPv4 /24s
        hosts = [str(h) for h in network.hosts()]
    except Exception:
        return

    ping_bin = "ping"
    is_win = platform.system().lower() == "windows"
    if is_win:
        ping_args = [ping_bin, "-n", "1", "-w", "500"]
    else:
        ping_args = [ping_bin, "-c", "1", "-W", "1"]

    def _ping(ip: str) -> None:
        try:
            subprocess.run(
                ping_args + [ip],
                capture_output=True,
                timeout=2,
                check=False,
            )
        except Exception:
            pass

    threads = [threading.Thread(target=_ping, args=(ip,), daemon=True)
               for ip in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3)


def run_nmap_discovery(target_cidr: str, tag_map: Dict[str, str], full_scan: bool = False) -> Tuple[CheckResult, List[Dict[str, Any]], Optional[str]]:
    if not shutil.which("nmap"):
        return (
            CheckResult(
                "discovery_scope",
                "yellow",
                "nmap not found. Install nmap to generate fleet discovery evidence (nmap -O -sV).",
            ),
            [],
            None,
        )

    # Pre-warm: ping all IPs in parallel so slow devices are in the ARP cache
    # before nmap's ARP sweep runs. Catches Raspberry Pis, smart TVs, embedded devices.
    print(f"  [0/2] Pre-warming ARP cache for {target_cidr} ...", flush=True)
    with _Spinner("Pinging all IPs in parallel to warm ARP cache..."):
        _prewarm_subnet(target_cidr)

    # Phase 1: multi-probe host sweep — ARP + ICMP + TCP on common ports.
    # -PR  = ARP ping (layer 2, cannot be firewalled on local LAN)
    # -PE  = ICMP echo
    # -PS22,80,443,3389,8080,8443 = TCP SYN to common ports (finds hosts that block ICMP,
    #         e.g. hardened Linux / Raspberry Pi with iptables DROP on icmp)
    # -PA80,443 = TCP ACK probes
    # Together these find: routers, smart TVs, Windows, hardened Linux, IoT
    # Detect IPv6 target — nmap needs -6 and different probe flags (no ARP on IPv6)
    try:
        _target_net = ipaddress.ip_network(target_cidr, strict=False)
        _is_v6_target = isinstance(_target_net, ipaddress.IPv6Network)
    except ValueError:
        _is_v6_target = ":" in target_cidr

    if _is_v6_target:
        ping_cmd = ["nmap", "-6", "-sn", "-PE", "-PS22,80,443,3389,8080,8443",
                    "-T4", "-oX", "-", target_cidr]
    else:
        ping_cmd = ["nmap", "-sn", "-PR", "-PE", "-PS22,80,443,3389,8080,8443", "-PA80,443",
                    "-T4", "-oX", "-", target_cidr]
    print(f"  [1/2] Host sweep across {target_cidr} (ARP + ICMP + TCP probes)...", flush=True)
    with _Spinner("Sweeping for live hosts — ARP, ICMP, and TCP probes combined..."):
        ping_rc, ping_out, ping_err = run_cmd(ping_cmd, timeout=60)
    live_ips = _parse_live_ips(ping_out or "") if ping_rc == 0 and ping_out else []

    # Fallback: read OS ARP cache directly (instant, catches hosts that block all probes)
    if not live_ips:
        print("  [1/2] nmap sweep found nothing — trying ARP cache fallback...", flush=True)
        live_ips = _arp_cache_ips(target_cidr)

    if not live_ips:
        print("  [1/2] No live hosts found via nmap or ARP cache.", flush=True)
        return (
            CheckResult("discovery_scope", "yellow", f"No live hosts found in {target_cidr} via nmap or ARP cache. Ensure you are on the correct subnet."),
            [],
            None,
        )
    source = "ARP cache" if ping_rc != 0 or not _parse_live_ips(ping_out or "") else "nmap sweep"
    print(f"  [1/2] Found {len(live_ips)} live host(s) via {source}: {', '.join(live_ips)}", flush=True)

    # Phase 2: OS + service scan on live hosts only.
    v6_flag = ["-6"] if _is_v6_target else []
    if full_scan:
        # Full scan: all 65535 ports + full version intensity
        # Budget: 120s per host, minimum 120s, no upper cap
        scan_timeout = max(len(live_ips) * 120, 120)
        cmd = ["nmap"] + v6_flag + ["-O", "-sV", "-p-", "-T4", "-oX", "-"] + live_ips
        mode_label = "all 65535 ports"
    else:
        # Fast scan: top 200 ports, lighter version probes (~98% coverage)
        # Budget: 30s per host, minimum 60s, capped at 300s
        scan_timeout = min(max(len(live_ips) * 30, 60), 300)
        cmd = ["nmap"] + v6_flag + ["-O", "-sV", "--version-intensity", "3",
               "--top-ports", "200", "-T4", "-oX", "-"] + live_ips
        mode_label = "top 200 ports"
    est = f"~{scan_timeout}s max"
    print(f"  [2/2] OS + service fingerprint scan on {len(live_ips)} host(s) ({mode_label}, {est})...", flush=True)
    with _Spinner(f"Fingerprinting {len(live_ips)} host(s) — {mode_label}, OS detection..."):
        rc, out, err = run_cmd(cmd, timeout=scan_timeout)
    if rc != 0 or not out:
        return (
            CheckResult("discovery_scope", "yellow", f"nmap discovery failed: {err or 'No XML output returned.'}"),
            [],
            None,
        )

    try:
        root = ET.fromstring(out)
    except Exception as exc:
        return (
            CheckResult("discovery_scope", "yellow", f"nmap XML parse failed: {exc}"),
            [],
            None,
        )

    inventory: List[Dict[str, Any]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
                break

        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        os_guess = "unknown"
        osmatch = host.find("os/osmatch")
        if osmatch is not None:
            os_guess = osmatch.get("name", "unknown")

        services: List[str] = []
        for port in host.findall("ports/port"):
            pstate = port.find("state")
            if pstate is None or pstate.get("state") != "open":
                continue
            svc = port.find("service")
            proto = port.get("protocol", "")
            portid = port.get("portid", "")
            if svc is not None:
                name = svc.get("name", "unknown")
                version = svc.get("version", "")
                product = svc.get("product", "")
                sig = f"{proto}/{portid}:{name}"
                if product or version:
                    sig += f" ({product} {version})".strip()
                services.append(sig)
            else:
                services.append(f"{proto}/{portid}")

        category = classify_asset(ip, hostname, tag_map, services)
        inventory.append(
            {
                "ip": ip,
                "hostname": hostname,
                "os_guess": os_guess,
                "services": services,
                "category": category,
            }
        )

    if not inventory:
        return (
            CheckResult("discovery_scope", "yellow", "nmap completed, but no live assets discovered in target range."),
            [],
            out,
        )

    # Print a human-readable table of discovered hosts to the console
    cat_abbrev = {
        "CUI Asset": "CUI",
        "Security Protection Asset": "SPA",
        "Contractor Risk Managed Asset": "CRMA",
        "Out-of-Scope": "OOS",
    }
    col_ip   = max(len(h["ip"])       for h in inventory) + 2
    col_os   = min(max(len(h["os_guess"]) for h in inventory) + 2, 44)
    col_cat  = 6
    print(f"\n  {'IP':<{col_ip}}  {'Cat':<{col_cat}}  {'OS Guess':<{col_os}}  Services")
    print(f"  {'-'*col_ip}  {'-'*col_cat}  {'-'*col_os}  --------")
    for h in inventory:
        svcs = ", ".join(h["services"][:3]) or "—"
        if len(h["services"]) > 3:
            svcs += f" (+{len(h['services'])-3})"
        abbr = cat_abbrev.get(h["category"], h["category"][:6])
        os_str = h["os_guess"][:col_os-2] if h["os_guess"] != "unknown" else "—"
        print(f"  {h['ip']:<{col_ip}}  {abbr:<{col_cat}}  {os_str:<{col_os}}  {svcs}")
    print()

    categories = sorted(set(x["category"] for x in inventory))
    return (
        CheckResult(
            "discovery_scope",
            "green",
            f"Discovered {len(inventory)} live assets via nmap -O -sV. Categories present: {', '.join(categories)}.",
        ),
        inventory,
        out,
    )
