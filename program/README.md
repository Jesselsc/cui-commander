# MSTechAlpine Fleet Commander

CMMC Level 2 / NIST 800-171 baseline diagnostic and fleet orchestration tool.


Program still needs to be tested on Windows*

---

## Quick Start

```bash
cd program
python3 -m venv .venv

# macOS/Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate

pip install -e .
```

---

## One-Click Launchers (no terminal needed)

| Platform | File |
|---|---|
| macOS | double-click `launcher/MSTechAlpine-Fleet-Commander.command` |
| Windows | double-click `launcher/MSTechAlpine-Fleet-Commander-Windows.cmd` |

---

## Usage Examples

### 1. Local diagnostic only
Runs all security checks on the current machine and saves a JSON evidence artifact.

```bash
fleet-commander --json-output evidence/diagnostic.json
```

### 2. Full C3PAO evidence package (recommended)
Runs everything: local checks, network discovery, SBOM, vulnerability scan, HTML report,
cloud portal checks, and SRM spreadsheet. This is the command for pre-assessment prep.

```bash
sudo fleet-commander \
  --discover-network auto \
  --auto-tag \
  --asset-tags evidence/asset-tags.json \
  --discovery-output evidence/fleet-discovery.json \
  --diagram-output evidence/network-architecture.svg \
  --sbom-output evidence/sbom.json \
  --srm evidence/srm.xlsx \
  --vuln-scan \
  --vuln-output evidence/vulns.json \
  --html-output evidence/report.html \
  --cloud-api \
  --sanitize \
  --json-output evidence/diagnostic-c3pao.json
```

After the run, the tool prints a `file://` URI — click it to open `report.html` directly in your browser.

### 3. Network discovery — explicit subnet
Use when auto-detect picks the wrong interface (e.g. VPN is active).

```bash
sudo fleet-commander \
  --discover-network 10.0.0.0/24 \
  --auto-tag \
  --asset-tags evidence/asset-tags.json \
  --discovery-output evidence/fleet-discovery.json \
  --diagram-output evidence/network-architecture.svg \
  --json-output evidence/diagnostic.json
```

### 4. Network discovery — full port scan (all 65535 ports)
Slower (~2 min/host) but finds obscure services. Use for deep audits, not daily runs.

```bash
sudo fleet-commander \
  --discover-network auto \
  --discovery-full-scan \
  --auto-tag \
  --asset-tags evidence/asset-tags.json \
  --discovery-output evidence/fleet-discovery.json \
  --diagram-output evidence/network-architecture.svg \
  --json-output evidence/diagnostic.json
```

### 5. Fleet orchestration — push diagnostic to remote hosts via SSH
Runs the diagnostic on every in-scope host over SSH, pulls back per-host JSON artifacts,
and SHA-256 hashes everything into the evidence ledger.

```bash
fleet-commander \
  --fleet-run \
  --fleet-inventory evidence/fleet-discovery.json \
  --fleet-user admin \
  --fleet-ssh-key ~/.ssh/id_ed25519 \
  --fleet-output-dir evidence/fleet-results \
  --hash-ledger evidence/hash-ledger.jsonl
```

---

## All Arguments

### Core output
| Flag | Default | Description |
|---|---|---|
| `--json-output PATH` | _(none)_ | Write diagnostic results to this JSON file |
| `--html-output PATH` | _(none)_ | Write an HTML report (RED/YELLOW/GREEN findings, CMMC domain map, remediation steps) |
| `--sbom-output PATH` | _(none)_ | Write a CycloneDX 1.6 Software Bill of Materials (JSON) |
| `--srm PATH` | _(none)_ | Write a Security Requirements Matrix spreadsheet (110 NIST 800-171 Rev 2 controls) |
| `--hash-ledger PATH` | `evidence/hash-ledger.jsonl` | Append-only SHA-256 hash-chained ledger for all artifacts |

### Network discovery
| Flag | Default | Description |
|---|---|-----------|
| `--discover-network [CIDR]` | _(none)_ | Run nmap discovery. Omit the value to **auto-detect your local subnet**. Pass a CIDR (e.g. `10.0.0.0/24`) to override. |
| `--discovery-full-scan` | off | Scan all 65535 ports instead of top 200 (slow, thorough) |
| `--auto-tag` | off | Write discovered IPs + auto-categories back to `--asset-tags` file |
| `--asset-tags PATH` | _(none)_ | JSON file mapping IP/hostname → 32 CFR 170.19 category (manual overrides) |
| `--discovery-output PATH` | `evidence/fleet-discovery.json` | Where to write the discovery JSON |
| `--diagram-output PATH` | `evidence/network-architecture.svg` | Where to write the SVG network diagram |

### Fleet orchestration (SSH/SCP agentless)
| Flag | Default | Description |
|---|---|---|
| `--fleet-run` | off | Push and run diagnostic on remote hosts via SSH |
| `--fleet-inventory PATH` | _(none)_ | Use a saved discovery JSON instead of running `--discover-network` |
| `--fleet-user NAME` | _(required)_ | SSH username for all remote hosts |
| `--fleet-ssh-key PATH` | _(none)_ | Path to SSH private key |
| `--fleet-ssh-port PORT` | `22` | SSH port |
| `--fleet-output-dir PATH` | `evidence/fleet-results` | Per-host artifact output directory |
| `--fleet-categories LIST` | `CUI Asset,Security Protection Asset,Contractor Risk Managed Asset` | Comma-separated category filter — only run on matching hosts |
| `--fleet-max-hosts N` | `0` (all) | Cap the number of hosts processed |

### Vulnerability scanning
| Flag | Default | Description |
|---|---|---|
| `--vuln-scan` | off | Cross-reference installed packages against OSV.dev CVE database (Homebrew, PyPI, npm, dpkg, Chocolatey, winget) |
| `--vuln-output PATH` | _(none)_ | Write CVE findings to this JSON file |

### Cloud portal checks
| Flag | Default | Description |
|---|---|---|
| `--cloud-api` | off | Run live checks against FedRAMP, Azure CA, Intune, and BeyondCorp endpoints |

### Audit & privacy
| Flag | Default | Description |
|---|---|---|
| `--sanitize` | off | Replace real usernames with `user_01`, `user_02`, … in all output. Detection logic still runs on real names before anonymization. Use when sharing artifacts in environments where usernames are PII or CUI metadata. |

---

## Checks Performed

| Check | Control | What it does |
|---|---|---|
| `is_admin_context` | IA.L2-3.5.1 | Detects if running as root/admin (signals access privilege context) |
| `check_encryption` | SC.L2-3.13.8 | FileVault / BitLocker / LUKS enabled |
| `check_mfa_signal` | IA.L2-3.5.3 | **Hardware FIDO2 AAGUID detection** — distinguishes hardware-bound keys (YubiKey, Feitian) from software authenticators. Windows: reads FIDO enrollment registry keys. Linux/macOS: reads `fido2-token -I` AAGUID and matches to known vendor list. |
| `check_remote_access_shadow_tools` | AC.L2-3.1.3 | Detects shadow RMM tools (TeamViewer, AnyDesk, etc.) |
| `check_time_sync_signal` | AU.L2-3.3.7 | NTP/chrony/timesyncd drift detection |
| `check_patch_signal` | SI.L2-3.14.1 | OS patch currency signals |
| `check_account_signal` | IA.L2-3.5.1 | Shared/generic account name detection. Supports `--sanitize`. |
| `check_audit_log_signal` | **AU.L2-3.3.1** | **Rev 3 IR window** — Verifies audit log continuity: macOS Unified Log (24 h event count), Linux journald + audit.log, Windows Security log. RED if zero events in 24 h. |
| `check_boundary_violations` | **AC.L2-3.1.20** | **VLAN/segment boundary enforcement** — On discovery, flags CUI assets co-mingled with Out-of-Scope hosts in the same /24, and OOS hosts with CUI-tier ports open (22, 443, 3389, 8443). |

> **Note on FIDO2 AAGUID checking**: The tool ships with a curated list of known hardware-key AAGUIDs (YubiKey 5 Series, Feitian ePass/BioPass, Windows Hello Hardware). Add your organization's issued key AAGUIDs to `_HARDWARE_KEY_AAGUIDS` in `cli.py` for a stronger enforcement signal.

---

## Asset Tag Categories (32 CFR 170.19)

Edit `evidence/asset-tags.json` to manually pin IPs to categories.
Use `--auto-tag` to let the tool fill this in from nmap signals.

| Category | Meaning |
|---|---|
| `CUI Asset` | Stores, processes, or transmits CUI — highest scrutiny |
| `Security Protection Asset` | Protects CUI (firewall, IdP, SIEM) — must be secured |
| `Contractor Risk Managed Asset` | On-network but not touching CUI — risk-managed |
| `Out-of-Scope` | Outside the assessment boundary |

---

## Output Files

| File | Contents |
|---|---|
| `evidence/diagnostic-c3pao.json` | Full diagnostic results — machine readable, SHA-256 hash-chained |
| `evidence/report.html` | Human-readable report — RED/YELLOW/GREEN findings, CMMC domain map, remediation steps |
| `evidence/sbom.json` | CycloneDX 1.6 Software Bill of Materials |
| `evidence/srm.xlsx` | Security Requirements Matrix — 110 NIST 800-171 Rev 2 controls |
| `evidence/fleet-discovery.json` | Discovered network assets with OS, open ports, auto-category |
| `evidence/network-architecture.svg` | Color-coded network topology diagram (open in any browser) |
| `evidence/asset-tags.json` | IP → 32 CFR 170.19 category map (auto-generated or manual) |
| `evidence/vulns.json` | CVE cross-reference against installed packages via OSV.dev |
| `evidence/hash-ledger.jsonl` | Append-only SHA-256 hash chain — tamper-evident audit trail |
| `evidence/fleet-results/<ip>/diagnostic.json` | Per-host diagnostic from fleet SSH run |

> All files in `evidence/` are gitignored. Keep them private — they contain hostnames, usernames, and network topology. All files are written with `0o600` permissions (owner read/write only).
