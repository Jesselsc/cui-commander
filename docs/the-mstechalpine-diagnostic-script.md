# Fleet Commander: The MSTechAlpine Diagnostic Tool

> [!NOTE]
> Fleet Commander runs compliance checks against the local endpoint. Network discovery (`--discover-network`) inventories hosts on your subnet but does not run compliance checks on remote machines. Combine script output with written SSP, POA&M, and policy documentation before any SPRS affirmation or C3PAO assessment.

The script's job is simple: ask your systems for the truth instead of asking people to guess.

Most failed assessments are not caused by people who built nothing. They are caused by people who thought they had it covered and did not have the evidence to prove it. The script closes that gap.

---

## What the Script Is and Is Not

**What it is:**
- A technical truth tool that reads system state
- A point-in-time check of your actual configuration
- A way to surface red findings before an assessor does

**What it is not:**
- A certification
- Legal advice
- An audit
- Permission to inspect systems you do not own or manage

> [!WARNING]
> Legal compliance still depends on documented policies, evidence quality, and contract-specific obligations. You can have a green script result and still fail an audit if your SSP is incomplete, your policies are not written down, or your evidence is not organized. The script finds technical facts. It does not find paperwork errors.

---

## Technical Truth vs. Legal Compliance

The script finds what is or is not configured on your systems. It cannot read a Word document, verify a policy is being followed, or check whether someone is forwarding contract drawings to a personal Gmail.

| Script can find | Script cannot find |
|---|---|
| Whether BitLocker is on | Whether the server room is physically secured |
| Whether MFA is enforced | Whether someone bypassed controls manually |
| Whether stale admin accounts exist | Whether your SSP accurately describes the environment |
| Whether patches are current | Whether your evidence package is audit-ready |
| Whether configuration has drifted | Whether your contractual interpretation is correct |

If the script turns up red, you are not just failing an audit. You are failing at basic security. Fix those findings regardless of what any assessment requires.

---

## Where It Runs

This is not a cloud dashboard. The script runs inside the environment you are checking, as close as possible to the system you are trying to verify.

Authorized locations:
- A contractor-owned workstation you manage
- A contractor-owned server you manage
- An administrative jump box with authorized remote access to the target system

If a system is owned by a cloud provider, MSP, prime, or another third party, you need clear documented administrative authority and explicit permission before running any validation tooling against it. "I have a login" is not the same as "I am authorized to run diagnostic tooling."

---

## How to Initialize It

**The fastest path is the launcher.** The launchers handle Python venv creation, package install, nmap, and graphviz automatically, then present a run menu.

- **macOS:** Double-click `launcher/MSTechAlpine-Fleet-Commander.command`
- **Windows:** Double-click `launcher/MSTechAlpine-Fleet-Commander-Windows.cmd`

Both launchers call the bootstrap script (`program/bootstrap/`) which installs all dependencies and drops you into a numbered menu. Pick option 2 for the full C3PAO evidence package.

---

**Manual setup (technical users / CI pipelines):**

1. Install Python 3.10+, `nmap`, and `graphviz` and confirm they are on your PATH.
   - macOS: `brew install nmap graphviz`
   - Ubuntu: `sudo apt-get install -y nmap graphviz`
   - RHEL: `sudo dnf install -y nmap graphviz`

2. From the repo root, navigate to `program/` and install the package:

```bash
cd program
python3 -m venv .venv
source .venv/bin/activate      # macOS/Linux
.venv\Scripts\activate          # Windows (PowerShell)
pip install -e .
```

3. Run the tool. For a full C3PAO evidence package:

```bash
sudo .venv/bin/fleet-commander \
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

Use the venv-installed executable for privileged runs. Plain `sudo fleet-commander` may bypass the virtualenv `PATH` and miss the install you just created.

For a minimal local-only run (no nmap or graphviz needed):

```bash
fleet-commander --json-output evidence/diagnostic.json
```

**No internet connection or cloud account required for local checks.** The `--cloud-api` flag is optional and only tests reachability against FedRAMP/Azure/Intune/BeyondCorp endpoints.

**Save the output.** The output is evidence. Every artifact is timestamped and SHA-256 hash-chained in `evidence/hash-ledger.jsonl`. Store the entire `evidence/` folder with your SSP and POA&M so you can show a timeline of your technical posture over time.

In 2026, this output is also the technical fact base your senior official is affirming each year under 32 CFR Part 170. Treat it like board-level evidence, not a disposable terminal log.

---

## What the Script Finds

- **Encryption status**: Is the device actually encrypted and configured correctly? Is TPM properly bound? Is crypto on an active FIPS path?
- **MFA signal quality**: Are phishing-resistant methods such as FIDO2 or Windows Hello for Business present, and do local signals suggest stronger MFA posture on privileged paths? Final enforcement still needs IdP, PAM, and policy verification.
- **Account hygiene**: Are there stale admin accounts, weak account practices, departed employees still active, or likely shared/generic account names (for example: Shop_PC, Admin, User01)?
- **Patch status**: Are critical systems lagging behind on updates?
- **Configuration drift**: Are machines deviating from the intended baseline?
- **Affirmation readiness**: Does the output provide a defensible technical fact base for the annual Senior Official Affirmation required under 32 CFR Part 170?
- **Incident logging hooks**: Is baseline logging present to support faster incident timelines, including Rev 3 and GSA 1-hour reporting workflows where applicable?

> [!IMPORTANT]
> **FIPS 140-3 Cliff (September 21, 2026):** If the script flags encryption as FIPS 140-2, treat that as a yellow warning, not a long-term green. You have until September 21, 2026 to transition to FIPS 140-3 validated modules. After that date, 140-2 certificates move to the historical list and can create audit failure risk for new acquisitions.

## Technical Comparison: Script Findings vs Auditor Expectations

| Control | Script Logic (Technical Truth) | Auditor Logic (Compliance Judgment) |
|---|---|---|
| Encryption | Checks device encryption state and FIPS posture signal (for example BitLocker status and FIPS mode indicators) | Requests module-level proof, including the specific NIST CMVP certificate path for the crypto module in use |
| MFA | Checks whether MFA is enforced and whether phishing-resistant methods (FIDO2/Windows Hello) are configured on privileged paths | Watches live login behavior to verify no bypass paths, fallback shortcuts, or unenforced exceptions |
| Accounts | Enumerates active local/domain accounts and flags stale, generic, and likely shared account patterns | Cross-checks account population against HR joiner/mover/leaver records to detect ghost users and control breakdown |

---

## Current Repository Status

Fleet Commander is published in this repository at `program/src/mstechalpine_fleet_commander/`. It is a production diagnostic tool — not a stub or placeholder.

A single full run produces:

| File | Description |
|---|---|
| `evidence/diagnostic-c3pao.json` | Full check results — machine readable, SHA-256 hash-chained |
| `evidence/report.html` | RED/YELLOW/GREEN findings report — open in any browser |
| `evidence/sbom.json` | CycloneDX 1.6 Software Bill of Materials |
| `evidence/srm.xlsx` | 110 NIST 800-171 Rev 2 controls mapped to your scan results |
| `evidence/fleet-discovery.json` | Network host inventory |
| `evidence/network-architecture.svg` | Auto-generated network topology diagram |
| `evidence/vulns.json` | CVE cross-reference via OSV.dev |
| `evidence/hash-ledger.jsonl` | Append-only tamper-evident audit trail |

The JSON output is suitable for direct inclusion in your SSP evidence package. The HTML report prints a clickable `file://` URI on completion.

---

## After You Run It

If all results are green and your documentation matches, you are in a good position.

If results are red, do not move forward with any SPRS affirmation until those findings are remediated. A red finding documented and ignored is worse legally than a red finding you did not know about.

## The Whistleblower Era Reality

Cyber-related False Claims Act recoveries accelerated in 2025, with DOJ reporting a record year in this area. In practice, this means documented red findings that are ignored can become legal landmines.

If a company affirms readiness while internal evidence clearly shows unresolved control failure, whistleblower exposure increases. Internal staff, contractors, or former employees can trigger investigations when technical facts and official affirmations do not match.

See [Implementation Paths](../README.md#07-implementation-paths-after-you-run-the-script) for what to do next based on your results.
