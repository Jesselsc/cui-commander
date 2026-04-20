# The MSTechAlpine Defense Baseline

## A Principal Architect's Guide to Federal Eligibility in 2026

> **⚠️ IMPORTANT DISCLAIMER**
>
> This is technical guidance for small federal contractors. It is NOT:
> - **Legal advice** - Consult your legal counsel on contract and compliance risks.
> - **An official DoD/GSA assessment** - Only C3PAOs (Certified Third Party Assessor Organizations) can certify CMMC compliance.
> - **A guarantee of contract eligibility** - Always verify your specific contract requirements with your prime/customer.
> - **A substitute for professional audit** - Use this repo to build understanding and prepare controls, then engage a C3PAO for formal assessment.
>
> This repo is free guidance to help you understand baseline requirements, build practical controls, and prepare for professional cybersecurity assessment.

Why this repo was created. I care about security and so should you and everyone at your company. I want to reduce the cost of building, not add to it.

If you are a construction owner, operations lead, or in house IT person and every security company is quoting you $6k to $10k per month, this repository is for you.

This resource is built specifically for companies where standard IT advice ("just move everything to the cloud") actually breaks the business. Big CAD assemblies that lag on OneDrive. CNC controllers that cannot run modern agents. HVAC firms with five employees and no IT department. If that is you, read on.

This project explains what matters, what does not, and how to build a practical CMMC aligned technical baseline without guessing. Coming from boots on the ground here, this is meant to be a hands on guide for what actually matters.

Most public SPRS and CMMC material is built for auditors, consultants, or enterprise IT teams. This repository is built for the owner, ops lead, estimator, project manager, or small MSP who just needs the truth: what level applies, what the clauses mean, what will fail you, and how to get moving without getting sold nonsense.

## Start Here

If you are new, do this in order:

1. Read this README end to end once to understand the big picture.
2. Not sure which level applies to you? Start here: [Which Level Do I Need?](docs/which-level-do-i-need.md)
3. Ready to build? Use the 14 day zero budget plan: [Getting Started: Zero Budget Baseline](docs/getting-started-zero-budget.md)
4. Use this level index to find your pass requirements: [CMMC Pass Requirements Index](docs/cmmc-pass-requirements-index.md).
5. Go deep only where you need to:
	- Level 1 pass requirements: [docs/cmmc-level-1-pass-requirements.md](docs/cmmc-level-1-pass-requirements.md)
	- Level 2 pass requirements: [docs/cmmc-level-2-pass-requirements.md](docs/cmmc-level-2-pass-requirements.md)
	- Level 3 pass requirements: [docs/cmmc-level-3-pass-requirements.md](docs/cmmc-level-3-pass-requirements.md)
	- C3PAO audit guide: [docs/c3pao-audit-what-actually-happens.md](docs/c3pao-audit-what-actually-happens.md)
	- Linux first CUI architecture: [docs/linux-first-cui-architecture.md](docs/linux-first-cui-architecture.md)

If you only handle FCI, start with Level 1 and keep it simple.

If you handle CUI, expect Level 2 depth: technical controls plus clean evidence.

### Who This Is Built For

| Segment | The Problem | Why This Repo Helps |
|---|---|---|
| Precision Machine Shops | CNC/G code files and shop floor controllers that cannot run modern security agents. | Practical VLAN and segmentation architecture you can actually build. |
| Aerospace / DIB Engineering | 50GB+ SolidWorks and CAD assemblies that lag under standard cloud migration advice. | Hybrid enclave model: local speed, cloud compliance. |
| Federal Prime Contractors | 50+ subs that are a security black box and a liability. | Baseline and scripts your supply chain can adopt as a standard. |
| Small Mid Specialized Trade | MEP, electrical, HVAC firms with 5 - 50 employees and no in house IT, scared of the False Claims Act. | Free plain English guides and evidence templates to get real, not guess. |
| Local MSPs | Small IT shops that are out of their depth with CMMC requirements. | A standardized SOP to help your clients stay eligible without having to hire a full time CISO. |

## Quick Definitions

If a term below is new to you, the first important use of it in this guide links back here.

<details>
<summary>Open the glossary</summary>

| Term | Plain English Meaning |
|---|---|
| CMMC | Cybersecurity Maturity Model Certification. This is the DoD framework that sets the cybersecurity level a contractor needs based on the information involved in the contract. |
| DoD | Department of Defense. This is the U.S. defense customer and rule-making environment driving most of these requirements. |
| FCI | Federal Contract Information. This is regular federal contract data that is not for public release, such as pricing, schedules, and contract performance information. |
| CUI | Controlled Unclassified Information. This is more sensitive government information that is still not classified, such as controlled drawings, technical packages, and protected project data. |
| NIST SP 800-171 | The security rulebook contractors typically follow when they handle CUI. It lays out the technical and administrative controls expected in a contractor environment. |
| SPRS | Supplier Performance Risk System. This is the DoD system used to record certain assessment results, including NIST 800-171 self-assessment scores when they apply. |
| C3PAO | Certified Third-Party Assessor Organization. This is the outside assessor used when a formal third-party CMMC assessment is required. |
| SSP | System Security Plan. This is the document that explains what your environment looks like and how your required controls are implemented. |
| POAM | Plan of Action and Milestones. This is the document that tracks security gaps, what needs to be fixed, and when remediation is expected. |
| TPM 2.0 | Trusted Platform Module 2.0. This is a security chip built into the computer that helps protect encryption keys and prove the device has trusted hardware. |
| Full disk encryption | A control that encrypts the entire drive so stolen laptops or servers cannot be read without proper access. |
| MFA | Multi Factor Authentication. This means a password alone is not enough; the user must prove identity with a second factor such as a key, app, or biometric. |
| FIDO2 | A modern phishing resistant login standard often used with hardware security keys or platform biometrics. |
| Phishing resistant MFA | MFA that is much harder to trick or steal with fake login pages, such as hardware keys or strong device backed biometric methods. |
| VLAN | Virtual Local Area Network. This is a way to separate different parts of a network so office traffic and sensitive systems do not all sit in one flat environment. |
| Segmentation | The practice of splitting systems and network zones apart so one compromised device does not automatically expose everything else. |
| Vulnerability management | The process of identifying, prioritizing, and fixing known security weaknesses in systems and software. |
| Continuous monitoring | Ongoing checking of systems over time instead of a one-time snapshot, so you can catch drift, failures, and new risks after initial setup. |

</details>

## 01. Why: The "Lock Your Doors" Reality

If you leave your job site trailer unlocked, your tools get stolen. In the digital world, foreign adversaries are systematically harvesting data from small contractors to bypass our defense systems. You guys weren't just leaving your doors unlocked, you left them wide f*$# open in a sketch neighborhood at night. So the government got involved, took them awhile, but here we are.

The U.S. Government is implementing CMMC because a single unsecured HVAC, electrical, fabrication, or roofing subcontractor can become the entry point for theft of bid specs, infrastructure maps, drawings, or personnel data. If you want to build for the [DoD](#quick-definitions), you have to lock your digital doors. It is good digital hygiene. Lock your door so hopefully the bad guy will go onto the next house that has the door open.

Most contractors do not need mystery software on step 1. They need a clear build plan. I know its not your bread and butter, but we live in a digital world. Maybe if we get lucky you can ask that lawyer or doctor to rough frame your house one day, see how he likes it. At minimum you want to know whats going on so you are not a girl going to an auto mechanic.

Security for defense adjacent work is not just an IT product decision. It is an infrastructure decision, the same way you think about a job architecture blue print. If the architecture blue print is wrong, your building might fall. Okay hopefully you get it by now. 

## 02. What: The CMMC Maturity Levels

You cannot protect what you have not identified. The first question is not "What security tool do I buy?" The first question is "What kind of government information am I receiving, storing, or touching on this contract?"

That answer drives the level.

| Level | Name | Information Handled | Assessment Type |
|---|---|---|---|
| Level 1 | Foundational | FCI (Federal Contract Information, such as pricing and schedules) | Annual self assessment |
| Level 2 | Advanced | CUI (Controlled Unclassified Information, such as drawings and technical data) | C3PAO or self assessment, depending on contract requirements |
| Level 3 | Expert | Critical technology or actively targeted programs | Government led assessment |

### What Decides Your Level

The level does not come from what you call yourself. It comes from the contract and the type of information involved.

For exact pass requirements by level, use the dedicated docs: [CMMC Pass Requirements Index](docs/cmmc-pass-requirements-index.md).

- If the contract only involves FCI, you are usually looking at Level 1.
- If the contract involves CUI, you are generally looking at Level 2 requirements.
- If the work is tied to especially sensitive or high priority national security programs, Level 3 can come into play.

In plain English:

- Level 1: "We have federal contract information, but not controlled technical data."
- Level 2: "We handle CUI, such as controlled drawings, technical packages, or protected program data."
- Level 3: "This program is important enough that the government wants deeper direct oversight."

### 2026 Rollout Reality

The practical timing matters.

> [!IMPORTANT]
> **PHASE 2 DEADLINE: November 10, 2026 - ACTIVE BID IMPACT NOW**
> 
> This is a hard cutoff for new CUI business that requires third party certification. If you are not C3PAO ready by then, you can be blocked from competing for new CUI opportunities.
>
> If you are bidding on Navy or Army work landing in Q4 2026, schedule your C3PAO assessment now. Backlogs are commonly 3 to 6 months before assessment work even starts.

**Rev 2 vs Rev 3 trap:** NIST 800-171 Rev 3 exists, but current CMMC Level 2 assessment is still graded against Rev 2. Do not use a Rev 3-only checklist for a current C3PAO audit.

**The Schedule Reality:** C3PAO scheduling and remediation take months. If you aren't ready by late 2025, you are already behind. Missing the November 2026 cutoff means you are effectively blocked from new CUI business.

### Where This Shows Up

For most contractors, this shows up in the solicitation, prime flow down requirements, and the contract clauses. The contract language and data handling requirements tell you what environment you need to build.

### How This Actually Flows

1. The contract tells you whether you handle FCI or CUI.
2. That decides the level and technical baseline you must build.
3. Your systems produce technical facts (script output and config state).
4. You turn those facts into evidence (SSP, POA&M, logs, inventories).
5. Evidence drives SPRS posture and/or assessment outcomes.
6. That posture drives whether you stay eligible for bids.

| If this is true | Then do this next |
|---|---|
| Contract says FCI only | Build Level 1 baseline, collect core evidence, run internal checks. |
| Contract says CUI | Build Level 2 baseline, tighten evidence quality, plan assessment early. |
| Script is green but docs are weak | Fix paperwork and evidence structure before any affirmation. |
| Script is red | Remediate immediately before claiming readiness. |

Bottom line: local technical reality plus clean evidence equals eligibility.

For many trade contractors, the most common path is:

- Early federal work: FCI only.
- More serious defense or technical subcontracting: CUI appears.
- High priority or highly sensitive programs: extra scrutiny beyond normal Level 2 expectations.

### Regulations and Scoring (Reference)

- SPRS scoring logic and point deductions
- Where SPRS fits in prime/government vetting workflows
- Rev 2 vs. Rev 3 transition reality and what you are graded on today

Read it here: [Regulations and Scoring Reference](docs/regulations-and-scoring.md)

## 03. Technical Standard (Overview)

The standard is simple:

- Hardware that can enforce encryption and trust (TPM 2.0 + FIPS-ready crypto path)
- Network segmentation between office and sensitive zones (VLAN + firewall boundaries)
- Strong identity controls (MFA for all users, phishing-resistant methods for privileged access)
- Hardened software and patch discipline for business and engineering workloads

If you want the full build details (hardware specs, segmentation examples, firewall logging, software hardening), use the deep dive:

- [Hardware and Networking Deep Dive](docs/hardware-and-networking-deep-dive.md)
- [Linux First CUI Architecture](docs/linux-first-cui-architecture.md)

## 04. The MSTechAlpine Diagnostic Script

**Important: This script validates one machine. Your environment is much larger.**

> [!NOTE]
> Fleet Commander runs compliance checks against the local endpoint. Network discovery (`--discover-network`) inventories hosts on your subnet but does not run compliance checks on remote machines. Combine script output with written SSP, POA&M, and policy documentation before any SPRS affirmation or C3PAO assessment.

Real networks are massive in scope: workstations, servers, routers, printers, tablets, CAD machines, field devices, backup systems. This script runs on a single endpoint. It checks one piece of a much bigger puzzle.

But here is the architecture that holds it all together:

| Layer | What it covers | What the script validates |
|---|---|---|
| **Layer 1: Hardware Foundation** | Encryption & TPM on every device (endpoints, servers, field equipment) | Does this endpoint have encryption tools and TPM present? |
| **Layer 2: Network Perimeter** | VLANs, segmentation, firewalls isolating CUI zones from office traffic | (Beyond script scope - evaluated in SSP) |
| **Layer 3: Build/Configuration** | Configuration baselines applied across all device types | (Beyond script scope - reviewed as policy evidence) |
| **Layer 4: Runtime Controls** | MFA enforcement, secrets rotation, least privilege across the org | Does this endpoint support MFA? Are accounts privileged? |
| **Layer 5: Data Protection** | Encryption in transit (TLS), at rest (disk), app-level for PII | Is disk encryption active on this endpoint? |
| **Layer 6: Detection & Response** | Logging, monitoring, incident response across all layers | (Beyond script scope - metrics gathered in SSP) |

**The script is Layer 1 + Layer 4 + Layer 5 validation for this one machine.** Your SSP, policies, and evidence artifacts cover the full scope across all devices and network zones.

**Before you run the script, get a fast SPRS triage read here:**

**[SPRS Mission Ready Pre-Check](https://app.renovationroute.com/public/sprs-precheck)** covers Rev 2 (DoD) and Rev 3 (GSA), flags the controls contractors fail most often, and gives you a readiness estimate in minutes. Built by the same team behind this repo.

The script checks actual system state (encryption, MFA, accounts, patch posture, drift) so you can catch issues before an assessor does.

Detailed run instructions, scope, and what it can/cannot find now live here:

- [The MSTechAlpine Diagnostic Script](docs/the-mstechalpine-diagnostic-script.md)
- [Fleet Commander CLI module](program/src/mstechalpine_fleet_commander/cli.py)

> [!WARNING]
> The script is a diagnostic tool, not an audit or certification. You can have a green script and still fail an audit if your policies and evidence are weak. If your script results are red, you are at risk.

Run it locally with:

```bash
# Minimal run (localhost only)
cd program && fleet-commander --json-output evidence/diagnostic.json

# Full C3PAO evidence package
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

The tool requires no third-party dependencies — pure Python 3.10+ stdlib. Evidence files are written to `evidence/` and permissions are locked to `0o600`.

## ⚠️ CRITICAL: Readiness ≠ Compliance (False Claims Act Risk)

**This section is non-negotiable. Read it before you affirm anything in SPRS.**

The U.S. Department of Justice's Civil Cyber-Fraud Initiative has been aggressive since 2025. A "green" diagnostic script result is NOT proof of compliance.

**What the script proves:** Your system has certain tools present (encryption tooling detected, MFA capable, patches available).

**What the script does NOT prove:**
- Controls are actually enforced or working
- You have written policies documenting them
- Evidence artifacts meet auditor standards
- You are legally compliant with NIST 800-171 or CMMC

**The Risk:** If you affirm a readiness score in SPRS without evidence to back it up, you are making a material misrepresentation to the federal government. That is False Claims Act exposure: criminal and civil liability, treble damages, and personal indemnification.

**The Safe Path:**
1. Run the script. Get a technical baseline.
2. Build the **evidence package** (written SSP, policy enforcement logs, audit trails, control testing).
3. **Before you affirm anything in SPRS**, have legal counsel and/or a C3PAO review your evidence package.
4. Only after professional review should you submit a readiness score.

**Bottom line:** Green script + weak evidence = fraud risk. Green script + strong evidence + professional review = defensible position.

If your script is all green but you don't have the paperwork, you are not ready to affirm. Fix the paperwork first.

## Evidence Artifacts Generated

Fleet Commander writes a complete evidence package in a single run:

| File | Description |
|---|---|
| `evidence/diagnostic-c3pao.json` | Full check results — machine readable, SHA-256 hash-chained ledger |
| `evidence/report.html` | Human-readable HTML report — RED/YELLOW/GREEN findings, CMMC domain map, remediation steps |
| `evidence/sbom.json` | CycloneDX 1.6 Software Bill of Materials |
| `evidence/srm.xlsx` | Security Requirements Matrix — 110 NIST 800-171 Rev 2 controls pre-mapped to your scan results |
| `evidence/fleet-discovery.json` | Network host inventory from active subnet scan |
| `evidence/network-architecture.svg` | Auto-generated network topology diagram |
| `evidence/asset-tags.json` | Hardware asset inventory (serial, TPM, OS, hostname) |
| `evidence/vulns.json` | CVE cross-reference against installed packages via OSV.dev |
| `evidence/hash-ledger.jsonl` | Append-only SHA-256 hash chain — tamper-evident audit trail |

All files are written `0o600` (owner read/write only). The HTML report prints a `file://` URI on completion and can be opened directly in any browser.

Ready for expert review? [Book a Tier 2 Validation](https://mstechalpine.com/contact). We will audit what you built and prioritize your next steps.

## 06. The C3PAO Audit: What Actually Happens

If you are aiming for Level 2, running Fleet Commander clean is only part of the battle. C3PAO assessors use methods of objective evidence. They do not just check boxes.

### 1. Interview (Do you actually do this?)

Assessors may pull a random estimator, PM, or office admin and ask process questions:

- Show how a bid package is sent to a subcontractor. Is it encrypted?
- What is the process if a company phone with email access is lost?

**Common failure:** Staff cannot explain or follow the policy, even when tools are installed.

### 2. Examination (Show me the receipts)

The script shows current point-in-time state. The assessor wants historical evidence.

- 90+ days of MFA and access logs
- Visitor/access logs and account review records
- Change records and policy acknowledgments

**Common failure:** No audit trail. If it was not logged, it is treated as not done.

### 3. Test (Show that controls actually work)

Assessors may ask for live demonstrations:

- Account lockout behavior after failed attempts
- Segmentation proof that dirty VLAN systems cannot reach CUI systems
- Access denial for out-of-scope users/devices

**Common failure:** Flat networks where everything can talk to everything.

### 2026 Bottleneck Warning

- **Wait time:** Plan for a 3 to 6 month queue just to get on an assessor calendar.
- **Cost range:** Small firm formal assessments commonly land in the $20k to $40k range for audit services alone.
- **One-shot risk:** You may receive a POA&M window for fixes, but failure on critical controls can still block contract progress.

### Top 3 Audit Killers We Keep Seeing

1. Shared accounts (for example: Shop_PC, Admin, generic floor logins)
2. Missing SSP (technical controls exist, but no written system narrative)
3. No MFA on webmail or remote access paths to CUI

This repo helps prevent these by forcing technical checks plus evidence discipline before affirmation.

## 07. Implementation Paths After You Run the Script

### The Patriot Path (DIY)

Best for 1-5 person shops. You have more time than money. Use the repo, join the community, and do the work yourself.

Use this repo. Do not pay anyone a dime. The guides, templates, and scripts are free and designed for exactly your situation. Level 1 is achievable without a consultant if you follow the evidence checklist and build the baseline.

### Risk Transfer Path (Validation + Enclave)

Best for firms with 20 or more seats or complex CAD requirements. You do not have time to be a part time security engineer. You pay us to move risk off your plate.

Doing this yourself is a real risk. Affirming a 110 score in SPRS without the technical evidence to back it up is a False Claims Act violation. An incorrect self assessment is not a paperwork problem; it is legal exposure. A failed C3PAO audit is not just a $20k cost. It is a 6 month block from bidding new work while the scheduler backs up.

### Paid support options (when you need them)

**Tier 2 Validation Review**
You ran the script. You have a score. You want a principal architect to tell you exactly what to fix before the auditor sees it.

- [ ] 4 hour Principal Architect review of your script output
- [ ] Prioritized remediation list specific to your environment
- [ ] Contact: [mstechalpine.com/contact](https://mstechalpine.com/contact)

**Tier 3 Enclave Build**
You need the safe room built, not just reviewed.

- [ ] We implement the firewalls, GCC High wrapper, FIPS validated encryption, and evidence package
- [ ] 30 day build, guaranteed to meet C3PAO evidence requirements
- [ ] Flat rate for small contractors, market rate for PE backed and enterprise firms
- [ ] Contact: [mstechalpine.com/contact](https://mstechalpine.com/contact)


## How To Use This Repository

1. Determine whether you handle FCI, CUI, or both.
2. Map your current environment across office, field, cloud, and local infrastructure.
3. Build in order: endpoint foundation, identity, segmentation, encryption, then validation.
4. Run evidence checks and capture the results.
5. Prioritize remediation by operational risk and eligibility impact.
6. Pair technical artifacts with the required policy and process documentation.

## Project Principles

- Build security as infrastructure, not as a black box subscription.
- Respect operational reality for dirt and diesel businesses.
- Preserve local performance where CAD and engineering workflows demand it.
- Use measurable evidence wherever possible.
- Keep the guidance practical for small and midsize contractors.

## Important Notes

- This repository provides technical guidance and automation support, not legal advice.
- Requirements and assessment pathways change. Always verify current official guidance and contract specific requirements.
- Automation can prove technical control state, but it cannot replace physical security, user discipline, or written governance.

## Repository Status

Public baseline in active development. Additional scripts, reference architectures, examples, and implementation guides will be added over time.

## License and Contributions

### License

The **documentation and guides** in this repository are licensed under **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)**.

The **Fleet Commander software** (`program/`) is licensed under the **Polyform Non-Commercial License 1.0.0**.

- Free for internal use by defense contractors and small businesses.
- Free for personal and educational use.
- **Prohibited** without a written commercial license: consulting delivery, MSSP tooling, C3PAO assessment services, SaaS platforms, or any client-facing commercial use.
- Commercial use requires a written license agreement — [mstechalpine.com/contact](https://mstechalpine.com/contact)

© 2026 Jesse Edwards / MSTechAlpine Ventures LLC

**Trademark Notice:** The "MSTechAlpine" name, the "Fleet Commander" name, and any associated logos are trademarks of MSTechAlpine Ventures LLC and are NOT included in any open license. Forks and derivatives must not represent themselves as official MSTechAlpine products. Attribution (banner, HTML footer, SBOM vendor field) is non-negotiable and must not be removed.

### Contributions

If you are an engineer or an owner who found a shortcut that works, open a Pull Request. Let's build a standard that does not cost $10k a month.
