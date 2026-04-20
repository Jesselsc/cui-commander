# Getting Started: Zero Budget CMMC Baseline (14 Days)

If you have $0 to spend and you need to move from "we have no idea what we are doing" to "we have a working baseline and evidence," this is your playbook.

This guide gets you to a defensible Level 1 baseline (or a strong foundation for Level 2) in 14 days using free tools and no outside help. At the end, you will run Fleet Commander, see your technical truth, and know exactly what to fix next.

## Why Zero Budget?

Most contractors are sold compliance as a subscription service starting at $5,000 to $10,000 per month. For a 5 person shop, that kills margin before a single bid goes out.

CMMC is an architecture problem, not a software problem. The tools you already own, BitLocker, FileVault, Windows Update, your router, a spreadsheet, can build a defensible baseline if you put them in the right order. This guide shows you how.

Where a $50 hardware key or a $200 switch will prevent an audit failure that costs thousands, it will be called out clearly as a professional grade upgrade. Those are investments, not subscription anchors.

---

## BEFORE YOU START: Make One Decision

Your baseline strategy depends on whether you are building for DoD or GSA work.

**This matters because as of March 2026, they are not the same.**

### DoD: Build for NIST SP 800-171 Revision 2

Most defense contracts still require Rev 2. The DoD issued a class deviation that keeps Rev 2 as the assessment standard while Rev 3 adoption rolls out slowly. If you do not know which you need, assume Rev 2.

- 110 controls across 14 families
- Current assessment baseline
- Simpler to implement for small shops

### GSA: Prepare for NIST SP 800-171 Revision 3

The General Services Administration (civilian federal work, citizen-facing services, some tech contracts) has started requiring Rev 3 for new solicitations. Rev 3 is newer, fewer contractors are ready, and it has different control emphasis.

- 97 reorganized controls (fewer, but different shape)
- Expanded supply chain requirements
- Organization-Defined Parameters (ODPs) that give you flexibility
- 1-hour incident response requirement explicitly stated

### Unknown or Bidding Both?

Build Rev 2 first. Design your environment with Rev 3 hooks (see "Rev 2 vs Rev 3: The Gap" section below).

When you move to Rev 3, you will not tear everything out. You will reorganize evidence, add supply chain documentation, and update response procedures. It is not a rebuild; it is a reframing.

---

## Rev 2 vs Rev 3: The Gap (What Actually Changes)

If you build for Rev 2, here is what you will need to add or adjust if you later move to Rev 3.

### Categories of Change

| Category | Rev 2 | Rev 3 | Practical Impact |
|---|---|---|---|
| **Control Count** | 110 controls | 97 controls (reorganized) | Fewer, but grouped differently. Some controls merge. |
| **Incident Response Time** | Not explicit | **1-hour external reporting requirement** | **This is a STOP WORK event.** You must have procedures and tooling to detect and report within 1 hour. If you miss this clock, you are in material breach. Most owners are not ready for this. |
| **Supply Chain Focus** | Light | Heavy (new SC family emphasis) | Document third-party risk, software provenance, vendor vetting. Rev 2 shops often skip this. |
| **ODP (Org-Defined Parameters)** | Minimal | Significant | You get to define some implementation details instead of one-size-fits-all. Flexibility, but requires documentation. |
| **Cloud/Remote Work** | Assumed but not explicit | Direct guidance on remote and cloud implementations | Rev 3 speaks directly to VPN, cloud identity, remote access. Rev 2 makes you infer it. |
| **Encryption** | AES-128 acceptable | AES-256 strongly preferred | If you use AES-128 for Rev 2, upgrade to AES-256 for Rev 3. |
| **MFA** | Required for privileged | Required for privileged; explicit OTP guidance | Rev 3 prefers modern MFA (FIDO2, Windows Hello), not SMS. |

### 8 Specific Controls Where Implementation Differs Most

1. **AC-2 Account Management**: Rev 3 adds explicit remote access account management. Rev 2 assumes collocated.
2. **IA-2 Authentication**: Rev 3 requires MFA without exception. Rev 2 allows some exceptions. Upgrade your exceptions.
3. **SI-12 Information Handling and Retention**: Rev 3 adds media sanitization proof requirements. Rev 2 is vague. Start documenting now.
4. **SC-7 Boundary Protection**: Rev 3 emphasizes explicit cloud boundary controls. Rev 2 lets you assume traditional network perimeter.
5. **SA-* (Supply Chain)**: Rev 3 expands supply chain vetting from 3 controls to 6+. Rev 2 shops often have zero. Start documenting vendor risk.
6. **IR-5 Incident Monitoring**: Rev 3 adds the 1 hour reporting clock. Rev 2 does not. You need logging, alerting, and escalation procedures.
7. **CA-9 Internal System Connections**: Rev 3 adds explicit interconnection documentation. Rev 2 leaves it implied.
8. **AU-6 Audit Review**: Rev 3 requires automated or semi automated analysis. Rev 2 accepts manual logs. Start collecting logs for analysis.

### Build Strategy

**If building Rev 2:** Do all 14 days below. Then for Rev 3 transition later, add supply chain controls, upgrade MFA, upgrade encryption to AES-256, and add the 1-hour incident clock.

**If building for GSA/Rev 3:** Do the 14 days, but when you select tools (days 8-10), **choose Rev 3-ready vendors where noted.** It costs the same but saves rework.

> **Rev 3 Sidebar: The $0 Fix for the 1-Hour Incident Clock**
>
> Rev 3 requires external reporting within 1 hour of detecting an incident. A zero budget shop has no automated monitoring to catch incidents the moment they happen. That means your detection depends on your people.
>
> If Bob sees a strange pop up at 8:00 AM and does not tell anyone until 10:00 AM, the 1 hour clock has already expired.
>
> Your zero budget tool here is a mandatory policy and a 5 minute staff meeting: "If anything looks wrong on your computer, your phone, or your email, tell the owner immediately. Do not wait until the end of the day. Do not try to fix it yourself first."
>
> Write that down as a one paragraph procedure, have every employee sign it, and keep the signed copies. That is your documented human detection process. It will not replace a SIEM, but it gives you a defensible starting point and satisfies the procedural evidence requirement while you build toward automated monitoring.

---

## The 14-Day Zero-Budget Baseline Plan

You are going to work in four phases:

```
Days 1-3       Days 4-7        Days 8-10       Days 11-14
INVENTORY      STAND UP        DOCUMENT        VALIDATE
-----------    -----------     -----------     -----------
Day 1:         Day 4:          Day 8:          Day 11:
Hardware       Encryption      SSP Starter     Run Script
Inventory
               Day 5:          Day 9:          Days 12-13:
Day 2:         MFA             Account +       Fix Red
User Audit                     Visitor Logs    Flags
               Day 6:
Day 3:         Segmentation    Day 10:         Day 14:
Network Map                    Patch Log       Re-run +
               Day 7:                          Baseline
               Patching
```

Go in order. Do not skip ahead.

---

## Days 1-3: Know What You Have

### Day 1: Hardware Inventory

**Sweat Equity:** 1-2 hours | **Cash Cost:** $0

Make a list of every computer, server, and network device you own. For each, note:

- **Device type**: Laptop, desktop, server, NAS, router, firewall, phone, tablet
- **Operating system**: Windows 10/11, macOS, Ubuntu, etc.
- **Who has admin access**: Anyone? Everyone? Specific people?
- **Is it encrypted?**: Full disk? Partial? None?
- **Does it have MFA setup?**: Yes or no. If yes, how? (app, hardware key, SMS, etc.)

**Tools:** Spreadsheet. That is it. Pencil and paper works too.

**Time:** 1-2 hours for a small shop.

**What you are finding:** Most shops discover they have zero encryption and everyone has admin rights. That is normal and fixable.

> **Windows 10 Warning:** Windows 10 reached end-of-life in October 2025. Running an unsupported operating system is a hard failure on patch management (FAR Requirement 13 / NIST 3.14.1). If any machine in your inventory is still on Windows 10, upgrading to Windows 11 is your zero-budget fix. It is free for eligible hardware and takes a few hours. Do not proceed with the rest of this guide on an EOL machine.

---

### Day 2: User Accounts Audit

**Sweat Equity:** 1-2 hours | **Cash Cost:** $0

List every person who has access to:
- Admin/root accounts
- Shared drives or cloud storage with CUI
- Email systems
- Any system with government data

For each person, note:
- Name and role
- What systems they can access
- When they last used each system
- Whether they still work here (this finds forgotten accounts; those are audit failures)

**Tools:** Spreadsheet. Check Active Directory if you have it (`Get-ADUser -Filter * | Select-Object Name | Export-Csv users.csv` in PowerShell).

**Time:** 1-2 hours.

**What you are finding:** Stale accounts you forgot about. Former employees still have access. Contractors with standing access. These kill audits.

---

### Day 3: Network Map

**Sweat Equity:** 1 hour | **Cash Cost:** $0

Draw or list how your network is organized:

- How many subnets/network zones do you have?
- Office network: who is on it?
- Engineering/CUI network: is it separate from office?
- IoT/embedded systems (HVAC, CNC, PLCs): are they segmented?
- Remote access: do you have VPN?
- Cloud services: what is connected?

**Tools:** Draw on paper, or use [draw.io](https://draw.io) (free, cloud-based, no signup required).

**Time:** 1 hour.

**What you are finding:** How bad (or how good) your segmentation is. Most small shops have zero segmentation. Everything talks to everything.

---

## Days 4-7: Stand Up Controls

Now you build the baseline. **Do weeks in this order. Do not skip.**

### Day 4: Encryption

**Sweat Equity:** 1 hour of setup | **Cash Cost:** $0

(Note: Actual encryption runs in the background overnight. You can move to other tasks while it works.)

**Goal: Enable full-disk encryption on every computer.**

#### Windows 10/11 (Free)
BitLocker is built in. Enable it:
1. Open "Manage BitLocker" from Windows Settings
2. Click "Turn on BitLocker"
3. Save recovery key (print it, lock it in a safe)
4. Let it encrypt overnight

**Time:** 30 minutes per machine. Runs in background.

#### macOS (Free)
FileVault is built in:
1. System Settings → Privacy & Security → FileVault
2. Turn on, save recovery key
3. Let it encrypt overnight

**Time:** 30 minutes per machine.

#### Linux (Free)
LUKS encryption during install, or enable on existing systems with `cryptsetup`.

**Time:** Varies. If doing fresh installs, do it during OS install. Easier.

#### Servers (Free or Low-Cost)
- **Windows Server:** BitLocker (built in)
- **Linux:** LUKS or dm-crypt (free)
- **Mac Mini/Studio:** FileVault (built in)

**For shared storage (NAS, cloud):**
- Enable encryption at rest on Synology, TrueNAS, or cloud provider
- Most cloud storage (AWS S3, Azure, Google Drive) encrypt at rest by default now

**Rev 3 note:** Make sure encryption is AES-256, not AES-128. Check your settings.

**Evidence to collect (Auditor will ask for these):**
- **Screenshot of encryption status for each machine** (BitLocker, FileVault, LUKS enabled)
- **List of recovery keys** (printed, stored securely, backed up)
- **Screenshot of cloud encryption settings** showing encryption enabled

---

### Day 5: Multi-Factor Authentication (MFA) for All Admin Accounts

**Sweat Equity:** 15-30 minutes per admin | **Cash Cost:** $0–75 (depends on choice)

**Goal: Nobody logs in as admin with just a password.**

#### Step 1: Identify Admin Accounts

From your Day 2 audit, list everyone with admin rights. For small shops, that is usually 2-3 people. For bigger shops, maybe more.

#### Step 2: Choose Your MFA Method

**Option A: Authenticator App (Free, Easier)**
- Windows/macOS: Download Microsoft Authenticator or Google Authenticator
- Each admin gets the app, they scan a QR code, and they have to open the app to approve logins
- No hardware cost
- Time: 15 minutes per person
- **Good for:** Rev 2 (DoD) work right now
- **Limitation:** Can be social-engineered if attacker has your phone

**Option B: Hardware Security Key (Free Trial or ~$50–75, RECOMMENDED FOR GSA/REV 3)**
- YubiKey or similar (you can get a free trial from some vendors)
- Physical key, no phone required, phishing-proof
- Time: 20 minutes per person
- **Cost:** ~$50-75 per key, but lasts forever
- **This is what GSA wants:** The GSA is actively pushing away from app-based MFA for Rev 3. Hardware-backed FIDO2 keys are the 2027 audit-proof choice.
- **Future-proof:** If you are doing any GSA work or planning to be audit-ready in 2027, skip the app. Go straight to hardware keys now. It costs $50 per person. Do not rework this later.

**Option C: Windows Hello / biometric (Free, Easy)**
- Windows 11: Fingerprint or face login
- Built in, free, secure
- Time: 10 minutes per person
- **Good for:** Local device access
- **Limitation:** Does not work for remote access or cloud admin accounts. Only devices with fingerprint/face hardware.

**My recommendation:**
- **If you are Rev 2 (DoD):** Start with Microsoft Authenticator (free). You can upgrade later.
- **If you are Rev 3 (GSA) or bidding both:** Buy the hardware keys now. ~$150–200 for a small team. Saves rework in 2027. This is the difference between "audit ready" and "audit scramble."

#### Step 3: Enable MFA on Key Systems

1. **Windows/macOS local admin accounts:** Use the OS built-in MFA (Windows Hello or biometric if available)
2. **Cloud admin accounts** (if you use cloud storage, email, etc.):
   - Google Workspace: Settings → Security → 2-Step Verification
   - Microsoft 365: Admin Center → Security → MFA
   - AWS/Azure: IAM → MFA
   - Most cloud services support authenticator apps

#### Step 4: Lock Down Default Accounts

Disable or rename the default "Administrator" account on Windows. It is a known target. If someone hacks your network, the first thing they try is "Administrator" with weak passwords.

**Evidence to collect (Auditor will ask for these):**
- **List of admin accounts with MFA enabled** (name, MFA method, date enabled)
- **Screenshot of MFA settings** showing MFA is active on each system
- **Log showing MFA deployment** (date applied, who applied it)

---

### Day 6: Network Segmentation (Basic)

**Sweat Equity:** 2-4 hours | **Cash Cost:** $0 (basic) to $300–500 (VLAN hardware if you go that route)

**Goal: Separate your office/business network from any system that touches CUI or sensitive data.**

If you only do Level 1 (FCI only, no CUI), this is lighter. If you are Level 2, this is mandatory.

#### Level 1: Basic Segmentation (Firewall Rules)

Most small shops have one network. Everyone is on it. Start here:

1. **If you have a managed firewall or WiFi router:** 
   - Create two WiFi networks: "Office" and "Guests"
   - Office network: Your employees, your computers
   - Guests: Visitors, contractors, phones
   - They cannot see each other or your printers

2. **If you have servers or storage with CUI:**
   - Put restrictive firewall rules on them
   - Only allow access from specific computers/IPs
   - Block everything else

3. **Cloud-based CUI (Google Drive, OneDrive, Sharepoint):**
   - Create a folder or site dedicated to CUI
   - Restrict sharing: only your employees, no external sharing
   - Document the restriction (screenshot of share settings)

#### Level 2: Better Segmentation (VLANs, if you have a capable switch)

If you have a managed switch or advanced router, create VLANs:

- **VLAN 1 (Office):** General business network. Everyone. Printers, etc.
- **VLAN 2 (CUI/Engineering):** Only machines that touch CUI. File servers, engineering machines, etc.
- A firewall rule blocks VLAN 1 from initiating connections to VLAN 2. One-way communication only.

**Tools:**
- Firewall: Use your existing router/firewall. Most support basic rules.
- Managed Switch: Netgear ProSafePlus, Ubiquiti EdgeSwitch, or equivalent. $200-400 on used market.
- **Free:** pfsense or OpenWrt if you want to build a DIY firewall (advanced, not recommended for beginners)

**Rev 3 note:** Rev 3 explicitly tests boundary protection between network zones. Your evidence should show network diagrams and firewall rule screenshots.

**Evidence to collect (Auditor will ask for these):**
- **Network diagram showing zones/VLANs** (hand-drawn or digital, annotated with IP ranges)
- **Screenshot of firewall rules** showing what traffic is allowed/blocked between zones
- **WiFi network names and access control settings** (which networks exist, who can join each)
- **Cloud folder/site sharing restrictions** (who has access to CUI storage)

---

### Day 7: Patch Management & Vulnerability Scanning (Basic)

**Sweat Equity:** 2-4 hours | **Cash Cost:** $0

**Goal: Make sure your systems are patched and you can prove it.**

#### Patches: Establish a Baseline

1. **Windows:** Enable automatic updates
   - Settings → System → Update & Security → Windows Update
   - Turn on "Automatic (recommended)"
   - Document when you last rebooted for patches

2. **macOS:** Enable automatic updates
   - System Settings → General → Software Update → Automatic Updates
   - Turn on all options

3. **Linux:** Set up automatic security updates
   - Ubuntu: `sudo apt install unattended-upgrades`
   - CentOS/RHEL: `sudo yum install yum-cron`

4. **Third-party software:** Chrome, Firefox, Zoom, etc.
   - Most auto-update by default
   - Check their settings to confirm

#### Vulnerability Scanning: Run a Free Scanner

Pick one and run it on a machine:

**Option A: Nessus Essentials (Free for home/small business)**
- Download from nessus.org
- Creates a local scan report showing missing patches, weak configs, etc.
- Time: 30 minutes to run

**Option B: OpenVAS (Free, open source, more complex)**
- Free but steeper learning curve
- Community version is solid

**Option C: Qualys CloudView (Free trial, limited)**
- Cloud-based, no install
- Limited scans per month on free tier

**My recommendation for Day 7:** Run Nessus Essentials. It will find missing patches and insecure settings. Document the results. This is your baseline vulnerability scan.

**Evidence to collect (Auditor will ask for these):**
- **Screenshot of Windows/macOS/Linux update settings** (showing all are set to automatic)
- **List of last patch dates for key machines** (spreadsheet with OS, machine name, last patched date)
- **Vulnerability scan report** (Nessus or equivalent, the actual report file)
- **Screenshot showing vulnerability status** (zero high-priority unpatched vulnerabilities, or a documented plan to fix them)

---

## Days 8-10: Document What You Did

**This is where most small contractors lose audits, not because the technical work is bad, but because they have no written evidence of it.**

You have technical controls in place. Now you need to write down what you did so:
1. You remember it 6 months from now
2. An auditor can verify you actually did it
3. You can prove it was intentional, not accidental

You are going to build three documents: a System Security Plan (SSP) starter, a list of accounts, and a patch log.

**Time investment on these three days is not optional.** If you have great technology and zero paperwork, you fail the audit. Auditors grade on evidence, not on vibes.

### Day 8: System Security Plan (SSP) Starter

**Sweat Equity:** 2-3 hours | **Cash Cost:** $0

The SSP is your security story. It answers:
- What information do you handle?
- What systems process it?
- What controls do you have?
- How do you know they work?

**Use the template:** For now, use the 5-question structure below as your working draft.

For now, answer these 5 questions in a document (Word, Google Docs, doesn't matter):

1. **What is your business and what information do you handle?**
   - "We are a CNC shop. We receive controlled engineering drawings from aerospace primes. We store them on a local NAS and a shared cloud drive."

2. **What are your systems?**
   - List your computers, servers, routers, printers, cloud services
   - Where does CUI go? List the systems

3. **What controls do you have in place?**
   - Encryption on all laptops and servers? ✓
   - MFA on admin accounts? ✓
   - Network segmentation between office and engineering? ✓
   - Automatic patches enabled? ✓
   - Firewall restricting access to CUI systems? ✓

4. **How do you know the controls work?**
   - Encryption status screenshots from each machine
   - MFA logs showing logins required 2FA
   - Network diagrams showing segmentation
   - Patch management logs showing auto-updates last ran on [date]

5. **What are your procedures for when things go wrong?**
   - If a laptop is stolen: immediately revoke accounts, change encryption key
   - If someone gets a phishing email: mark it, move to quarantine
   - If a machine gets malware: disconnect it, scan, rebuild if needed
   - If a user leaves: disable account, collect equipment, wipe hard drive

**Time:** 2-3 hours to write the first version.

**Format:** Plain text or Word doc. Does not have to be fancy. Auditors want clear, honest, factual.

---

### Day 9: Account Management Log & Visitor Log

**Sweat Equity:** 1 hour | **Cash Cost:** $0

#### Account Inventory

From your Day 2 audit, create a clean **Account Inventory** document. **This is one of the first documents an auditor will ask for.** They want to verify that:
- You know who has access
- Inactive accounts have been removed
- Each account has a business reason
- Admin accounts are locked down

| Account Name | System | User | Access Level | Last Used | Status | MFA Enabled |
|---|---|---|---|---|---|---|
| admin | Windows Server | John Smith | Admin | 2026-04-05 | Active | Yes |
| john.smith | Windows 10 laptop | John Smith | User | 2026-04-06 | Active | Yes |
| qa_shared | NAS 1 | Quality Team | Read/Write | 2026-04-06 | Active | No |
| intern_temp | Windows 10 | temp contractor | User | 2026-03-15 | INACTIVE | No |

**Action:** Delete or disable inactive accounts (like the temp contractor above).

**Why this matters:** Auditors check for stale accounts. They are a Common audit failure.

#### Visitor / Contractor Access Log

If you ever bring in contractors, temps, or visitors who touch your network or workspace:

| Visitor Name | Company | Role | System/Area Access | Start Date | End Date | Supervising Employee |
|---|---|---|---|---|---|---|
| Bob Johnson | XYZ Consulting | Network setup | Server room, domain admin | 2026-03-20 | 2026-03-22 | John Smith |
| Mary Lee | Vendor Support | Remote support | Remote SSH access | 2026-04-01 | 2026-04-03 | IT |

**Time:** 1 hour to create and review.

**Evidence:** Keep this log. Auditors will ask for it.

---

### Day 10: Patch and Security Update Log

**Sweat Equity:** 1 hour to create, 15 minutes per month to maintain | **Cash Cost:** $0

Create a simple log of patches and security scans. **Auditors will ask to see a history of patching over time.** Do not skip this.

| System | OS/Software | Patch Date | Description | Verified By | Notes |
|---|---|---|---|---|---|
| laptop-001 | Windows 11 | 2026-04-06 | Monthly Patch Tuesday | John | Automatic, rebooted |
| server-01 | Ubuntu | 2026-04-05 | Security updates | John | unattended-upgrades, ran auto |
| All machines | Nessus Scan | 2026-04-06 | Vulnerability assessment | John | Baseline scan, 0 critical issues |

**Time:** 1 hour to set up, then 15 minutes each month to update.

**Why this matters:** Auditors want to see a **pattern**, not a one-time event. Showing you have patched consistently over time (even if it is just 2 months of entries) is far more credible than showing one audit.

---

## Days 11-14: Validate and Discover Gaps

### Day 11: Run Fleet Commander

**Sweat Equity:** 30 minutes to run, 30 minutes to interpret | **Cash Cost:** $0

You are going to run Fleet Commander. This is where you find out your real technical truth.

**Before you run it:**
1. Read [The MSTechAlpine Diagnostic Script](the-mstechalpine-diagnostic-script.md)
2. Understand what it checks and what it cannot check
3. Run it on a representative machine (a laptop or server that touches CUI if you have one)

**What it checks:**
- Encryption status
- MFA configuration
- Account status (enabled, disabled, stale)
- Firewall/network rules (Linux and macOS)
- Vulnerability scan results
- Patch status

**What it flags:**
- ✅ Green: Control is in place
- 🟡 Yellow: Control is partial or needs review
- ❌ Red: Control is missing and is a compliance risk

**Time:** 30 minutes to run and interpret.

**What you will see:**
- Probably some yellow and red flags in areas you did not plan for
- That is normal. The scripts finds the gap between "what we think we did" and "what is actually configured"

**Keep the output.** You will need it for evidence.

---

### Day 12-13: Fix the Red Flags

**Sweat Equity:** 1-4 hours (depends on what broke) | **Cash Cost:** Varies

The script will tell you what didn't work. Go fix it.

Common issues:
- MFA is enabled but not on all admin accounts → add the remaining accounts
- Encryption is on disks but not on USB drives → encrypt them
- Firewall rules exist but have exceptions → tighten the rules
- Patch logs show some machines have not patched in 60+ days → run updates

**Time:** Depends on what the script found. Could be 1 hour, could be 4 hours.

**Document what you fix.** Take a screenshot or note showing the before/after.

---

### Day 14: Re-run the Script and Get Your Baseline Score

**Sweat Equity:** 30 minutes | **Cash Cost:** $0

Run Fleet Commander again. You should have fewer red flags.

Fleet Commander will show a RED/YELLOW/GREEN result for each control — this is your technical baseline. Red findings are gaps that must be fixed before any SPRS affirmation.

This is your technical baseline.

---

## What You Have Built (In 14 Days)

**Total Time Invested:** ~30–40 hours of focused work
**Total Cash Spent:** $0–$75 (depending on MFA choice)
**What You Own:** A defensible baseline with evidence

- ✅ Full-disk encryption on all systems
- ✅ MFA on all admin accounts
- ✅ Network segmentation (basic or VLANs)
- ✅ Automatic patch management
- ✅ Vulnerability baseline scan
- ✅ System Security Plan (draft)
- ✅ Account and visitor logs
- ✅ Patch management log
- ✅ Fleet Commander results
- ✅ Written evidence for each control (auditors want this more than tech specs)

**For Level 1 (FCI only):** You are 75%+ done. You need to:
- Clean up evidence documentation
- Add a few missing procedural controls (e.g., media disposal, visitor access)
- Get script gaps to yellow/green
- Realistically another 2–4 weeks of work

**For Level 2 (CUI):** You have a strong foundation. You need to add:
- 20–30 more controls (access logging, incident response, supply chain vetting, etc.)
- Better documentation (more detail in SSP, more evidence logs)
- More rigorous testing (vulnerability scans not just at baseline, but quarterly)
- Realistically another 8–12 weeks of work, or Tier 2 review to prioritize it

---

## What Now? Three Paths

### Path 1: Keep Going Yourself (Patriot Path)

Take the remaining gaps the script flagged. Fix them using the repo guides:
- [Level 1 Pass Requirements](cmmc-level-1-pass-requirements.md)
- [Level 2 Pass Requirements](cmmc-level-2-pass-requirements.md)
- [Common Failure Patterns](common-failure-patterns.md)

**Cost:** $0–$1,000 depending on tools you adopt
**Time:** 4–8 weeks
**Risk:** Medium - you own all execution risk

### Path 2: Get a Review Before You Claim Readiness (Tier 2 Validation)

You have 14 days of work done. A principal architect reviews your environment:
- Script output
- Network/firewall configuration
- Documentation quality
- Evidence gaps
- Prioritized remediation list

Then you know exactly what to fix before an auditor sees it.

**Cost:** Contact [mstechalpine.com/contact](https://mstechalpine.com/contact) for pricing
**Time:** 1 week turnaround
**Risk:** Low. You get expert validation before you claim anything in SPRS.

### Path 3: Full Implementation + Enclave Build (Tier 3 Enclave)

You do not have time or confidence to build it yourself. We implement:
- Firewall/boundary protection configured correctly
- FIPS-validated encryption deployed
- Complete evidence package ready for C3PAO
- 30-day build, guaranteed to meet assessment standards

**Cost:** Flat-rate for small contractors, market rate for bigger firms
**Time:** 30 days
**Risk:** None. Fully managed, guaranteed readiness.

---

## Staying Ready: After Day 14

Once you have built this baseline, keep it alive:

- **Monthly:** Update your patch log. Confirm patches ran.
- **Monthly:** Update your account log. Remove stale accounts.
- **Quarterly:** Re-run Fleet Commander. Address any new red findings before they accumulate.
- **Annually:** Re-run a full vulnerability scan. Check for new gaps.

**Cost:** 1–2 hours per month. Free.

---

## Free Tools Used in This Guide

| Control | Free Tool | Cost | Notes |
|---|---|---|---|
| Full-disk encryption | BitLocker, FileVault, LUKS (built in) | $0 | Already on your devices |
| MFA (App) | Microsoft Authenticator | $0 | Good for Rev 2 (DoD) |
| MFA (Hardware) | YubiKey, Titan Key, etc. | $50–75 per key | Recommended for Rev 3 (GSA) |
| Network diagram | draw.io, Lucidchart | $0 | Free cloud tools, save locally |
| Firewall rules | Your existing router/firewall | $0 | Most routers support basic rules |
| Managed switch (optional) | Netgear ProSafePlus, Ubiquiti | $200–500 used | Only if you want VLANs |
| Patch management | Windows/macOS/Linux built-in | $0 | Already configured |
| Vulnerability scanning | Nessus Essentials | $0 | Free for small business |
| Documentation | Google Docs, Word, Markdown | $0 | You already have access |
| Fleet Commander | fleet-commander (this repo) | $0 | Included — run from program/ |

**Path A (Bare Minimum):** $0 | Authenticator app MFA, no new hardware
**Path B (GSA/Rev 3 Future Proof):** $50–150 | Hardware keys for admin team, saves 2027 rework
**Path C (Small Team with VLAN):** $300–500 | Add managed switch for network segmentation (not required for Level 1)

---

## Critical: Before You Affirm Anything in SPRS

**This is the legal liability checkpoint.** Affirming a score without backing evidence is a False Claims Act violation. Before you click "affirm" in SPRS, verify:

1. ✅ Script is green or yellow (no reds)
2. ✅ You have written evidence for each control (SSP, logs, screenshots)
3. ✅ You have not affixed CUI-related data to systems without encryption
4. ✅ Admin accounts have MFA
5. ✅ You are not lying about controls you do not have (False Claims Act)

If any of these are not true, fix them first.

**Not sure?** Run the SPRS pre-check: [SPRS Mission Ready Pre-Check](https://app.renovationroute.com/public/sprs-precheck)

**Still not sure?** Get the Tier 2 review. It is cheaper than a failed audit.

---

## If You Hit a Wall

You have done solid work. If you get stuck on a specific control:

1. Check [Level 1 Pass Requirements](cmmc-level-1-pass-requirements.md) or [Level 2 Pass Requirements](cmmc-level-2-pass-requirements.md) for plain-English explanations
2. Review the controls breakdown in the pass requirements docs for examples of what to document
3. Run the SPRS pre-check to see where you stand relative to others
4. Open a GitHub Issue or Discussion on the repo with your specific question

You are not alone in this. Hundreds of small contractors are doing exactly this right now.

---

*This guide assumes Level 1 or early Level 2 work. For Level 3, consult the government directly. This is not legal or compliance advice; it is a practical starting point.*
