# Hardware, Networking, and Software: Technical Deep Dive

This document covers the technical implementation standard for the MSTechAlpine baseline. The README gives you the overview. This is where you build from.

---

## Hardware: The Physical Foundation

You cannot build a secure house on a rotten foundation. Every control you implement on software sits on top of what the hardware can actually enforce.

### Endpoints

Use Windows 11 Pro or Enterprise on managed, business class devices. Not consumer home editions. Home editions do not support the Group Policy and device management features you need for evidence collection.

If you want a Linux first approach, go [here](linux-first-cui-architecture.md). Linux is a valid path for CUI environments but requires specific distribution choices and validated crypto modules.

**What "business class" actually means in this context:**
- The device must support TPM 2.0 (Trusted Platform Module 2.0). This is the hardware chip that protects encryption keys and proves the device has trusted firmware. TPM 2.0 is required for BitLocker and Windows Hello for Business to work properly.
- If the laptop was bought at a consumer retailer, verify TPM 2.0 is present before deploying it in a CUI environment.

**The VS Code Exception:**

If your development team uses VS Code in a CUI environment, you must address telemetry. VS Code collects telemetry by default, and CUI metadata can leak through it.

- Disable telemetry globally: Add `"telemetry.telemetryLevel": "off"` to `settings.json`
- Enforce this via Group Policy (Windows) or MDM (all platforms)
- An auditor will ask how you prevent proprietary code and CUI metadata from leaving the network. Your answer must include proof that telemetry is locked off via policy, not just user choice

### Encryption

Use hardware that supports TPM 2.0 and full disk encryption with validated cryptographic modules. Prioritize products that are FIPS 140-3 ready so your crypto stack does not age out during certification timelines.

**The 2026 FIPS Cliff:**

FIPS 140-2 validation sunset occurs on September 21, 2026. If you are buying hardware or software today, do not accept FIPS 140-2 only.

- Ensure your TPM 2.0 modules and SSDs are FIPS 140-3 validated or on the NIST CMVP active roadmap
- Products with only 140-2 validation will need replacement or re-validation in shorter timelines
- Contractors who deploy 140-2-only systems near the 2026 deadline will face re-audit costs

**Windows BitLocker Specific:**

BitLocker must be configured with the FIPS-compliant algorithms policy enabled via Group Policy. If BitLocker is running in standard mode without this policy, you take a 3-point deduction in a Level 2 audit.

- Enable: `Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption > Operating System Drives > Require additional authentication at startup`
- Enable: `Computer Configuration > Administrative Templates > System > Cryptography > Use FIPS-compliant algorithms`

**Practical list for Windows environments:**
- BitLocker with TPM 2.0 protector and FIPS-compliant algorithms policy for full disk encryption
- AES-256 encryption (AES-128 is technically Rev 2 compliant but AES-256 is strongly recommended and required for Rev 3)
- Windows FIPS-compliant cryptographic algorithms policy enabled via Group Policy
- Hardware security keys (FIDO2) for phishing resistant MFA where possible

**Practical list for Linux environments:**
- Ubuntu Pro or RHEL with FIPS-validated crypto modules enabled
- dm-crypt/LUKS with AES-256 for full disk encryption
- Verify the specific kernel and OpenSSL version against the NIST CMVP validated modules list

### Servers

Physical servers, especially CAD and SolidWorks systems, must be in locked rooms or restricted access racks.

- No servers under desks.
- No servers in open trailers or job site offices without physical access control.
- If the server room does not have a lock and a log, you have a physical security gap that no software control can fix.

CAD file servers deserve special attention. A SolidWorks assembly directory with unencrypted access is a CUI exposure if those drawings contain technical data covered by your contract. Treat the file server like a safe, not a shared drive.

### Mobile and Field Devices

Field tablets and laptops must be:
- Encrypted (full disk)
- Centrally managed via MDM/endpoint management (Intune or equivalent)
- Enrolled in device management before they are used on any contract work
- Wiped or transferred only through documented device procedures

A laptop left in a truck is not just a theft issue. If it has unencrypted contract drawings on it, it is a DFARS 252.204-7012 incident.

---

## Networking: Segmentation Is the Gate

You do not let the delivery guy walk through your entire house. Your network should work the same way.

### Boundary Defense

Use a business grade firewall that supports:
- Stateful packet inspection
- Encrypted remote access with MFA (VPN using IKEv2 or WireGuard, with FIPS-validated crypto where applicable)
- Outbound filtering so compromised devices cannot phone home to external C2
- Log forwarding to a central server so logs cannot be wiped locally

Consumer routers from big box stores do not meet this requirement. Ubiquiti, Fortinet, Palo Alto, and Cisco all count. Pick a real firewall.

**Logging Requirement:** Firewall and switch logs must be offloaded to a central Syslog server. If logs only exist on the device itself, compromised systems can wipe logs to hide attacker activity. This is an audit failure

### VLAN Segmentation

Separate your business office zone from your CUI zone using VLANs (Virtual Local Area Networks). Use this clean room architecture:

- **VLAN 10 (Office):** General business, email, guest WiFi, accounting systems
- **VLAN 20 (CUI Enclave):** Engineering workstations, CAD servers, GCC High sync clients, project management with CUI
- **VLAN 30 (Shop Floor/OT, if applicable):** CNC controllers, PLCs, embedded systems. These are often legacy and cannot be patched. Firewall them off from the internet entirely and block all initiation to VLAN 20.

**Why this matters in plain English:** If an employee clicks a phishing link on an office machine (VLAN 10), segmentation and firewall rules prevent the attacker from walking directly into the CUI enclave (VLAN 20). Without segmentation, one bad click is a full network compromise.

### Least Exposure

If a server does not need internet access to function, do not give it internet access. A CAD file server does not need to reach the internet. Lock it down at the firewall and at the host.

Rules to enforce:
- Block all outbound from CUI servers except explicitly required traffic
- No direct RDP or SSH access from internet. Use a jump box or VPN.
- Unused ports closed, unused services disabled

### Logging

Put firewall and switch logs somewhere you can actually review them. Logging that no one reads is not a control.

At minimum:
- Log successful and failed authentication at boundary
- Log inter VLAN traffic at the firewall
- Log DNS queries from CUI zone (easiest way to catch beaconing behavior)
- Retain logs for at least 90 days, longer if your contract or SSP requires it

If you have no SIEM budget, centralized syslog to a locked down log server works. Do not store logs only on the device being monitored.

---

## Software and Identity: The Lock

### Cloud Anchor

For CUI handling, standard commercial email and file sharing setups are not sufficient. Microsoft 365 Commercial (non-GCC) and standard OneDrive do not meet CUI protection requirements.

**The GCC High Decision:**

If your contract contains ITAR (International Traffic in Arms Regulations) or CUI Specified, standard Microsoft 365 Commercial is a hard no.

Migrating from Commercial to GCC High later is a $20,000+ effort. If you plan to grow and pursue defense work, start in GCC High now.

**Your options:**
- **Microsoft 365 GCC** for baseline CUI contracts
- **Microsoft 365 GCC High** for ITAR or restricted CUI contracts (required for most aerospace/defense)
- **CMMC compliant cloud storage** solutions with FedRAMP Moderate or High authorization
- **Hybrid enclave model:** Local storage for CAD/large files, GCC High for email, docs, and collaboration

**FedRAMP Marketplace Requirement:**

Every cloud tool that touches CUI (Slack, Dropbox, Jira, Monday.com, etc.) must be on the FedRAMP Marketplace with Moderate or High authorization. If it is not, it cannot touch CUI. This is an audit ending gap.

Check your contracting officer or read the contract carefully. If it mentions ITAR, CTI, or references DFARS 252.204-7012 with specific data types, GCC High is mandatory.

### Identity and MFA

MFA is mandatory for all users and all admins. No exceptions.

**The 2026 Standard: Phishing Resistant MFA**

By April 2026, push notifications on your phone are being phased out as a "best practice" in favor of FIDO2 hardware keys (YubiKeys, Titan Keys).

When an auditor asks, "Show me how an attacker with a stolen password and a fake login page cannot get in," your answer is: "We use hardware backed FIDO2 keys that require physical presence. An attacker cannot bypass them remotely."

**Stronger options (in order):**
1. **Hardware security keys (YubiKey or Titan, FIDO2 protocol)** - Phishing proof, requires physical key
2. **Windows Hello for Business with TPM backed credentials** - Built in, hard to phish, Windows only
3. **Microsoft Authenticator with number matching and additional context** - Better than TOTP but still phishable

For admin accounts at Level 2: phishing resistant MFA is not optional. Use hardware keys.

Remove stale accounts on a documented schedule. Every account that exists and is not reviewed is an attack surface. Document your account review process so you can show evidence of it.

### Software Supply Chain

Engineering software and development tools get special attention:

**CAD and Design Software (SolidWorks, AutoCAD, Revit):**
- Disable cloud sync features that push files to non-compliant storage
- Review what telemetry and sharing features come enabled by default and turn off what you do not need
- Keep applications patched; vulnerability disclosures for design software are real
- Limit who can install software on CUI devices. Standard users should not have local admin

**Development Tools (VS Code, JetBrains IDEs, etc.):**
- Create a whitelist of approved extensions. Every extension is a potential backdoor.
- Enforce the whitelist via Group Policy or MDM
- Disable all telemetry (VS Code: `"telemetry.telemetryLevel": "off"`)

**AI Tools for Development (Copilot, ChatGPT, Claude, etc.):**
- Use only the Enterprise version where your code is not used for training
- For high sensitivity work, run Llama 3 (Meta's open model) locally on your desktop to keep CUI inside your physical four walls
- Document your AI tool policy and approval process

**Patch Management:**
Critical patches on CUI systems should be applied within 14 days of release. Document the process and capture evidence of patch runs.

### Encryption: Data at Rest and in Transit

- **Data at rest:** Full disk encryption on all endpoints and servers, FIPS-validated (AES-256 minimum)
- **Data in transit:** Enforce TLS 1.2 minimum; TLS 1.3 preferred; disable legacy SSL/TLS versions
- **File shares:** Do not serve CUI over SMBv1 or unencrypted FTP. Use SMB 3.x with encryption enabled.
- **Email:** If you send CUI by email, it must be encrypted in transit and ideally at rest in a compliant environment (GCC/GCC High). Do not send CUI through commercial Outlook.com or Gmail.

If you are using consumer grade tools for any of these workflows, assume you have a gap and document a remediation plan before you self assess.

---

## 2026 Technical Checklist

| Component | Minimum Standard | Why This Matters |
|---|---|---|
| OS | Windows 11 Pro/Enterprise or Ubuntu Pro (FIPS Mode) | Home editions and legacy OS lack policy enforcement and patch support |
| TPM | Version 2.0 (Required) | Protects encryption keys; required for BitLocker, Windows Hello, FIPS compliance |
| Encryption | BitLocker/LUKS with AES-256, FIPS-validated algorithm policy | Non-FIPS or AES-128 is a 3+ point audit deduction; 140-2 sunset is Sept 2026 |
| MFA (Admins) | FIDO2 hardware keys for all administrative access | Phishing proof; required at Level 2; SMS/TOTP alone may fail modern audits |
| Cloud | Microsoft 365 GCC High (ITAR) or GCC (standard CUI); all tools FedRAMP authorized | Commercial cloud is an automatic audit failure for CUI |
| Network | VLAN segmentation (Office, CUI, OT) + stateful firewall + central log forwarding | Segmentation prevents lateral movement; log offloading prevents evidence tampering |
| VPN | IKEv2 or WireGuard with FIPS crypto + MFA required | Username/password VPN alone is insufficient for CUI |
| Telemetry | Disabled on all development and CUI touching devices (VS Code, browsers, OS) | Prevents CUI metadata from leaving the network |
| Supply Chain | Approved extension whitelist for IDEs; approved AI tools (Enterprise only) | Backdoors and exfiltration vectors; Copilot training exposure without Enterprise |
| Patch Cadence | Critical patches within 14 days; quarterly vulnerability scans | Compliance requirement and audit ending gap if missed |

Deployment Priority: Bottom up from OS and encryption, then network, then identity and tooling. Do not stand up cloud storage until VLAN segmentation and firewall logging are in place.
