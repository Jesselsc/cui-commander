# Linux-First CUI Architecture Notes

Look, I absolutely love Linux, but my feelings don't matter. Trying to force it into these federal requirements is a massive uphill battle. It isn't a technical failure of Linux itself, it’s largely political.

I’ve sat in those NIST workshops, and the room was always split. Half the people there knew exactly what was happening, they saw that the new requirements were being written in a way that effectively priced out or technically blocked Linux.

Linux is built on freedom and community collaboration, so seeing the door slammed on it as a viable option for small contractors just doesn't sit right with me. The bureaucracy has made using it for CUI a nightmare which means, yes you will have to pay more.

## 1. The DFARS 7012 Legal Trap

If you handle CUI, your contract likely includes `DFARS 252.204-7012`. This clause has sections, especially paragraphs `(c)` through `(g)`, that require you to report cyber incidents to the DoD within 72 hours and provide forensic images of your systems if requested.

### The Problem: Forensic Image Liability

Paragraphs (f) and (g) are the hidden killers for custom-built Linux stacks.

If you run a custom-built mail server or file share on a generic VPS (Linode, DigitalOcean, etc.), those providers have no legal framework to support DoD forensic image requests. If the DoD demands a forensic image at 2:00 AM Friday, your VPS provider will not help.

Standard commercial cloud providers like regular Google Workspace or standard Microsoft 365 also do not contractually commit to those DoD-specific reporting and forensic obligations.

### The Solution: Shift the Risk to Microsoft

`GCC High` is positioned as a sovereign cloud environment. Microsoft contractually supports **all** reporting and forensic obligations associated with DFARS 7012 paragraphs (c) through (g).

If you build your own Linux-only stack, you are the one responsible for providing forensic images and supporting DoD investigation requests `24/7/365`. That liability does not fit in a small contractor's risk profile.

## 2. The FIPS 140-3 Cliff (September 21, 2026)

CMMC Level 2 requires FIPS-validated encryption for CUI at rest. There is a hard cutoff date on the calendar.

### The Problem

On September 21, 2026, all FIPS 140-2 certificates will be moved to the "Historical List" by NIST. After that date, 140-2 is no longer approved for new certifications or compliance claims.

If your Ubuntu workstations are using FIPS 140-2 modules for CUI disk encryption, an audit conducted after September 21 may fail unless you have a documented migration plan to FIPS 140-3.

### The Solution

Use **Ubuntu Pro 24.04 LTS** or **RHEL 9.x**. These distributions have automated, assessor-approved paths to FIPS 140-3 validated modules.

- **Ubuntu Pro:** Includes the "FIPS-updates" repository with FIPS 140-3 validated kernel, OpenSSL, and dm-crypt modules updated automatically
- **RHEL 9.x:** Red Hat's FIPS Image with active support for 140-3 compliance

Other distributions do not have clear FIPS 140-3 roadmaps that an auditor will accept. Do not use CentOS 7, Debian 11, or unsupported Ubuntu LTS for CUI if you want to pass a 2026+ audit.

## 2b. FedRAMP Moderate Requirement

### The Problem

If you use a custom-built Linux server for email or file sharing, you may have to prove to an assessor that your environment satisfies the cloud security expectations that would otherwise be inherited from an approved provider.

### The Solution

By using `GCC High`, you inherit Microsoft's authorized cloud controls instead of trying to recreate that entire compliance burden yourself in your `SSP`.

## 3. Identity: The Entra ID Anchor

Even if every workstation is Ubuntu, you still need a central source of truth for who is allowed access.

In 2026, you should not be managing local `/etc/passwd` files across a CUI environment. That is a scalability and audit nightmare.

### The Move: Entra ID with Conditional Access

Join your Ubuntu systems to Microsoft Entra ID (formerly Azure AD) using `sssd` or the `aad-auth` package.

**Why this matters:**
- Centralized identity control auditors understand
- Enforcement of Conditional Access policies
- Single source of truth for authorized users
- Audit log of every Linux login in one place

**Conditional Access Example:**
```
Only allow login to this Linux CAD workstation if:
  1) User has completed Phishing-Resistant MFA (YubiKey)
  2) Device is marked "Compliant" in Microsoft Intune
  3) Login occurs from approved IP ranges (office network)
```

This gives you automated enforcement of "least privilege on Linux" without writing custom PAM modules.

### The Evidence You Get

Intune and Entra ID generate audit logs showing every login attempt, MFA result, and conditional access decision. This is exactly what a C3PAO auditor wants to see.

## How To Do a Linux First Setup the Right Way

If you want to stay Linux first, do not think of `GCC High` as your operating system. Think of it as the compliance shield around identity, messaging, storage, and regulated data handling.

| Component | Recommended Choice | Why it's the "Architect's Move" in 2026 |
|---|---|---|
| OS | Ubuntu Pro 24.04 LTS | Includes the "FIPS-updates" repository with automated FIPS 140-3 compliance. FIPS 140-2 sunsets Sept 21. |
| Data Enclave | GCC High (Microsoft 365) | Contractually satisfies DFARS 7012 (c)-(g) forensic reporting automatically. Shifts 2:00 AM DoD liability to Microsoft. |
| MFA | FIDO2 (YubiKey) | Meets the 2026 "Phishing-Resistant" preference for GSA/DoD contracts. Cannot be social-engineered remotely. |
| Disk Encryption | LUKS + TPM 2.0 | Uses hardware-backed secrets. Auditor-friendly "at rest" proof. AES-256 minimum. |
| Identity | Microsoft Entra ID via sssd | Allows Conditional Access (MFA required, device compliance required, IP restrictions). Centralized audit log. |
| Device Management | Microsoft Intune for Linux | New in 2026. Pushes compliance policies to Ubuntu systems. |
| Backups | Azure Government Storage | Keeps off-site backup data in a U.S. government-aligned environment. |
| Logging | Entra ID audit logs + Azure Monitor | Centralized, DoD-auditable, forensic-capable. |

## The "Boots on the Ground" Reality

Do not try to be a hero and build a FIPS-validated mail server on a weekend. Use Linux for what it is best at: high-performance engineering work, CAD workflows, and software development.

Let the boring corporate cloud (GCC High) handle the legal liability, forensic reporting, and compliance burden. Your job is to secure the workstations and enforce access control. Microsoft's job is to satisfy the federal requirements.

When an auditor asks, "What is your incident response procedure?" your answer is: "We report to Microsoft within 72 hours. They provide the forensic images to the DoD. Here is our SLA with Microsoft." End of story.