# CMMC Level 1 Pass Requirements

This document is a practical pass checklist for CMMC Level 1.

## What Level 1 Applies To

Level 1 generally applies when the contractor handles FCI (Federal Contract Information) and does not handle CUI in scope.

## Exact Pass Requirements

To pass Level 1, the organization must:

1. Implement all 15 requirements from FAR 52.204-21.
2. Complete the required annual self-assessment.
3. Submit required annual senior official affirmation(s).
4. Scope the assessment correctly to systems handling FCI.
5. Demonstrate that all applicable Level 1 requirements are met.

## Legal Weight of the Affirmation

The senior official affirmation is not just an IT checkbox. It is a legal representation by company leadership.

If a company certifies controls that are not actually implemented, that can create serious contractual and False Claims Act risk.

The affirmation expires every 365 days. Lapses in annual affirmation can trigger an automatic ineligible flag in your SPRS profile, which may block your ability to pull new work or exercise contract options. Put the renewal date on the calendar the day you submit.

## Scoping Tip: Keep Your FCI Boundary Small

You do not have to secure every device in the company. If only your estimating and finance teams touch federal contract documents, their systems are in scope and the field crew's tablets generally are not.

Use network segmentation to keep the FCI boundary small. If a field technician never opens a federal bid or contract document, their phone or laptop may be entirely out of scope. Fewer systems in scope means a smaller, cheaper, and more defensible assessment.

## Pass/Fail Rule for Level 1

Level 1 is a hard pass/fail gate.

- There is no partial-credit model for missing required Level 1 practices.
- You cannot treat missing controls as a normal "fix later" path and still claim Level 1 is met.

## In Plain English

To pass Level 1:

1. Put the basic 15 security controls in place.
2. Do the yearly check and document it.
3. Have a company executive sign that the submission is true.
4. Only include systems that actually handle federal contract information.
5. Be able to show evidence that the controls are really running.

## The 15 FAR 52.204-21 Requirement Areas

| Requirement | Plain English |
|---|---|
| 1. Limit system access to authorized users and devices. | Only approved people and approved company devices should be able to get into your systems. |
| 2. Limit user access to permitted transactions and functions. | Give people only the access they need to do their job, not full access to everything. |
| 3. Verify and control external system connections. | Know every outside system connected to you and block anything not approved. |
| 4. Control posting of federal contract information on public systems. | Do not post contract-sensitive data on public websites, shared drives, or social media. |
| 5. Identify users, processes acting on behalf of users, and devices. | Your systems should always know who is doing what and from which device. |
| 6. Authenticate users, processes, and devices. | Require valid login proof before granting access, not trust by default. |
| 7. Sanitize or destroy media before disposal or reuse. | Wipe or destroy old drives and media so data cannot be recovered later. This includes office printers and copiers. Many have internal hard drives that store every document scanned or printed. Wipe them before selling, returning to a leasing company, or disposing of the hardware. |
| 8. Limit physical access to systems, equipment, and operating environments. | Keep servers, network gear, and workstations physically secured from unauthorized people. |
| 9. Escort visitors and maintain physical access records. | Visitors should be escorted and logged so you know who entered sensitive areas and when. |
| 10. Monitor and control remote access sessions. | Remote connections must be approved, controlled, and monitored. |
| 11. Use malware protection mechanisms. | Run antivirus or endpoint protection on systems that can receive malicious files. |
| 12. Keep malware protection updated. | Keep malware signatures and protection tools current so they catch new threats. |
| 13. Apply security patches in a timely manner. | Install operating system and software security updates quickly, not months later. |
| 14. Perform periodic and real-time scans from external files and media. | Scan downloads, email attachments, USB drives, and other incoming files for threats. |
| 15. Perform additional safeguards as required by FAR 52.204-21 implementation guidance. | Follow any extra safeguard details required by the FAR clause and your contract context. |

### In Plain English

Level 1 is basic cyber hygiene:

- Only approved people get access.
- Keep malware out and patch systems quickly.
- Protect physical access to systems.
- Control remote access and external connections.
- Do not leak federal contract information publicly.

To translate the compliance language: "Media Sanitization" means do not throw a hard drive in the dumpster. "Physical Access" means keep the office door locked and do not let an unfamiliar delivery driver wander into the server closet unescorted. "Authentication" means require a password or login before anyone gets in.

## Level 1 At a Glance

| Feature | Requirement for Level 1 |
|---|---|
| Primary focus | Basic safeguarding of FCI |
| Control count | 15 (FAR 52.204-21) |
| Assessment type | Annual self-assessment |
| POA&Ms | Not permitted. All 15 must be met to pass. |
| System of record | SPRS |
| Sign-off | Senior company official (CEO or owner) |
| Affirmation expiry | 365 days. Lapsed affirmation can flag your SPRS profile. |

## Evidence You Should Have Ready

- System inventory for FCI scope.
- Access control and account management records.
- Patch management evidence.
- Endpoint protection status evidence.
- Physical security and visitor process evidence, including visitor logs and access records.
- Media sanitization and disposal evidence for drives, removable media, and retired hardware.
- Self-assessment record and senior official affirmation.

## Level 1 Identity Hardening (Best Practice)

Phishing-resistant MFA is not explicitly required by the Level 1 text itself, but it is strongly recommended.

Using phishing-resistant MFA can materially strengthen identity and authentication controls and reduce the most common account-compromise paths.

## Contract Reality

The contract language and flow-downs decide whether Level 1 is sufficient. If CUI appears in scope, Level 2 requirements generally apply.
