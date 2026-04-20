# CMMC Level 3 Pass Requirements

This document is a practical pass checklist for CMMC Level 3.

## What Level 3 Applies To

Level 3 applies to high priority CUI programs targeted by Advanced Persistent Threats. If your contract involves critical technology, next-generation weapon systems, or sensitive research, Level 3 is the applicable tier.

## Exact Pass Requirements

To pass Level 3, the organization must meet the following:

| Requirement | Plain English |
|---|---|
| 1. Final Level 2 (C3PAO) status | You must have a final Level 2 certificate with a 110/110 score in eMASS/SPRS. You cannot begin a Level 3 audit with open Level 2 gaps. |
| 2. Implement 24 enhanced controls from NIST SP 800-172 | These 24 requirements focus on resilience, proactive defense, and advanced threat response. |
| 3. Government-led DIBCAC assessment | Level 3 assessments are conducted exclusively by DCMA DIBCAC. Private C3PAOs cannot certify Level 3. |
| 4. Annual senior official affirmation | An executive must attest every year that all 134 controls (110 plus 24) are operational. |
| 5. Strict POA&M rules | Level 3 has near-zero tolerance for gaps. Any allowed gaps must close within 180 days or certification is revoked. |

## In Plain English

To pass Level 3:

1. Get a perfect Level 2 score first. DIBCAC will not schedule a Level 3 audit without a validated Level 2 certificate.
2. Implement the 24 advanced controls. Level 3 is not just more controls, it requires capabilities like threat hunting, deception systems, and proven resilience under active compromise.
3. Be ready for government auditors, not a commercial C3PAO. DIBCAC personnel will spend extended time in your environment and expect to see live operational evidence.
4. Company leadership is personally attesting to the security of a high-priority national asset. The affirmation is annual.
5. Treat any open gap as a critical item. You have 180 days to reach a clean 134/134. Missing that deadline revokes the certification.

## Legal Weight of the Affirmation

The senior official affirmation at Level 3 is a legal representation tied to high-priority national security programs.

If a company represents controls as implemented when they are not, the legal and contractual exposure can be severe.

## The 2026 DIBCAC Reality

As of April 2026, DIBCAC is the sole authority for Level 3 assessments.

- Scheduling begins by emailing DIBCAC with your Level 2 Unique Identifier from eMASS.
- If your scope changed between Level 2 certification and the Level 3 audit, DIBCAC will re-audit your Level 2 controls. A single Level 2 failure at that point can pause or terminate the Level 3 audit immediately.
- DIBCAC assessors expect two forms of objective evidence per control. A screenshot alone is not sufficient without a supporting interview or configuration pull.

## Hard Gates for Level 3

- Final Level 2 (C3PAO) status is a hard technical prerequisite. It cannot run in parallel.
- DIBCAC requires two forms of objective evidence for every control.
- Level 3 scope must be equal to or a subset of the certified Level 2 scope. You cannot add unvetted systems to a Level 3 audit.
- Any open-gap handling must follow the exact rules for the Level 3 path.

## The 24 Enhanced Requirement Areas (NIST SP 800-172)

These go beyond standard cyber hygiene into proactive and resilience-focused capabilities:

- **Advanced command and control.** Proactive threat hunting teams looking for adversary presence inside the environment.
- **Resilience.** Systems designed to continue operating under active compromise, not just to detect and shut down.
- **Deception.** Decoy credentials, systems, and honeypots to detect and trap sophisticated attackers.
- **Risk management.** Deeper supply chain scrutiny including hardware integrity and vendor vetting.

## Level 3 At a Glance

| Metric | Level 3 Requirement |
|---|---|
| Control count | 134 (110 from Level 2 plus 24 from Level 3) |
| Assessor | DCMA DIBCAC (government personnel only) |
| Validity | 3 years with annual senior official affirmation |
| POA&M allowed | Only for select 1-point and 3-point controls. Zero tolerance for 5-point gaps. |
| Closure window | 180 days for any conditional pass items. |

## Evidence You Should Have Ready

- Final Level 2 C3PAO certificate.
- Advanced SIEM or SOC logs proving active threat hunting, not just passive monitoring.
- Network deception evidence: honeypots or decoy systems with detection logs.
- Supply Chain Risk Management (SCRM) plan with documented vendor vetting.
- Incident response maturity evidence including tabletop exercises with APT scenarios.
- Program-specific architecture, boundary, and segmentation evidence.
- Government assessment support artifacts and affirmations.

At Level 3, evidence quality and operational maturity are the deciding factors, not documentation volume.

## Contract Reality

Level 3 is not chosen by preference. It is contract- and program-driven by DoD requirements. It applies to a small portion of the Defense Industrial Base, primarily contractors supporting critical technology, next-generation weapon systems, or sensitive research programs.

If Level 2 is building a secure facility, Level 3 is staffing it with a 24/7 security team, installing hardened access points, and running live-adversary drills every quarter to catch an intruder before they reach the most sensitive systems.
