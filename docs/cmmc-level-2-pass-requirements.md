# CMMC Level 2 Pass Requirements

This document is a practical pass checklist for CMMC Level 2.

## What Level 2 Applies To

Level 2 generally applies when the contractor handles CUI (Controlled Unclassified Information).

## Exact Pass Requirements

To pass Level 2, the organization must meet the following:

| Requirement | Plain English |
|---|---|
| 1. Implement all 110 requirements in NIST SP 800-171 Rev. 2. | You must cover all required controls, not a partial subset. |
| 2. Correctly scope all CUI assets, security protection assets, and connected assets as required by CMMC scoping guidance. | You must define exactly which systems are in scope and protect all systems that can impact CUI protection. |
| 3. Complete the required assessment path for the contract (self-assessment for select acquisitions or C3PAO for prioritized acquisitions). | Your contract decides whether you self-assess or go through a third-party assessment. |
| 4. Submit required senior official affirmation(s). | A company executive must attest that submissions are accurate. |
| 5. Meet required scoring and evidence expectations for applicable controls. | You must prove controls are implemented and working, not just documented. |
| 6. Manage POA&Ms only within what is allowed by the applicable CMMC rule and assessment guidance. | If gaps are allowed, they must be tracked and closed under the allowed rules and deadlines. |

## In Plain English

To pass Level 2:

1. Implement all 110 NIST 800-171 controls, not just part of them.
2. Define exactly which systems touch CUI and include them in scope.
3. Follow the assessment path your contract requires, either self or C3PAO.
4. Have an executive formally attest your submission.
5. Keep evidence that proves controls are implemented and operating.
6. If gaps are allowed on a POA&M, track them and close them on time.

## Legal Weight of the Affirmation

The senior official affirmation is a legal representation, not an IT formality.

If a company certifies controls as implemented when they are not, that can create significant contractual and False Claims Act risk.

## Hard Gates for Level 2

Level 2 is not a "good enough" maturity score.

- You must follow the exact assessment path required by contract language.
- You must provide sufficient evidence that controls are implemented and operating.
- POA&Ms are only valid where explicitly permitted by applicable rule and assessment constraints.
- Missing required controls outside allowed POA&M treatment can block a passing outcome.

### The 88 Rule: Conditional Pass

A C3PAO assessment can produce a conditional certification if two strict conditions are both met:

1. **No 3 or 5-point failures.** If any high-weight control is marked Not Met, the assessment fails immediately regardless of total score. There is no conditional path through a critical control failure.
2. **Score of 88 or higher.** If the score lands between 88 and 109 and no critical controls failed, the assessor may issue a conditional certification. The remaining gaps go on a POA&M and must be fully closed and verified within 180 days. Missing that deadline revokes the certification.

Final certification requires 110 out of 110. Every control must be marked Met and supported by evidence. The conditional path is a cleanup window, not a substitute for preparation.

**SPRS math:** The total available score is 110. A conditional pass allows a maximum of 22 points of gaps. That sounds like room to work with, but it is not. Four missing 5-point controls puts you at 90 points and still fails the audit outright because those controls are ineligible for POA&M. You can only reach the 88 floor safely through small, low-weight gaps.

**FIPS encryption exception (SC.L2-3.13.11):** If encryption is already running but lacks a FIPS-validated certificate, you take a 3-point deduction and can put it on a POA&M. If encryption is entirely absent, it is a 5-point deduction and an immediate failure with no conditional path.

## High-Stakes Controls: The 5-Point Killers and the 6 Hidden 1-Point Killers

In NIST 800-171 scoring, some controls carry more point weight than others. The heavy weight controls are also the ones least likely to be eligible for POA&M treatment. If these are not solid on assessment day, the audit will likely end in a failure rather than a conditional pass.

| Control | Why It Cannot Wait |
|---|---|
| MFA on all remote and privileged access | Missing MFA is an immediate high-impact finding. No workaround is accepted in lieu. |
| FIPS-validated encryption | Non-FIPS encryption of CUI at rest or in transit is a hard failure. Commercial grade is not equivalent. See FIPS exception note above. |
| System Security Plan (SSP) | No SSP means no evidence baseline. Assessors have nothing to evaluate against. |
| Least privilege enforcement | Broad admin rights across standard users is one of the top audit killers in 2026. |

Do not enter a C3PAO assessment with any of these unresolved.

### The 6 Hidden 1-Point Killers

These controls are only worth 1 point each, but they are also not eligible for POA&M treatment. Missing any one of them fails the audit just as fast as a missing 5-point control.

| Control | Plain English |
|---|---|
| AC.L2-3.1.20 | Control and monitor all external system connections. |
| AC.L2-3.1.22 | Control what information about your systems gets posted publicly. |
| CA.L2-3.12.4 | Have a written and maintained SSP. |
| PE.L2-3.10.3 | Escort visitors in areas with CUI systems. |
| PE.L2-3.10.4 | Maintain physical access logs of who entered sensitive areas. |
| PE.L2-3.10.5 | Manage and audit physical access devices (keys, badges, cards). |

Do not let the 1-point label fool you. These are audit-ending gaps.

## Scoping: The Connected Asset Trap

Most small firms get blindsided by connected asset scope expansion.

If a system can reach the CUI environment or any security tool protecting it, it may be in scope. That includes office Wi-Fi if it shares a flat network with your CUI server. Personal phones on that network may follow.

The fix is a dedicated CUI enclave or hard VLAN separation with a documented and provable boundary. If you cannot demonstrate to an assessor that the boundary is enforced and airtight, they will treat the broader environment as in scope. Keeping the boundary small reduces assessment cost and risk.

## The 14 NIST SP 800-171 Rev. 2 Control Families

| Control Family | Plain English |
|---|---|
| Access Control | Decide who can access what and enforce least privilege. |
| Awareness and Training | Train users so they do not create avoidable security failures. |
| Audit and Accountability | Log activity so you can see what happened and who did it. |
| Configuration Management | Keep system settings controlled and prevent unauthorized drift. |
| Identification and Authentication | Verify identity before granting access. |
| Incident Response | Detect, contain, and recover from security incidents. |
| Maintenance | Securely maintain and service systems without creating new exposure. |
| Media Protection | Protect and handle drives, backups, and removable media safely. |
| Personnel Security | Manage user risk across hiring, role changes, and termination. |
| Physical Protection | Control physical access to systems and sensitive spaces. |
| Risk Assessment | Identify and prioritize security risks on an ongoing basis. |
| Security Assessment | Periodically check whether controls are present and effective. |
| System and Communications Protection | Protect data and traffic in systems and across network paths. |
| System and Information Integrity | Detect and fix system flaws, malware, and integrity issues quickly. |

### In Plain English

These 14 families are just the major buckets of cybersecurity work:

- Who can access what.
- How users are trained and authenticated.
- How systems are configured, patched, and monitored.
- How incidents are detected and handled.
- How data, media, and networks are protected.
- How you continuously assess risk and prove controls are working.

## SPRS Relationship

SPRS is not the CMMC level itself. SPRS records NIST SP 800-171 self-assessment scoring where applicable under contract requirements. For CUI environments, SPRS posture is often a practical gate for eligibility.

In practical procurement workflows, weak or missing SPRS posture can reduce competitiveness before a full technical conversation even begins.

## Level 2 At a Glance

| Metric | Level 2 Requirement |
|---|---|
| Control count | 110 (NIST 800-171 Rev 2) |
| Max score | 110 |
| Minimum to pass | 110 for final certification. Conditional pass at 88+ with zero 3 or 5-point control misses; 180-day POA&M clock starts immediately. |
| 180-day rule | POA&M gaps expire. If not closed and verified by a C3PAO within 180 days, certification is revoked. |
| All-in prep cost | $75k to $120k (2026 market average for 25 to 50 person firms, first year, including prep, tooling, remediation, and audit). |
| FIPS encryption | Mandatory. Validated modules only. |
| MFA | Mandatory for all remote and privileged access. |
| Assessment path | C3PAO (third-party) or self-assessment depending on contract. |
| Cloud services touching CUI | Must be FedRAMP Moderate authorized or carry a formal equivalency package. |

## Evidence You Should Have Ready

- Complete SSP that maps implementation to all 110 requirements.
- POA&M (if allowed) with clear ownership and closure targets.
- Technical evidence for each control family.
- Network and data flow diagrams for CUI scope, including VLAN boundary proof.
- Identity, endpoint, logging, and incident response evidence.
- Affirmation and assessment artifacts required by the contract path.
- For every cloud service touching CUI: proof of FedRAMP Moderate authorization or a formal equivalency package on file. Standard commercial tools such as Dropbox, personal Slack, or Google Drive are not acceptable for CUI and will produce an immediate audit failure.

Most failed outcomes are evidence failures, scope failures, or operational gaps, not lack of policy text.

## Contract Reality

The contract and prime flow-down language determine whether Level 2 self-assessment or Level 2 C3PAO assessment is required.

Think of Level 2 like a structural inspection on a high rise. Level 1 is checking whether the doors lock. Level 2 is checking the metallurgical composition of the steel beams and the torque on every bolt. You do not just say it is strong. You show the torque wrench calibration logs.
