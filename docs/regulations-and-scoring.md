# CMMC Regulations and Scoring: Reference Guide

This document is for contractors who want to go deeper on how SPRS scoring works, how CMMC levels and NIST revisions relate, and where this all shows up in practice.

If you are just trying to figure out your level and what you need to pass, start with the [CMMC Pass Requirements Index](cmmc-pass-requirements-index.md).

---

## The SPRS Score: Your Cyber Credit Score

SPRS is not "the CMMC level." SPRS is the scoring and reporting mechanism tied to your NIST SP 800-171 self-assessment posture for CUI-related requirements.

- CMMC level tells you what bucket of requirement you are in.
- SPRS tells the government how your NIST 800-171 implementation scores out when that scoring applies.

You start at 110. For every required control you have not implemented, you subtract points based on severity.

| Control Gap | Point Deduction |
|---|---|
| Missing a required practice entirely | -5 |
| Partially implemented | -3 |
| Not yet started but planned | -1 |

**FIPS 140-2 Sunset Warning (September 21, 2026):**

Encryption validation matters heavily in scoring. If Fleet Commander flags your encryption as FIPS 140-2 validated, you are technically compliant today but will be in material breach after September 21, 2026. Treat 140-2 findings as a 60-day action item: transition to FIPS 140-3 validated modules or plan a remediation before the sunset date.

Common showstoppers that tank scores fast:
- Missing MFA on admin accounts
- Unencrypted endpoints or servers
- No vulnerability management process
- Stale or unreviewed accounts still active
- No boundary enforcement between business and CUI zones

A poor score or weak evidence can put federal eligibility and subcontracting opportunities at risk. In 2026, primes and procurement workflows use automated vetting against government data sources. If your SPRS posture is weak or your submission is missing, you can become functionally invisible in early subcontractor screening before a human ever sees your bid.

**The Senior Official Affirmation:**

SPRS is more than just a score. Under 32 CFR Part 170, every CMMC affirmation must be signed by a senior company official (CEO, owner, or designated executive). That executive is making a legal representation to the federal government that the controls described are actually implemented.

Fleet Commander provides the technical facts that executive is signing their name to. If the results show gaps and you affirm readiness anyway, you have created False Claims Act exposure.

**Want to see where you stand right now?** The [SPRS Mission Ready Pre-Check](https://app.renovationroute.com/public/sprs-precheck) covers both Rev 2 (DoD) and Rev 3 (GSA), walks through the controls contractors fail most often, and gives you an educational readiness estimate in minutes. Built by the same team behind this repo. It is not an official assessment. It is a fast triage tool so you know what to fix before it matters.

---

## Where SPRS Fits in the Bigger Picture

If you are in Level 1 territory only, SPRS is usually not the main story.

If you are handling CUI and working under the NIST 800-171 world, SPRS becomes much more important because it reflects whether your required controls are actually in place.

The chain looks like this:

- Contract tells you what information you will handle.
- Information type drives the level.
- Level drives the control expectations.
- For CUI-related requirements, SPRS reflects how complete that implementation actually is.
- Your senior official's annual affirmation is a legal binding based on SPRS accuracy.

For most contractors entering or expanding in defense work, Level 2 planning is where technical architecture discipline becomes non-optional.

---

## Rev 2 vs. Rev 3: What You Are Actually Being Graded On

This is a real source of confusion in 2026.

**NIST SP 800-171 Rev 2** is the current baseline for active Level 2 scoring and assessment. If you are going through a C3PAO assessment today, you are graded against Rev 2. It has 110 controls across 14 control families.

**NIST SP 800-171 Rev 3** is the direction of travel. It adds modernization items, expanded supply chain emphasis, and organization-defined parameters (ODPs) that give you some implementation flexibility. Rev 3 also reorganizes some controls.

**Practical legal reality for April 2026:** Current DoD implementation still grades Level 2 against Rev 2. A class deviation is in effect that keeps Rev 2 as the assessment standard while Rev 3 is being formally adopted. Most contractors should focus on Rev 2 for active assessments happening now.

**Direct guidance:** Do not use a Rev 3-only checklist as your primary yardstick for a C3PAO assessment happening today. You can design forward for Rev 3, but your audit evidence must still satisfy Rev 2 control expectations.

Do not rip out compliant Rev 2 implementations before your assessor grades Rev 3. That is how you create gaps right before audit.

**What to do now:**
- **For active DoD/DFARS CUI work:** Build for Rev 2 compliance first. Pass your assessment, then plan Rev 3 upgrades.
- **For new GSA or civilian federal work:** Check your contract. If it references Rev 3, design with both revisions in mind from day one.
- **For both:** Do not shortcut encryption, MFA, or scoping to fit one version. Both Rev 2 and Rev 3 require these fundamentals.

---

## Where This Shows Up in Contracts

For most contractors, CMMC and CUI handling requirements show up in:

- The solicitation or RFP (Level requirements stated explicitly)
- Prime contractor flow-down requirements ("your subcontract is Level 2" or "self-assessment required")
- **DFARS 252.204-7012** - CUI handling obligation (applies to all CUI contracts)
- **DFARS 252.204-7021** - CMMC requirement clause (specifies the level: L1, L2, or L3)
- **FAR 52.204-21** - Level 1 basic safeguarding (applies to FCI contracts)
- **32 CFR Part 170** - The final CMMC rule itself (mandatory affirmation and annual reaffirm requirements)

The contract language and data handling requirements tell you what environment you need to build and what your SPRS submission must reflect.

**Phase 1 (Now Through November 10, 2026):**
- Self-assessment in SPRS is permitted for non-prioritized acquisitions
- Senior official annual affirmation required (32 CFR 170)
- C3PAO assessment required for prioritized acquisitions

If you are not sure what clause applies to your situation or whether you are in a prioritized acquisition, talk to your contracting officer or prime before you self-assess. Asserting the wrong score in SPRS on the wrong contract type is not just an IT problem. It is a legal representation problem tied to your official affirmation.
