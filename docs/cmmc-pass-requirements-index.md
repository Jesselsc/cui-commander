# CMMC Pass Requirements Index

Use these level-specific docs for exact pass requirements and evidence expectations.

- [Level 1 Pass Requirements](cmmc-level-1-pass-requirements.md)
- [Level 2 Pass Requirements](cmmc-level-2-pass-requirements.md)
- [Level 3 Pass Requirements](cmmc-level-3-pass-requirements.md)

## Quick Rule

- Handle FCI only: start with Level 1 requirements.
- Handle CUI: Level 2 is the primary requirement path.
- High-priority CUI program with government-directed requirements: Level 3 path may apply.

Contract language and flow-downs always control final assessment path.

## Find Your Path by Contract Clause

If you are not sure which level applies to you, find the clause in your contract or solicitation:

| Contract clause | Your likely path | What to do |
|---|---|---|
| FAR 52.204-21 | Level 1 (FCI) | Focus on the 15 basic controls and annual affirmation. |
| DFARS 252.204-7012 | Level 2 (CUI) | You need all 110 controls. Check whether your contract requires a C3PAO or self-assessment. |
| DFARS 252.204-7021 | Level 1, 2, or 3 | This is the official CMMC clause. The required level is specified in the contract. Read it carefully. |

If your subcontract flows down CUI handling obligations from a prime, ask your prime which clause and level apply before you self-assess anything.

## The Three Essentials (All Levels)

Before diving into a level-specific doc, confirm you can answer yes to all three:

1. **Scope.** Do you know exactly which computers, servers, and people touch federal data? Not your whole company, just the ones that actually handle federal contract information or CUI.
2. **Evidence.** Can you prove your controls were working last Tuesday, not just today? Auditors want historical logs, not live demos only.
3. **Accountability.** Is a company executive ready to sign their name to a legal affirmation? At every level, a senior official must attest the submission is accurate.

If any of these is a no, start there before working through the control lists.

## Scoping: Do Not Audit Your Whole Company

If you have 100 employees but only 5 handle federal contracts, use network segmentation to isolate those 5. Keeping the boundary small can dramatically reduce compliance cost and audit surface.

If you do not segment, an assessor may treat the broader environment as in scope, including the shop floor tablet and the front desk machine. Define the boundary first, then secure it, then document it.

## Reciprocity: Other Certs Do Not Transfer

If your company already holds FedRAMP, ISO 27001, SOC 2, or another certification, those credentials can inform your CMMC preparation but they do not count as a passing outcome. You still need to map your controls to CMMC requirements and produce CMMC-specific evidence. There is no automatic reciprocity.

## Assessment Readiness Triage

If you are unsure where to start:

1. Run Fleet Commander (`fleet-commander`) on your most sensitive machine.
2. If the result suggests significant technical gaps, fix the red items before building documentation. A polished SSP on top of broken technical controls will not survive an audit.
3. Once the technical baseline is solid, move to the appropriate level doc to build your evidence package.

