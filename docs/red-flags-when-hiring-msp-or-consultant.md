# Red Flags When Hiring an MSP or Consultant

Choosing a provider in 2026 is high stakes. With the November 10, 2026 Phase 2 deadline fast approaching, many providers are rushing to market with "CMMC in a box" solutions that may not survive a DIBCAC or C3PAO audit.

Use this checklist to separate the experts from the opportunists.

---

## Green Flags (What Good Looks Like)

A trustworthy provider in 2026 will:

- Ask about your contract clauses (FAR/DFARS) before pitching a single piece of software
- Explain the "88-Rule" and the 180-day POA&M window clearly (88/110 scores and conditional pass realities)
- Distinguish between being an RPO (Registered Provider Organization) and a C3PAO (Assessor), explaining why they cannot be both for you due to conflict-of-interest rules
- Know whether you need NIST Rev 2 (DoD) or Rev 3 (GSA) and build accordingly, not "one size fits all"
- Show you sample evidence artifacts (redacted SSPs or log reports) rather than just sales decks
- Prioritize scoping: Immediately talk about how to segment your network to reduce the number of seats you have to pay to protect
- Understand the 2026 liability landscape and explain their professional liability coverage

---

## Red Flags (Walk Away)

### 1) "We guarantee a 110/110 score"

Why it is bad:
- No third party can guarantee how a government led or C3PAO auditor will interpret your specific implementation. A guarantee is a sign of a salesperson, not an engineer.

### 2) "Just use our 'Compliant Cloud' and you're done"

Why it is bad:
- Even if your files are in a FedRAMP Moderate cloud, you are still responsible for local endpoints, physical office security, and staff training. A cloud is a tool, not a total solution.
- If they say cloud solves everything, they do not understand the full 110 controls.

### 3) They do not know the difference between NIST Rev 2 and Rev 3

Why it is bad:
- As of April 2026, the DoD still audits against Rev 2, while some GSA contracts are moving to Rev 3. If your consultant builds to the wrong version, your assessment will be an expensive failure.
- Rev 3 has a 1-hour incident reporting requirement Rev 2 does not. Missing this gap is an audit-ending mistake.

### 4) They hold your documentation "hostage"

Why it is bad:
- If they say the System Security Plan (SSP) is "proprietary" to their firm and you cannot have the raw files, they are locking you into a permanent subscription. You must own your compliance artifacts.

### 5) "MFA via SMS is fine for Level 2"

Why it is bad:
- In 2026, phishing-resistant MFA (like FIDO2/YubiKeys) is the gold standard. A provider suggesting SMS or simple push notifications is giving you 2022 advice for a 2026 problem.
- An auditor will ask how you prevent phishing. SMS does not pass that question.

### 6) They cannot explain the 88-Rule

Why it is bad:
- If they do not understand that you can conditionally pass at 88/110 but only with zero 3 or 5-point control misses and a 180-day POA&M clock, they do not understand 2026 assessment reality.

### 7) They say "everyone needs a C3PAO"

Why it is bad:
- Some contractors only need a Level 1 self-assessment. Some contracts allow Phase 1 self-assessment paths. Pushing everyone to a C3PAO is revenue maximization, not good advice.

### 8) No clear incident response ownership

Why it is bad:
- During a real event, fuzzy ownership creates missed timelines and contract risk. Ask them directly: "If we detect an incident at 3 AM Saturday, who from your team do we call and what happens in the first hour?"

### 9) They bundle everything into a long multiyear contract

Why it is bad:
- Phase 2 deadline is November 10, 2026. You should not sign a 3-year contract starting now. Get readiness help for 6-12 months, then reevaluate.

> [!TIP]
> **Insurance and Liability Red Flag:** Ask whether their professional liability or cyber insurance specifically covers compliance failures or errors and omissions tied to CMMC or NIST SP 800-171 work.
>
> If they say "we do not need that," they are not treating your contract risk as their own.
>
> In 2026, the DOJ is aggressively using the False Claims Act to target misrepresentation. If your provider gives you bad advice and you sign false affirmations based on it, you carry the liability. Ask about their indemnification coverage.

---

## The "2026 Liability" Question

In 2026, the DOJ is aggressively using the False Claims Act to target misrepresentation. Ask your prospective provider:

**"If we are sued under the False Claims Act because of a control failure you claimed was 'ready,' what does our contract say about your liability or indemnification?"**

If they fumble this answer, they are not ready for the legal weight of federal contracting. A good provider will have:
- Professional liability insurance that covers CMMC/NIST work
- Clear indemnification language in their statement of work
- Documented assumptions about what they tested and what remains the client's responsibility

## RPO vs. C3PAO: Know the Difference

| Feature | RPO (Consultant) | C3PAO (Assessor) |
|---|---|---|
| Primary Goal | Get you ready / gap analysis | Grade you / issue certificate |
| Can they fix things? | Yes, they are your "coach" | No, they are the "referee" |
| Can they do both? | NO. (Major conflict of interest) | NO. (Forbidden by Cyber-AB) |
| When to hire | Now (for readiness, before deadline) | 6 months before your contract expires |
| Liability model | Shares risk as your advisor | Neutral third party; limited liability by charter |
| Best use case | Build your baseline and SSP | Validate you are audit-ready |

If a firm claims to be both an RPO and ready to pursue C3PAO assessment for you, ask hard questions about how they manage conflict of interest. A reputable firm will either advise you on readiness OR conduct the assessment, not both.

---

## Questions to Ask Before You Sign

1. Which specific clauses are you designing against for us (FAR 52.204-21, DFARS 7012, 7019, 7020, or 7021)?
2. Do you understand the 88-Rule and 180-day POA&M window? Explain it back to me.
3. Are you an RPO, a C3PAO, or both? If both, how do you manage conflict of interest?
4. NIST Rev 2 or Rev 3? Which version is our contract targeting, and how will you verify it?
5. How do you map each control to actual evidence artifacts (screenshots, logs, policies)? Show me a redacted example.
6. What does your handoff package include if we stop using you next year?
7. Who owns incident response actions and timing, and what is the escalation path at 2 AM Saturday?
8. Can you show a redacted sample of your evidence quality from a similar sized contractor?
9. Does your professional liability or cyber policy explicitly cover compliance errors/omissions related to CMMC/NIST?
10. What assumptions are you making about our environment, and which items are explicitly out of scope?

If they cannot answer these clearly and in writing, keep shopping.

---

## Contract Terms to Protect Yourself

Ask for:

- 30-day termination option (or clear early exit terms) — Do not lock in until after your first assessment checkpoint
- Deliverables defined by artifact, not vague outcomes (e.g., "Complete SSP per CMMC L2 standard" not "Full compliance consultation")
- Data export rights (logs, configs, documents, SSPs) — You must own your compliance artifacts
- Named response time commitments (especially for incident escalation)
- Change-order rules in writing — Scope creep is expensive
- Clear liability and indemnification language if errors in their guidance lead to compliance failures

---

## Quick Scoring Card

Score each item 0 to 2.

- Clause understanding
- Evidence quality
- Scope clarity
- Pricing transparency
- Incident ownership
- Exit terms

Score guide:
- 10-12: strong candidate
- 7-9: proceed with caution
- 0-6: do not sign yet

---

## Bottom Line

A good MSP or consultant reduces risk, makes your team smarter, and owns part of the outcome.

A bad one sells comfort while increasing long-term exposure and locks you into dependency.

Choose the one who can explain your actual compliance gaps after one meeting, not the one with the slickest deck or the loudest guarantee.

---

## Related Guides

- [Common Failure Patterns](common-failure-patterns.md)
- [Questions to Ask Your Prime](questions-to-ask-your-prime.md)
- [Legal Guardrails](legal-guardrails.md)
- [CMMC Level 2 Pass Requirements](cmmc-level-2-pass-requirements.md)

---

*This document is practical buyer guidance, not legal advice.*
