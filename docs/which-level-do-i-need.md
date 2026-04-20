# Which CMMC Level Do I Actually Need?

If you are asking this question, you are ahead of most contractors. The level is not based on what you call yourself. It is based on what kind of government information physically flows to your company through the contract.

That is the whole answer. Everything else is details.

---

## The One Question That Decides Everything

**Do any controlled technical documents, drawings, specifications, or program data come to you as part of doing the work?**

- **No**: You only receive pricing, schedule, and standard contract paperwork. You are almost certainly **Level 1**.
- **Yes**: Technical packages, controlled drawings, specs, or program data lands on your systems or in your hands. You are almost certainly **Level 2**.
- **Yes, and the program is specifically flagged as high priority or highly sensitive**: Level 3 may apply. The government or prime will usually tell you directly.

---

## The Decision Tree

Work through this top to bottom. Stop at the first "yes."

---

**Step 1: Do you fabricate, machine, or manufacture parts or assemblies from technical drawings?**

For example: CNC shop running a controlled part print. Sheet metal shop building assemblies from engineering packages. Composites shop working from controlled layup specs.

→ **Yes: You are Level 2.** The drawings themselves are CUI.

→ No: Keep going.

---

**Step 2: Do you receive, store, or review engineering specifications, controlled technical packages, or defense program data?**

For example: You are a quality or inspection firm reviewing controlled part drawings. You are a testing lab receiving controlled specs. You are an engineering sub getting technical data packages from a prime.

→ **Yes: You are Level 2.**

→ No: Keep going.

---

**Step 3: Does your IT system or network store or process any information the prime or government has marked as CUI, FOUO, or "controlled"?**

For example: A shared drive with controlled documents. An email chain with marked attachments. A project management system with restricted program data.

→ **Yes: You are Level 2.**

→ No: Keep going.

---

**Step 4: Are you doing physical construction, facility work, or standard trade work on a federal property or military installation?**

For example: Pouring concrete on a base. Running electrical in a standard federal building. HVAC on a general-use facility. Roofing on a standard government structure.

→ You likely handle FCI (contract pricing, schedules, standard project data) but not CUI. **You are Level 1.** Confirm this with your prime or contracting officer before assuming.

---

**Step 5: You are not sure.**

Ask your contracting officer or prime two direct questions:

1. "Does this contract involve CUI as defined under the CUI Registry?"
2. "Is DFARS 252.204-7012 a clause in this contract?"

If the answer to either is yes, plan for Level 2.

---

## Trade-by-Trade Examples

| Trade | Typical Situation | Likely Level |
|---|---|---|
| Concrete / Sitework | Pouring on base, standard specs | Level 1 |
| General Electrical | Standard federal building wiring | Level 1 |
| HVAC | Standard facility mechanical | Level 1 |
| Roofing / Envelope | Federal facility projects | Level 1 |
| CNC / Precision Machining | Parts from controlled technical drawings | Level 2 |
| Sheet Metal Fabrication | Assemblies from defense engineering packages | Level 2 |
| Aerospace / Composites | Controlled layup specs, program data | Level 2 |
| Quality / Inspection | Reviewing controlled part prints | Level 2 |
| Structural Steel (defense) | Drawings marked controlled or CUI | Level 2 |
| HVAC (SCIF or secure facility) | Controlled facility specs, classified adjacency | Level 2, confirm with prime |
| Weapons system component supplier | Flagged high priority program | Level 3, government will notify |

This table is a starting point, not legal guidance. The contract and flow-down requirements always control.

---

## What If I Am Level 1?

Good news: Level 1 is 15 basic safeguarding practices under FAR 52.204-21. It is achievable without a consultant if you follow the evidence checklist and build the baseline.

Start here: [Level 1 Pass Requirements](cmmc-level-1-pass-requirements.md)

Use the free resources in this repo. You do not need to pay anyone.

---

## What If I Am Level 2?

Level 2 is 110 controls across 14 families from NIST SP 800-171. It requires clean technical implementation and clean evidence. This is where most small contractors underestimate the work.

Start here: [Level 2 Pass Requirements](cmmc-level-2-pass-requirements.md)

**The honest reality:** affirming a score in SPRS without the technical evidence to back it up is a False Claims Act exposure. A failed C3PAO audit is not just a $20k cost. It is a 6 month block from bidding new work while the scheduler fills back up.

If you are Level 2 and you want a principal architect to review your environment before your auditor does, that is what [Tier 2 Validation](../README.md#07-implementation-paths-after-you-run-the-script) is for.

---

## What If I Am Level 3?

The government will usually identify this explicitly. Level 3 involves NIST SP 800-172 requirements and a government-led assessment through DIBCAC. If you think you might be Level 3, confirm directly with your prime or contracting officer before building anything.

Start here: [Level 3 Pass Requirements](cmmc-level-3-pass-requirements.md)

---

## When You Don't Know Your Level Yet

There are more ways to land in "I don't know" than most people realize. Here are the real scenarios and what to do in each one.

---

### Scenario 1: You are a new sub and haven't seen the prime contract

This is the most common. You are being brought in under a prime, work has not started, and nobody has told you exactly what information will flow to you.

**How to find out:**

Ask the prime these two questions in writing:

> "Will any CUI flow to our company as part of performing this scope?"
> "Is DFARS 252.204-7012 a clause in the prime contract that flows down to subs?"

A legitimate prime will answer this. If they dodge it or say they don't know, that is a red flag.

Also ask if there is a **DD Form 254** (Contract Security Classification Specification). If the prime has one, it lists exactly what controlled or classified information is involved in the program. This document will tell you more than any conversation will.

---

### Scenario 2: Your scope changes mid-contract

You started doing general concrete work. Now the prime is sending you drawings for a secured facility entrance, or you are being asked to work in areas with controlled specs.

The scope changing is not just a schedule issue. If CUI starts flowing to you mid-project, your level obligation changes at that point.

**How to find out:**

Look at what is being sent to you. If documents are:
- Marked "CUI," "FOUO," "Controlled," or have a distribution restriction statement
- Technical packages, specs tied to a controlled system, or drawings for a sensitive structure

...then CUI has entered your scope and Level 2 obligations apply from that point forward.

Tell someone if you are not sure. Calling your contracting officer with a question is not a mistake. Staying silent while handling CUI without Level 2 controls is.

---

### Scenario 3: You are bidding on a solicitation with vague language

The RFP does not explicitly say "CUI" anywhere. But the scope involves technical work for a defense program, and the project involves drawings or specifications.

**How to find out:**

Read Sections H, I, and J of the solicitation. Those sections contain contract clauses and attached documents. Look for:
- `DFARS 252.204-7012` in the clause list
- `DFARS 252.204-7021` explicitly requires CMMC
- `FAR 52.204-21` is the Level 1 minimum and always the floor for federal work
- Any reference to a DD Form 254 as an attachment

If you cannot find those sections or do not know how to look, see [How to Read Your Contract Clauses](how-to-read-your-contract-clauses.md).

If the RFP is truly silent and you still cannot tell, submit a question to the contracting officer during the Q&A period. That is what it is for.

---

### Scenario 4: You are on a teaming agreement before contract award

The prime has not been selected yet. You have a teaming agreement that says you will be a sub if they win. No contract exists yet.

You have no obligation now, but you need to be ready before work starts.

**How to find out:**

Ask the prime what CMMC level they are building to for this pursuit. Primes who win CUI contracts must flow requirements down to all subs who handle CUI. If they are pursuing a CUI program and you will handle any part of the technical scope, assume Level 2 and start building now.

Waiting until award to start building is too late. C3PAO scheduling and remediation take months.

---

### Scenario 5: You are an IT vendor or MSP supporting a defense contractor

You do not fabricate parts or touch technical drawings. You manage the IT environment for a company that does.

If you have access to systems, networks, or data that process or store CUI, you can inherit the CUI obligation through your service relationship.

**How to find out:**

Ask your client directly:
- "Does your environment contain or process CUI?"
- "Am I listed in your System Security Plan as a service provider?"
- "Does our contract include DFARS 252.204-7012 or a flow-down clause?"

If the answer to any of these is yes, your environment and access controls are in scope for Level 2 assessment purposes. This is not a commonly understood fact among MSPs, and it is exactly the kind of gap that creates False Claims Act exposure for both you and your client.

---

### Scenario 6: You are taking over a scope from another sub

A sub dropped off a project mid-stream and you are stepping in. You inherit their drawings, their files, and possibly their obligations.

**How to find out:**

Treat everything you receive as potentially CUI until you confirm otherwise. Ask the prime what information classification applies to everything handed over. Do not assume the prior sub had clean controls. Do not add those files to an uncontrolled environment until you know what they are.

---

### Scenario 7: You work on a facility that might be sensitive but cannot tell from the scope description

HVAC work, electrical, roofing, or general construction, but the building description is vague or mentions "sensitive operations," federal agencies, or restricted access.

SCIFs, secure communications facilities, data centers supporting classified programs, and certain federal operations buildings can bring controlled specifications into your scope even for trade work.

**How to find out:**

Ask the prime or GC: "Are there any controlled or restricted specifications for this facility that require special handling?" If the facility has a DD Form 254, that document will describe what information is in scope.

If you are working on what might be a SCIF or secure facility and nobody has mentioned CUI or a DD Form 254, ask before you start. The cost of asking is zero.

---

### The Universal Rule

When in doubt, build for Level 1 now and stay ready for Level 2.

Level 1 is 15 practices. You can do it free. It does not block you from the Level 2 path. It is a subset of it. Starting clean at Level 1 costs almost nothing. Starting wrong at Level 2 costs you everything.

**Do not sign any subcontract containing DFARS 252.204-7012 and then do nothing.** That clause creates a legal obligation. Signing it means you are affirming you will comply. Ignorance of the clause is not a defense under the False Claims Act.

---

## Still Not Sure?

Run the SPRS pre-check first: [SPRS Mission Ready Pre-Check](https://app.renovationroute.com/public/sprs-precheck)

It will surface the controls you are likely missing before you spend time building the wrong baseline. Built by the same team behind this repo.

---

*This document provides technical guidance and general decision support, not legal advice. Contract language and official agency guidance always control.*
