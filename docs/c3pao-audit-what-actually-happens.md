# The C3PAO Audit: What Actually Happens

If you are aiming for CMMC Level 2, running Fleet Commander clean is only part of the preparation.

C3PAO assessors use methods of objective evidence. In practice, that means interview, examination, and test.

## 1) Interview (Do you actually do this?)

Assessors may interview a random estimator, PM, admin, or technician and ask process questions:

- Show how you send a bid package to a subcontractor. Is it encrypted?
- What happens if a phone with company email access is lost?
- Who approves access changes, and where is that documented?

Failure pattern:
- Staff do not know the policy or follow it consistently.
- Tool exists, but workflow is not understood.

## 2) Examination (Show me the receipts)

Expect requests for:

- 90+ days of MFA/access logs
- Account review records and approvals
- Visitor/access logs (physical office or server room)
- Change records and patch history
- Policy acknowledgments and training records

Failure pattern:
- No retained logs, incomplete records, or evidence that cannot be traced to scope.

## 3) Test (Show that controls actually work)

Assessors may request live demonstrations:

- Account lockout after repeated failed login attempts
- Segmentation proof: dirty VLAN cannot reach CUI server
- Access denial for out of scope users/devices

Failure pattern:
- Flat network paths, broad admin privileges, and inconsistent enforcement.

## Rev 2 vs Rev 3: Do Not Use the Wrong Yardstick

NIST SP 800-171 Rev 3 exists, but current CMMC Level 2 assessment is still tied to Rev 2 expectations.

- Build with Rev 3 awareness for future transition.
- Audit and evidence prep for current C3PAO work must still satisfy Rev 2.
- Do not run a Rev 3-only checklist and assume you are audit-ready today.

## 2026 Bottleneck Reality

As of April 2026, rollout pressure is active, not theoretical.

- Active solicitations in Navy and Army pipelines already include language pushing Level 2 C3PAO readiness.
- Queue time: 3 to 6 months is common just to land on an assessor calendar.
- Action now: If you plan to bid Q4 2026 CUI work, schedule your assessment now.

### Cost Reality (2026)

- Audit-only range for very small firms often lands around $20k to $40k.
- For 25 to 50 person firms, first-year all-in spend (prep, tooling, remediation, and audit) commonly lands around $75k to $120k.

## Auditor Sampling Reality

Assessors do not test every endpoint. They sample and trace consistency.

- Expect random sample selection across users, endpoints, and evidence records.
- In practice, many teams should plan for roughly 10% to 20% endpoint sampling pressure, depending on scope and risk profile.
- If one sampled "back corner" machine breaks policy, the control can fail for the environment.

Consistency across all in-scope systems is the only reliable way to pass.

## Conditional Pass and 180-Day POA&M Reality

Conditional outcomes may allow POA&M closure windows for certain lower-impact findings.

- Typical expectation: up to 180 days to close eligible minor gaps.
- Critical control failures can still produce immediate adverse outcomes.
- In practice, controls tied to high impact scoring (for example MFA/encryption-related failures) are treated as high risk and can block eligibility quickly.

Treat POA&M as a narrow cleanup path, not a strategy for major control gaps.

## Top 3 Audit Killers (2026 Edition)

1. Out-of-scope claims that do not match real CUI data flow or boundary diagrams.
2. Standard users operating with local admin/sudo rights by default.
3. External cloud app drift (personal Dropbox/Drive/Slack paths used for CUI because official path was slower).

## How to Use This Repo for Audit Readiness

1. Run Fleet Commander on each in-scope endpoint, not just one machine.
2. Build an SSP that matches real architecture and control operation.
3. Keep 90+ days of evidence for control operation and account activity.
4. Perform an internal mock interview with non-IT staff.
5. Validate segmentation with a simple deny-path test and save the result.

## If I Am the Strict Auditor, Here Is What I Ask

### Scope and Boundaries (first 15 minutes)

- Show your in-scope system list for CUI: endpoints, servers, cloud apps, mobile devices, network gear, and shared services.
- Show the boundary diagram with CUI flow from intake to storage to transmission to archive/destruction.
- Which systems are explicitly out of scope, and what technical controls keep them out?
- When was scope last reviewed, by whom, and where is that record?

Immediate concern flags:
- "Everything is in scope" or "nothing is in scope" answers.
- Diagram does not match real environment.
- No asset inventory with owners.

### Identity and Access Control

- Show joiner/mover/leaver process with approvals and timestamps.
- Show admin account inventory and proof each admin account is named to one person.
- Show MFA policy and evidence that webmail, VPN, and privileged access enforce MFA.
- Show last quarterly access review and removals.

Immediate concern flags:
- Shared accounts (Shop_PC, FrontDesk, Admin).
- Disabled users still in privileged groups.
- Break-glass account with no monitoring.

### Configuration and Change Control

- Show your baseline standards (endpoint hardening, server hardening, firewall rules, MDM policy).
- Show recent change tickets for security-impacting changes and who approved them.
- Show rollback plan for critical changes.

Immediate concern flags:
- Production changes with no ticket/approval.
- Baseline exists but cannot prove deployment to all in-scope assets.

### Logging, Monitoring, and Retention

- Show where authentication logs, admin actions, and security alerts are centralized.
- Show retention policy and proof logs are retained for required period.
- Show one incident from the last 90 days and the response timeline.

Immediate concern flags:
- Logs only local to endpoints.
- No alert triage workflow.
- Time sync issues (timestamps do not line up across systems).

### Network Segmentation and Boundary Defense

- Show VLAN map, ACL/firewall rule sets, and management plane restrictions.
- Demonstrate deny path: dirty VLAN cannot reach CUI zone except approved ports.
- Show remote access controls (VPN, device posture, geo/IP restrictions).

Immediate concern flags:
- Flat east-west access.
- "Allow any any" rules for convenience.
- Printer/IoT/tablet segments with broad route access to CUI systems.

### Vulnerability and Patch Management

- Show vulnerability scan cadence, findings, and remediation SLA by severity.
- Show patch compliance report by asset class (workstations, servers, network gear).
- Show exception register for delayed patches and compensating controls.

Immediate concern flags:
- Critical findings older than SLA with no approved exception.
- Missing network device firmware patch process.

### Incident Response and Recovery

- Show IR plan, contact tree, legal/contract notification path, and tabletop evidence.
- Show latest backup restore test for a CUI system.
- Show ransomware containment playbook and decision authority.

Immediate concern flags:
- Backup exists but no restore test evidence.
- IR plan drafted but never exercised.

### SSP and Evidence Quality (where most small firms fail)

- Show SSP control narratives mapped to real systems, not generic templates.
- For any control sampled, show policy, procedure, technical evidence, and responsible owner.
- Show POA&M with dates, owners, and closure evidence.

Immediate concern flags:
- SSP says one thing, logs/screenshots show another.
- Evidence screenshots with no timestamp/context.
- POA&M open items with no target dates.

## Auditor Sampling Pattern You Should Expect

- Pick one control in each major area (access, logging, segmentation, incident response).
- Trace from policy -> system config -> live test -> historical evidence.
- Ask two random staff members to describe the same process and compare answers.

If those three lines do not match, confidence drops fast.

### Deep Dive Example: AC.L2-3.1.1 (Account Access Control)

If an auditor picks this control, they will not just ask if you have passwords. They will trace a four-point path:

1. **Policy.** Show the written rule stating users receive least-privilege access only.
2. **Procedure.** Show the ticket or approval record where the admin created the account and restricted folder access.
3. **Live test.** Log in as that user and attempt to open a restricted folder. Access denied is the expected result.
4. **Historical evidence.** Show the log entry from a prior date proving the restriction was enforced before today.

If any one of these four points fails, the control fails.

## 10 Questions to Rehearse Before Assessment Day

1. What is your CUI boundary and who owns it?
2. Which systems can transmit CUI externally, and how is encryption enforced?
3. How do you prove MFA cannot be bypassed for privileged access?
4. How quickly can you disable access for a terminated employee?
5. Show your last access review and one removal action.
6. Show one firewall deny rule that protects the CUI zone.
7. Show 90 days of relevant logs and one investigated alert.
8. Show your latest backup restore test result for an in-scope system.
9. Show one closed POA&M item with evidence of completion.
10. Where does SSP narrative exactly match current technical reality?

## Important Reminder

A green script result is not legal safe harbor and not a certification result.

Fleet Commander is a baseline signal tool. Use it to surface technical facts, then prove implementation with policy, logs, and evidence quality before any affirmation in SPRS.
