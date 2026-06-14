# Reference Deployment: Deadline Room

**Audience:** Architecture review board, CISO office, breach counsel, GRC team.
**Purpose:** Show how Deadline Room slots into an enterprise estate, end to end.
**Honest labeling:** [BUILT] = shipped in the hackathon build. [STUB] = documented
contract, not a live connector; a production deployment would add this.

---

## 1. Boundary Diagram

```
   ┌──────────────────────────────────────────────────────────────────────────┐
   │  ENTERPRISE PERIMETER                                                    │
   │                                                                          │
   │  ┌────────────────────────────┐                                          │
   │  │  SIEM / SOAR               │  [STUB: live connector not built]        │
   │  │  (Splunk, Sentinel, XSOAR) │                                          │
   │  │                            │  Detection alert fires on confirmed       │
   │  │  Alert payload:            │  breach. In production this alert IS     │
   │  │  - incident_id             │  the fact-record payload that opens      │
   │  │  - incident_start_utc      │  the room. The payload schema is        │
   │  │  - systems, data_categories│  CANONICAL_FACTS in run_floor.py.        │
   │  │  - records_affected        │  Today: the fact-record is authored      │
   │  │  - blast_radius            │  by hand in run_floor.py.                │
   │  └──────────────┬─────────────┘                                          │
   │                 │ structured fact-record (JSON)                           │
   │                 ▼                                                          │
   │  ╔═════════════════════════════════════════════════════════════════════╗  │
   │  ║  TRUST BOUNDARY: everything inside this box that gates, counts,    ║  │
   │  ║  clocks, or releases is deterministic Python (warden/). No LLM     ║  │
   │  ║  crosses into the control path. Byte-identical replay verifiable.  ║  │
   │  ║                                                                     ║  │
   │  ║  ┌───────────────────────────────────────────────────────────────┐ ║  │
   │  ║  │  Deadline Warden (warden/)  [BUILT]                           │ ║  │
   │  ║  │  - typed state machine: illegal transitions rejected at table  │ ║  │
   │  ║  │  - statutory clocks from regimes.yaml (NIS2 24h/72h, DORA     │ ║  │
   │  ║  │    72h, SEC 4 business days from determination, UK ICO 72h,    │ ║  │
   │  ║  │    NYDFS 72h calendar hours from recruit moment)               │ ║  │
   │  ║  │  - idempotency ledger: exactly-once under live agent kill      │ ║  │
   │  ║  │  - two-key release gate: GC AND Head of IR, enforced in code   │ ║  │
   │  ║  │  - contradiction diff: blocks signoff if any two filings       │ ║  │
   │  ║  │    disagree on a load-bearing fact                             │ ║  │
   │  ║  │  - byte-identical replay from append-only run log (JSONL)      │ ║  │
   │  ║  │  - Ed25519 detached signature over the run log                 │ ║  │
   │  ║  └────────────────────────────┬──────────────────────────────────┘ ║  │
   │  ║                               │                                     ║  │
   │  ║  Band room: incident war room  [BUILT]                              ║  │
   │  ║  ┌───────────────────────────────────────────────────────────────┐ ║  │
   │  ║  │ Triage agent  NIS2 Drafter  DORA Drafter  SEC Drafter         │ ║  │
   │  ║  │ (facts)       (LLM draft)   (LLM draft)   (LLM draft)         │ ║  │
   │  ║  │                                                                │ ║  │
   │  ║  │ Runtime recruits (content-driven, [BUILT]):                    │ ║  │
   │  ║  │   UK ICO Drafter, NYDFS Drafter -- recruited when blast       │ ║  │
   │  ║  │   radius names a UK / NY entity; clock starts at recruit       │ ║  │
   │  ║  └───────────────────────────────────────────────────────────────┘ ║  │
   │  ║                               │                                     ║  │
   │  ║  Output artifacts  [BUILT]    │                                     ║  │
   │  ║  ┌───────────────────────────────────────────────────────────────┐ ║  │
   │  ║  │ Examiner Packet (HTML + JSONL): filings, handoff trace,        │ ║  │
   │  ║  │ state transitions, clocks, contradiction diff, chaos record,   │ ║  │
   │  ║  │ replay hash, Ed25519 signature. Self-contained; browser-       │ ║  │
   │  ║  │ verifiable without server.                                     │ ║  │
   │  ║  └─────────────────────────┬─────────────────────────────────────┘ ║  │
   │  ╚═══════════════════════════╪═════════════════════════════════════════╝  │
   │                              │                                             │
   │        ┌─────────────────────┼─────────────────────┐                     │
   │        │                     │                      │                     │
   │        ▼                     ▼                      ▼                     │
   │  ┌───────────┐    ┌─────────────────┐    ┌──────────────────────┐        │
   │  │ Regulator  │    │  GRC / Case     │    │  WORM Evidence Store │        │
   │  │ filing     │    │  System         │    │  (immutable archive) │        │
   │  │ channels   │    │  (ServiceNow    │    │                      │        │
   │  │            │    │   IRM, Archer)  │    │  Append-only JSONL   │        │
   │  │ NIS2 CSIRT │    │                 │    │  run log + signature  │        │
   │  │ DORA NCA   │    │  Receives the   │    │  land here; this is  │        │
   │  │ SEC EDGAR  │    │  Examiner Packet│    │  the record an       │        │
   │  │ UK ICO     │    │  and opens a    │    │  examiner subpoenas. │        │
   │  │ NYDFS      │    │  review ticket. │    │                      │        │
   │  │            │    │                 │    │  [STUB: S3 Object    │        │
   │  │ [STUB: no  │    │  [STUB: no live │    │   Lock / Azure WORM; │        │
   │  │  live push; │    │   push; packet  │    │   run log is written │        │
   │  │  human      │    │   is exported   │    │   locally today]     │        │
   │  │  submits]  │    │   manually]     │    │                      │        │
   │  └───────────┘    └─────────────────┘    └──────────────────────┘        │
   └──────────────────────────────────────────────────────────────────────────┘
```

Each incident is its own Band room with its own append-only run log and its own
correlation ids. The architecture isolates incidents by construction; a bank running
multiple concurrent incidents creates one room per incident, each with an independent
idempotency ledger and clock set.

---

## 2. RACI Table

| Responsibility | Responsible | Accountable | Consulted | Informed |
|---|---|---|---|---|
| Regime catalog (regimes.yaml): own and update | Compliance Engineering | Chief Compliance Officer | Legal / Breach Counsel | CISO |
| YAML change review: clock or format edit | Compliance Engineering | Chief Compliance Officer | Legal | CISO, SOC |
| Warden operation (3am incident) | SOC / Incident Response | Head of IR ("Lena") | CISO | GC |
| GC release key: hold and exercise | General Counsel | General Counsel | Breach Counsel | CCO |
| Head of IR release key: hold and exercise | Head of IR ("Lena") | CISO | SOC Lead | GC, CCO |
| Fact-record authoring (opening the room) | Triage / SOC analyst | Head of IR | Forensics team | GC |
| Filed content (the Examiner Packet) | Compliance Engineering | CCO | Legal, Breach Counsel | Board, Regulator |
| WORM archive / evidence store | GRC team | CCO | Legal, InfoSec | External examiner |
| Drafter agent provisioning (Band) | Platform / DevOps | CISO | Compliance Engineering | SOC |

**Two-key gate note:** `REQUIRED_ROLES = frozenset({"head_of_ir", "general_counsel"})` is
enforced in `warden/release_gate.py`. The same role signing twice does not count; a stray
role is rejected with a ValueError before the signature lands. Every release, initial and
amendment, resets the lock and demands both keys again from scratch.

---

## 3. Change-Control Workflow: Adding a Regulator

Regulation-as-config means adding a jurisdiction is a reviewed data change, not a code change.
The Warden core (`warden/`) is never edited.

```
1. PROPOSE
   Compliance Engineer opens a pull request adding one YAML block to
   floor/regimes.yaml. Required fields: key, authority, branch, regime_label,
   trigger_event, clock (length, unit, business_days, holiday_calendar),
   format_profile, start.mode + anchor (or recruit.jurisdiction + name_tokens).
   Example: adding CIRCIA when the final rule is in force is a single YAML block.

2. AUTOMATED GATE (CI, no human step)
   The existing scale test (tests/test_regimes.py, part of the 247-test suite) runs
   on the PR. It loads the catalog with the new block and asserts:
     - the new clock appears in ClockEngine.all()
     - the run log is byte-identical to prior runs on the unchanged branches
     - no edit to any file under warden/ is required
   A failing test means the YAML is malformed or conflicts with an existing branch
   key. The PR cannot merge until the suite is green.

3. REVIEW
   The CCO and a designated breach counsel reviewer sign off on the YAML diff.
   They confirm: clock length and unit match the statute, trigger_event is correct
   (occurrence vs awareness vs determination), format_profile maps to the right
   filing skeleton.

4. DEPLOY
   The reviewed YAML lands on main. A Band agent for the new drafter role is
   provisioned by DevOps (one human step: create the agent in the Band UI, add
   its keys to the env). From that point the new regime is live: the next incident
   that opens a room starts the new clock automatically.

5. AUDIT
   The YAML change is in git history with the reviewer's approval. The CI receipt
   proves zero Warden edits. Both artifacts travel with the Examiner Packet for
   that regime's first live incident.
```

---

## 4. Stubbed vs. Production: Honest Comparison

| Edge / Capability | What is real today [BUILT] | What a production deployment adds [STUB / Phase 2] |
|---|---|---|
| Inbound: SIEM/SOAR feed | Fact-record hand-authored as a Python dict in `run_floor.py` (CANONICAL_FACTS). Schema is documented and matches what a SIEM alert payload would carry. | Live webhook or SOAR connector (e.g. Splunk Adaptive Response, Sentinel playbook, XSOAR automation) that fires on a confirmed breach alert and POSTs the fact-record JSON to the Warden's ingest endpoint. Auth via mTLS or HMAC-signed webhook. |
| Release identities | `gc` and `lena` are string constants with fixed demo timestamps. The role validation and two-key gate logic are fully real. | IdP-backed identities (Okta, Azure AD, PingFederate). Non-repudiation via PKI-signed sign-off tokens. The gate mechanism requires no change; only the identity binding changes. |
| Signing key | Ed25519 demo key committed to the repo for reproducibility. The signature mechanism (sign, verify, tamper detection) is fully real. | HSM/KMS-backed private key (AWS CloudHSM, Azure Dedicated HSM). Key rotation policy. RFC 3161 trusted timestamping so the signature carries a legally defensible wall-clock assertion. See `warden/keys/README.md`. |
| Outbound: regulator filing | Examiner Packet exported as HTML/JSONL, reviewed and submitted by a human. Filing content is recognizable and correctly structured against the public templates; not a legally filed document. | Authenticated submission to EDGAR (SEC), CSIRT national portal (NIS2), ICO breach portal (UK GDPR), NYDFS cybersecurity portal. Each channel has its own auth (API key, SAML, client cert). The Warden's outbound interface is a documented contract today. |
| GRC / case integration | Examiner Packet exported manually. | REST push to ServiceNow IRM or Archer on HUMAN_RELEASED event. The packet's JSON schema is stable enough to map to a ServiceNow record today. |
| WORM archive | Append-only JSONL run log written to local filesystem. | S3 Object Lock (Compliance mode, retention period matching the regulation: NIS2 suggests 5 years, SEC Rule 17a-4 requires 6 years) or Azure Immutable Blob Storage. The run log format and hash chain are identical; only the storage backend changes. |
| Multi-incident isolation | One room, one incident, one log. | One Band room and one run log per incident. Correlation ids are already opaque and incident-scoped (`inc-NNNN:branch`); the Warden's per-branch lock and ledger are keyed by correlation id. Concurrent incidents are isolated by construction; no shared mutable state exists in `warden/`. |
| Drafter agent provisioning | Agents provisioned manually in the Band UI per run. | Automated provisioning via Band API on room creation. Agent pool per regime (one warm agent per drafter role); the Warden recruits from the pool using `/agent/peers`. |

**DORA modeling note (honest):** The build models DORA as a single 72h major-incident
follow-up report, labeled "intermediate report, 72h from classification." The DORA RTS
also specifies a 4h initial notification (Article 19, RTS on DORA). That initial
notification is a disclosed modeling choice, not implemented. A production deployment
would add a second DORA clock (4h, trigger: classification) as a second YAML block,
requiring zero Warden edits.
