# Deadline Room: Formal Specification of the Deterministic Warden

This document is the written specification that the Deadline Room's verification suite
discharges mechanically. It states the system model, the named invariants, the
guarantees that sit beyond the state machine, the one-command artifacts that prove each
one, and an honest scope of what is and is not formally claimed.

The Warden is the no-LLM trust core of the Deadline Room. Anything that gates, counts,
clocks, releases, or seals is pure Python; LLM drafter agents produce content and legal
rationale only and never enter the gate path. Because the Warden is finite, its claims
are not asserted, they are proven: the reachable configuration space is enumerated in
full and every safety and progress invariant is checked at every reachable node. This
specification names the proof obligations; the code in `warden/` and `scripts/`
discharges them, and the citation column points at the exact module, script, or test
that does so.

Every number in this document is taken from the shipped code and the runnable scripts,
not from prose. The reachable-state count (111), the transition count (222), the
run-shape count for the determinism certificate (32), the failure-fuzz headline (5,000
schedules, 0 double-files), the exactly-once benchmark (10,000 schedules), and the test
count (448) are all reproducible with the one-command receipts cited in Section 4.

---

## 1. System model

The Warden is a finite automaton composed of four real mechanisms. Each is read from its
shipped module, never re-implemented:

1. the typed protocol state machine (`warden/state_machine.py`),
2. the authority relation over events (`EVENT_AUTHORITY` in the same module),
3. the two-key release gate (`warden/release_gate.py`),
4. the amendment negotiation guard (`warden/negotiation.py`).

### 1.1 State space

A single branch (one regulatory filing, correlation id `<incident>:<branch>`, e.g.
`inc-8842:nis2`) occupies one of ten named protocol states (`warden/state_machine.py`,
`State`):

| State | Meaning |
|---|---|
| `INITIATED` | branch opened, no fact record yet |
| `FACT_RECORD_READY` | Triage has posted the typed fact record |
| `DRAFTING` | a drafter is composing the filing |
| `DRAFT_SUBMITTED` | a draft has been posted, awaiting the contradiction diff |
| `CONTRADICTION_CHECKED` | the cross-draft diff passed (no conflicts) |
| `AWAITING_HUMAN_SIGNOFF` | the two-key human release gate is open |
| `RELEASED` | the filing released; reopenable only by a fact amendment |
| `AMENDING` | a released branch reopened by a load-bearing fact revision |
| `SUPPRESSED` | terminal: the duty did not attach (e.g. SEC materiality veto) |
| `FAILED` | terminal: a statutory clock breached |

`SUPPRESSED` and `FAILED` are the terminal (absorbing) states
(`TERMINAL_STATES`). `RELEASED` is deliberately not terminal: it is reopenable
(`REOPENABLE_STATES`) by exactly one event, `FACT_AMENDED`, which begins the
amendment sub-cycle.

### 1.2 Events and the transition relation

Eleven typed events drive the machine (`Event`). The transition relation is a total
partial function `TRANSITIONS: (State, Event) -> State`. An event with no edge from the
current state is an illegal move and is rejected before any downstream message is sent;
the machine never guesses. The explicit edges are:

```
INITIATED              --FACT_RECORD_POSTED--> FACT_RECORD_READY
INITIATED              --SUPPRESS-----------> SUPPRESSED
FACT_RECORD_READY      --DRAFT_STARTED------> DRAFTING
FACT_RECORD_READY      --SUPPRESS-----------> SUPPRESSED
DRAFTING               --DRAFT_POSTED-------> DRAFT_SUBMITTED
DRAFTING               --SUPPRESS-----------> SUPPRESSED
DRAFT_SUBMITTED        --DIFF_PASSED--------> CONTRADICTION_CHECKED
DRAFT_SUBMITTED        --DIFF_BLOCKED-------> DRAFTING
CONTRADICTION_CHECKED  --SIGNOFF_OPENED-----> AWAITING_HUMAN_SIGNOFF
CONTRADICTION_CHECKED  --DIFF_BLOCKED-------> DRAFTING
AWAITING_HUMAN_SIGNOFF --HUMAN_RELEASED-----> RELEASED
AWAITING_HUMAN_SIGNOFF --DIFF_BLOCKED-------> DRAFTING
RELEASED               --FACT_AMENDED-------> AMENDING
AMENDING               --DRAFT_POSTED-------> DRAFT_SUBMITTED
```

plus a uniform rule: `CLOCK_BREACHED` from any non-terminal, non-`RELEASED` state
transitions to `FAILED`. A `RELEASED` branch has a stopped clock, so a breach cannot
fire there. This rule is the only non-tabular edge and it is generated programmatically
over every eligible state, so no eligible state can quietly omit it.

The `AMENDING -> DRAFT_SUBMITTED` edge is additionally gated outside the pure table by the
negotiation guard (Section 1.5), and `AWAITING_HUMAN_SIGNOFF -> RELEASED` is additionally
gated outside the pure table by the two-key release gate (Section 1.4).

### 1.3 Authority relation

Authority is a total relation `EVENT_AUTHORITY: Event -> set of roles`
(`warden/state_machine.py`). Every event has a defined, non-empty authority set. An event
emitted by a role outside its authority set is rejected and does not move state. This is
the RBAC mirror of the Band room roles:

| Event | Authorized roles |
|---|---|
| `FACT_RECORD_POSTED` | `triage` |
| `DRAFT_STARTED` | `drafter` |
| `DRAFT_POSTED` | `drafter` |
| `DIFF_PASSED` | `warden` |
| `DIFF_BLOCKED` | `warden` |
| `SIGNOFF_OPENED` | `warden` |
| `HUMAN_RELEASED` | `human_owner`, `human_admin` |
| `SUPPRESS` | `materiality` |
| `CLOCK_BREACHED` | `warden` |
| `FACT_AMENDED` | `triage` |

A drafter can never self-release: `HUMAN_RELEASED` is authorized only for the human
roles, and the model-checker proves this for every state, not only the two a unit test
would poke.

### 1.4 Two-key release gate

The single `AWAITING_HUMAN_SIGNOFF -> RELEASED` edge is fired only when the two-key gate
admits it (`warden/release_gate.py`). `REQUIRED_ROLES` is the set of two distinct human
roles `{head_of_ir, general_counsel}` that must both sign before release is admitted.
One key alone never turns the lock, and the same key twice (one role signing twice) never
turns it either: `decision()` releases only when `REQUIRED_ROLES - have == empty`.
`reset()` clears a branch's lock after a release so that a later amendment re-release must
collect both distinct keys again from scratch, not inherit the first release's keys. This
is the segregation of duties on the human release, composed outside the transition table.

### 1.5 Amendment negotiation guard

The amendment sub-cycle is the only place one drafter reads and answers another. The
guard (`warden/negotiation.py`) is purely structural: it checks that a reconciliation
happened and converged before the amendment is allowed to advance, and it never judges
the legal characterization (that stays the drafters' job, so the Warden stays no-LLM).
`MAX_ROUNDS = 3` bounds the negotiation. `can_submit_amendment(branch, round)` admits the
`AMENDING -> DRAFT_SUBMITTED` edge only when a `CONCUR` envelope exists for the current
round. Envelopes are content-addressed (`sha256` over the canonical envelope) and a
`CONCUR`/`COUNTER` must hash-link to the prior envelope it answers, so the negotiation
chain is tamper-evident.

### 1.6 The composed machine and its finite reachable space

The model-checker (`warden/modelcheck.py`) treats the full composed configuration of one
branch as a node:

```
Node(state, have_keys, released_once, amend_round, concurred)
```

where `state in State`, `have_keys` is a subset of `REQUIRED_ROLES`, `released_once` and
`concurred` are booleans, and `amend_round` is an integer in `0..MAX_ROUNDS`. The
transition relation out of a node is the composition of the four mechanisms above plus
three composed gate-side actions that drive the auxiliary variables: signing each of the
two distinct release keys (`SIGN_HEAD_OF_IR`, `SIGN_GENERAL_COUNSEL`) and posting a
concurrence envelope (`POST_CONCUR`). The checker never re-implements the table or the
gates: it seeds a real `ProtocolStateMachine` at each state and asks the shipped
`apply()`, drives a real `TwoKeyReleaseGate`, and drives a real `NegotiationGuard`.

Because `State` is finite, `have_keys` is a subset of a two-element set, two fields are
booleans, and `amend_round` is bounded by `MAX_ROUNDS`, the space is finite and a
breadth-first enumeration from the single start node terminates and visits every
reachable configuration exactly once. The current enumeration, reproducible with
`py scripts/model_check.py`, is:

- **111 reachable states**
- **222 transitions explored**

This is the decisive property: the trust core is small enough to enumerate exhaustively,
so "0 violations across 111 reachable states, enumerated exactly" is a theorem, not an
estimate over a random sample.

---

## 2. The invariants

Each invariant has a stable id, a one-line plain statement, the precise condition it
asserts, and the mechanism that discharges it. SAFE-1 through SAFE-5 are safety
properties evaluated at every reachable node or edge; PROG-1 is the progress (no-deadlock)
property evaluated over the reachable graph. All six are stated in the
`warden/modelcheck.py` module docstring as the formal spec, and `check_invariants()`
returns a per-invariant PASS/FAIL with, on any failure, the first violating node and the
shortest counterexample path from the start node.

### SAFE-1: no release without a passed diff and two distinct keys

- **Plain statement:** a filing can be released only after the contradiction diff passed
  and two distinct human keys both signed.
- **Condition:** no reachable node in `RELEASED` has `have_keys != REQUIRED_ROLES`, and
  every edge whose destination is `RELEASED` is a `HUMAN_RELEASED` edge whose source node
  held both distinct keys. The only path into `RELEASED` runs through
  `AWAITING_HUMAN_SIGNOFF`, which is reachable only via `SIGNOFF_OPENED` from
  `CONTRADICTION_CHECKED`, which is reachable only via `DIFF_PASSED`; so a release implies
  a prior diff pass and a prior two-key collection. The one-key path is simply not in the
  reachable set, and the checker asserts it.
- **Discharged by:** the exhaustive model-check (`_check_safe1`, `scripts/model_check.py`,
  `tests/test_modelcheck.py::test_real_machine_passes_every_invariant`). The
  non-vacuity is proven by a negative control:
  `tests/test_modelcheck.py::test_negative_control_two_key_bypass_is_caught` plants a
  two-key bypass and asserts SAFE-1 catches the release-without-two-keys with a
  counterexample path, and `test_negative_control_planted_backdoor_edge_is_caught`
  plants a back-door release edge straight out of `DRAFT_SUBMITTED` (skipping the diff)
  and asserts SAFE-1 catches a release reached without a `diff_passed` step. The same
  property is checked over the sealed artifact by the audit's TWO-KEY RELEASE predicate
  (`scripts/audit_run.py::check_two_key_release`).

### SAFE-2: terminal states are absorbing

- **Plain statement:** once suppressed or failed, a branch never moves again.
- **Condition:** no reachable terminal node (`SUPPRESSED` or `FAILED`) has any outgoing
  transition, for every event, not only the few a unit test pokes. The state machine's
  `apply()` rejects every event from a terminal state; SAFE-2 certifies that rejection is
  total over the enumerated graph.
- **Discharged by:** the exhaustive model-check (`_check_safe2`), plus
  `tests/test_modelcheck.py::test_negative_control_planted_terminal_exit_breaks_safe2`,
  which asserts that `successors()` of a `SUPPRESSED` node and of a `FAILED` node are both
  empty.

### SAFE-3: authority is total and single-valued

- **Plain statement:** every event has a defined, non-empty set of roles allowed to emit
  it, and no role is both allowed and forbidden for one event.
- **Condition:** for every `Event`, `EVENT_AUTHORITY[event]` exists and is non-empty, and
  for every role in the full role universe membership is unambiguous (the membership
  predicate is a function). Each composed gate action also has a defined, non-empty
  authority (`GATE_ACTION_AUTHORITY`), so no composed action is authority-less.
- **Discharged by:** the exhaustive model-check (`_check_safe3`), which sweeps every event
  against every role in `ALL_ROLES` (the union of every role named in either authority
  table), and `tests/test_modelcheck.py::test_checker_reads_the_real_authority_tables`,
  which confirms the checker reads the shipped `EVENT_AUTHORITY`, not a copy.

### SAFE-4: amendment needs concurrence

- **Plain statement:** a reopened (amended) filing cannot reach a re-released state
  without a concurrence for its round.
- **Condition:** no reachable edge leaves `AMENDING` on a `DRAFT_POSTED` (the amendment
  submission) with `concurred == False`. The negotiation guard composed in `successors()`
  forbids the edge otherwise; SAFE-4 certifies that no amendment path slips into a
  re-released state without a `CONCUR` for its round, with the round counter bounded by
  `MAX_ROUNDS` to keep the space finite.
- **Discharged by:** the exhaustive model-check (`_check_safe4`), with non-vacuity proven
  by `tests/test_modelcheck.py::test_negative_control_concurrence_bypass_is_caught`,
  which bypasses the guard and asserts SAFE-4 catches the amendment-without-concurrence
  with a counterexample path that names a `fact_amended` step. The algebraic properties of
  the guard (a matching `CONCUR` settles its round regardless of interleaved traffic;
  replaying an envelope is a no-op; an over-`MAX_ROUNDS` envelope is rejected identically
  regardless of initiator) are checked by the metamorphic relations NEG-SETTLE,
  NEG-IDEMPOTENT, and NEG-MAXROUNDS (`tests/test_metamorphic.py`).

### SAFE-5: state-level exactly-once (release write-once per lifecycle)

- **Plain statement:** a branch never files (releases) twice without the facts genuinely
  changing first.
- **Condition:** no reachable edge fires `HUMAN_RELEASED` while its source node already
  holds `released_once == True`. The only legal path to a second release runs through a
  `FACT_AMENDED` reopen, which clears `released_once`, so the second release is on the
  amended filing, not a duplicate of the first. The diff-block re-draft loop
  (`DIFF_BLOCKED` back to `DRAFTING`) is not a double-file, because a re-draft is a new
  unit of work with a new round in its ledger dedup key; the write-once property that
  matters at the state level is the release commit, which `released_once` tracks.
- **Discharged by:** the exhaustive model-check (`_check_safe5`). The run-level form of
  exactly-once (under live kills and lost acks) is proven separately by the failure fuzz
  and the in-log audit, and is the subject of Section 3.2; SAFE-5 is the state-machine
  half of that guarantee.

### PROG-1: no protocol deadlock (progress)

- **Plain statement:** the protocol can never wedge in a state with no legal way forward.
- **Condition:** every reachable non-terminal node has at least one admitted outgoing
  transition and can reach a terminal or released outcome (`RELEASED` is treated as
  progress-complete; `SUPPRESSED` and `FAILED` are terminal). No reachable node is a dead
  end.
- **Discharged by:** the exhaustive model-check (`_check_prog1`), which checks both that
  each non-terminal node has a successor and that a forward BFS from it can reach a
  terminal or released outcome.
- **Scope note:** PROG-1 is a finite-reachability progress property, not a liveness
  theorem under scheduler fairness. The honest limit is stated in Section 5.

---

## 3. Guarantees beyond the state machine

These four guarantees hold over the run artifact (the append-only run log and its
sidecars), not over the abstract state graph. They are what let an organization hand the
output to a regulator, an examiner, an auditor, and a court.

### 3.1 Determinism and byte-identical replay

The run log is an append-only JSONL stream (`warden/replay.py`). Replay feeds the saved
protocol events back through a fresh `ProtocolStateMachine` and re-emits every other entry
verbatim; the output is byte-identical to the original. Canonicalization is sorted-key,
separator-tight JSON, so the sealed `sha256` over the canonical JSONL is a deterministic
function of the event sequence: there is no `now()` or RNG in the sealing path.

The model-checker folds in a determinism certificate (`certify_determinism()`) that proves
this over the reachable run space rather than a random sample: it enumerates every
admitted run shape the model permits (currently **32 run shapes**, reproducible with
`py scripts/model_check.py`) and, for each, asserts `replay(replay(log)) == replay(log)`
(idempotence) and that the sealed `(sha256, chain_head)` pair is identical across two
independent constructions of the same sequence (a pure function of the events). The same
property is exercised adaptively over the generated input space by the Hypothesis property
REPLAY-DET (`tests/test_properties_hypothesis.py`).

### 3.2 Exactly-once under kill, lost-ack, and duplicate

The exactly-once handoff layer (`warden/ledger.py`) keys each unit of work by its natural
dedup key (e.g. `draft:nis2:inc-8842:round-1`). A re-delivered message whose key is
already recorded is acknowledged and dropped, never double-counted, through a read-then-act
guard owned by the poster (never reliance on re-delivery). This holds under three failure
modes an SRE actually fears, modeled honestly in `warden/fake_band.py` and driven through
the real pipeline by `warden/simulate.py`:

- crash position A (killed before posting): the key is not yet recorded, the re-run is
  admitted, idempotent by re-execution;
- crash position B (killed after posting, before marked processed): the key is recorded,
  the duplicate is dropped;
- lost-ack partition (the post lands but the ack is lost, and `/next` re-serves the
  identical message with the attempt counter unchanged): the read-then-act dedup drops the
  redelivery on the attempt-independent natural key.

- **Headline:** the failure-fuzz benchmark (`scripts/failure_fuzz_benchmark.py`) drives
  **5,000 randomized schedules** (master seed 20260617, lost-ack + interleaved
  cross-branch storm + simultaneous multi-branch kill, schedule space lower-bounded at
  ~384,000) with **0 double-files, 0 lost filings, 0 clock breaches, 0 replay drifts**.
  The earlier exactly-once benchmark (`scripts/exactly_once_benchmark.py`) holds the same
  result across **10,000 schedules** (master seed 20260616).
- **Discharged by:** `tests/test_failure_fuzz.py` (the in-suite version of the benchmark),
  the Hypothesis property EXACTLY-ONCE and LEDGER-IDEM
  (`tests/test_properties_hypothesis.py`), and the in-log EXACTLY-ONCE predicate over the
  sealed artifact (`scripts/audit_run.py::check_exactly_once`). The fuzz asserts are hard:
  a fabricated double-accept trips the detector, so the 0 is real, not green-washed.

### 3.3 Provenance: hash chain and bound Ed25519 signature

Integrity, ordering, and authenticity are three separate, stacked guarantees:

- the flat `RunLog.sha256()` over the canonical JSONL catches any field edit (one byte
  moves the digest);
- the per-entry hash chain (`warden/chain.py`) folds each entry's hash into the next
  (`entry_hash[i] = sha256(entry_hash[i-1] || canon(entry[i]))`), so a reorder or omission
  moves the `chain_head` and the first broken link is point-at-able. The chain is a derived,
  read-only sidecar; it never mutates a logged entry and never enters the hashed JSONL, so
  replay and the run-log sha are unaffected;
- the detached Ed25519 signature (`warden/signing.py`) is taken over the bound payload
  `bound_payload_bytes(sha256, chain_head)`, a canonical JSON object that names both the
  run-log sha256 and the chain head. A valid signature therefore reads as "this exact
  ordered, complete run, attested by this key". A field flip moves the sha, a reorder or
  omission moves the chain head; either changes the bound payload, so either invalidates
  the signature.

Ed25519 is deterministic, so the captured signatures are reproducible byte for byte.

- **Honest caveat (stated, not hidden):** the private key shipped in the repo is a
  demonstration key. The signature mechanism is fully real (one flipped byte makes it
  invalid), but the key's secrecy is not production-grade: it proves "signed by whoever
  holds this demo key", not HSM/KMS-grade custody. KMS/HSM custody, key rotation, a
  published key directory, and RFC-3161 timestamping are explicit Phase 2 work
  (`DEMO_KEY_CAVEAT`).
- **Discharged by:** `scripts/verify_signature.py` (the signature verifies over the bound
  payload), `scripts/tamper_test.py` (a field flip and a reorder each break the signature),
  the SIGNATURE and CHAIN predicates in `scripts/audit_run.py`, and the metamorphic
  relation REPLAY-PREFIX (`tests/test_metamorphic.py`), which proves the chain head is a
  prefix-extension homomorphism (a tamper at position i moves every head from i onward and
  nothing before it).

### 3.4 Statutory clock semantics

The clock engine (`warden/clocks.py`) drives deadlines from real timestamps, never
wall-clock cosmetics. All comparisons are canonicalized to UTC (`parse_ts` normalizes any
ISO-8601 offset, including a `Z` suffix, to UTC). The hour-counted regimes (NIS2 early
warning 24h and full 72h, DORA 72h, UK ICO/GDPR 72h, NYDFS 72h) are an exact translation
of the start instant: `deadline = start + N hours`. The SEC 8-K clock counts four
business days from the materiality determination instant (not occurrence or discovery),
skipping weekends and US federal holidays, with the observed-date rule (5 U.S.C. 6103: a
holiday on a Saturday is observed the preceding Friday, on a Sunday the following Monday).
The holiday table (`_HOLIDAYS_BY_YEAR`) covers 2026 through 2028; a business-day count
that rolls into an uncovered year raises `HolidayYearNotCovered` rather than silently
skipping that year's weekends but not its holidays (a quietly wrong deadline is refused
loudly).

- **Discharged by:** the Hypothesis property CLOCK-CORRECT
  (`tests/test_properties_hypothesis.py`), which checks the business-day math against an
  independent reference implementation, monotonicity in the day count, and
  timezone-equivalence for both the business-day and the hour clocks; the metamorphic
  relations CLOCK-WEEKSHIFT and CLOCK-HOURSADD (`tests/test_metamorphic.py`); the
  contradiction diff's UTC canonicalization, checked by DIFF-TZ
  (the same instant in two zones is never a contradiction, genuinely different instants
  always are); and the CLOCK-MONOTONIC predicate over the sealed artifact
  (`scripts/audit_run.py::check_clock_monotonic`).

---

## 4. The verification suite

Each invariant and guarantee maps to a one-command, judge-runnable artifact. The scripts
are keyless and offline; the test files run under `py -m pytest tests/ -q` (448 tests
green at the time of writing).

| Property | Statement | Discharged by (command / test) |
|---|---|---|
| SAFE-1 | no release without a passed diff and two distinct keys | `py scripts/model_check.py`; `tests/test_modelcheck.py` (positive + two-key-bypass + back-door negative controls); `scripts/audit_run.py` TWO-KEY RELEASE |
| SAFE-2 | terminal states absorbing | `py scripts/model_check.py`; `tests/test_modelcheck.py::test_negative_control_planted_terminal_exit_breaks_safe2` |
| SAFE-3 | authority total and single-valued | `py scripts/model_check.py`; `tests/test_modelcheck.py::test_checker_reads_the_real_authority_tables` |
| SAFE-4 | amendment needs concurrence | `py scripts/model_check.py`; `tests/test_modelcheck.py::test_negative_control_concurrence_bypass_is_caught`; `tests/test_metamorphic.py` (NEG-SETTLE, NEG-IDEMPOTENT, NEG-MAXROUNDS) |
| SAFE-5 | release write-once per lifecycle | `py scripts/model_check.py` (`_check_safe5`); run-level form via Section 3.2 |
| PROG-1 | no protocol deadlock | `py scripts/model_check.py` (`_check_prog1`) |
| DETERMINISM / REPLAY | replay is a pure function of the events; same input yields the same sealed sha | `py scripts/model_check.py` (determinism certificate, 32 run shapes); `tests/test_properties_hypothesis.py` REPLAY-DET; `scripts/audit_run.py` REPLAY |
| EXACTLY-ONCE (run level) | each filing lands once under kill / lost-ack / duplicate | `py scripts/failure_fuzz_benchmark.py` (5,000 schedules, 0 double-files); `py scripts/exactly_once_benchmark.py` (10,000 schedules); `tests/test_failure_fuzz.py`; `tests/test_properties_hypothesis.py` EXACTLY-ONCE / LEDGER-IDEM; `scripts/audit_run.py` EXACTLY-ONCE |
| PROVENANCE (chain) | reorder or omission moves the chain head | `py scripts/tamper_test.py`; `scripts/audit_run.py` CHAIN; `tests/test_metamorphic.py` REPLAY-PREFIX |
| PROVENANCE (signature) | the bound Ed25519 signature over {sha256, chain_head} verifies; any tamper breaks it | `py scripts/verify_signature.py`; `py scripts/tamper_test.py`; `scripts/audit_run.py` SIGNATURE |
| CLOCK semantics | business-day + holiday + timezone canonicalization | `tests/test_properties_hypothesis.py` CLOCK-CORRECT / DIFF-TZ; `tests/test_metamorphic.py` CLOCK-WEEKSHIFT / CLOCK-HOURSADD; `scripts/audit_run.py` CLOCK-MONOTONIC |
| ALL (sealed artifact) | every in-log invariant proven from the sealed bytes | `py scripts/audit_run.py` (WELL-FORMED, REPLAY, CHAIN, SIGNATURE, EXACTLY-ONCE, TWO-KEY RELEASE, CLOCK-MONOTONIC over all four sealed captures) |

The audit (`scripts/audit_run.py`) is the strongest single statement: it proves the
invariants from the sealed artifact a judge holds, independent of how it was produced, and
exits nonzero with a named locus on any tamper.

---

## 5. Scope and non-claims

This specification claims exactly what the code proves, and no more.

1. **Liveness under adversarial scheduling is not proven.** A true liveness theorem under
   weak or strong scheduler-fairness assumptions is a temporal-logic obligation that a
   Python BFS cannot honestly discharge; claiming it would be test-theater. The honest,
   provable substitute is PROG-1: every reachable non-terminal node has an outgoing
   transition and can reach a terminal or released outcome (no dead end). This is a
   finite-reachability property, not a fairness-conditioned liveness theorem, and the
   distinction is stated rather than blurred.

2. **The LLM drafters are outside the trusted base, by design.** Drafter agents (different
   frameworks, different models) produce filing content and legal rationale. They never
   gate, count, clock, release, or seal. The only thing that crosses from an LLM into the
   gate is a typed claim (a structured fact envelope), which the deterministic diff and
   the deterministic gates then judge. No LLM verdict is ever load-bearing in the trust
   core. Qualitative quality of the drafted prose is a separate, measured concern (a
   scorer, never a gate) and is not the subject of this specification.

3. **The signing key's secrecy is not production-grade.** The signature mechanism is real
   and independently checkable today; the demo key's custody is not. KMS/HSM custody, key
   rotation, a published key directory, and RFC-3161 trusted timestamping are Phase 2, and
   the demo-key caveat travels with every signature output rather than being hidden.

4. **A second formal model (TLA+/TLC, SMT) is deliberately not maintained.** A separate
   formal model is a second source of truth that can drift from the shipped Python. The
   model-checker here enumerates the actual transition table and the actual gates that
   ship, with a judge-runnable receipt and no abstraction gap, which is the stronger claim
   for a finite, tiny space. A TLA+ model is noted as possible Phase 2 work, not a current
   claim.

5. **The numbers are point-in-time and reproducible.** The 111 reachable states, 222
   transitions, 32 run shapes, 5,000 / 10,000 fuzz schedules, and 448 tests are the values
   the shipped code produces today. Every one is reproducible with the command cited
   beside it; if the protocol grows, the model-checker reports the new count and this
   document is updated to match, because the checker, not the prose, is the source of
   truth.
