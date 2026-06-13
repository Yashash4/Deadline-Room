# Codeband PR: ready to paste

Branch: `deadline-protocol-state-machine`
Target: `thenvoi/codeband` `main`
Status: merge-ready. Verified locally against the contributor gate (pytest, ruff). See "Local verification" at the bottom.

---

## Title

```
Code-backed protocol state machine and idempotency ledger for the Code Review protocol
```

## Body

```
This adds a typed, deterministic state machine and an exactly-once idempotency
ledger for the Code Review protocol, scoped as a first additive slice toward the
"Code-backed protocol state," "Deterministic Conductor state machine," and
"Protocol acknowledgment states" items on the Known Limitations roadmap.

Today the Conductor tracks protocol progress by reading state envelopes out of
memory and reasoning about them in model context. The README names this directly:
"the Conductor relies on model context plus memory state to track protocol
progress." Prompt-enforced state tracking breaks exactly where it matters most,
under high concurrency (several simultaneous Code Review cycles) and after context
truncation in long sessions. A typed transition table and a dedup ledger do not.

What it adds

- src/codeband/orchestration/protocol_state.py
  ProtocolStateMachine models one Code Review interaction (one PR, possibly many
  rounds) as a typed transition table keyed by correlation id:
  INITIATED -> FINDINGS_POSTED -> CHANGES_PUSHED -> (FINDINGS_POSTED | RESOLVED),
  with ABORTED reachable from any non-terminal state. A move not in the table is
  rejected before any downstream notification would be routed, so an illegal step
  fails closed instead of advancing silently. Role authority and the existing
  5-round hard safety limit from prompts/conductor.md are enforced in code rather
  than counted by the model. ProtocolStore replays the state envelopes agents
  already write through the typed machine, skipping malformed or out-of-order
  records, so the machine is the arbiter of protocol position, not the prose in
  the envelope.

- src/codeband/orchestration/idempotency.py
  IdempotencyLedger.record is a read-then-act dedup guard keyed by the natural key
  of a unit of work (cr_<pr>_r<round> for Code Review). The first offer of a key is
  accepted and the caller does the work; every later offer is dropped and the caller
  skips it. A re-delivered message, or a message re-emitted after a supervisor
  restart, becomes a safe no-op instead of a second review round or a duplicate
  nudge. Acknowledgment states (DELIVERED, ACKNOWLEDGED, COMPLETED) let the Watchdog
  tell an unacknowledged handoff (consumer may be down, act now) from an
  acknowledged-but-quiet one (consumer is working, give it room), instead of
  inferring liveness from message timestamps alone. The furthest beat never moves
  backward, so a stale re-delivery cannot regress state.

Why it is safe to adopt

The change is additive: two new modules in src/codeband/orchestration/ and two new
test files. It touches no existing file, changes no envelope format, and removes no
behavior. Producing agents keep writing exactly the envelopes they write today, so
existing readers and content_query filters keep working. The Conductor and Watchdog
can start folding envelopes through ProtocolStore and the ledger incrementally, with
no flag day.

Tests

- tests/test_protocol_state.py (22 tests): happy path, every rejection class (illegal
  transition, authority violation, terminal interaction, round limit), envelope
  parsing including malformed input, and ProtocolStore.rebuild against a duck-typed
  memory backend, including skip-on-malformed and skip-on-illegal-ordering.
- tests/test_idempotency.py (10 tests): dedup accept and drop, new-round-is-a-new-key,
  acknowledgment ordering, no-backward-regression, the proactive watch list, and the
  combined replay-after-restart case.

Both modules are pure Python with no LLM and no network, and import nothing that
requires Band.ai credentials, so the tests run standalone. They are written in the
existing test style (pytest, asyncio_mode = "auto", class-grouped) and pass
ruff check at the repo's line-length = 100, target-version = py311. Verified locally
with the contributor commands from the README:

    pip install -e ".[dev]"
    pytest
    ruff check src/ tests/

Deliberately out of scope (natural follow-up)

This is one protocol by design, the highest-frequency one. Extending the same pattern
to the Clarification, Merge Conflict, Test Failure, and Plan Revision protocols is the
obvious next step. The Watchdog is the cleanest first consumer: it already reads memory
envelopes in Python (_read_latest_swarm_status parses swarm status envelopes via the
memory store), so folding them through ProtocolStore.rebuild() and watching
unacknowledged_keys() would make stall detection proactive without changing any envelope
format. I kept this PR additive so it can land without touching liveness behavior, and
left the Watchdog wiring as a follow-up to review separately. Wiring this into the
Conductor is intentionally not attempted here: conductor.py composes a system prompt and
hands an adapter to Agent.create() rather than running a Python protocol loop, so there
is no in-code seam to call apply() from yet. That seam is itself the "Deterministic
Conductor state machine" roadmap item, a larger change best reviewed on its own.
```

---

## Local verification (real output, this run)

Branch is 2 commits ahead of `origin/main` (`5825f9f`) and 0 behind; merge-base equals
the current upstream main tip, so the branch is already cleanly based on the freshest
upstream main. Run a final `git rebase origin/main` after a fresh fetch right before
pushing as a courtesy no-op.

```
$ pytest tests/test_protocol_state.py tests/test_idempotency.py -q
................................                                          [100%]
32 passed in 0.08s

$ ruff check src/codeband/orchestration/protocol_state.py \
             src/codeband/orchestration/idempotency.py \
             tests/test_protocol_state.py tests/test_idempotency.py
All checks passed!
```

Do not claim "passes their CI": their only GitHub Actions workflow is a tag-driven
PyPI publish (`.github/workflows/publish.yml`); there is no PR test CI. The accurate
claim is "passes the contributor gate their README documents (pytest, ruff), verified
locally."

---

## Human steps remaining (GitHub actions an agent must not take)

1. `git -C c:\yash\band\research\repos\codeband fetch origin main` then
   `git rebase origin/main` on `deadline-protocol-state-machine` (no-op if upstream is
   still at `5825f9f`; resolves any drift if not).
2. Add your fork as a remote and push the branch:
   `git remote add fork https://github.com/<your-user>/codeband.git`
   `git push fork deadline-protocol-state-machine`.
   (Fork `thenvoi/codeband` first on GitHub if you have not.)
3. Open the PR against `thenvoi/codeband:main` from your fork's branch. Paste the
   Title and Body above.
