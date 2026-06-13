# PR: Code-backed protocol state machine and idempotency for the Code Review protocol

Branch: `deadline-protocol-state-machine`
Target: `thenvoi/codeband` `main`

## What this closes

Two items from the README "Known Limitations" / "Current planned work" list:

- **Code-backed protocol state** and **Deterministic Conductor state machine.** Today the Conductor tracks protocol progress by reading state envelopes out of memory and reasoning about them in model context (`prompts/conductor.md`, ARCHITECTURE.md "Memory Model"). The README names this limitation directly: "the Conductor relies on model context plus memory state to track protocol progress."
- **Protocol acknowledgment states.** Protocols have no explicit "I received and understood this" beat, which, as the limitations section notes, makes stall detection reactive rather than proactive.

Both are implemented against Codeband's actual code, scoped first to the Code Review protocol (the highest-frequency protocol, exactly as the README scope hint suggests), and wrap the existing JSONL / Band.ai memory backend rather than replacing it.

## Commit 1: typed `ProtocolStateMachine` + `ProtocolStore`

`src/codeband/orchestration/protocol_state.py`

- `ProtocolStateMachine` models one Code Review interaction (one PR, possibly many rounds) as a typed transition table keyed by correlation id. The whole protocol reads in one screen: `INITIATED -> FINDINGS_POSTED -> CHANGES_PUSHED -> (FINDINGS_POSTED | RESOLVED)`, with `ABORTED` reachable from any non-terminal state. A move not in the table is rejected before any downstream notification would be routed, so an illegal step fails closed instead of advancing silently.
- Role authority is enforced in code: reviewers post findings and pass, coders request review and push changes, the Conductor or Watchdog trips the round limit. The existing 5-round hard safety limit from `prompts/conductor.md` ("no protocol should exceed 5 rounds") is enforced here rather than counted by the model.
- `ProtocolStore` wraps the memory backend Codeband already resolved (Band.ai REST memory on the paid tier, `LocalMemoryStore` on the free tier). It is backend-agnostic: it only depends on the duck-typed `await list(...) -> .data -> .content` shape both expose, so it imports no backend directly. It replays the existing state envelopes through the typed machine, skipping malformed or out-of-order records, so the machine is the arbiter of protocol position, not the prose in the envelope.
- The state-envelope format is unchanged. Producing agents keep writing exactly what they write today, so existing readers and `content_query` filters keep working. `parse_review_envelope` reads the documented first-line format (`protocol code_review cid cr_<pr>_r<round> ... state <...> from <...> to <...>`) by key, not by position, and returns `None` on anything malformed so an unrelated memory record is a safe skip.

The correlation-id convention follows Codeband's own: a round suffix (`_r<n>`) identifies one round, but a review interaction spans rounds, so the stable key is the round-stripped base id (`cr_42`). `base_cid` derives it.

## Commit 2: `IdempotencyLedger` + acknowledgment states

`src/codeband/orchestration/idempotency.py`

- `IdempotencyLedger.record` is a read-then-act dedup guard keyed by the natural key of a unit of work (`cr_<pr>_r<round>` for Code Review). The first offer of a key is `ACCEPTED` and the caller performs the work; every later offer is `DUPLICATE_DROPPED` and the caller skips it. This makes a re-delivered message, or a message re-emitted after a `session/supervisor.py` restart, a safe no-op instead of a second review round, a duplicate nudge, or a re-applied transition. At-least-once delivery and worker auto-restart can both replay a message, so this guard is what protocol units need to stay exactly-once.
- Acknowledgment states close the acknowledgment-state gap. The producer records `DELIVERED` when it posts a handoff; the consumer records `ACKNOWLEDGED` when it picks the work up, then `COMPLETED` when done. The Watchdog can then distinguish an unacknowledged handoff (consumer may be down, act now) from an acknowledged-but-quiet one (consumer is working, give it room), instead of inferring liveness from message and mention timestamps alone (`agents/watchdog.py`). `unacknowledged_keys()` is the proactive watch list. The furthest beat never moves backward, so a stale re-delivery cannot regress state, the same replay-safety property as `record`.

## Why this matters for Band

This is the Internet of Agents thesis in concrete code. An open network of autonomous agents needs trust primitives that do not depend on any one agent behaving: a coding agent cannot reliably enforce its own protocol state, because the same context truncation and self-preference that make same-model review weak also make a model an unreliable bookkeeper of its own progress. Moving protocol state and exactly-once into deterministic Python is the same move Codeband already makes with cross-model review, applied to coordination: the platform, not the model, is the source of truth for where a handoff is. Band's interaction layer (persistent identity, shared memory, mention routing) is what makes a code-backed arbiter possible across heterogeneous agents in the first place.

Prompt-enforced state tracking breaks exactly where it matters most: under high concurrency (several simultaneous Code Review cycles) and after context truncation in long sessions. A typed table and a dedup ledger do not.

## Testing and mergeability

- `tests/test_protocol_state.py` (22 tests): happy path, every rejection class (illegal transition, authority violation, terminal interaction, round limit), envelope parsing including malformed input, and `ProtocolStore.rebuild` against a duck-typed memory backend, including skip-on-malformed and skip-on-illegal-ordering.
- `tests/test_idempotency.py` (10 tests): dedup accept/drop, new-round-is-a-new-key, acknowledgment ordering, no-backward-regression, the proactive watch list, and the combined replay-after-restart case.
- Both new modules are pure Python with no LLM and no network, and import nothing that requires Band.ai credentials, so their tests run standalone in CI. Tests are written in the existing repo style (pytest, `asyncio_mode = "auto"`, class-grouped) and pass under `ruff check` at the repo's `line-length = 100`, `target-version = py311`.

The change is additive: two new modules in `src/codeband/orchestration/` and two new test files. It touches no existing file, changes no envelope format, and removes no behavior, so it can be adopted incrementally (the Conductor and Watchdog can start folding envelopes through `ProtocolStore` and the ledger without any flag day). It is a first deterministic slice scoped to one protocol, by design; extending the same pattern to the Clarification, Merge Conflict, Test Failure, and Plan Revision protocols is the natural follow-up.

## Note for a clean PR

Open against `main` after rebasing on the latest upstream. The branch is based on commit `5825f9f` (the current `main` tip at preparation time).
