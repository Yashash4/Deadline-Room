# Codeband PR 2: ready to paste

Branch: `deadline-watchdog-deterministic-stall`
Target: `thenvoi/codeband` `main`
Stacks on: PR 1 (`deadline-protocol-state-machine`). See "Stacking" below.
Status: merge-ready once PR 1 lands. Verified locally against the contributor gate (pytest, ruff). See "Local verification" at the bottom.

---

## Title

```
Deterministic protocol-stall detection in the Watchdog (closes a Known Limitations item)
```

## Body

```
This wires the typed protocol state machine from the previous PR into the
Watchdog so it can detect a stalled Code Review handoff deterministically,
instead of inferring one from message silence. It closes the "Protocol
acknowledgment states" item on the Known Limitations roadmap.

The roadmap names this gap. README Known Limitations:

  "the Conductor relies on model context plus memory state to track protocol
  progress. The roadmap is to move more protocol state and branch enforcement
  into deterministic Python code."

and lists, under Current planned work:

  - Code-backed protocol state
  - Deterministic Conductor state machine
  - Code-backed branch enforcement
  - Protocol acknowledgment states

The previous PR added the first two pieces as additive modules. This PR is the
first consumer of them: it gives the Watchdog a code-backed answer to "is this
handoff actually open" that does not exist today.

The problem

Today the Watchdog detects staleness from chat message and mention timestamps
(see _patrol in agents/watchdog.py). That signal cannot tell apart three
different situations that all look like silence:

- a coder that finished its fix and is correctly quiet (not stalled),
- a coder that owes a fix on an open review round and has gone silent (stalled),
- a reviewer that owes a re-review on a pushed change and has gone silent
  (stalled).

A timestamp clock sees only "no message for N seconds," so it either nudges
correctly-idle agents (noise) or waits a full staleness window before reacting
to a genuinely dropped handoff (slow). This is exactly the "stall detection
reactive rather than proactive" gap the roadmap calls out.

What this adds

- src/codeband/orchestration/protocol_watch.py
  detect_protocol_stalls(machine) is a pure function over a typed
  ProtocolStateMachine. A Code Review interaction the machine places in a
  non-terminal state is, by definition, an open required handoff:
  FINDINGS_POSTED is waiting on the coder, CHANGES_PUSHED is waiting on the
  reviewer. RESOLVED and ABORTED are terminal and never stall; INITIATED (a PR
  announced with no findings yet) carries no owed move and is excluded by
  construction, so this does not re-introduce the timestamp clock's false
  positives. Each returned stall names the role that owes the next move, so the
  silence is interpreted rather than guessed. Results are sorted by correlation
  id, so the output is deterministic across runs, which is the whole point.

- src/codeband/agents/watchdog.py
  WatchdogDaemon.detect_protocol_stalls is the opt-in consumer. It reads the
  same protocol code_review ... state ... envelopes agents already write,
  through the same memory backend the swarm-status gate already uses
  (_read_latest_swarm_status): the injected LocalMemoryStore on free tier, the
  agent memories client on paid tier. It folds those envelopes through
  ProtocolStore.rebuild to get the typed position of each interaction and
  returns the open ones. A small _protocol_memory adapter forwards the paid-tier
  list_agent_memories call into the list(...) shape ProtocolStore expects,
  mirroring the free/paid branch the swarm-status read already makes. A memory
  error returns an empty list, never raises, so a caller can fall back to the
  timestamp patrol.

Why it is safe to adopt

This is additive and behavior-preserving. detect_protocol_stalls is a new method
and is not called from _patrol, so the existing nudge and escalate state machine
is byte-for-byte unchanged. It reads envelopes that already exist and changes no
envelope format, so existing readers and content_query filters keep working. A
maintainer can adopt it incrementally: call detect_protocol_stalls when you want
a deterministic stall list, with no flag day and no change to the timestamp path.

To keep the surface small and reviewable, this PR adds the detector and proves it
end to end, and does not yet make _patrol act on its output. Folding the result
into the patrol's nudge decision (for example, nudging the role that owes the
move the moment its handoff is open past a threshold, rather than waiting for the
staleness window) is the natural next step and is intentionally left to a
follow-up so the new detector can be reviewed on its own. So this PR delivers the
deterministic acknowledgment signal the roadmap asks for and a first real
consumer of it, while leaving the patrol's existing behavior untouched.

Tests

- tests/test_protocol_watch.py (7 tests): findings_posted is a stall owed by the
  coder; changes_pushed is a stall owed by the reviewer; resolved and aborted
  are not stalls; initiated carries no owed handoff; the empty machine is empty;
  multiple open interactions come back sorted by cid with resolved ones dropped.
- tests/test_watchdog.py, new TestDeterministicStallDetection (5 tests): the
  Watchdog method reports an open findings round (owed by coder) and an open
  changes_pushed round (owed by reviewer); a resolved review with since-silent
  agents is not flagged (the case a timestamp clock would wrongly nudge); the
  paid tier reads through agent_api_memories; a memory backend error returns an
  empty list instead of raising.

Both modules are pure Python with no LLM and no network, written in the existing
test style (pytest, asyncio_mode = "auto", class-grouped), and pass ruff check at
the repo's line-length = 100, target-version = py311.

Stacking

This branch is stacked on PR 1 (the typed ProtocolStateMachine and
IdempotencyLedger slice), because the detector imports ProtocolStateMachine and
ProtocolStore from that PR. The branch contains PR 1's three commits plus one new
commit on top (Wire deterministic protocol-stall detection into the Watchdog).
Please merge PR 1 first; once it lands on main, this PR's diff against main is the
single new commit. Happy to rebase onto main after PR 1 merges so the diff shows
only the Watchdog wiring.
```

---

## Local verification (real output, this run)

The new commit sits on top of the PR 1 branch; the branch is 4 commits ahead of
`origin/main` (`5825f9f`) and 0 behind. Three of those commits are PR 1; the
fourth is this PR. After PR 1 merges, rebase onto the updated main so this PR is
a single commit.

```
$ py -3.14 -m pytest tests/test_protocol_watch.py tests/test_watchdog.py \
                     tests/test_protocol_state.py tests/test_idempotency.py \
                     tests/test_watchdog_probe.py -q
96 passed, 1 warning in 0.61s

$ py -3.14 -m ruff check src/codeband/orchestration/protocol_watch.py \
                         src/codeband/agents/watchdog.py \
                         tests/test_protocol_watch.py tests/test_watchdog.py
All checks passed!
```

The one warning is a pre-existing Pydantic-v1-on-Python-3.14 notice from the Band
SDK (`thenvoi_rest`), unrelated to this change.

Zero-regression check, same machine: the full `pytest` run on `main` and on this
branch produced an identical set of pre-existing failures and collection errors
(the Windows-only `fcntl` import in `memory/local_store.py` blocks four memory
test files from collecting, and a handful of modules that transitively import it
fail the same way on both branches). On `main`: 426 passed, 43 failed, 55 errors.
On this branch with the same command: 470 passed, same 43 failed, same 55 errors.
The 44 added passes are this PR's and PR 1's tests; this branch adds zero new
failures. On a Linux CI runner (where `fcntl` exists and the Band SDK is present)
the full suite is expected to be green, the same claim PR 1 makes.

Do not claim "passes their CI": their only GitHub Actions workflow is a tag-driven
PyPI publish (`.github/workflows/publish.yml`); there is no PR test CI. The
accurate claim is "passes the contributor gate their README documents (pytest,
ruff), verified locally."

---

## What is wired vs left as a follow-up (honest scope)

- Wired, real, and tested: a deterministic stall detector that reads the actual
  state envelopes through the actual Watchdog memory backend and is a method on
  the real `WatchdogDaemon` class. This is not a standalone helper bolted on the
  side; it is on the daemon and uses its injected memory store.
- Deliberately NOT wired yet: the timestamp patrol (`_patrol`) does not call the
  detector. We kept the patrol untouched so the existing nudge/escalate behavior
  and its ~30 regression tests stay byte-for-byte green, and so the new detector
  is reviewable in isolation. Making `_patrol` act on the detector's output is
  the clearly-named follow-up.

Why this path and not a direct edit to `_patrol`: the patrol is one large async
method pinned by a large regression suite that asserts exact nudge and escalate
timing. Threading acknowledgment state through that loop in the same PR would be
a behavior-changing edit with real risk of breaking those tests. The additive
detector delivers the roadmap's deterministic signal now, on the real class,
with zero behavior change, and leaves the (smaller, isolated) patrol-integration
change to its own review. This is the same additive discipline as PR 1.

---

## Human steps remaining (GitHub actions an agent must not take)

1. Land PR 1 (`deadline-protocol-state-machine`) first. This PR stacks on it.
2. After PR 1 merges to `thenvoi/codeband:main`:
   `git -C c:\yash\band\research\repos\codeband fetch origin main` then
   `git rebase origin/main` on `deadline-watchdog-deterministic-stall`. The
   three PR 1 commits drop out (they are now in main) and the branch becomes a
   single commit: the Watchdog wiring.
3. Push the branch to your fork:
   `git push fork deadline-watchdog-deterministic-stall`.
   (Fork `thenvoi/codeband` first on GitHub if you have not.)
4. Open the PR against `thenvoi/codeband:main` from your fork's branch. Paste the
   Title and Body above. Link PR 1 in the description so reviewers see the stack.
