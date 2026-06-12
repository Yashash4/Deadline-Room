# CLAUDE.md: Deadline Room repo

Multi-agent regulated breach-reporting war room on the Band platform (band.ai). A deterministic no-LLM **Deadline Warden** enforces typed protocol handoffs, exactly-once semantics, byte-identical replay, statutory clocks, and a cross-filing contradiction veto over Band rooms where LLM drafter agents (different frameworks, different models) race regulatory deadlines.

The build-ready spec lives OUTSIDE this repo at `../research/specs/design-spec-v2.md` (architecture, demo beats, spike plan, cut ladder). The locked scope: `../docs/01-PROJECT.md`. Do not invent scope; follow the floor-then-stretch ladder.

## Commands

- Run tests: `py -m pytest tests/ -q` (must stay green; 32 baseline tests)
- Partner API spike: `py spikes/partner_api_spike.py` (needs AIML_API_KEY, FEATHERLESS_API_KEY env vars)
- Band live spikes: `py spikes/band_spikes.py` (needs BAND_API_KEY; run before any live binding work)

## Layout

- `warden/`: the deterministic core (NO LLM CALLS EVER in this package). state_machine.py (typed transitions, illegal moves rejected), ledger.py (exactly-once dedup), diff.py (contradiction diff, UTC-canonicalized), replay.py (byte-identical replay from JSONL run log), clocks.py (statutory clocks, US-federal-holiday-aware business days), negotiation.py (amendment negotiation guard, hash-linked envelopes), fake_band.py (in-process Band for tests), simulate.py (fixture-driven incident simulation).
- `tests/`: property tests. Judges run these; they are part of the product.
- `spikes/`: API verification scripts. Results inform design; never assume undocumented behavior.
- `shell/`: band_agent_shell.py, the reference pattern for binding agents to live Band (connect, drain /messages/next, rehydrate /context, lifecycle, heartbeat). Verify against spike results before trusting.

## Hard conventions

1. **No em-dashes or en-dashes anywhere** (code, comments, commits, docs). Use commas, colons, parentheses.
2. **The Warden stays deterministic.** Any logic that gates, blocks, releases, or counts must be pure Python, replayable byte for byte. LLMs draft content and rationale only.
3. **No TODO/FIXME markers. No AI attribution in code.** Errors surface structurally, never swallowed.
4. **Every new behavior ships with a test.** The suite must pass before any commit.
5. Band API facts: message_created WebSocket events are @MENTION-FILTERED (every protocol envelope must @mention the Warden); /agent/peers supports only not_in_chat filtering (role matching is token-match in our code); one WebSocket connection per agent ID, last connection wins (container-per-agent deployment); 30-second heartbeats on raw WebSocket clients; exactly-once uses a read-then-act dedup guard owned by the poster, never reliance on re-delivery.
6. Commits: imperative, plain, no dashes; this repo goes public at submission, write everything as if a judge reads it.
