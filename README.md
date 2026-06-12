# Deadline Room — Day-1 Deterministic Core (Warden)

The never-cut core of M1, built pure-Python against a fake in-memory Band,
per the Day-1 spike plan. **19/19 property tests green** before a single
line of LLM or real-API code exists.

## What's here

```
warden/
  state_machine.py   Typed protocol state machine. Transition table is a
                     plain dict readable in 30 seconds (J4's probe). Includes
                     the RBAC authority mirror (drafters can't release,
                     only the Warden opens signoff, only humans close it).
  clocks.py          Statutory clock engine driven by real timestamps.
                     SEC clock computes REAL business days — skips weekends
                     and US federal holidays. Juneteenth (Fri Jun 19, 2026)
                     falls inside hackathon week: a naive now+96h clock is
                     wrong by 3+ days for our demo incident. Show this on camera.
  ledger.py          IdempotencyLedger — exactly-once layer (G2 fold-in).
                     Handles crash positions A and B.
  diff.py            Contradiction diff over canonicalized fact claims.
                     UTC normalization + attacker alias table, so timezone
                     equivalence is never a false contradiction and
                     same-wallclock-different-zone never slips through.
  replay.py          Append-only JSONL run log + byte-for-byte replay.
  fake_band.py       In-memory Band: lifecycle (delivered→processing→
                     processed/failed), attempt auto-increment, chaos kills.
  simulate.py        Full incident harness with injectable kill schedules
                     and an optional injected contradiction.

tests/
  test_exactly_once.py           50 randomized-kill runs, invariant filings,
                                 position-B duplicate dropped.
  test_illegal_transition.py     Out-of-order handoffs + authority violations
                                 rejected before any message would be sent.
  test_replay_byte_identical.py  Byte-identical replay under chaos AND
                                 contradiction; tz-canonicalization; SEC
                                 business-day clock.
```

## Run

```
pip install pytest
python3 -m pytest tests/ -v
```

## Day-2 binding notes

- `fake_band.py` encodes our assumptions for spike items 1–3 (lifecycle
  semantics, /messages/next drain, crash-position-B re-delivery). Validate
  each against the live API on June 13, then swap FakeBand for a thin client
  with the same four methods. The Warden never imports anything else.
- Real LLM drafters plug in behind the same dedup-key + claims envelope the
  stub uses in `simulate.py`. The Warden cannot tell the difference — that
  is the design.
- The two Codeband PR commits extract from here: `state_machine.py` →
  ProtocolStateMachine (roadmap #1), `ledger.py` → IdempotencyLedger + ack
  states (roadmap #4).

## v2 extension (A1 + spec-named test files) — June 12, post-spec-v2

- `warden/negotiation.py` — the A1 amendment-negotiation guard and
  NegotiationEnvelope schema (spec section 2.11). Hash-linked propose/
  counter/concur chain, MAX_ROUNDS=3 bound, can_submit_amendment and
  can_pass_diff gates. Purely structural; the Warden stays no-LLM.
- `state_machine.py` — RELEASED is now REOPENABLE (not terminal):
  (RELEASED, FACT_AMENDED) -> AMENDING -> DRAFT_SUBMITTED -> ... -> RELEASED.
  Only Triage may emit FACT_AMENDED (authority table). A released branch
  rejects every other event.
- `simulate.py` — the full hour-6 amendment beat: revision posted, premature
  SEC submission blocked by the guard, propose/(counter)/concur exchange,
  amended 8-K + NIS2 intermediate report, value-match gate, amendment diff,
  re-release. Baseline records_affected aligned to spec (48,000 -> 2,100,000).
- `tests/test_amendment_cycle.py` (A1) and `tests/test_holiday_clock.py` (A3)
  match the spec section-10 file names exactly.

**32/32 tests green**, including: amendment-is-noop-until-concur, bounded
counter round (propose -> counter -> propose -> concur), value-mismatch
blocks the diff, byte-identical replay of an amendment run, and the combined
stress run (chaos kills + injected contradiction + amendment in one incident,
still exactly-once and byte-identical on replay).

### Day-2 binding note for the negotiation beat
On live Band, the propose/counter/concur exchanges in `simulate.py` are
replaced by real LLM turns: the SEC Drafter's shell posts the envelope as a
room message @mentioning the NIS2 Drafter; the NIS2 `handle()` produces the
concur/counter; the Warden validates each envelope through the SAME
NegotiationGuard. The guard, the schema, the bound, and the gates do not
change — only who authors the characterization strings.
