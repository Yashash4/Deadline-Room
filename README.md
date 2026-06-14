# Deadline Room

**The second a bank gets breached, four government clocks start. Deadline Room runs the filing teams as agents racing those clocks through Band, while a deterministic referee refuses any handoff that breaks the rules.**

<!-- At submission, when the repo is public, swap the static CI badge below for the
     live workflow badge: ![ci](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg) -->
![ci](https://img.shields.io/badge/ci-pytest%20%2B%20ruff%20%2B%20hygiene-3fd07f)
![tests](https://img.shields.io/badge/tests-245%20passing-3fd07f)
![warden](https://img.shields.io/badge/Warden-deterministic%20%2F%20no%20LLM-4da3ff)
![replay](https://img.shields.io/badge/replay-byte--identical-ffb547)
![license](https://img.shields.io/badge/license-MIT-8b9bb4)

---

## The problem (and the dollar number)

When a bank is breached, it does not file one report. It files several, to several governments, each on its own statutory clock, each in a different format:

| Regime | Authority | Clock |
|---|---|---|
| NIS2 | EU national competent authority | early warning within 24h, full notification within 72h |
| DORA | EU financial regulator | major-incident follow-up within 72h, separate format |
| SEC Item 1.05 | US, EDGAR | material disclosure within 4 business days |
| UK ICO (GDPR Art. 33) | UK | within 72h |

Miss one and the exposure is real: NIS2 penalties reach **EUR 10 million or 2% of global turnover**, and DORA penalties stack on top. A tested incident-response plan cuts average breach cost by **USD 2.66 million** (IBM Cost of a Data Breach). These are laws with fine dates, not nice-to-haves.

The hard part is not writing any one report. It is filing four that **agree with each other**, on time, while the facts are still changing under you, with several teams working in parallel and no shared source of truth. Today that is humans in a war room cross-checking spreadsheets. One transposed start time across two filings is a regulatory inconsistency.

> Without this: four teams, four versions of the truth. With it: one consistent filing set, on time.

## The 5-second pitch

A multi-agent regulated breach-reporting war room on [Band](https://band.ai). LLM drafter agents race the statutory clocks; a deterministic, no-LLM **Deadline Warden** holds the clocks, enforces typed handoffs, blocks any two filings that contradict each other, recovers exactly-once when an agent is killed mid-flight, and replays the whole run byte for byte.

**The dinner sentence:** It is the system where, the second a bank gets breached, four government clocks start and four agent teams race to file four different reports in parallel, a deterministic referee holds the clocks and refuses any handoff that breaks the protocol, and even when you kill an agent live on stage the books still come out exactly once and no two filings are allowed to contradict each other.

---

## What you can run in 2 minutes

Every command below was run on this repo against live Band and live Featherless. The output is pasted verbatim, trimmed only for length where marked. Clone, install, set your keys (see [Quickstart](#quickstart)), and reproduce.

| What | Command | What you see |
|---|---|---|
| The property suite | `py -m pytest tests/ -q` | `245 passed` |
| Break the evidence yourself | `py scripts/tamper_test.py` | flip one field, the sealed hash, the chain head, AND the signature all break |
| Verify the Warden's signature | `py scripts/verify_signature.py` | VALID, signed by the Warden's key (public key ships in the repo) |
| A clean incident, end to end | `py floor/run_floor.py` | Examiner Packet, diff GREEN, replay True |
| The contradiction veto | `py floor/run_floor.py --inject-contradiction` | the red BLOCKED block, then re-run GREEN |
| Exactly-once under a live kill | `py floor/run_floor.py --chaos` | the duplicate dropped, filing lands once |
| Transparent deliberation on an amendment | `py floor/run_floor.py --amendment` | two drafters reconcile, then re-release |
| The hosted demo viewer | `cd web && py -m http.server 8000` | four scenarios, in-browser hash verify |

### 1. The tests are real and green

```
$ py -m pytest tests/ -q
........................................................................ [ 29%]
........................................................................ [ 58%]
........................................................................ [ 88%]
.............................                                            [100%]
245 passed in 1.88s
```

### 2. A clean incident: four clocks, the Examiner Packet, byte-identical replay

```
$ py floor/run_floor.py
=== Deadline Room floor run (LIVE Band + Featherless) mode=normal provider=dev ===

[1] Warden identity:  2a495c04-bc1e-429d-8a73-a75f827e55b6
    NIS2 Drafter:  3aa52157-... (featherless:deepseek-ai/DeepSeek-V3.2)
    SEC Drafter:   e7c1a638-... (featherless:deepseek-ai/DeepSeek-V3-0324)
    DORA Drafter:  fedbb8d4-... (featherless:Qwen/Qwen2.5-72B-Instruct)
[2] Warden created incident room e5b0c51d-... and recruited Triage + 3 drafters
[3] Started 4 statutory clocks at T0 2026-06-16T02:14:00+00:00
[4] Triage posted the fact-record, @mentioned all drafters (msg e4548623-...)
[5.nis2] NIS2 Drafter saw the mention; calling Featherless ...
    NIS2 Drafter drafted 866 chars, posted back @mention Warden (msg 4aace8a6-...)
[6.nis2] Warden parsed nis2 claims, recorded DRAFT_POSTED
    ... (SEC and DORA drafters do the same) ...
[7] Contradiction diff: GREEN (no conflicts across 3 filings)
[8] Warden opened signoff; human released; clocks stopped
[9] Replay byte-identical: True (sha 16dbef4ab1f5...)
[10] Examiner Packet written: floor/out/examiner-packet.html
```

The named, judge-legible output artifact is the **Examiner Packet** (`floor/out/examiner-packet.html` and `.json`): the filings, the handoff trace, the state transitions, the per-chat message lifecycle, the clocks, the contradiction diff, the chaos record, the breached-clock list, and the replay hash, all in one self-contained file that carries Band's own room and message ids.

### 3. The contradiction veto: submission blocked until the filings agree

One drafter is fed a perturbed incident start time. The Warden's diff catches it across filings and refuses signoff. This is a deterministic check over canonicalized facts, not a model opinion.

```
$ py floor/run_floor.py --inject-contradiction
...
[7] Contradiction diff: BLOCKED. The Warden refused signoff.
        RED: NIS2 says incident_start_utc=2026-06-16T02:14:00+00:00; SEC says
             incident_start_utc=2026-06-16T02:41:00+00:00. Submission blocked.
        RED: SEC says incident_start_utc=2026-06-16T02:41:00+00:00; DORA says
             incident_start_utc=2026-06-16T02:14:00+00:00. Submission blocked.
[7b] Fact corrected on SEC; diff re-run GREEN; signoff unblocked.
[8] Warden opened signoff; human released; clocks stopped
[9] Replay byte-identical: True (sha 76315fe27ad6...)
```

Timezone equivalence never trips a false contradiction, and the same wall-clock in a different zone never slips through. The veto is binding: the human release cannot click past a red diff.

### 4. Exactly-once under a live agent kill

The SEC drafter is killed at the worst possible moment: after it posts its filing but before it acknowledges. At-least-once delivery would re-process that message as a second filing. The idempotency ledger drops the duplicate.

```
$ py floor/run_floor.py --chaos
...
    SEC Drafter drafted 1017 chars, posted back @mention Warden (msg 5ad67597-...)
    [CHAOS] SEC Drafter killed at position B (posted, not yet acked); /next will re-serve the mention
    SEC Drafter restarting, re-draining /next ...
    SEC Drafter recovered: duplicate dropped (ledger duplicate_dropped), no double draft
[6.sec] Warden parsed sec claims, recorded DRAFT_POSTED
[7] Contradiction diff: GREEN (no conflicts across 3 filings)
[9] Replay byte-identical: True (sha 9a85a5d4f47b...)
```

### 5. The facts change mid-incident: transparent deliberation with an audit trail

After release, forensics revise the records-affected figure upward. The two released filings reopen into an amending state. The SEC and NIS2 drafters reconcile one shared figure through Band over hash-linked propose, counter, and concur envelopes (bounded rounds). The Warden holds the amended diff blocked until they concur, then re-releases.

```
$ py floor/run_floor.py --amendment
...
[7] Contradiction diff: GREEN (no conflicts across 3 filings)
[8] Warden opened signoff; human released; clocks stopped
[A1] Triage posted the fact amendment 48,211 -> 2,100,000; SEC and NIS2 branches reopened to amending (msg 0d3fe0d8-...)
[A2] Warden guard BLOCKED the amendment before reconciliation: no concur envelope for amend round 1
[A3] SEC Drafter @mentioned NIS2 Drafter proposing how to characterize 2,100,000 (msg ecb6bcde-...)
[A4] NIS2 Drafter @mentioned SEC Drafter back, CONCUR (hash-linked to the proposal, msg d22e1c1c-...)
[A5] Both branches submitted their amendments at the reconciled figure 2,100,000
[A6] Amended diff GREEN only after concurrence; both amendments signed and released
[9] Replay byte-identical: True (sha c24488d6499d...)
```

The Warden never reasons here. It holds the amended diff blocked because no concur envelope exists for the round (a structural check), and admits each envelope by verifying its hash-link, nothing more. The drafters author the characterizations; deterministic Python owns the gate.

### 6. The hosted demo viewer (no API keys)

```
$ cd web && py -m http.server 8000
# open http://localhost:8000
```

Four selectable scenarios (normal, contradiction, chaos, amendment), each a captured run with its own run log. The page recomputes the SHA-256 of the bundled run log in the browser and checks it against the hash the Warden recorded, so the byte-identical replay claim is verifiable on the page, with no server. This is forensic playback of a captured live Band run, not a simulator.

---

## Architecture

Six agents in one Band room, plus a deterministic referee:

```
                         Band room (the incident war room)
   ┌──────────┐   @mention   ┌──────────────────────────────────────┐
   │  Triage  │ ───────────► │  NIS2  DORA  SEC  UK-ICO   drafters   │
   │ (facts)  │              │  (one regime each, racing its clock)  │
   └────┬─────┘              └──────────────────┬───────────────────┘
        │  fact-record                          │ filings, @mention Warden
        ▼                                       ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                   Deadline Warden  (pure Python, NO LLM)         │
   │  typed state machine  ·  statutory clocks  ·  contradiction diff │
   │  exactly-once ledger  ·  byte-identical replay  ·  binding veto  │
   └─────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                          The Examiner Packet
```

- The **drafter agents** are LLMs on different model families and providers, on purpose. They draft filing content and rationale only.
- The **Deadline Warden** (`warden/`) is the deterministic core. Anything that gates, blocks, releases, counts, or clocks is pure Python, replayable byte for byte. It never calls an LLM. It is the source of truth for where every handoff is.
- **Everything flows through Band:** agent identity, the room, the @mention-routed handoffs, the per-chat message lifecycle, peer discovery. Remove Band and the workflow breaks, there is no other transport and no shared state.

The split is deliberate. LLMs are good at drafting regulator-facing prose; they are unreliable bookkeepers of their own protocol state under concurrency and context truncation. So the model drafts, and a typed table plus a dedup ledger decide what is allowed and what has already happened.

## How Band is used

Band is the spine, not a leaf node. The verified API surface this build relies on:

- **Rooms** are the incident war room. The Warden creates the room and recruits the agents into it.
- **@mention routing** carries every typed handoff. `message_created` events are mention-filtered, so every protocol envelope @mentions its recipient, and every filing @mentions the Warden.
- **Per-chat message lifecycle** (`GET /agent/chats/{cid}/messages/next` drains the oldest unprocessed mentioned message; `delivered -> processing -> processed`) plus a read-then-act dedup guard owned by the poster give exactly-once semantics. We never rely on re-delivery for correctness.
- **Context rehydration** (`GET /agent/chats/{cid}/context`) lets a restarted agent rebuild its position from the room.
- **Peer discovery** (`GET /agent/peers?not_in_chat={cid}`) recruits drafters into the room, including the UK regime recruited at runtime.
- One WebSocket connection per agent id (last wins), 30-second heartbeats: a container-per-agent deployment shape.

The coordination trace, the room id, and the message ids all appear **inside the Examiner Packet**, not just in the build logs. Band's involvement is visible in the deliverable itself.

## What makes it different

Plenty of teams will ship a state machine. The separator is what happens under stress, on camera:

- **Exactly-once under a live kill.** Kill an agent after it posts and before it acks; the filing still lands exactly once.
- **Byte-identical replay.** The whole run reproduces from its append-only log, hash for hash, and the demo page re-verifies that hash in the browser.
- **Signed provenance.** The Warden signs the run-log bytes with a detached Ed25519 signature, so integrity (the hash) becomes authenticity (signed by this key). `py scripts/verify_signature.py` checks it against the committed public key; one flipped byte makes it INVALID, as `py scripts/tamper_test.py` shows alongside the hash and chain breaks. Honest caveat: the private key shipped here is a demonstration key, committed for reproducibility, so it proves "signed by whoever holds this demo key", not HSM/KMS-grade secrecy. The signature mechanism is fully real; the key's secrecy is not production-grade (HSM/KMS, rotation, and RFC-3161 timestamping are Phase 2). See `warden/keys/README.md`.
- **A binding contradiction veto.** No two filings may disagree on a load-bearing fact; the human release physically cannot proceed past a red diff.

## Partner usage

The provider split wins both partner stories while respecting each platform's real constraints. Model ids are the ones verified live on the keys.

**AI/ML API** (multi-model gateway, OpenAI-compatible, `https://api.aimlapi.com/v1`) runs the **parallel racing drafters**, a different named model per role with on-camera rationale:

| Role | Model |
|---|---|
| Triage | `gemini-3.5-flash` |
| NIS2 Drafter | `claude-sonnet-4-20250514` |
| DORA Drafter | `gpt-5-chat-latest` |
| SEC Drafter | `claude-opus-4-1-20250805` |

**Featherless** (40k+ open models, flat-rate serverless) runs **two real authority roles on big open models**, the roles that do not need to fire simultaneously, the data-sovereignty story (a bank can self-host the model that makes the highest-stakes calls):

| Role | Model |
|---|---|
| Materiality | `deepseek-ai/DeepSeek-V3.2` |
| UK ICO Drafter | `MiniMaxAI/MiniMax-M2.7` |

Both partners are load-bearing: cut either and a real agent role goes dark. The dev provider set (`--provider dev`, the default) runs every role on Featherless flat-rate for zero-cost reproduction; the hero recorded run uses the split above (`--provider prod`). The Warden uses no LLM in any configuration.

## Contributing back: the Codeband PR

The deterministic core is not just ours to keep. We extracted the two primitives that matter most for an open agent network and prepared them as an upstream pull request to [Codeband](https://github.com/thenvoi/codeband), Band's own coding-agent reference: a typed **ProtocolStateMachine** and an **IdempotencyLedger** with acknowledgment states, scoped first to its Code Review protocol, additive, with 32 new tests. See [`contrib/codeband-pr.md`](contrib/codeband-pr.md).

This is the **Internet of Agents** thesis in concrete code: an open network of autonomous agents needs trust primitives that do not depend on any one agent behaving. A coding agent cannot reliably enforce its own protocol state, the same context truncation and self-preference that make same-model review weak also make a model an unreliable bookkeeper of its own progress. Moving protocol state and exactly-once into deterministic Python is the same move Codeband already makes with cross-model review, applied to coordination.

## Enterprise Fit

Built for the question "would my org actually run this":

- **SIEM hook.** The incident room is opened by the Warden from a structured fact-record; in production that record is the payload of a detection alert, so a SIEM or SOAR event triggers the war room directly.
- **RBAC.** Authority is enforced in code, not convention: drafters cannot release, only the Warden opens signoff, only a human closes it. The stretch path adds a two-key release gate (compliance officer and general counsel).
- **Exportable audit log.** Every run is an append-only JSONL log plus a self-contained Examiner Packet that carries the full handoff trace, state transitions, message lifecycle, and the replay hash. It is the record an examiner of record would ask for, and it replays byte for byte.

## Agent Safety

What the agents are architecturally **prevented** from doing, by construction, not by prompt:

- **Illegal handoffs cannot execute.** The state machine is a typed transition table; a move not in the table is rejected before any downstream message would be routed. Out-of-order or wrong-authority handoffs fail closed.
- **No agent can release on its own.** A drafter cannot open or close signoff; the authority table forbids it.
- **No agent can push a contradiction through.** The contradiction diff is a Warden gate, not a drafter courtesy; a red diff blocks signoff outright.
- **No LLM is in the control path.** Nothing an agent says can talk the Warden into an illegal move, because the Warden does not reason, it checks a table. The model drafts; deterministic Python decides.

## Honest limitations

- The filings are recognizable, correctly structured drafts built from public templates. They are not legally perfect filings and we never claim "court-admissible" or "legally filed".
- The demo's contradiction (start time 02:14 vs 02:41) is an **injected fault**, shown deliberately. So are the chaos kill and the amendment conflict. The three unhappy paths are demonstrated on purpose, not accidents.
- Featherless runs one big (70B+) open model at a time on our plan, so the hero open-model roles are sequenced rather than fired in parallel; the parallel racing drafters run on the AI/ML API gateway instead. Context is capped at 32k, which is comfortable for these small incident payloads.

## Quickstart

```
git clone <repo-url>
cd code
pip install -r requirements.txt

# copy the env template and fill in your keys
cp .env.example .env
#   BAND_API_KEY=...          (live Band)
#   FEATHERLESS_API_KEY=...   (open-model roles; dev provider uses only this)
#   AIML_API_KEY=...          (gateway roles; only needed for --provider prod)

# verify the deterministic core (no keys needed)
py -m pytest tests/ -q

# run a live incident (needs BAND_API_KEY + FEATHERLESS_API_KEY)
py floor/run_floor.py

# preview the hosted replay viewer (no keys needed)
cd web && py -m http.server 8000   # then open http://localhost:8000
```

The 245-test deterministic core needs nothing but `pytest` and the standard library. Only the live floor run needs API keys.

### One command

On Linux, macOS, or any machine with `make`:

```
make test      # the 245-test suite (no keys, no network)
make lint      # ruff over the repository
make verify    # the tamper receipt: break the evidence, watch the seal fail
make demo      # a live incident (needs BAND_API_KEY + FEATHERLESS_API_KEY)
make check     # test + lint + the dash/attribution hygiene gate (the CI gate)
```

On Windows, where `make` is often absent, run the same steps directly (the launcher is `py`):

```
py -m pytest tests/ -q        # = make test
py -m ruff check .            # = make lint
py scripts/tamper_test.py     # = make verify
py floor/run_floor.py         # = make demo
py scripts/hygiene_gate.py    # the dash/attribution hygiene gate
```

Or with Docker, no local Python at all (the default command runs the suite):

```
docker build -t deadline-room .
docker run --rm deadline-room
```

Every push and pull request runs the same three gates in GitHub Actions (`.github/workflows/ci.yml`): the suite, ruff, and the hygiene gate that fails the build on any stray em/en dash or AI-attribution trailer.

## Demo and video

- Demo application (hosted replay viewer): _URL to be added at submission._
- Video presentation: _link to be added at submission._

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Yashash S S.
