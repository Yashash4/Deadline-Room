# Deadline Room: slide deck

Twelve slides for the lablab "Band of Agents" submission. Each slide is a
title, three to five bullets, and a speaker note. Lead with the regulatory
clock, never the architecture. The separator leads with exactly-once under
live kill, byte-identical replay, and the contradiction veto.

---

## Slide 1: title

**Deadline Room**

- Multi-agent regulated breach-reporting war room, built on Band.
- The second a bank gets breached, four government clocks start.
- Four agent teams race to file four different reports in parallel.
- A deterministic referee holds the clocks and refuses any unsafe handoff.
- 133 property tests passing, byte-identical replay, exactly-once under live kill.

Speaker note: open on the cover, the four countdown clocks already ticking and
the red VETO banner visible. Say the dinner sentence in full before anything
else. Do not explain the architecture yet, sell the room first.

---

## Slide 2: the felt need (the forcing function)

**Four governments, four clocks, one breach**

- NIS2 early warning in 24 hours, full notification in 72 (EU).
- DORA major-incident follow-up in 72 hours, separate format (EU financial).
- SEC Item 1.05 material disclosure in 4 business days on EDGAR (US).
- UK ICO under GDPR Article 33 in 72 hours, recruited at runtime.
- Miss one and the fine reaches EUR 10 million or 2% of global turnover (NIS2), DORA penalties stack on top.

Speaker note: the dollar number lands here in the first minute. The pain is not
invented, it is statutory and dated. A tested incident-response plan cuts breach
cost by USD 2.66 million (IBM Cost of a Data Breach). This is a law with a fine,
not a nice-to-have. That forcing function is what the winners we studied all had.

---

## Slide 3: who is in the room

**Six agents, honestly heterogeneous**

- Triage: classifies the incident and owns the fact-record (the source of truth).
- NIS2, DORA, SEC, UK ICO drafters: one regime each, racing its own clock.
- The Deadline Warden: a deterministic, no-LLM referee that gates every handoff.
- Drafters run on different model families and providers, on purpose.
- Cross-model independence is the point: no single model is the bookkeeper.

Speaker note: name the split out loud, judge Brizhatiuk (AI/ML API) and the two
Featherless judges are listening for meaningful, per-role model use. The Warden
is not an agent that "tries hard", it physically cannot make an illegal move.

---

## Slide 4: the demo arc

**Watch it run, on live Band**

- Triage posts the fact-record and @mentions every drafter through a Band room.
- Each drafter drafts its filing and posts back, the Warden records each handoff.
- The contradiction diff runs across all four filings before any signoff.
- A human releases, the four clocks stop, the Examiner Packet seals.
- Then we break it on purpose: contradiction, live kill, mid-incident amendment.

Speaker note: the Band room log is on screen the whole time. Coordination is
visible: mentions route work, the Warden gates, state advances. This is not a
storyboard, it is a real run with real Band message ids and real model output.

---

## Slide 5: unhappy path 1, the contradiction veto

**No two filings may contradict each other**

- One drafter reports the incident start as 02:41, the others say 02:14.
- The Warden's diff turns red and refuses signoff: submission blocked.
- This is a deterministic check over canonicalized facts, not a model opinion.
- The fact is corrected, the diff re-runs green, signoff unblocks.
- Without this: four teams, four versions of the truth. With it: one consistent filing set, on time.

Speaker note: say plainly that the contradiction is an injected fault, we show it
deliberately (Jaloszynski, ex-Palantir, rewards a shown unhappy path). Timezone
equivalence never trips a false contradiction, and same-wallclock-different-zone
never slips through. The veto is binding, the human cannot click past it.

---

## Slide 6: unhappy path 2, exactly-once under a live kill

**Kill an agent on stage, the books still balance**

- A drafter is killed after it posts but before it acknowledges.
- At-least-once delivery would re-process that message as a second filing.
- The idempotency ledger is a read-then-act dedup guard owned by the poster.
- On restart the duplicate is dropped, the filing lands exactly once.
- Byte-identical replay reproduces the whole run from its log, hash for hash.

Speaker note: this is the separator, lead with it. Quote the green test run on
screen (judges do not read READMEs). The replay hash is recomputed in the browser
on the demo page, so the claim is checkable, not asserted.

---

## Slide 7: unhappy path 3, transparent deliberation with an audit trail

**The facts change mid-incident**

- After release, forensics revise records affected from 48,211 to 2.1 million.
- The two released branches reopen into an amending state.
- The SEC and NIS2 drafters reconcile one shared figure through Band.
- They exchange hash-linked propose, counter, and concur envelopes (bounded rounds).
- The Warden holds the amended diff blocked until they concur, then re-releases.

Speaker note: call this transparent deliberation with an audit trail, never
"negotiation", compliance-minded judges hesitate at that word. Every envelope is
hash-linked and replayable. The drafters author the words, the Warden owns the gate.

---

## Slide 8: architecture, Band is the spine

**Remove Band and the workflow breaks**

- Band rooms are the incident war room, every agent is a real Band participant.
- @mention routing carries each typed handoff, the Warden is always mentioned.
- Per-chat message lifecycle plus a dedup guard give exactly-once delivery.
- Peer discovery recruits drafters into the room (and the UK regime at runtime).
- The Warden is pure Python: it gates, clocks, counts, and vetoes, never an LLM.

Speaker note: stress that Band is load-bearing, not a leaf node. The coordination
trace, the rooms, the handoffs all appear inside the Examiner Packet itself, not
just in the build process. The verified API surface: rooms, messages/next drain,
context rehydrate, peers with not_in_chat filtering, one socket per agent.

---

## Slide 9: the output artifact

**The Examiner Packet**

- One self-contained, judge-legible artifact per incident.
- Filings, handoff trace, state transitions, message lifecycle, clocks, diff.
- The chaos record, the breached-clock list, and the replay hash, all inside.
- It carries Band's room and message ids, so the coordination is in the deliverable.
- A hosted replay viewer plays any captured run and re-verifies the hash client-side.

Speaker note: the artifact is named, visual, and self-contained, the pattern both
retrievable BOB winners used. A non-technical judge can read it top to bottom. The
demo URL is the viewer, zero API keys needed, forensic playback of a captured run.

---

## Slide 10: judging criteria, answered

**Why this scores on all four**

- Application of technology: Band is the spine, remove it and it breaks, real discovery and state-across-failure.
- Presentation: opens on the business problem, the room log is on screen, clean repo, one-command green tests.
- Business value: named industry (regulated finance), named pain (EUR 10M fines), multi-agent is load-bearing.
- Originality: an unexpected domain, a designed topology (write vs read authority, a binding veto), intentional partner choices.

Speaker note: one bullet per official criterion, said explicitly. The panel skews
enterprise engineers and managers (Amazon, Meta, Wayfair, Workday, Oracle, Deloitte):
"would my org run this" is the median lens, and the war-room framing answers it.

---

## Slide 11: partners and the contribute-back

**Meaningful, not decorative**

- AI/ML API: the parallel racing drafters, a different named model per role (Gemini, Claude, GPT) through one gateway.
- Featherless: two real authority roles on big open models (Materiality and UK ICO), the data-sovereignty story.
- Both are load-bearing roles, documented in the README with real model ids.
- Codeband PR: we contribute a typed protocol state machine and idempotency ledger upstream.
- Framed in the Internet of Agents thesis: a coding agent cannot reliably bookkeep its own protocol state.

Speaker note: show the Codeband PR on screen for fifteen seconds. Reference Ofer
Mendelevitch's "your coding agent can't review its own work" thesis, he is the
Band voice on the panel at founder level, the PR is the signal for him.

---

## Slide 12: Phase 2 roadmap

**Where it goes after the hackathon**

- More jurisdictions and regimes, each a drop-in drafter behind the same envelope.
- SIEM ingestion: trigger the room straight from a detection alert.
- RBAC and a two-key human release gate (compliance officer and general counsel).
- Exportable, signed audit log for the examiner of record.
- Parked concepts live in POST_HACKATHON.md, one line each, zero scope creep before submission.

Speaker note: close by returning to the dinner sentence. The enterprise-fit work
(SIEM hook, RBAC, exportable audit) is the path to a paying customer, that is the
business-value through-line. Land on "one consistent filing set, on time."
