# band-once

Exactly-once delivery for Band agents, as a tiny, reusable library.

Band serves an agent's inbox through a lifecycle cursor: `GET /agent/chats/{id}/messages/next`
returns the oldest not-yet-processed message and **re-serves the same message** on every call
until you mark it `processed` or `failed`. That cursor is correct, but it means a crash anywhere
in the middle of handling a message (before you post, after you post but before you ack, or with
a lost ack on the way back) leads to the same message being delivered again. Handle it naively and
you double-post; guard it wrong and you lose work. There is no reference implementation of getting
this right, so most Band agents either fake the lifecycle or get exactly-once subtly wrong.

`band-once` is that reference implementation, lifted out of a production system and stripped of
every application concern. You supply one `handle()` function; the shell owns the drain, the
`processing`/`processed`/`failed` lifecycle, the post, the read-then-act dedup guard, and bounded
retry on transient HTTP. It ships with a runnable proof and a public conformance check that an LLM
cannot self-certify.

## Install

```
pip install band-once          # once published to PyPI
```

Locally, from this directory:

```
pip install -e .
```

## The shell: write only handle()

```python
from band_once import BandAgentShell, strip_mention_markers

def handle(message: dict, context: list[dict]) -> dict | None:
    body = strip_mention_markers(message["content"])
    # ... do your framework-specific work (LLM call, graph, tool) ...
    return {
        "content": f"echo: {body}",
        "mentions": [peer_uuid],          # Band requires at least one mention
        "dedup_key": f"echo:{message['id']}",  # the natural key of this unit of work
    }

shell = BandAgentShell(api_key=KEY, agent_name="my_agent",
                       dedup_namespace="echo", max_attempts=3)
shell.whoami()
shell.join(chat_id)
shell.run(handle, idle_breaks=5)   # drain -> processing -> handle -> post -> processed
```

`dedup_key` is the natural key of the unit of work (for example
`draft:nis2:inc-8842:round-1`). Before re-posting, the shell reads the room and drops the post if
the key is already present. A crash and re-delivery therefore re-runs the work but never
double-posts. See `examples/echo_agent.py` for a complete agent.

## The proof: a receipt, not a vibe

```
python -m band_once.proof
```

drives a large, seeded space of kill + duplicate schedules (kill before post, kill after post,
lost-ack) through the real `BandAgentShell` dedup guard and the real `IdempotencyLedger`, then
prints:

```
exactly-once held across 10000 schedules: 0 double-posts, 0 lost messages
```

The master seed and the schedule-space size are printed in the output, so anyone re-running the
exact command gets the exact same number. No API keys, no network. Exit code is 0 only when
exactly-once held on every schedule.

## The conformance check: an external prover

Ofer's thesis for Band is that your coding agent cannot review its own work. The same applies to
exactly-once: an agent author should not mark their own homework. `verify_exactly_once` is the
independent grader.

```python
from band_once import verify_exactly_once, clean_echo_agent

result = verify_exactly_once(clean_echo_agent)
assert result.ok           # passes the reference correct agent
print(result.schedules_checked)
```

You hand it an `agent_factory` that builds a fresh agent over a shared `IdempotencyLedger`; it
drives seeded kill + duplicate schedules through that agent and asserts exactly-once on every one.
On a violation it returns a typed `ConformanceResult` naming the **first** schedule that broke the
invariant (its seed and a one-clause reason), the same way `first_broken_index` names the exact
link a hash chain breaks at:

```python
def buggy_factory():
    # records the work BEFORE checking the ledger, so a redelivery double-posts
    def agent(ledger, dedup_key, attempt, ts):
        ...
    return agent

result = verify_exactly_once(buggy_factory)
assert not result.ok
print(result.first_violating_seed, result.reason)
# 20260616 key 'work:k3:job-1:round-1' was ACCEPTED 2 times ...: a double-post
```

The grader never trusts the agent's claim about itself: it re-derives the invariant from the
deliveries and the agent's own dispositions.

## What is in here

| File | What |
|---|---|
| `band_once/shell.py` | `BandAgentShell`: the lifecycle shell. Imports only stdlib + `requests` + the sibling retry helper. |
| `band_once/ledger.py` | `IdempotencyLedger`: one ACCEPTED per natural key, every redelivery dropped. |
| `band_once/retry.py` | Bounded full-jitter exponential backoff on transient HTTP only. |
| `band_once/fake_band.py` | An in-process Band double for the proof and tests (delivered / processing / processed, the three kill positions). |
| `band_once/proof.py` | The kill-storm receipt. `python -m band_once.proof`. |
| `band_once/verify.py` | `verify_exactly_once`, the external prover, and `clean_echo_agent`, the reference correct agent. |
| `examples/echo_agent.py` | A complete agent built on the shell. |
| `BAND_API_FIELD_GUIDE.md` | The verified Band Agent API surface this shell encodes. |

## Verified Band API facts this shell encodes

- Base `https://app.band.ai/api/v1`, auth header `X-API-Key: <agent key>` (not `Authorization: Bearer`).
- `mentions` is required on every message; the mentioned agent must already be a participant; you cannot mention yourself.
- `/messages/next` is per-chat and re-serves the same message until it is marked `processed`/`failed`; it is a cursor, not a destructive pop.
- The lifecycle endpoints are per-chat under the message; `processed`/`failed` must follow `processing`; `failed` carries `{"error": <string>}`.
- Exactly-once is owned by the poster via a read-then-act dedup guard, never by relying on re-delivery.

See `BAND_API_FIELD_GUIDE.md` for the full table.

## License

MIT. See `LICENSE`.
