"""Cross-family model failover for the drafting chokepoint (E5.7 part 1).

When the primary model a role wants is DOWN with a TERMINAL error (a model 404,
a forbidden key, a hard 4xx refusal, an empty completion that never clears), a
production gateway does not abort the filing: it FAILS OVER to the next model in
an ordered preference chain, on a genuinely different model family. This module
walks that chain.

It mirrors floor/retry.py exactly, one level up:

  - retry.py retries the SAME (provider, model) on a TRANSIENT failure (a 429 or
    5xx or a transport hiccup) with bounded backoff. That is a within-model retry.
  - model_fallback.py moves to the NEXT (provider, model) on a TERMINAL failure
    (the model itself is unusable). That is a cross-model failover.

The two compose: each chain entry is attempted with retry's transient backoff
(via the drafter's max_attempts), and only a TERMINAL error advances the chain.
A transient blip is recovered in place by retry; a dead model is stepped over
here.

Out-of-log by construction. Like retry's recovered count, the served_by_model /
fell_back_from record is read from the live FailoverResult at packet time and
rendered into an additive Examiner Packet section; it is NEVER written into the
hashed run-log JSONL, and the chain is only walked when a caller asks for
failover, so a clean single-model run produces the SAME bytes and replay stays
byte-identical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class FailoverAttempt:
    """One model the failover walk tried: the (provider, model) and, when it did
    not serve, the terminal error string that pushed the walk to the next entry."""
    provider: str
    model: str
    error: str = ""  # "" when this entry SERVED; the terminal error otherwise


@dataclass
class FailoverResult:
    """The outcome of a failover walk over an ordered model chain.

    value         the result the serving model returned.
    served_by     the (provider, model) that produced the result.
    fell_back_from the ordered list of (provider, model) entries that failed
                  terminally BEFORE the serving model (empty when the primary
                  served, which is the clean default).
    attempts      every entry the walk touched, in order, with its error (or "").
    """
    value: object
    served_by: tuple[str, str]
    fell_back_from: list[tuple[str, str]] = field(default_factory=list)
    attempts: list[FailoverAttempt] = field(default_factory=list)

    @property
    def did_fail_over(self) -> bool:
        """True iff the primary did NOT serve (at least one terminal fallback)."""
        return bool(self.fell_back_from)

    def as_dict(self) -> dict:
        """The out-of-log record for the packet. Read at packet time, never logged
        into the hashed run-log JSONL."""
        return {
            "served_by_provider": self.served_by[0],
            "served_by_model": self.served_by[1],
            "fell_back_from": [
                {"provider": p, "model": m} for p, m in self.fell_back_from
            ],
            "did_fail_over": self.did_fail_over,
            "attempts": [
                {"provider": a.provider, "model": a.model, "error": a.error}
                for a in self.attempts
            ],
        }


class FailoverExhausted(RuntimeError):
    """Every model in the chain failed terminally. Carries the per-entry errors so
    the failure is reported in full, never swallowed. Raised only when the WHOLE
    chain is down, which is the same end-state a single-model drafter would reach
    (its typed error), just after trying every fallback first."""

    def __init__(self, attempts: list[FailoverAttempt]) -> None:
        self.attempts = attempts
        detail = "; ".join(
            f"{a.provider}:{a.model} -> {a.error}" for a in attempts)
        super().__init__(f"all {len(attempts)} model(s) failed: {detail}")


def call_with_failover(
    chain: list[tuple[str, str]],
    fn: Callable[[str, str], T],
    *,
    classify_terminal: Callable[[BaseException], bool],
) -> FailoverResult:
    """Call fn(provider, model) over an ordered model chain, failing over to the
    next entry on a TERMINAL error.

    chain:            the ordered (provider, model) preference list. Entry 0 is the
                      primary; later entries are the cross-family fallbacks.
    fn:               the drafting call, taking (provider, model). It may itself
                      retry transient failures internally (retry.call_with_retry);
                      only the error it ultimately RAISES is judged here.
    classify_terminal given the exception fn raised, return True iff it is a
                      TERMINAL model failure worth failing over (a bad model, a bad
                      key, an empty/refused completion). A False verdict re-raises
                      immediately: a non-failover error (e.g. a programming bug) is
                      never hidden behind a fallback.

    On the first entry that serves, returns a FailoverResult recording the serving
    model and any entries fallen back from. If every entry fails terminally, raises
    FailoverExhausted with the full per-entry error list, so a total outage
    surfaces structurally and is never swallowed. An empty chain is a programming
    error and raises ValueError."""
    if not chain:
        raise ValueError("call_with_failover: empty model chain")
    attempts: list[FailoverAttempt] = []
    fell_back_from: list[tuple[str, str]] = []
    for provider, model in chain:
        try:
            value = fn(provider, model)
        except BaseException as e:  # noqa: BLE001 -- re-raised below when terminal-but-not-failover, or aggregated
            if not classify_terminal(e):
                # Not a failover-worthy error: re-raise unchanged so a real bug is
                # never masked by trying the next model.
                raise
            attempts.append(FailoverAttempt(provider, model, error=str(e)))
            fell_back_from.append((provider, model))
            continue
        attempts.append(FailoverAttempt(provider, model, error=""))
        # This entry SERVED, so it is the served_by model and is not part of
        # fell_back_from (only the earlier terminal entries are).
        return FailoverResult(
            value=value, served_by=(provider, model),
            fell_back_from=list(fell_back_from), attempts=attempts)
    raise FailoverExhausted(attempts)
