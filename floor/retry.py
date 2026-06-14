"""Bounded exponential-backoff retry for the two network chokepoints.

The Deadline Room talks to exactly two networks: the LLM providers (through
floor.drafter.llm_complete) and Band (through shell.band_agent_shell.
BandAgentShell._call). Both are single-egress functions, so a retry policy
applied at each one hardens every drafting, characterization, materiality, and
Band call in one place.

The policy is deliberately conservative:

  - Retry ONLY transient failures: a transport error (connection reset, read
    timeout) or an HTTP 429 / 5xx. These are the failures that clear on a second
    try (the roster documents transient 503 capacity errors on the plan).
  - NEVER retry a 4xx other than 429: a 400/401/403/404 is a real, terminal
    error (bad request, bad key, forbidden, not found). Retrying it wastes time
    and hides a bug, so it fails fast through the caller's existing typed error.
  - Bounded: max_attempts is small and the total wait is capped at a few
    seconds, never infinite.
  - Default-safe: the DEFAULT is one attempt, so the deterministic, offline,
    FakeBand-backed test suite and the byte-identical replay are unchanged. The
    live runner raises the default to a handful of tries where retries help.

The recovered-retry count is a process-wide counter, read at packet-assembly
time into an additive Examiner Packet field. It is NEVER written into the hashed
run-log JSONL, so replay stays byte-identical: a retried call that ultimately
succeeds produces the SAME bytes a first-try success would have, and the counter
is rendered from a live tally, not from any logged event.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Callable, Optional, TypeVar

# The structured per-call telemetry goes here. Quiet by default (a library logger
# with no handler installed emits nothing unless the application configures one),
# so it never spams the demo stdout, but it is available to any operator who
# wires up logging.
log = logging.getLogger("deadline_room.net")

T = TypeVar("T")


class _RetryCounter:
    """Process-wide tally of retries that RECOVERED a transient failure (a later
    attempt succeeded after an earlier one failed transiently). Read at packet
    time for the receipt; never serialized into the hashed run log."""

    def __init__(self) -> None:
        self._recovered = 0

    def record_recovered(self, n: int) -> None:
        if n > 0:
            self._recovered += n

    @property
    def recovered(self) -> int:
        return self._recovered

    def reset(self) -> None:
        self._recovered = 0


# The single shared counter. floor.run_floor resets it at the start of a run and
# reads it at packet time.
COUNTER = _RetryCounter()


def is_transient_status(status: int) -> bool:
    """True for the HTTP statuses worth retrying: 429 (rate limited) and any 5xx
    (server-side, typically transient). Every other status, including all the
    other 4xx, is terminal and must fail fast."""
    return status == 429 or 500 <= status <= 599


class _Transient(Exception):
    """Internal signal that an attempt failed transiently and may be retried.
    Carries the original exception so the final raise re-raises it unchanged."""

    def __init__(self, original: BaseException) -> None:
        super().__init__(str(original))
        self.original = original


def _sleep_seconds(attempt_index: int, base_delay: float, cap_delay: float) -> float:
    """Full-jitter exponential backoff for the wait BEFORE the next attempt.
    attempt_index is 0 for the wait after the first attempt, 1 after the second,
    and so on. The deterministic ceiling is min(cap_delay, base_delay * 2**i);
    the actual sleep is a uniform random draw in [0, ceiling] (full jitter), which
    spreads retries and avoids a thundering herd. The total wait is bounded
    because the ceiling is capped."""
    ceiling = min(cap_delay, base_delay * (2 ** attempt_index))
    return random.uniform(0, ceiling)


def call_with_retry(
    fn: Callable[[], T],
    *,
    classify: Callable[[BaseException], bool],
    max_attempts: int = 1,
    base_delay: float = 0.5,
    cap_delay: float = 4.0,
    sleep: Callable[[float], None] = time.sleep,
    on_attempt: Optional[Callable[[int, Optional[BaseException]], None]] = None,
) -> T:
    """Call fn() with bounded exponential backoff on transient failures.

    fn:           the zero-arg operation (a closure over the real network call).
    classify:     given the exception fn raised, return True iff it is transient
                  (retryable). A False verdict re-raises immediately (fail fast).
    max_attempts: total attempts including the first. Default 1 (no retry), which
                  keeps offline tests and replay byte-identical. The live runner
                  passes a small number (e.g. 3).
    base_delay/cap_delay: the backoff schedule; the per-wait ceiling is capped at
                  cap_delay so the total wait is a few seconds, never infinite.
    sleep:        injectable for tests (so they never actually wait).
    on_attempt:   optional hook called after each attempt with
                  (attempt_number, error_or_None) for structured logging.

    On success returns fn()'s value. If the value came after one or more
    transient failures, the recovered count is added to COUNTER. After exhausting
    attempts the LAST exception is re-raised unchanged, so the caller's existing
    typed error (DrafterError / BandError) surfaces exactly as before: retries are
    additive, they never swallow a final failure."""
    attempts = max(1, int(max_attempts))
    last_error: Optional[BaseException] = None
    transient_failures = 0
    for i in range(attempts):
        attempt_number = i + 1
        try:
            result = fn()
        except BaseException as e:  # noqa: BLE001 -- re-raised below; never swallowed
            transient = classify(e)
            if on_attempt is not None:
                on_attempt(attempt_number, e)
            if not transient or attempt_number >= attempts:
                # Terminal error, or out of attempts: re-raise unchanged so the
                # caller's typed error is what the run sees.
                raise
            transient_failures += 1
            last_error = e
            sleep(_sleep_seconds(i, base_delay, cap_delay))
            continue
        if on_attempt is not None:
            on_attempt(attempt_number, None)
        if transient_failures:
            # A later attempt succeeded after a transient failure: this is a
            # RECOVERED retry, the receipt the Examiner Packet surfaces.
            COUNTER.record_recovered(transient_failures)
        return result
    # Unreachable: the loop either returns or raises. Present so type checkers see
    # a terminal path.
    raise last_error if last_error is not None else RuntimeError("retry exhausted")
