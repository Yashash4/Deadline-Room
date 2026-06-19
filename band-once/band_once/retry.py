"""Bounded exponential-backoff retry for a single network chokepoint.

The Band shell talks to exactly one network (the Band Agent API through
BandAgentShell._call), so a retry policy applied at that one call hardens every
identity, room, post, and lifecycle call in one place.

The policy is deliberately conservative:

  - Retry ONLY transient failures: a transport error (connection reset, read
    timeout) or an HTTP 429 / 5xx. These are the failures that clear on a second
    try.
  - NEVER retry a 4xx other than 429: a 400/401/403/404 is a real, terminal
    error (bad request, bad key, forbidden, not found). Retrying it wastes time
    and hides a bug, so it fails fast through the caller's existing typed error.
  - Bounded: max_attempts is small and the total wait is capped at a few
    seconds, never infinite.
  - Default-safe: the DEFAULT is one attempt, so a deterministic offline test
    suite is unchanged. A live runner raises the default to a handful of tries
    where retries help.

This module is concept-agnostic: it knows nothing about the application that
uses the shell. It depends only on the stdlib.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Callable, Optional, TypeVar

# The structured per-call telemetry goes here. Quiet by default (a library logger
# with no handler installed emits nothing unless the application configures one),
# so it never spams stdout, but it is available to any operator who wires up
# logging.
log = logging.getLogger("band_once.net")

T = TypeVar("T")


def is_transient_status(status: int) -> bool:
    """True for the HTTP statuses worth retrying: 429 (rate limited) and any 5xx
    (server-side, typically transient). Every other status, including all the
    other 4xx, is terminal and must fail fast."""
    return status == 429 or 500 <= status <= 599


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
                  keeps offline tests deterministic. A live runner passes a small
                  number (e.g. 3).
    base_delay/cap_delay: the backoff schedule; the per-wait ceiling is capped at
                  cap_delay so the total wait is a few seconds, never infinite.
    sleep:        injectable for tests (so they never actually wait).
    on_attempt:   optional hook called after each attempt with
                  (attempt_number, error_or_None) for structured logging.

    On success returns fn()'s value. After exhausting attempts the LAST exception
    is re-raised unchanged, so the caller's existing typed error surfaces exactly
    as before: retries are additive, they never swallow a final failure."""
    attempts = max(1, int(max_attempts))
    last_error: Optional[BaseException] = None
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
            last_error = e
            sleep(_sleep_seconds(i, base_delay, cap_delay))
            continue
        if on_attempt is not None:
            on_attempt(attempt_number, None)
        return result
    # Unreachable: the loop either returns or raises. Present so type checkers see
    # a terminal path.
    raise last_error if last_error is not None else RuntimeError("retry exhausted")
