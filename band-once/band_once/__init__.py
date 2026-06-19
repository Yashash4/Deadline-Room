"""band-once: the exactly-once lifecycle shell for Band agents.

A tiny, concept-agnostic library that gives any Band agent exactly-once delivery
against the re-serving lifecycle cursor under a live kill, with a runnable proof
and a public conformance check an LLM cannot self-certify.

Public surface:
    BandAgentShell      the lifecycle shell (drain, processing, post, processed,
                        the read-then-act dedup guard, bounded retry).
    IdempotencyLedger   the exactly-once core: one ACCEPTED per natural key.
    verify_exactly_once an external prover: hand it an agent_factory, it names the
                        first schedule that breaks exactly-once, or passes.
    ConformanceResult   the typed verdict verify_exactly_once returns.
"""

from band_once.ledger import Disposition, IdempotencyLedger, LedgerEntry
from band_once.shell import BandAgentShell, BandError, strip_mention_markers
from band_once.verify import (
    ConformanceResult,
    clean_echo_agent,
    verify_exactly_once,
)

__all__ = [
    "BandAgentShell",
    "BandError",
    "strip_mention_markers",
    "IdempotencyLedger",
    "LedgerEntry",
    "Disposition",
    "verify_exactly_once",
    "ConformanceResult",
    "clean_echo_agent",
]

__version__ = "0.1.0"
