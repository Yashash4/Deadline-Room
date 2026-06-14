"""Per-entry hash chain over a run log: a DERIVED, append-only sidecar.

The flat `RunLog.sha256()` over the whole JSONL already catches any field
edit: change one byte, the digest moves. What it does NOT catch cleanly is
REORDERING or OMISSION of entries. A whole-log hash tells you "something
moved"; it cannot point at WHICH entry broke, and a clever forger who
re-seals after editing would defeat a bare digest entirely.

A hash CHAIN fixes the ordering/omission gap and makes the break
point-at-able. Each entry's hash folds in the prior entry's hash:

    entry_hash[0] = sha256(GENESIS || canon(entry[0]))
    entry_hash[i] = sha256(entry_hash[i-1] || canon(entry[i]))

so every entry is cryptographically bound to the exact sequence of entries
before it. Swap two entries and both of their hashes (and the head) change.
Drop one and every hash after it (and the head) changes. The `chain_head`
is the single value that summarizes the whole ordered run.

CRITICAL: this is a DERIVED sidecar. It is computed FROM the existing
canonical run-log entries using the SAME canonicalization replay uses
(`warden.replay._canon`). It does NOT mutate any logged entry, does NOT add
fields into the hashed JSONL payload, and does NOT touch RunLog or replay's
behavior. The byte-identical replay guarantee and `RunLog.sha256()` are
completely unaffected: the chain reads the same bytes, it never writes them.
"""

from __future__ import annotations

import hashlib

from .replay import RunLog, _canon

# Fixed genesis seed: sha256 of the empty string. Pinning it (rather than a
# random nonce) keeps the chain reproducible across machines and runs, which
# is the whole point of a tamper-evident receipt.
GENESIS = hashlib.sha256(b"").hexdigest()


def _entry_hash(prev_hash: str, entry: dict) -> str:
    """Fold one canonical entry into the running chain hash.

    The previous hash and the canonical entry bytes are concatenated with a
    newline separator (an unambiguous delimiter: canonical JSON never
    contains a raw newline) so that the boundary between prev_hash and entry
    cannot be shifted by crafted content.
    """
    material = f"{prev_hash}\n{_canon(entry)}".encode()
    return hashlib.sha256(material).hexdigest()


def chain_over(entries: list[dict]) -> list[str]:
    """Return the per-entry hash chain for `entries`, in order.

    The returned list has one hash per entry: result[i] binds entry[i] to
    every entry before it. Computed purely from the canonical bytes; the
    input is never mutated.
    """
    chain: list[str] = []
    prev = GENESIS
    for entry in entries:
        prev = _entry_hash(prev, entry)
        chain.append(prev)
    return chain


def chain_head(entries: list[dict]) -> str:
    """Return the final chain hash (the head) that summarizes the whole run.

    Genesis for an empty log, otherwise the last per-entry hash.
    """
    chain = chain_over(entries)
    return chain[-1] if chain else GENESIS


def chain_for_log(log: RunLog) -> list[dict]:
    """Build the sidecar records `[{"seq", "entry_hash"}, ...]` for a RunLog.

    Pairs each entry's logged `seq` with its chain hash, so a verifier can
    line the chain up against the JSONL by sequence number. The log is read
    only; nothing is written back.
    """
    entries = log.entries()
    hashes = chain_over(entries)
    return [
        {"seq": entry["seq"], "entry_hash": h}
        for entry, h in zip(entries, hashes)
    ]


def head_for_log(log: RunLog) -> str:
    """Convenience: the chain head computed from a RunLog's entries."""
    return chain_head(log.entries())


def verify_chain(entries: list[dict], expected_head: str) -> bool:
    """True iff the recomputed chain head equals `expected_head`.

    A verifier recomputes the chain from the JSONL it holds and checks it
    against a head it trusts out of band (or, once signed, against a head
    bound to the Warden's key). Any reorder or omission moves the head and
    this returns False.
    """
    return chain_head(entries) == expected_head


def first_broken_index(entries: list[dict], trusted_chain: list[str]) -> int | None:
    """Index of the FIRST entry whose chain hash diverges from `trusted_chain`.

    Given a chain of hashes captured when the log was sealed, recompute the
    chain over `entries` and return the first position where they differ:
    the exact link where the tamper begins. Returns None when every shared
    position matches AND the lengths agree (no edit, no reorder, no
    omission). A length mismatch (an entry was dropped or appended) reports
    the first index past the shorter chain, naming where the divergence
    starts.
    """
    recomputed = chain_over(entries)
    for i, (got, expected) in enumerate(zip(recomputed, trusted_chain)):
        if got != expected:
            return i
    if len(recomputed) != len(trusted_chain):
        return min(len(recomputed), len(trusted_chain))
    return None
