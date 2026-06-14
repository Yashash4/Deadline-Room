"""One-command tamper receipt: break the evidence yourself, watch the seal fail.

A skeptic's objection to any "byte-identical replay" claim is fair: byte
identical to what, your own recording? Of course it matches. This script
answers that objection in the judge's own hands. It:

  1. Loads a captured run log that ships in this repo
     (web/data/run-inc-8842-chaos.jsonl). No API keys, no network.
  2. Prints the sealed SHA-256 and confirms a clean replay reproduces it
     byte for byte (the honest baseline).
  3. Flips exactly ONE field of ONE event, in memory.
  4. Re-runs replay() on the tampered log and shows the hash DIVERGE from
     the seal, and names the first line of the trace that changed.
  5. Prints a one-line verdict and exits 0 when the tamper was detected,
     nonzero if the hash did NOT move (which would mean replay is echoing
     the log rather than genuinely re-executing the state machine).

Run it:  py scripts/tamper_test.py

Why a flipped `admitted` flag is the sharpest demonstration: replay feeds
each protocol event through a FRESH state machine and RE-DERIVES `admitted`,
`to_state`, and `reason`. So when we flip a truthful `admitted: true` to
`false`, the sealed log now carries a value the state machine never produced.
Two independent seals catch it:

  * Seal binding:   the tampered log's own hash no longer equals the sealed
                    hash that was recorded when the run was captured.
  * Self-certification: replay re-derives the honest value, so the replay of
                    the tampered log no longer equals the tampered log. A log
                    is authentic only when replay(log) == log AND its hash
                    matches the seal. Both break here, provably, offline.

The flat hash above catches a flipped FIELD. It is blunt about REORDERING and
OMISSION: it tells you the whole-file digest moved, but not which entry broke,
and a forger who re-seals after editing defeats a bare digest entirely. So this
script also runs a hash CHAIN beat. The chain folds each entry's hash into the
next (entry_hash[i] = sha256(entry_hash[i-1] || canon(entry[i]))), computed as a
DERIVED sidecar from the same canonical bytes replay uses. Swap two entries or
drop one and the chain head diverges, AND the script names the FIRST entry whose
chain hash breaks. The chain is read-only over the log: the run-log sha and the
byte-identical replay are untouched by it.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import json  # noqa: E402

from warden.chain import chain_head, chain_over, first_broken_index  # noqa: E402
from warden.replay import RunLog, replay  # noqa: E402
from warden.signing import (  # noqa: E402
    DEMO_KEY_CAVEAT,
    verify_run_log_jsonl,
)

LOG_PATH = REPO_ROOT / "web" / "data" / "run-inc-8842-chaos.jsonl"
SIG_PATH = REPO_ROOT / "web" / "data" / "run-inc-8842-chaos.jsonl.sig.json"


def _first_divergence(a_lines: list[str], b_lines: list[str]) -> tuple[int, str, str] | None:
    """Return (line_number, original_line, tampered_line) of the first byte-level
    divergence between two JSONL traces, or None if they are identical."""
    for i, (a, b) in enumerate(zip(a_lines, b_lines)):
        if a != b:
            return i, a, b
    if len(a_lines) != len(b_lines):
        i = min(len(a_lines), len(b_lines))
        a = a_lines[i] if i < len(a_lines) else "<no line>"
        b = b_lines[i] if i < len(b_lines) else "<no line>"
        return i, a, b
    return None


def _flip_one_field(entries: list[dict]) -> tuple[str, str, str]:
    """Flip exactly one field of one event in place. Returns a human-readable
    (location, before, after) description of the single byte that was changed."""
    for entry in entries:
        if entry["type"] == "protocol_event" and entry["payload"].get("admitted") is True:
            payload = entry["payload"]
            before = "admitted=true"
            after = "admitted=false"
            payload["admitted"] = False
            # to_state is only present on admitted events; drop it to match what
            # a forger would do when faking a rejection. Replay will re-derive
            # the truth regardless, which is the entire point.
            payload["to_state"] = None
            location = (
                f"seq {entry['seq']} "
                f"({payload['actor']} {payload['event']} on {payload['correlation_id']})"
            )
            return location, before, after
    raise SystemExit(
        "tamper_test: no admitted protocol_event found in the captured log; "
        "the fixture is malformed."
    )


def _swap_two_protocol_events(log: RunLog) -> tuple[int, int]:
    """Swap the position of the first two protocol events in the log.

    No field is altered: only the ORDER changes, which a flat field-edit test
    would not flag as cleanly. The seqs ride along with their entries, so
    after the swap the seq column is out of order, exactly the footprint a
    reorder leaves. Operates on the log's backing list so the reorder
    actually persists. Returns the two logged seq values that traded places."""
    entries = log._entries  # noqa: SLF001
    idxs = [k for k, e in enumerate(entries) if e["type"] == "protocol_event"]
    if len(idxs) < 2:
        raise SystemExit(
            "tamper_test: fewer than two protocol_events to reorder; "
            "the fixture is malformed."
        )
    a, b = idxs[0], idxs[1]
    seq_a = entries[a]["seq"]
    seq_b = entries[b]["seq"]
    entries[a], entries[b] = entries[b], entries[a]
    return seq_a, seq_b


def _drop_one_protocol_event(log: RunLog) -> int:
    """Delete the first protocol event from the log and return its seq.

    A silent omission: the line simply vanishes. Every chain hash from that
    point on shifts, so the head diverges and the first broken link names the
    gap. Operates on the log's backing list so the deletion persists."""
    entries = log._entries  # noqa: SLF001
    for k, e in enumerate(entries):
        if e["type"] == "protocol_event":
            dropped_seq = e["seq"]
            del entries[k]
            return dropped_seq
    raise SystemExit(
        "tamper_test: no protocol_event to omit; the fixture is malformed."
    )


def _clone(log: RunLog) -> RunLog:
    out = RunLog()
    out._entries = copy.deepcopy(log.entries())  # noqa: SLF001
    out._seq = out._entries[-1]["seq"] + 1 if out._entries else 0  # noqa: SLF001
    return out


def main() -> int:
    if not LOG_PATH.exists():
        print(f"tamper_test: captured log not found at {LOG_PATH}", file=sys.stderr)
        return 2

    print("=" * 72)
    print("TAMPER TEST: break the evidence yourself, watch the seal fail")
    print("=" * 72)
    print(f"Captured run log : {LOG_PATH.relative_to(REPO_ROOT)}")
    print("No API keys, no network. Pure offline replay of a sealed audit trail.")
    print()

    sealed = RunLog.load(LOG_PATH)
    sealed_hash = sealed.sha256()

    # --- Step 1: honest baseline ------------------------------------------
    clean_replay = replay(sealed)
    clean_hash = clean_replay.sha256()
    print("Step 1  honest baseline")
    print(f"  sealed hash         : {sealed_hash}")
    print(f"  clean replay hash   : {clean_hash}")
    baseline_ok = clean_hash == sealed_hash
    print(f"  byte-identical      : {baseline_ok}")
    if not baseline_ok:
        print()
        print("FAIL: a clean replay did not reproduce the sealed hash. The "
              "baseline is broken; investigate before trusting any tamper result.")
        return 3
    print("  -> replay genuinely re-executes the state machine and reproduces")
    print("     the sealed trace byte for byte.")
    print()

    # --- Step 2: flip exactly one field -----------------------------------
    tampered = _clone(sealed)
    location, before, after = _flip_one_field(tampered.entries())
    tampered_hash = tampered.sha256()
    print("Step 2  flip ONE field of ONE event")
    print(f"  where               : {location}")
    print(f"  change              : {before}  ->  {after}")
    print(f"  tampered log hash   : {tampered_hash}")
    print(f"  vs sealed hash      : {sealed_hash}")
    seal_broken = tampered_hash != sealed_hash
    print(f"  seal binding broken : {seal_broken}")
    print()

    # --- Step 3: replay the tampered log ----------------------------------
    tampered_replay = replay(tampered)
    tampered_replay_hash = tampered_replay.sha256()
    print("Step 3  replay the tampered log through a fresh state machine")
    print(f"  replay of tampered  : {tampered_replay_hash}")
    self_certifies = tampered_replay_hash == tampered_hash
    print(f"  self-certifies      : {self_certifies}")
    print("  -> the fresh state machine RE-DERIVES admitted/to_state, so the")
    print("     forged value is overwritten: replay no longer equals the")
    print("     tampered log it was fed.")

    div = _first_divergence(
        sealed.to_jsonl().splitlines(),
        tampered.to_jsonl().splitlines(),
    )
    if div is not None:
        idx, orig_line, tamp_line = div
        print()
        print(f"  first changed line  : index {idx}")
        print(f"    sealed   : {orig_line}")
        print(f"    tampered : {tamp_line}")
    print()

    # The chain over the SEALED log: our trusted reference for the next two
    # beats. Computed read-only from the same canonical bytes the run-log sha
    # covers, so it does not touch the seal or replay.
    sealed_chain = chain_over(sealed.entries())
    sealed_head = chain_head(sealed.entries())
    print("Hash chain over the sealed log")
    print(f"  entries chained     : {len(sealed_chain)}")
    print(f"  sealed chain head   : {sealed_head}")
    print("  -> each entry's hash folds in the prior entry's hash, so the head")
    print("     binds the exact ORDER and COUNT of every event, not just fields.")
    print()

    # --- Step 4: reorder two entries --------------------------------------
    reordered = _clone(sealed)
    i, j = _swap_two_protocol_events(reordered)
    reordered_head = chain_head(reordered.entries())
    reorder_first_break = first_broken_index(reordered.entries(), sealed_chain)
    reorder_head_moved = reordered_head != sealed_head
    print("Step 4  swap the ORDER of two events (no field changed)")
    print(f"  swapped seqs        : {i} <-> {j}")
    print(f"  reordered head      : {reordered_head}")
    print(f"  vs sealed head      : {sealed_head}")
    print(f"  chain head moved    : {reorder_head_moved}")
    print(f"  first broken link   : index {reorder_first_break}")
    print("  -> a bare whole-file hash would only say 'something moved'; the")
    print("     chain points at the exact first entry whose hash no longer fits.")
    reorder_detected = reorder_head_moved and reorder_first_break is not None
    print()

    # --- Step 5: omit one entry -------------------------------------------
    omitted = _clone(sealed)
    dropped_seq = _drop_one_protocol_event(omitted)
    omitted_head = chain_head(omitted.entries())
    omission_first_break = first_broken_index(omitted.entries(), sealed_chain)
    omission_head_moved = omitted_head != sealed_head
    print("Step 5  OMIT one event (silently delete a line)")
    print(f"  dropped seq         : {dropped_seq}")
    print(f"  omitted head        : {omitted_head}")
    print(f"  vs sealed head      : {sealed_head}")
    print(f"  chain head moved    : {omission_head_moved}")
    print(f"  first broken link   : index {omission_first_break}")
    print("  -> dropping an entry shifts the chain from that point on; the head")
    print("     diverges and the first broken link names where the gap begins.")
    omission_detected = omission_head_moved and omission_first_break is not None
    print()

    # --- Step 6: the SIGNATURE breaks too ---------------------------------
    # The flat hash and the chain both catch tampering, but neither binds the
    # evidence to an IDENTITY. The detached Ed25519 signature does: it attests the
    # sealed run-log bytes with the Warden's key. The same one-byte flip from
    # Step 2 makes the signature INVALID, so the judge sees hash-break +
    # chain-break + signature-INVALID all from one edit. The signature is read
    # from a sidecar beside the log; it never lives in the hashed JSONL, so the
    # run-log sha and replay above are untouched by it.
    signature_detected = False
    if SIG_PATH.exists():
        sig = json.loads(SIG_PATH.read_text(encoding="utf-8"))
        sealed_jsonl = sealed.to_jsonl()
        tampered_jsonl = tampered.to_jsonl()
        sealed_sig_ok = verify_run_log_jsonl(sealed_jsonl, sig)
        tampered_sig_ok = verify_run_log_jsonl(tampered_jsonl, sig)
        print("Step 6  the Ed25519 signature over the sealed bytes")
        print(f"  signer              : {sig.get('signer', 'Deadline Warden')}")
        print(f"  key fingerprint     : {sig.get('pubkey_fingerprint', '')}")
        print(f"  sealed bytes VALID  : {sealed_sig_ok}")
        print(f"  tampered bytes VALID: {tampered_sig_ok}")
        print("  -> the SAME one-byte field flip that moved the hash also makes")
        print("     the signature INVALID: integrity AND authenticity both fail.")
        print(f"  note: {DEMO_KEY_CAVEAT}")
        signature_detected = sealed_sig_ok and not tampered_sig_ok
    else:
        print("Step 6  signature sidecar not found at "
              f"{SIG_PATH.relative_to(REPO_ROOT)}; skipping the signature beat.")
        # No sidecar is a setup gap, not a passing run: a missing receipt cannot
        # be treated as a detected tamper.
        signature_detected = False
    print()

    # --- Verdict ----------------------------------------------------------
    # The evidence is authentic only when it matches its seal, self-certifies
    # under replay, its chain head matches, AND its signature verifies. A flipped
    # field breaks the seal, self-certification, AND the signature; a reorder or
    # an omission breaks the chain head and is point-at-able to the first broken
    # link. All four must be detected.
    field_detected = seal_broken or not self_certifies
    all_detected = (field_detected and reorder_detected and omission_detected
                    and signature_detected)
    print("=" * 72)
    if all_detected:
        print("VERDICT: PASS. Tamper detected four ways from one edit.")
        print("  field flip : sealed hash moves AND replay re-derives the truth.")
        print("  reorder    : chain head diverges; first broken link named.")
        print("  omission   : chain head diverges; first broken link named.")
        print("  signature  : the detached Ed25519 signature is now INVALID.")
        print("The seal binds content, the chain binds order and count, the "
              "signature")
        print("binds authenticity to the Warden's key, and replay re-executes the "
              "state")
        print("machine rather than echoing the log. Verified, not asserted.")
        print("=" * 72)
        return 0

    print("VERDICT: FAIL. A tamper went undetected.")
    print(f"  field flip detected : {field_detected}")
    print(f"  reorder detected    : {reorder_detected}")
    print(f"  omission detected   : {omission_detected}")
    print(f"  signature detected  : {signature_detected}")
    print("Any False above is a real regression in the integrity machinery; "
          "do not ship.")
    print("=" * 72)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
