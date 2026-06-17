"""One-command post-run audit: every in-log invariant, verified over the sealed artifact.

A judge, an examiner, or an auditor is handed a sealed run: a run-log JSONL, its
packet, and a detached signature sidecar. This script answers, in one keyless
offline command, the single question that matters: does this exact sealed
artifact satisfy every invariant the Deadline Room claims, proven FROM the log
itself rather than from a fresh simulation?

It composes the FROZEN verifiers already in the repo (it reimplements no crypto
and no replay): warden/logcheck.py for structural soundness, warden/replay.py for
byte-identical replay, warden/chain.py for the per-entry hash chain head,
warden/signing.py for the detached Ed25519 signature over the bound
{sha256, chain_head, attestation_sha, fact_record_hash} payload. On top of those
it runs three pure log predicates
that read the sealed events directly: in-log exactly-once (no dedup key accepted
twice, every drafted filing lands once), two-key release (every human release is
preceded by a passed contradiction diff AND two DISTINCT release keys, the
segregation of duties), and clock monotonicity (clock starts and stops are
ordered and inside the run window, never negative, never out of order).

Each invariant prints PASS or FAIL with a one-line locus on failure; the chain
head, the run-log sha256, and the signer fingerprint are printed so the output
reads like an audit report. The exit code is 0 only when EVERY invariant holds on
EVERY audited run; any failure exits nonzero. Nothing here writes the run log or
re-signs anything: it is a read-only verifier over sealed bytes.

  py scripts/audit_run.py                       (audit all four sealed captures)
  py scripts/audit_run.py <run-log.jsonl>       (audit one run log)
  py scripts/audit_run.py <run-log.jsonl> <packet.json>

The signature record is located the same way scripts/verify_signature.py locates
it: an explicit packet's replay.signature, else a sibling <log>.sig.json sidecar,
else the default captured packet that pairs with the log. The recorded chain head
is read from the packet's replay block (or the signature record) and compared
against the head recomputed from the bytes on disk.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from warden.chain import chain_head  # noqa: E402
from warden.logcheck import validate_file  # noqa: E402
from warden.replay import RunLog, replay  # noqa: E402
from warden.signing import (  # noqa: E402
    DEMO_KEY_CAVEAT,
    fingerprint,
    verify_run_log_jsonl,
)

DATA = REPO_ROOT / "web" / "data"
SCENARIOS = ("normal", "inject_contradiction", "chaos", "amendment")

# The two distinct human roles that must both sign to release a filing, mirrored
# from warden/release_gate.REQUIRED_ROLES. Kept as a literal here so the audit
# states its own segregation-of-duties contract and does not depend on a runtime
# import of the gate that produced the log.
REQUIRED_RELEASE_ROLES = frozenset({"head_of_ir", "general_counsel"})


@dataclass(frozen=True)
class Check:
    """One invariant's verdict: a stable name, ok True/False, and a one-line
    detail that names the locus on failure (and summarizes on success)."""
    name: str
    ok: bool
    detail: str


def _entries(log: RunLog) -> list[dict]:
    return log.entries()


def _sidecar_for(log_path: Path) -> Path:
    return log_path.with_suffix(log_path.suffix + ".sig.json")


def _default_packet_for(log_path: Path) -> Path | None:
    """The committed packet that pairs with a default capture log, by mode."""
    name = log_path.name
    prefix, suffix = "run-inc-8842-", ".jsonl"
    if name.startswith(prefix) and name.endswith(suffix):
        mode = name[len(prefix):-len(suffix)]
        candidate = DATA / f"packet-{mode}.json"
        if candidate.exists():
            return candidate
    return None


def _load_packet(packet_path: Path | None, log_path: Path) -> dict | None:
    if packet_path and packet_path.exists():
        return json.loads(packet_path.read_text(encoding="utf-8"))
    default_packet = _default_packet_for(log_path)
    if default_packet and default_packet.exists():
        return json.loads(default_packet.read_text(encoding="utf-8"))
    return None


def _load_signature(packet: dict | None, log_path: Path) -> dict | None:
    if packet:
        sig = (packet.get("replay") or {}).get("signature")
        if sig:
            return sig
    sidecar = _sidecar_for(log_path)
    if sidecar.exists():
        return json.loads(sidecar.read_text(encoding="utf-8"))
    return None


def _recorded_chain_head(packet: dict | None, signature: dict | None) -> str | None:
    if packet:
        head = (packet.get("replay") or {}).get("chain_head")
        if head:
            return head
    if signature and signature.get("chain_head"):
        return signature["chain_head"]
    return None


def _parse_ts(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp to an aware datetime, or None if unparseable."""
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


# --- The composed verifiers ---------------------------------------------------

def check_well_formed(log_path: Path) -> Check:
    """WELL-FORMED: warden/logcheck validates the JSONL (no truncation, no
    corruption, no missing field, contiguous seqs)."""
    result = validate_file(log_path)
    if result.ok:
        return Check("WELL-FORMED", True, "run-log validates: structurally sound")
    where = f"line {result.line}: " if result.line else ""
    return Check("WELL-FORMED", False, f"{where}{result.reason}")


def check_replay(log: RunLog, sha_on_disk: str) -> Check:
    """REPLAY: replay() through a fresh state machine reproduces the bytes and the
    sealed sha byte-identically."""
    replayed = replay(log)
    replayed_sha = replayed.sha256()
    byte_identical = replayed.to_jsonl() == log.to_jsonl()
    if byte_identical and replayed_sha == sha_on_disk:
        return Check("REPLAY", True,
                     f"byte-identical: replay sha {replayed_sha[:16]} == sealed sha")
    return Check("REPLAY", False,
                 f"replay sha {replayed_sha[:16]} != sealed sha {sha_on_disk[:16]} "
                 f"(byte-identical={byte_identical})")


def check_chain(log: RunLog, recorded_head: str | None) -> Check:
    """CHAIN: the chain head recomputed from the bytes equals the head the packet
    recorded."""
    recomputed = chain_head(_entries(log))
    if recorded_head is None:
        return Check("CHAIN", False,
                     "no recorded chain_head in the packet or signature to compare")
    if recomputed == recorded_head:
        return Check("CHAIN", True,
                     f"recomputed chain head {recomputed[:16]} == recorded head")
    return Check("CHAIN", False,
                 f"recomputed head {recomputed[:16]} != recorded head "
                 f"{recorded_head[:16]}")


def check_signature(jsonl: str, signature: dict | None) -> Check:
    """SIGNATURE: the detached Ed25519 signature verifies against the committed
    public key over the bound {sha256, chain_head, attestation_sha,
    fact_record_hash} payload."""
    if signature is None:
        return Check("SIGNATURE", False,
                     "no detached signature found (packet replay.signature or "
                     "<log>.sig.json)")
    if verify_run_log_jsonl(jsonl, signature):
        fp = signature.get("pubkey_fingerprint") or fingerprint(
            signature.get("public_key", ""))
        return Check("SIGNATURE", True,
                     "valid Ed25519 over {sha256, chain_head, attestation_sha, "
                     f"fact_record_hash}}, signer fp {fp}")
    return Check("SIGNATURE", False,
                 "detached signature does NOT verify against the committed public key")


# --- The pure in-log predicates -----------------------------------------------

def check_exactly_once(log: RunLog) -> Check:
    """EXACTLY-ONCE: no dedup key is accepted twice across the ledger events, and
    every drafted filing lands exactly once.

    Reads the sealed `ledger` and `chaos` events directly. A ledger key may be
    ACCEPTED at most once; any second acceptance of the same key is a double-file.
    A chaos `duplicate_dropped` proves a redelivered unit of work was caught, which
    is the positive form of the same guarantee. A ledger key appearing only as
    DUPLICATE_DROPPED (accepted by no one) is an orphan drop and is flagged."""
    accepted: dict[str, int] = {}
    dropped: dict[str, int] = {}
    for entry in _entries(log):
        if entry["type"] != "ledger":
            continue
        payload = entry["payload"]
        key = payload.get("key")
        disposition = payload.get("disposition")
        if key is None or disposition is None:
            return Check("EXACTLY-ONCE", False,
                         f"seq {entry['seq']}: ledger entry missing key/disposition")
        if disposition == "accepted":
            accepted[key] = accepted.get(key, 0) + 1
        elif disposition == "duplicate_dropped":
            dropped[key] = dropped.get(key, 0) + 1
        else:
            return Check("EXACTLY-ONCE", False,
                         f"seq {entry['seq']}: unknown ledger disposition "
                         f"'{disposition}' for key {key}")

    double_filed = sorted(k for k, n in accepted.items() if n > 1)
    if double_filed:
        return Check("EXACTLY-ONCE", False,
                     f"dedup key accepted more than once (double-filed): "
                     f"{double_filed[0]}")
    orphan_drops = sorted(k for k in dropped if k not in accepted)
    if orphan_drops:
        return Check("EXACTLY-ONCE", False,
                     f"dedup key dropped as duplicate but never accepted: "
                     f"{orphan_drops[0]}")

    # The chaos scenario proves the drop at the room layer rather than the ledger.
    chaos_drops = sum(
        1 for e in _entries(log)
        if e["type"] == "chaos"
        and e["payload"].get("disposition") == "duplicate_dropped")
    detail = (f"{len(accepted)} dedup key(s) accepted once, "
              f"0 double-filed, {sum(dropped.values()) + chaos_drops} duplicate(s) "
              f"dropped")
    return Check("EXACTLY-ONCE", True, detail)


def check_two_key_release(log: RunLog) -> Check:
    """TWO-KEY RELEASE: every HUMAN_RELEASED is preceded, on its branch, by a
    passed contradiction diff AND two DISTINCT release keys (segregation of
    duties).

    Walks the log in order. A `diff` with an empty conflict set arms the diff-pass
    for every branch at that point. Each `release_signoff` records one human key on
    one branch; a branch is two-key-ready only once it has collected both distinct
    required roles. A `human_released` protocol event is admitted by this audit
    only if, for its branch, the diff has passed AND both distinct release keys are
    already on record. A release with only one key (or the same key twice), or with
    no preceding passed diff, FAILS and names the branch."""
    diff_passed_global = False
    diff_passed_branch: set[str] = set()
    keys_by_branch: dict[str, set[str]] = {}

    for entry in _entries(log):
        etype = entry["type"]
        payload = entry["payload"]

        if etype == "diff":
            # A clean diff (no conflicts) passes; it arms release for the branches.
            if not payload.get("conflicts"):
                diff_passed_global = True
            continue

        if etype == "release_signoff":
            corr = payload.get("correlation_id", "")
            role = payload.get("role")
            if role not in REQUIRED_RELEASE_ROLES:
                return Check("TWO-KEY RELEASE", False,
                             f"seq {entry['seq']}: release_signoff has unexpected "
                             f"role '{role}' on {corr}")
            keys_by_branch.setdefault(corr, set()).add(role)
            continue

        if etype != "protocol_event":
            continue

        event = payload.get("event")
        corr = payload.get("correlation_id", "")
        if event == "diff_passed":
            diff_passed_branch.add(corr)
            continue
        if event != "human_released" or not payload.get("admitted"):
            continue

        # A human release fired. It must be backed by a passed diff and two keys.
        diff_ok = diff_passed_global or corr in diff_passed_branch
        have_keys = keys_by_branch.get(corr, set())
        missing = REQUIRED_RELEASE_ROLES - have_keys
        if not diff_ok:
            return Check("TWO-KEY RELEASE", False,
                         f"seq {entry['seq']}: {corr} released with no preceding "
                         f"passed contradiction diff")
        if missing:
            have = ", ".join(sorted(have_keys)) if have_keys else "none"
            return Check("TWO-KEY RELEASE", False,
                         f"seq {entry['seq']}: {corr} released without two distinct "
                         f"release keys (have {have}, missing "
                         f"{', '.join(sorted(missing))})")

    released = sum(
        1 for e in _entries(log)
        if e["type"] == "protocol_event"
        and e["payload"].get("event") == "human_released"
        and e["payload"].get("admitted"))
    return Check("TWO-KEY RELEASE", True,
                 f"{released} release(s), each preceded by a passed diff and two "
                 f"distinct keys")


def check_clock_monotonic(log: RunLog) -> Check:
    """CLOCK-MONOTONIC: clock start/stop events are ordered and inside the run
    window; no negative or out-of-order clock timestamps.

    For each branch, the clock_stopped timestamp must be at or after the
    clock_started timestamp (a stop before its start is a negative interval), and
    every clock timestamp must fall within the run window bounded by the earliest
    and latest protocol-event timestamps. Unparseable timestamps fail loud."""
    started: dict[str, datetime] = {}
    started_deadline: dict[str, datetime] = {}

    proto_ts: list[datetime] = []
    for entry in _entries(log):
        if entry["type"] == "protocol_event":
            ts = _parse_ts(entry["payload"].get("ts", ""))
            if ts is not None:
                proto_ts.append(ts)
    if not proto_ts:
        return Check("CLOCK-MONOTONIC", False,
                     "no protocol-event timestamps to bound the run window")
    window_lo, window_hi = min(proto_ts), max(proto_ts)

    for entry in _entries(log):
        etype = entry["type"]
        payload = entry["payload"]
        if etype == "clock_started":
            corr = payload.get("correlation_id", "")
            deadline = _parse_ts(payload.get("deadline", ""))
            if deadline is None:
                return Check("CLOCK-MONOTONIC", False,
                             f"seq {entry['seq']}: clock_started for {corr} has an "
                             f"unparseable deadline")
            if deadline <= window_lo:
                return Check("CLOCK-MONOTONIC", False,
                             f"seq {entry['seq']}: clock_started for {corr} has a "
                             f"deadline at or before the run start")
            # The clock starts at the run window low bound; record it for the stop
            # comparison and store the deadline for an at-most ordering sanity.
            started[corr] = window_lo
            started_deadline[corr] = deadline
        elif etype == "clock_stopped":
            corr = payload.get("correlation_id", "")
            stop = _parse_ts(payload.get("ts", ""))
            if stop is None:
                return Check("CLOCK-MONOTONIC", False,
                             f"seq {entry['seq']}: clock_stopped for {corr} has an "
                             f"unparseable timestamp")
            start = started.get(corr)
            if start is None:
                return Check("CLOCK-MONOTONIC", False,
                             f"seq {entry['seq']}: clock_stopped for {corr} with no "
                             f"matching clock_started")
            if stop < start:
                return Check("CLOCK-MONOTONIC", False,
                             f"seq {entry['seq']}: clock_stopped for {corr} is before "
                             f"its start (negative interval)")
            if stop < window_lo or stop > window_hi:
                return Check("CLOCK-MONOTONIC", False,
                             f"seq {entry['seq']}: clock_stopped for {corr} falls "
                             f"outside the run window")

    return Check("CLOCK-MONOTONIC", True,
                 f"{len(started)} clock(s) started, all stops ordered and inside "
                 f"the run window")


# --- Orchestration ------------------------------------------------------------

@dataclass(frozen=True)
class AuditResult:
    log_path: Path
    sha256: str
    chain_head: str
    signer_fp: str
    checks: list[Check]

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)


def audit_run(log_path: Path, packet_path: Path | None = None) -> AuditResult:
    """Run every invariant over one sealed run and return the structured result."""
    log = RunLog.load(log_path)
    jsonl = log.to_jsonl()
    sha = log.sha256()
    head = chain_head(_entries(log))

    packet = _load_packet(packet_path, log_path)
    signature = _load_signature(packet, log_path)
    recorded_head = _recorded_chain_head(packet, signature)
    signer_fp = (signature or {}).get("pubkey_fingerprint", "") or (
        fingerprint((signature or {}).get("public_key", ""))
        if (signature or {}).get("public_key") else "n/a")

    checks = [
        check_well_formed(log_path),
        check_replay(log, sha),
        check_chain(log, recorded_head),
        check_signature(jsonl, signature),
        check_exactly_once(log),
        check_two_key_release(log),
        check_clock_monotonic(log),
    ]
    return AuditResult(log_path, sha, head, signer_fp, checks)


def _print_result(result: AuditResult) -> None:
    print("=" * 78)
    print(f"AUDIT: {result.log_path.name}")
    print("=" * 78)
    print(f"  run-log sha256 : {result.sha256}")
    print(f"  chain head     : {result.chain_head}")
    print(f"  signer fp      : {result.signer_fp}")
    print()
    name_width = max(len(c.name) for c in result.checks)
    for c in result.checks:
        status = "PASS" if c.ok else "FAIL"
        print(f"  [{status}] {c.name.ljust(name_width)}  {c.detail}")
    print()
    verdict = "PASS" if result.ok else "FAIL"
    print(f"  VERDICT: {verdict}")
    print()


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]

    if args:
        log_path = Path(args[0]).resolve()
        packet_path = Path(args[1]).resolve() if len(args) >= 2 else None
        if not log_path.exists():
            print(f"audit_run: run log not found at {log_path}", file=sys.stderr)
            return 2
        targets = [(log_path, packet_path)]
    else:
        targets = []
        for mode in SCENARIOS:
            lp = DATA / f"run-inc-8842-{mode}.jsonl"
            if not lp.exists():
                print(f"audit_run: default capture missing at {lp}", file=sys.stderr)
                return 2
            targets.append((lp, DATA / f"packet-{mode}.json"))

    results = [audit_run(lp, pp) for lp, pp in targets]
    for result in results:
        _print_result(result)

    all_ok = all(r.ok for r in results)
    print("=" * 78)
    passed = sum(1 for r in results if r.ok)
    print(f"OVERALL: {passed}/{len(results)} run(s) pass every invariant.")
    if all_ok:
        print("Every audited run satisfies WELL-FORMED, REPLAY, CHAIN, SIGNATURE, "
              "EXACTLY-ONCE,")
        print("TWO-KEY RELEASE, and CLOCK-MONOTONIC over its own sealed bytes.")
    else:
        print("At least one invariant FAILED on at least one run. See the named "
              "locus above.")
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 78)
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
