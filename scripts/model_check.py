"""One-command model-check receipt: prove the gate, do not just test it.

Every "property test" in this repo is Monte Carlo: it drives the simulator with a
random schedule and observes that nothing broke. "0 double-files in 10,000 random
draws" is an estimate over a SAMPLE of the state space. This script is different.
The Warden's typed protocol is a finite automaton, so its reachable configuration
space is enumerable. This receipt does an EXHAUSTIVE breadth-first enumeration of
the WHOLE composed reachable space (the protocol state machine + the two-key
release gate + the amendment negotiation guard) and mechanically verifies a
written, named invariant set at EVERY reachable node. It reports the exact node
count it proved over, so the claim is "checked exhaustively across N reachable
states," not "0 failures in a sample."

What it prints:
  1. The named invariant set (SAFE-1..5, PROG-1) as the formal spec.
  2. The reachable-state count and edge count the enumeration covered.
  3. PASS (exit 0) when every invariant holds at every reachable node, or the
     failing invariant plus the EXACT counterexample path (exit nonzero).
  4. A determinism certificate over the reachable run space: replay is idempotent
     and the sealed (sha256, chain head) is a pure function of the event sequence.

No API keys, no network. Pure offline enumeration of the shipped transition table
and gates. The checker is a READER of warden/state_machine.py, release_gate.py,
and negotiation.py; it edits no control logic and touches no sealed artifact.

Run it:  py scripts/model_check.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from warden.modelcheck import (  # noqa: E402
    certify_determinism,
    model_check,
)


def main() -> int:
    print("=" * 72)
    print("MODEL CHECK: enumerate the reachable space, prove the invariants")
    print("=" * 72)
    print("The Warden protocol is a finite automaton. Instead of sampling it with")
    print("random schedules, this enumerates the WHOLE reachable composed state")
    print("space and checks a named invariant set at EVERY reachable node.")
    print("No API keys, no network. Pure exact enumeration of the shipped table.")
    print()

    print("The named invariant set (the formal spec the checker discharges):")
    print("  SAFE-1  no released state without BOTH distinct release keys (two-key")
    print("          segregation of duties holds on every path into released).")
    print("  SAFE-2  terminal states (suppressed, failed) are absorbing: no exit.")
    print("  SAFE-3  EVENT_AUTHORITY is total and single-valued: every event has a")
    print("          defined, non-empty authority; no role both allowed and forbidden.")
    print("  SAFE-4  a FACT_AMENDED reopen cannot re-release without a CONCUR for")
    print("          its round (amendment needs concurrence).")
    print("  SAFE-5  exactly-once at the state level: no path fires HUMAN_RELEASED")
    print("          twice for one branch without an intervening FACT_AMENDED reopen.")
    print("  PROG-1  no protocol deadlock: every reachable non-terminal node has an")
    print("          outgoing transition and can reach a terminal/released outcome.")
    print()

    t0 = time.perf_counter()
    result = model_check()
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    print("Exhaustive enumeration")
    print(f"  reachable states    : {result.reachable_states}")
    print(f"  transitions explored: {result.edges_explored}")
    print(f"  wall time           : {elapsed_ms:.1f} ms")
    print()

    print("Invariant verdicts (checked at every reachable node)")
    all_pass = True
    for inv in result.invariants:
        verdict = "PASS" if inv.passed else "FAIL"
        print(f"  {inv.invariant_id:7s} {verdict}  {inv.description}")
        if not inv.passed:
            all_pass = False
            print(f"          counterexample detail: {inv.detail}")
            if inv.counterexample_node is not None:
                print(f"          violating node : {inv.counterexample_node}")
            print("          counterexample path (from the initial state):")
            for step, label in enumerate(inv.counterexample_path, start=1):
                print(f"            {step:2d}. {label}")
    print()

    print("Determinism certificate (over the reachable run space, not a sample)")
    cert = certify_determinism()
    print(f"  run shapes checked  : {cert.paths_checked}")
    print(f"  replay idempotent   : {cert.replay_idempotent}")
    print(f"  sha is a pure fn    : {cert.sha_is_pure_function}")
    if not cert.passed:
        print(f"  detail              : {cert.detail}")
    print("  -> replay(replay(log)) == replay(log) on every enumerated run shape,")
    print("     and the sealed (sha256, chain head) is a deterministic image of the")
    print("     event sequence: proven over the whole reachable run space, not")
    print("     merely observed stable across seeds.")
    print()

    print("=" * 72)
    if all_pass and cert.passed:
        print(f"VERDICT: PASS. {len(result.invariants)} invariants (SAFE-1..5, "
              "PROG-1) hold at every one of the")
        print(f"  {result.reachable_states} reachable states; 0 counterexamples; "
              f"{result.edges_explored} transitions explored by exact")
        print("  enumeration. The determinism certificate is green. This is a")
        print("  theorem over the whole reachable space, not an estimate over a sample.")
        print("=" * 72)
        return 0

    print("VERDICT: FAIL. The exhaustive enumeration surfaced a reachable invariant")
    print("  violation. The counterexample path above is the exact illegal trace.")
    print("  Do not ship: this is a real reachability hole in the composed gate.")
    print("=" * 72)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
