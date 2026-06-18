"""One-command separation-of-duties matrix: the SoD proof across the whole run, on the terminal.

The two-key release gate proves segregation of duties on ONE action: a filing
cannot release without two distinct human keys. An auditor's SoD question is
broader: prove that across the ENTIRE run no single identity ever spanned a pair
of duties that must stay separated, authoring a filing AND releasing it, or gating
a filing AND authoring it. This script prints that proof for a captured packet: the
observed actor x action matrix (per identity, its role(s), duty class, and protocol
actions) and the named SoD invariants, each PASS / FAIL with its basis.

It derives the matrix PURELY from the assembled packet (floor/sod.py over
packet["state_transitions"] + packet["release"]["signoffs"]). No LLM, no now(), no
run-log mutation: it is a read-only render over the packet the examiner receives,
speaking the same role vocabulary the Warden's authority table defines.

The matrix is the real check, not a decoration: a genuine SoD violation makes its
invariant FAIL and names the violating actor. Exit 0 only when every SoD invariant
holds; exit 1 when an invariant FAILS (a real violation) or the packet exercised no
separation-of-duties path.

  py scripts/sod_matrix.py                 (the default sealed normal packet)
  py scripts/sod_matrix.py <packet.json>   (a specific packet)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.sod import sod_record  # noqa: E402

DATA = REPO_ROOT / "web" / "data"
# The normal capture carries the full released filing set (three branches, two-key
# release on each), so it is a complete SoD receipt; fall back to the submit capture
# and then a freshly run floor packet.
DEFAULT_PACKET_CANDIDATES = (
    DATA / "packet-normal.json",
    DATA / "packet-submit.json",
    REPO_ROOT / "floor" / "out" / "examiner-packet.json",
)

_BADGE = {"PASS": "PASS", "FAIL": "FAIL"}


def _first_existing(paths) -> Path | None:
    for p in paths:
        if p.exists():
            return p
    return None


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    packet_path = (Path(args[0]).resolve() if args
                   else _first_existing(DEFAULT_PACKET_CANDIDATES))

    print("=" * 78)
    print("SEPARATION-OF-DUTIES MATRIX: proven across the whole run")
    print("=" * 78)

    if packet_path is None or not packet_path.exists():
        print("sod_matrix: no packet found. Run `py floor/run_floor.py` first, "
              "or pass a packet.json path.", file=sys.stderr)
        return 2
    print(f"Packet : {packet_path}")
    print()

    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    # Prefer the sod block the packet already carries (derived at assembly); if absent
    # (an older packet), derive it now from the same pure function.
    record = packet.get("sod") or sod_record(packet)
    invariants = record.get("invariants", []) if record else []
    if not invariants:
        print("NOT PROVEN: this packet exercised no separation-of-duties path "
              "(no release, no draft to segregate).")
        print("=" * 78)
        return 1

    # The observed actor x action matrix.
    print("Actor x action matrix (identity, role(s), duty class, protocol actions):")
    print()
    actors = record.get("actors", [])
    actor_w = max((len(a.get("actor", "")) for a in actors), default=5)
    role_w = max((len(", ".join(a.get("roles", []))) for a in actors), default=4)
    duty_w = max((len(", ".join(a.get("duties", []))) for a in actors), default=4)
    for a in actors:
        actor = a.get("actor", "")
        roles = ", ".join(a.get("roles", []))
        duties = ", ".join(a.get("duties", []))
        actions = ", ".join(a.get("actions", []))
        print(f"  {actor.ljust(actor_w)}  [{roles.ljust(role_w)}]  "
              f"({duties.ljust(duty_w)})  {actions}")
    print()

    # The named SoD invariants.
    print("Separation-of-duties invariants (each asserted on every path):")
    print()
    for inv in invariants:
        badge = _BADGE.get(inv.get("status", ""), inv.get("status", ""))
        print(f"  [{badge}]  {inv.get('id', '')}: {inv.get('title', '')}")
        print(f"            {inv.get('detail', '')}")
        print()

    print("-" * 78)
    print(record.get("verdict", ""))
    if record.get("all_hold", False):
        print("Every separation-of-duties invariant holds across the whole run; no")
        print("identity spanned a conflicting pair of duties. An auditor re-derives the")
        print("same matrix from the sealed packet bytes.")
        print("=" * 78)
        return 0
    print("At least one separation-of-duties invariant FAILED: an identity spanned a")
    print("conflicting pair of duties (see the named row). This is a real violation, "
          "not green-washed.")
    print("=" * 78)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
