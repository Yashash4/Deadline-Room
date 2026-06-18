"""One-command control-evidence register: the audit-committee receipt, on the terminal.

An auditor does not ask "did it file on time". They ask which named control
framework each Warden mechanism satisfies, where the run evidence is that the
control OPERATED, and what immutable artifact seals it. This script prints that
register for a captured packet: per control, the Warden mechanism, the specific
named controls it satisfies across SOC 2, ISO/IEC 27001:2022, and NIST CSF 2.0,
the run-log evidence (the event type(s) found in this run, sealed at the chain
head), and an OPERATED / NOT-EXERCISED status.

It derives the register PURELY from the assembled packet (floor/controls.py +
the declarative floor/controls.yaml catalog): it reads the structured mirror of
the sealed run-log (release.signoffs, diff.blocked_conflicts, chaos.ledger,
clocks, reportability, replay.chain_head + signature). No LLM, no now(), no
run-log mutation: it is a read-only render over the packet the examiner receives.

NOT-EXERCISED is honest, not a failure: it states this run's scenario did not
exercise that control path (for example the contradiction veto on a run with no
planted contradiction). Exit 0 when at least one control OPERATED and is
evidenced; exit 1 when the packet carries no catalogued control or none operated.

  py scripts/control_register.py                 (the default sealed normal packet)
  py scripts/control_register.py <packet.json>   (a specific packet)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.controls import controls_record  # noqa: E402

DATA = REPO_ROOT / "web" / "data"
# The inject_contradiction capture exercises the most controls (the veto fires),
# so it is the most complete receipt; fall back to the normal capture and then a
# freshly run floor packet.
DEFAULT_PACKET_CANDIDATES = (
    DATA / "packet-inject_contradiction.json",
    DATA / "packet-normal.json",
    REPO_ROOT / "floor" / "out" / "examiner-packet.json",
)

_BADGE = {"OPERATED": "OPERATED     ", "NOT-EXERCISED": "NOT-EXERCISED"}


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
    print("CONTROL-EVIDENCE REGISTER: named-framework control mapping")
    print("=" * 78)

    if packet_path is None or not packet_path.exists():
        print("control_register: no packet found. Run `py floor/run_floor.py` "
              "first, or pass a packet.json path.", file=sys.stderr)
        return 2
    print(f"Packet : {packet_path}")
    print()

    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    # Prefer the controls block the packet already carries (derived at assembly);
    # if absent (an older packet), derive it now from the same pure function.
    record = packet.get("controls") or controls_record(packet)
    controls = record.get("controls", []) if record else []
    if not controls:
        print("EMPTY: this packet carries no catalogued control to evaluate.")
        print("=" * 78)
        return 1

    chain_head = ""
    for c in controls:
        head = (c.get("evidence", {}) or {}).get("chain_head")
        if head:
            chain_head = head
            break
    if chain_head:
        print(f"Run evidence seal (per-entry hash chain head): {chain_head}")
        print("Every OPERATED control's evidence is bound to this head and the")
        print("detached Ed25519 signature over it.")
        print()

    for c in controls:
        badge = _BADGE.get(c.get("status", ""), c.get("status", ""))
        print(f"[{badge}]  {c.get('id', '')}: {c.get('title', '')}")
        print(f"    Mechanism : {c.get('mechanism', '')}")
        for fw in c.get("frameworks", []):
            print(f"    Framework : {fw.get('standard', '')} {fw.get('ref', '')}"
                  f"  ({fw.get('criterion', '')})")
        ev = c.get("evidence", {}) or {}
        found = ev.get("found_events", []) or []
        if found:
            print(f"    Evidence  : {', '.join(found)}")
            print(f"                {ev.get('detail', '')}")
        else:
            print(f"    Evidence  : {ev.get('detail', '')}")
        print()

    print("-" * 78)
    print(record.get("verdict", ""))
    if record.get("operated_count", 0) > 0:
        print("Each OPERATED control maps to its named framework ids and points the")
        print("evidence at the run-log event(s) sealed at the chain head; an auditor")
        print("re-derives the same register from the sealed bytes.")
        print("=" * 78)
        return 0
    print("No control was exercised by this run's scenario.")
    print("=" * 78)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
