"""One-command cross-filing consistency sheet: the examiner's cross-read, on the terminal.

When the same incident is filed to several regulators, the examiner CROSS-READS the
filings: a records count or incident_start that differs across filings is a referral.
The contradiction veto catches the BLOCKING conflicts internally; this script prints
the affirmative CONSISTENCY ATTESTATION an examiner wants, that the load-bearing facts
are IDENTICAL across all N filings, with each shared value shown once, a per-fact
CONSISTENT / CONFLICT status, and the overall verdict.

It derives the sheet PURELY from the packet's already-reconciled claims
(packet["diff"]["final_claims"], via floor/consistency.py), computed through the SAME
warden/diff.py canonicalization the veto uses (so a timezone-equivalent value is still
CONSISTENT). No LLM, no now(), no run-log mutation: it is a read-only render over the
packet the examiner receives.

Exit 0 only when every load-bearing fact is CONSISTENT across two or more filings.
Exit 1 when a fact conflicts (or nothing was cross-read).

  py scripts/consistency_sheet.py                 (the default sealed submit packet)
  py scripts/consistency_sheet.py <packet.json>   (a specific packet)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.consistency import consistency_record  # noqa: E402

DATA = REPO_ROOT / "web" / "data"
# The submit capture carries the full reconciled filing set (four regimes), so it is
# the default; fall back to a freshly run floor packet.
DEFAULT_PACKET_CANDIDATES = (
    DATA / "packet-submit.json",
    REPO_ROOT / "floor" / "out" / "examiner-packet.json",
)

_BADGE = {"CONSISTENT": "CONSISTENT", "CONFLICT": "CONFLICT  "}


def _first_existing(paths) -> Path | None:
    for p in paths:
        if p.exists():
            return p
    return None


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    packet_path = (Path(args[0]).resolve() if args
                   else _first_existing(DEFAULT_PACKET_CANDIDATES))

    print("=" * 74)
    print("CROSS-FILING CONSISTENCY SHEET: the examiner's cross-read")
    print("=" * 74)

    if packet_path is None or not packet_path.exists():
        print("consistency_sheet: no packet found. Run "
              "`py floor/run_floor.py --submit` first, or pass a packet.json path.",
              file=sys.stderr)
        return 2
    print(f"Packet : {packet_path}")
    print()

    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    # Prefer the consistency block the packet already carries (derived at assembly);
    # if absent (an older packet), derive it now from the same pure function.
    record = packet.get("consistency") or consistency_record(packet)
    facts = record.get("facts", []) if record else []
    if not facts:
        print("NOT CROSS-READ: this packet carries fewer than two filings' claims "
              "(nothing to cross-read across).")
        print("=" * 74)
        return 1

    filings = ", ".join(record.get("filings", []))
    consistent = record.get("consistent", False)
    print(f"Filings cross-read ({record.get('filing_count', 0)}): {filings}")
    print()
    for fact in facts:
        badge = _BADGE.get(fact.get("status", ""), fact.get("status", ""))
        label = fact.get("label", fact.get("fact", ""))
        if fact.get("status") == "CONSISTENT":
            print(f"  {badge}  {label}: {fact.get('agreed_value')}")
            print(f"             asserted identically by: "
                  f"{', '.join(fact.get('filings', []))}")
        else:
            print(f"  {badge}  {label}: CONFLICT")
            for p in fact.get("conflict", []):
                print(f"             {p.get('filing')} says {p.get('value')}")
        print()

    print("-" * 74)
    print(record.get("verdict", ""))
    if consistent:
        print("Every load-bearing fact is asserted identically across the filing set; "
              "an examiner")
        print("cross-reading the filings finds no mismatch.")
        print("=" * 74)
        return 0
    print("At least one load-bearing fact conflicts across the filings; an examiner "
          "would refer")
    print("this, and the contradiction veto blocks release on the same conflict.")
    print("=" * 74)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
