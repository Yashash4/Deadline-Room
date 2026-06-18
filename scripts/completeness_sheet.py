"""One-command completeness sheet: the examiner's first auto-screen, on the terminal.

An examiner's intake system does not read the prose first. It auto-screens the
STRUCTURED submission against each regime's mandated fields, and only a complete
submission routes to a human; an empty mandated field draws a deficiency notice.
This script prints that screen for a captured packet: per regime, the green/amber
PRESENT / EMPTY / NOT-APPLICABLE matrix over the EXACT mandated field labels the form
defines, with the per-regime complete/incomplete verdict and the overall verdict.

It derives the sheet PURELY from the packet's drafted filings (floor/completeness.py):
it reads the labelled sections from the filing prose against the mandated-field labels
drawn from the same regime catalog that drives the statutory clocks. No LLM, no now(),
no run-log mutation: it is a read-only render over the packet the examiner receives.

Exit 0 only when every owed (applicable) regime is COMPLETE: every mandated field of
every regime that owes a filing is present. Exit 1 when a mandated field is empty.

  py scripts/completeness_sheet.py                 (the default sealed submit packet)
  py scripts/completeness_sheet.py <packet.json>   (a specific packet)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.completeness import completeness_record  # noqa: E402

DATA = REPO_ROOT / "web" / "data"
# The submit capture carries fully labelled filings (the examiner's structured form),
# so it is the default; fall back to a freshly run floor packet.
DEFAULT_PACKET_CANDIDATES = (
    DATA / "packet-submit.json",
    REPO_ROOT / "floor" / "out" / "examiner-packet.json",
)

_BADGE = {"PRESENT": "PRESENT", "EMPTY": "EMPTY  ", "NA": "N/A    "}


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
    print("COMPLETENESS SHEET: the examiner's first auto-screen")
    print("=" * 74)

    if packet_path is None or not packet_path.exists():
        print("completeness_sheet: no packet found. Run "
              "`py floor/run_floor.py --submit` first, or pass a packet.json path.",
              file=sys.stderr)
        return 2
    print(f"Packet : {packet_path}")
    print()

    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    # Prefer the completeness block the packet already carries (derived at assembly);
    # if absent (an older packet), derive it now from the same pure function.
    record = packet.get("completeness") or completeness_record(packet)
    sheets = record.get("sheets", []) if record else []
    if not sheets:
        print("INCOMPLETE: this packet carries no screenable filing (no regime named "
              "a known mandated-field form).")
        print("=" * 74)
        return 1

    all_complete = record.get("all_complete", False)
    for sheet in sheets:
        regime = sheet.get("regime", "")
        print(f"[{regime}] {sheet.get('form_title', '')}")
        print(f"  {sheet.get('verdict', '')}")
        for fld in sheet.get("fields", []):
            badge = _BADGE.get(fld.get("status", ""), fld.get("status", ""))
            print(f"    {badge}  {fld.get('label', '')}")
        print()

    print("-" * 74)
    if all_complete:
        print("COMPLETE. Every mandated field of every owed regime is present; the "
              "structured")
        print("submission clears the automated intake completeness screen.")
        print("=" * 74)
        return 0
    print("INCOMPLETE. At least one mandated field is empty; a real intake desk "
          "would return")
    print("a deficiency notice naming the empty field above.")
    print("=" * 74)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
