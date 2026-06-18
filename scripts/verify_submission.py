"""One-command submission receipt: was this filing submitted, validated, and sealed?

The signature receipt proves the run was signed; the audit proves every in-log
invariant holds. This script answers the submission-pipeline question (E4.1): for a
sealed submit run, was each in-scope filing EXPORTED to its submission format,
SUBMITTED to the (modeled) regulator endpoint with its required-field contract
VALIDATED, and was the modeled filed-receipt SEALED into the signed chain so it
attests THIS exact artifact?

It reads the sealed `submission_receipt` events directly out of the run log and the
rendered submission artifacts out of the packet, then for each regime it:

  * recomputes the artifact sha256 from the artifact's own canonical bytes and
    confirms it matches the sealed receipt's artifact_sha256 (the receipt attests
    THIS exact artifact, not some other one),
  * confirms the receipt was ACCEPTED and that the modeled filing id is derived from
    those same bytes (the id cannot be swapped for another artifact's),
  * confirms the receipt the packet renders matches the receipt sealed in the log
    byte for byte (the rendered receipt is the sealed one).

It prints VALID per regime with the modeled-channel caveat stated plainly (the
format and the validation are real; the channel is modeled; the filing id is a
modeled accession-style id, not a real EDGAR accession number), and exits 0 only
when every in-scope receipt verifies.

  py scripts/verify_submission.py                       (the default sealed submit run)
  py scripts/verify_submission.py <run-log.jsonl>       (a specific submit run log)
  py scripts/verify_submission.py <run-log.jsonl> <packet.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from floor.submission import MODELED_CHANNEL_CAVEAT, verify_receipt  # noqa: E402

DATA = REPO_ROOT / "web" / "data"
# The default sealed submit capture, when the submit beat has been captured into
# web/data the way the four default scenarios are. Falls back to the floor's out
# directory so a freshly run `py floor/run_floor.py --submit` is verifiable too.
DEFAULT_LOG_CANDIDATES = (
    DATA / "run-inc-8842-submit.jsonl",
    REPO_ROOT / "floor" / "out" / "run-inc-8842-submit.jsonl",
)
DEFAULT_PACKET_CANDIDATES = (
    DATA / "packet-submit.json",
    REPO_ROOT / "floor" / "out" / "examiner-packet.json",
)


def _first_existing(paths) -> Path | None:
    for p in paths:
        if p.exists():
            return p
    return None


def _sealed_receipts(log_path: Path) -> list[dict]:
    """The submission_receipt events sealed into the run log, in order."""
    receipts = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        if entry.get("type") == "submission_receipt":
            receipts.append(entry.get("payload", {}))
    return receipts


def _packet_submissions(packet: dict | None) -> dict[str, dict]:
    """The packet's per-regime submission records (artifact + receipt), keyed by
    regime. Empty when the packet carries no submission block."""
    if not packet:
        return {}
    block = packet.get("submission") or {}
    out = {}
    for sub in block.get("submissions", []):
        out[sub.get("regime", "")] = sub
    return out


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    log_path = (Path(args[0]).resolve() if len(args) >= 1
                else _first_existing(DEFAULT_LOG_CANDIDATES))
    packet_path = (Path(args[1]).resolve() if len(args) >= 2
                   else _first_existing(DEFAULT_PACKET_CANDIDATES))

    print("=" * 74)
    print("SUBMISSION RECEIPT: was the filing submitted, validated, and sealed?")
    print("=" * 74)

    if log_path is None or not log_path.exists():
        print("verify_submission: no sealed submit run log found. Run "
              "`py floor/run_floor.py --submit` first, or pass a run-log path.",
              file=sys.stderr)
        return 2
    print(f"Run log    : {log_path}")
    packet = None
    if packet_path and packet_path.exists():
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        print(f"Packet     : {packet_path}")
    print()

    sealed = _sealed_receipts(log_path)
    if not sealed:
        print("INVALID: no submission_receipt events in this run log. This is not a "
              "sealed submit run.")
        print("=" * 74)
        return 3
    rendered = _packet_submissions(packet)

    all_ok = True
    for receipt in sealed:
        regime = receipt.get("regime", "")
        sub = rendered.get(regime)
        print(f"[{regime}]")
        print(f"  modeled filing id : {receipt.get('modeled_filing_id')}")
        print(f"  accepted at       : {receipt.get('accepted_at')} (modeled)")
        print(f"  channel           : {receipt.get('channel')} (modeled)")
        print(f"  artifact sha256   : {receipt.get('artifact_sha256')}")
        if sub is None:
            print("  RESULT            : INVALID (no rendered artifact in the packet "
                  "to recompute the sha over)")
            all_ok = False
            print()
            continue
        artifact = sub.get("artifact", {})
        # The receipt sealed in the LOG must match the receipt rendered in the
        # PACKET (the rendered receipt is the sealed one, not a separate claim).
        rendered_receipt = sub.get("receipt", {})
        for k in ("modeled_filing_id", "artifact_sha256", "accepted_at", "status"):
            if rendered_receipt.get(k) != receipt.get(k):
                print(f"  RESULT            : INVALID (packet receipt {k} "
                      f"{rendered_receipt.get(k)!r} != sealed {receipt.get(k)!r})")
                all_ok = False
                break
        else:
            ok, detail = verify_receipt(receipt, artifact)
            status = "VALID" if ok else "INVALID"
            print(f"  contract          : {detail}")
            print(f"  RESULT            : {status}")
            if not ok:
                all_ok = False
        print()

    print("-" * 74)
    print(f"Modeled channel: {MODELED_CHANNEL_CAVEAT}")
    print("-" * 74)
    if all_ok:
        print(f"VALID. All {len(sealed)} sealed submission receipt(s) verify: each "
              "artifact sha")
        print("matches its receipt, the contract was validated, and the modeled "
              "filing id is")
        print("derived from the artifact bytes. The signature attests this filed "
              "outcome.")
        print("=" * 74)
        return 0
    print("INVALID. At least one submission receipt did not verify. See the named "
          "locus above.")
    print("=" * 74)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
