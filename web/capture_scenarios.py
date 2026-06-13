"""Capture the four Deadline Room scenarios as static assets for the replay viewer.

This writes one Examiner Packet JSON plus its matching run-log JSONL per scenario
into web/data/, so the hosted viewer (web/index.html) can load real captured runs
and re-verify each replay hash in the browser against the bundled log.

The amendment scenario is the real live capture (real Band ids, real Featherless
models, real filing prose, sha 157e8f08...): it is copied verbatim from
floor/out/examiner-packet.json and floor/out/run-inc-8842-amendment.jsonl.

The normal, contradiction, and chaos scenarios are regenerated through the same
floor orchestration over the in-process fake Band so this script is reproducible
offline with no API keys. Each packet's original_sha256 matches the sha256 of its
own bundled run log, so the viewer's in-browser verify is exact and honest. The
regulator-facing filing prose from the live amendment capture is grafted in by
regime (same incident, same drafters, same models) so the rendered filings read as
real regulatory notifications rather than test stubs. Filing text is not part of
the run log, so grafting prose never changes the verifiable replay hash.

Run from code/:  py web/capture_scenarios.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

_CODE = Path(__file__).resolve().parent.parent
if str(_CODE) not in sys.path:
    sys.path.insert(0, str(_CODE))

from floor.run_floor import DRAFTER_ROLES, run_floor  # noqa: E402
from floor.shell_adapter import FakeBandClient, FakeRoom  # noqa: E402
from warden.replay import RunLog  # noqa: E402

OUT = _CODE / "web" / "data"
LIVE_PACKET = _CODE / "floor" / "out" / "examiner-packet.json"
LIVE_AMEND_LOG = _CODE / "floor" / "out" / "run-inc-8842-amendment.jsonl"


def _build_clients():
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    return room, clients


def _real_prose_by_regime() -> dict:
    """Pull the genuine round-1 Featherless filing prose from the live amendment
    capture, keyed by regime. These are the real notifications the live drafters
    produced for inc-8842."""
    live = json.loads(LIVE_PACKET.read_text(encoding="utf-8"))
    prose = {}
    for f in live["filings"]:
        # first filing per regime is the round-1 draft (amended re-files come later)
        prose.setdefault(f["regime"], f["text"])
    return prose


def _stub_draft_fns(prose: dict):
    """Drafter stubs that return the real captured prose for each regime, so the
    structured [CLAIMS] block the floor appends is parsed off genuine text."""
    def make(regime):
        text = prose.get(regime, "")

        def fn(claim_facts):
            return text
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def _capture(mode: str, prose: dict) -> dict:
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(OUT), mode=mode, clients=clients,
                       draft_fns=_stub_draft_fns(prose))
    # The floor wrote examiner-packet.json (generic name) and the run log. Move the
    # packet to a scenario-specific name and keep the matching run log.
    src = OUT / "examiner-packet.json"
    dst = OUT / f"packet-{mode}.json"
    shutil.move(str(src), str(dst))
    # Drop the generic html the floor also wrote; the viewer renders from JSON.
    html = OUT / "examiner-packet.html"
    if html.exists():
        html.unlink()
    # Verify the hash the packet claims matches its own bundled run log.
    log = RunLog.load(OUT / f"run-inc-8842-{mode}.jsonl")
    assert log.sha256() == packet["replay"]["original_sha256"], \
        f"{mode}: bundled log hash does not match packet replay hash"
    return packet


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    prose = _real_prose_by_regime()

    captured = {}
    for mode in ("normal", "inject_contradiction", "chaos"):
        p = _capture(mode, prose)
        captured[mode] = p["replay"]["original_sha256"]

    # Amendment: copy the real live capture verbatim, packet + run log.
    shutil.copyfile(LIVE_PACKET, OUT / "packet-amendment.json")
    shutil.copyfile(LIVE_AMEND_LOG, OUT / "run-inc-8842-amendment.jsonl")
    amend = json.loads((OUT / "packet-amendment.json").read_text(encoding="utf-8"))
    amend_log = RunLog.load(OUT / "run-inc-8842-amendment.jsonl")
    assert amend_log.sha256() == amend["replay"]["original_sha256"], \
        "amendment: bundled log hash does not match packet replay hash"
    captured["amendment"] = amend["replay"]["original_sha256"]

    manifest = {
        "incident_id": "inc-8842",
        "scenarios": [
            {"id": "normal", "label": "Normal run",
             "packet": "data/packet-normal.json",
             "run_log": "data/run-inc-8842-normal.jsonl",
             "blurb": "Three regimes draft, claims agree, the contradiction diff is "
                      "green, every clock stops on release."},
            {"id": "inject_contradiction", "label": "Contradiction block",
             "packet": "data/packet-inject_contradiction.json",
             "run_log": "data/run-inc-8842-inject_contradiction.jsonl",
             "blurb": "One filing disagrees on the incident start time. The Warden's "
                      "deterministic diff turns red and refuses signoff, then clears "
                      "once the fact is corrected."},
            {"id": "chaos", "label": "Exactly-once under kill",
             "packet": "data/packet-chaos.json",
             "run_log": "data/run-inc-8842-chaos.jsonl",
             "blurb": "A drafter is killed after posting but before acking. On "
                      "restart the dedup ledger drops the duplicate, so the filing "
                      "lands exactly once."},
            {"id": "amendment", "label": "Amendment reconciliation (live capture)",
             "packet": "data/packet-amendment.json",
             "run_log": "data/run-inc-8842-amendment.jsonl",
             "blurb": "After release a load-bearing fact is revised. Two drafters "
                      "reconcile through Band over hash-linked envelopes; the amended "
                      "diff stays blocked until they concur."},
        ],
    }
    (OUT / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print("Captured scenarios into", OUT)
    for mode, sha in captured.items():
        print(f"  {mode:22s} sha {sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
