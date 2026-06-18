"""Capture the submission-pipeline scenario (E4.1) as a sealed static asset.

This writes the submit-beat Examiner Packet JSON plus its matching run-log JSONL and
the detached signature sidecar into web/data/, so scripts/verify_submission.py and
scripts/audit_run.py can verify the sealed FILED-receipt loop offline, with no API
keys, against committed bytes.

It is SEPARATE from web/capture_scenarios.py (which captures the four default
scenarios) by design: the submission_receipt event INTENTIONALLY enters the hashed
run-log, so the submit beat is its OWN scenario and must never regenerate the four
default captures. This script touches only the submit-* assets.

The filings are grafted with realistic per-regime prose written INTO the real
mandated field labels (the contract a compliant drafter satisfies under
floor.formats.prompt_for), so the structured submission artifacts carry genuine
labelled sections and the required-field contract validates honestly rather than on
test-stub text. The prose is a deterministic statement per field from the canonical
fact-record (no LLM, no now()), so the capture is reproducible byte for byte.

Run from code/:  py web/capture_submit.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

_CODE = Path(__file__).resolve().parent.parent
if str(_CODE) not in sys.path:
    sys.path.insert(0, str(_CODE))

from floor.formats import format_profile_for  # noqa: E402
from floor.run_floor import CANONICAL_FACTS, DRAFTER_ROLES, run_floor  # noqa: E402
from floor.shell_adapter import FakeBandClient, FakeRoom  # noqa: E402
from warden.replay import RunLog  # noqa: E402
from warden.signing import verify_run_log_jsonl  # noqa: E402

OUT = _CODE / "web" / "data"

# The recruited UK ICO peer, discoverable over the FakeBand directory so the ICO
# branch is in scope for submission (the same peer the UK recruit tests use).
UK_PEER = {"id": "uk-ico-agent-id", "name": "UK ICO Drafter",
           "handle": "uk_ico_drafter"}

# Branch -> format profile id for every drafter that files in the submit beat.
_PROFILE_BY_BRANCH = {
    "nis2": "nis2_full", "sec": "sec_8k", "dora": "dora", "uk": "ico_art33",
}


def _field_prose(label: str, facts: dict) -> str:
    """A deterministic, realistic statement for one mandated field, from the
    canonical fact-record. Written the way a compliant drafter fills the labelled
    slot, so the submission artifact carries genuine content and the field contract
    validates honestly. Pure string assembly: no LLM, no now()."""
    records = f"{facts['records_affected']:,}"
    entity = facts["regulated_entity"]
    attacker = facts["attacker"]
    systems = ", ".join(facts["systems"])
    start = facts["incident_start_utc"]
    containment = facts["containment"].replace("_", " ")
    catalog = {
        # SEC 8-K Item 1.05
        "Nature of the incident": (
            f"{entity} experienced a cybersecurity incident attributed to the threat "
            f"actor {attacker}, affecting its {systems}."),
        "Scope of the incident": (
            f"The incident affected approximately {records} records across the "
            f"affected systems ({systems})."),
        "Timing of the incident": (
            f"The incident began {start}; containment status is {containment} as of "
            f"this filing."),
        "Material impact or reasonably likely material impact": (
            "The registrant is assessing the material impact, or reasonably likely "
            "material impact, on its financial condition and results of operations, "
            "confined to what the fact-record supports."),
        # NIS2 Article 23 incident notification
        "Initial severity and impact assessment": (
            f"A significant incident affecting {records} records of {entity} was "
            f"assessed as high severity; the {systems} were impacted."),
        "Indicators of compromise": (
            f"Known indicators: threat actor {attacker}; affected systems {systems}."),
        "Suspected unlawful or malicious act and cross-border impact": (
            "The incident is suspected to be a malicious act; cross-border impact is "
            "possible given the entity's EU and UK establishments."),
        # ICO Article 33(3)
        "Nature of the breach": (
            f"A personal data breach at {entity} attributed to {attacker} affected "
            f"the {systems}."),
        "Categories and approximate number of data subjects and records": (
            f"Approximately {records} records and their data subjects "
            f"({', '.join(facts['data_categories'])}) were concerned."),
        "Likely consequences": (
            "The likely consequences include risk to the affected individuals from "
            "exposure of the categories of personal data involved."),
        "Measures taken or proposed": (
            f"Containment is {containment}; remediation and notification measures are "
            "underway to mitigate the breach's adverse effects."),
    }
    return catalog.get(label, "Stated from the fact-record for this field.")


def _labelled_prose(branch: str) -> str:
    """Realistic filing prose for a branch, every mandated field as its own labelled
    section (the exact label from the format profile followed by a colon), built
    deterministically from the canonical fact-record."""
    profile = format_profile_for(_PROFILE_BY_BRANCH[branch])
    lines = [profile.cover_tag, ""]
    for f in profile.fields:
        lines.append(f"{f.label}: {_field_prose(f.label, CANONICAL_FACTS)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _build_clients():
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    clients["uk"] = FakeBandClient(room, UK_PEER["id"], "uk_drafter", "draft:uk")
    room.directory.append(UK_PEER)
    return room, clients


def _draft_fns():
    fns = {r.branch: (lambda b: (lambda _facts: _labelled_prose(b)))(r.branch)
           for r in DRAFTER_ROLES}
    fns["uk"] = lambda _facts: _labelled_prose("uk")
    return fns


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    room, clients = _build_clients()
    packet = run_floor(out_dir=str(OUT), mode="submit", clients=clients,
                       draft_fns=_draft_fns())

    # Name the packet for the submit scenario and drop the generic html.
    src = OUT / "examiner-packet.json"
    dst = OUT / "packet-submit.json"
    shutil.move(str(src), str(dst))
    html = OUT / "examiner-packet.html"
    if html.exists():
        html.unlink()

    log_path = OUT / "run-inc-8842-submit.jsonl"
    log = RunLog.load(log_path)
    assert log.sha256() == packet["replay"]["original_sha256"], \
        "submit: bundled log hash does not match packet replay hash"
    assert packet["replay"]["byte_identical"] is True, "submit: replay not byte-identical"

    # Write the detached signature sidecar beside the run log (the same sidecar the
    # four default captures carry), so the verifier and audit find it offline.
    signature = packet["replay"]["signature"]
    assert verify_run_log_jsonl(log.to_jsonl(), signature), \
        "submit: the packet signature does not verify over the run-log bytes"
    sidecar = log_path.with_suffix(log_path.suffix + ".sig.json")
    sidecar.write_text(json.dumps(signature, indent=2) + "\n", encoding="utf-8")

    receipts = [s["receipt"]["modeled_filing_id"]
                for s in packet["submission"]["submissions"]]
    print("Captured submit scenario into", OUT)
    print(f"  run-log sha {packet['replay']['original_sha256']}")
    print(f"  sealed receipts: {', '.join(receipts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
