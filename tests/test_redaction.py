"""test_redaction.py -- the publish-layer PII redaction (E9.5).

The published Examiner Packet (rendered to a shared room and a hosted web URL)
must mask PII-class fact-record field values while keeping every statutory fact
and the [CLAIMS] block the Warden gated on verbatim. These tests prove:

  1. redact_fact_record masks only the PII-class fields, by value, deep-copied,
     and reports exactly which fields it masked.
  2. The statutory facts and the filing identity survive verbatim.
  3. redact_packet_for_publication is pure and additive: the input packet is
     never mutated, the replay hash is untouched, the [CLAIMS] block inside the
     filings is byte-for-byte unchanged, and a redaction receipt is attached.
  4. write_packet(publish=True) renders the masked fact-record and the receipt
     into both the JSON sidecar and the HTML, while the default write is
     unredacted, so the run-log seal and the existing presentation are unchanged.
"""

import json
from pathlib import Path

from floor.packet import write_packet
from floor.redaction import (
    PII_FACT_FIELDS,
    REDACTION_MASK,
    redact_fact_record,
    redact_packet_for_publication,
    redaction_receipt,
)
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom

# The load-bearing statutory facts and the filing identity that MUST stay verbatim
# in a published packet (a regulator still gets the real numbers and the named
# reporting entity).
STATUTORY_FIELDS = (
    "incident_id",
    "incident_start_utc",
    "records_affected",
    "attacker",
    "containment",
    "regulated_entity",
    "competent_authority",
)


def _sample_fact_record():
    return {
        "incident_id": "inc-8842",
        "incident_start_utc": "2026-06-16T02:14:00+00:00",
        "records_affected": 48211,
        "attacker": "LockBit 3.0",
        "containment": "partially_contained",
        "systems": ["core banking ledger", "customer KYC store"],
        "data_categories": ["name", "address", "account_number"],
        "regulated_entity": "Meridian Trust Bank N.V.",
        "competent_authority": "national CSIRT (NIS2)",
        "blast_radius": ["EU: Meridian Trust Bank N.V."],
    }


# ---- 1. The field-level pass masks PII by value, reports the masked fields ----

def test_redact_fact_record_masks_pii_fields():
    fr = _sample_fact_record()
    redacted, masked = redact_fact_record(fr)
    # Every PII-class field present is masked, element by element, length kept.
    assert redacted["systems"] == [REDACTION_MASK, REDACTION_MASK]
    assert redacted["data_categories"] == [REDACTION_MASK] * 3
    # The masked-field list names exactly the PII-class fields that were present.
    assert masked == sorted(["data_categories", "systems"])
    assert set(masked) <= PII_FACT_FIELDS


def test_redact_fact_record_keeps_statutory_verbatim():
    fr = _sample_fact_record()
    redacted, _ = redact_fact_record(fr)
    for field in STATUTORY_FIELDS:
        assert redacted[field] == fr[field], field


def test_redact_fact_record_is_pure():
    fr = _sample_fact_record()
    snapshot = json.dumps(fr, sort_keys=True)
    redact_fact_record(fr)
    # The input dict (and its nested lists) is never mutated.
    assert json.dumps(fr, sort_keys=True) == snapshot


def test_redact_fact_record_only_masks_present_fields():
    fr = {"records_affected": 5, "systems": ["a"]}
    _, masked = redact_fact_record(fr)
    # data_categories is in the catalogue but absent here, so it is not reported.
    assert masked == ["systems"]


# ---- 2. The receipt is honest about what it masked --------------------------

def test_redaction_receipt_counts_and_names():
    receipt = redaction_receipt(["data_categories", "systems"])
    assert receipt["redacted_field_count"] == 2
    assert receipt["redacted_fields"] == ["data_categories", "systems"]
    assert receipt["summary"] == "2 fields redacted for publication"
    assert "verbatim" in receipt["note"]


def test_redaction_receipt_zero_fields_is_honest():
    receipt = redaction_receipt([])
    assert receipt["redacted_field_count"] == 0
    assert receipt["summary"] == "0 fields redacted for publication"


# ---- 3. The packet-level pass is pure, additive, and seal-safe --------------

def _normal_packet(tmp_path):
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")

    def make(regime):
        def fn(claim_facts):
            return (f"{regime} mandatory notification. Meridian Trust Bank N.V. "
                    f"reports an incident starting {claim_facts['incident_start_utc']} "
                    f"affecting {claim_facts['records_affected']} records, attacker "
                    f"{claim_facts['attacker']}, containment "
                    f"{claim_facts['containment']}. Deterministic test stub.")
        return fn
    fns = {r.branch: make(r.regime) for r in DRAFTER_ROLES}
    return run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                     draft_fns=fns)


def test_redact_packet_is_pure_and_seal_safe(tmp_path):
    packet = _normal_packet(tmp_path)
    before = json.dumps({k: v for k, v in packet.items() if k != "_paths"},
                        sort_keys=True, default=str)
    published = redact_packet_for_publication(
        {k: v for k, v in packet.items() if k != "_paths"})
    after = json.dumps({k: v for k, v in packet.items() if k != "_paths"},
                       sort_keys=True, default=str)
    # The input packet is not mutated by the pass.
    assert before == after
    # The replay hash is carried through verbatim: redaction never moves the seal.
    assert published["replay"]["original_sha256"] == \
        packet["replay"]["original_sha256"]
    # The fact-record in the published packet is masked.
    pfr = published["incident"]["fact_record"]
    assert pfr["systems"] == [REDACTION_MASK, REDACTION_MASK]
    assert pfr["data_categories"] == [REDACTION_MASK] * 3
    # The receipt is attached and accurate.
    assert published["redaction"]["redacted_field_count"] == 2


def test_published_packet_keeps_claims_block_verbatim(tmp_path):
    packet = _normal_packet(tmp_path)
    published = redact_packet_for_publication(packet)
    # Every filing's [CLAIMS] block (the bytes the Warden parsed and gated on) is
    # byte-for-byte identical between the unredacted and the published packet.
    for original, pub in zip(packet["filings"], published["filings"]):
        o_text, p_text = original["text"], pub["text"]
        assert "[CLAIMS]" in o_text
        oi = o_text.index("[CLAIMS]")
        pi = p_text.index("[CLAIMS]")
        assert o_text[oi:] == p_text[pi:]
        # The statutory figures inside the claims survive.
        assert "records_affected=48211" in p_text


def test_published_packet_keeps_statutory_facts_verbatim(tmp_path):
    packet = _normal_packet(tmp_path)
    published = redact_packet_for_publication(packet)
    pfr = published["incident"]["fact_record"]
    ofr = packet["incident"]["fact_record"]
    for field in STATUTORY_FIELDS:
        assert pfr[field] == ofr[field], field


# ---- 4. write_packet(publish=...) is the render/publish seam ----------------

def test_write_packet_publish_masks_pii_in_json_and_html(tmp_path):
    packet = _normal_packet(tmp_path)
    json_path, html_path = write_packet(
        packet, tmp_path, stem="published", publish=True)
    sidecar = json.loads(Path(json_path).read_text(encoding="utf-8"))
    html = Path(html_path).read_text(encoding="utf-8")
    # PII masked in the published JSON sidecar.
    assert sidecar["incident"]["fact_record"]["systems"] == \
        [REDACTION_MASK, REDACTION_MASK]
    # The raw PII strings do not appear in the published HTML fact-record block.
    assert "core banking ledger" not in html
    assert "account_number" not in html
    # The mask and the receipt summary do appear.
    assert REDACTION_MASK in html
    assert "2 fields redacted for publication" in html
    # Statutory facts and the named reporting entity survive in the published HTML.
    assert "Meridian Trust Bank N.V." in html
    assert "48211" in html


def test_write_packet_default_is_unredacted(tmp_path):
    packet = _normal_packet(tmp_path)
    json_path, html_path = write_packet(packet, tmp_path, stem="plain")
    sidecar = json.loads(Path(json_path).read_text(encoding="utf-8"))
    html = Path(html_path).read_text(encoding="utf-8")
    # The default write carries the real PII and no redaction receipt, so the
    # legacy artifact and the run-log seal are unchanged.
    assert sidecar["incident"]["fact_record"]["systems"] == \
        ["core banking ledger", "customer KYC store"]
    assert "redaction" not in sidecar
    assert "core banking ledger" in html
    assert REDACTION_MASK not in html
