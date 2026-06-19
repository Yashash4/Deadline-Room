"""test_privilege.py -- the privilege / work-product designation (E4.10).

The PRIVILEGE / WORK-PRODUCT designation splits the war-room record into a
DISCLOSABLE set (the filings + the statutory-required content, produced to a
regulator) and a PRIVILEGED set (the internal legal deliberation: the materiality
/ reportability rationale, the determination memos, the reconciliation, the
Challenger critique, the legal-hold counsel direction), each tagged with its
privilege basis (privileged legal advice / attorney work-product). It is a pure
derived classification keyed ENTIRELY by the run-log event type, never an LLM
judging privilege, exactly like the control-evidence register (E4.4) and the
separation-of-duties matrix (E4.5).

Layers:

  Map layer over PRIVILEGE_CLASS: every event type maps to a real basis; the four
  bases roll into exactly one of the two top-level sets.

  Unit layer over floor/privilege.py: a packet's artifacts are sorted into the
  disclosable and privileged sets by their event type; the privileged set is never
  leaked into the disclosable set; the work-product banner travels with the
  privileged set.

  Render layer over the packet HTML: the two-bucket split renders with the banner.

  Derived layer: no LLM surface, no run-log mutation, deterministic across runs.

  Guard layer: the four DEFAULT sealed captures and their run-log shas are
  byte-for-byte unchanged by this render/derive-only feature.
"""

import hashlib
import inspect
import json
from pathlib import Path

import floor.privilege as privilege_mod
from floor.privilege import (
    BASIS_DISCLOSABLE_FILING,
    BASIS_NON_PRIVILEGED_REGULATORY,
    BASIS_PRIVILEGED_LEGAL,
    BASIS_WORK_PRODUCT,
    PRIVILEGE_BANNER,
    PRIVILEGE_CLASS,
    SET_DISCLOSABLE,
    SET_PRIVILEGED,
    _SET_FOR_BASIS,
    designate,
    privilege_record,
)

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "web" / "data"
DEFAULT_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


def _packet(mode: str) -> dict:
    return json.loads((DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))


# ---- map layer: the classification table is sound ---------------------------

def test_every_event_maps_to_a_real_basis():
    valid = {BASIS_PRIVILEGED_LEGAL, BASIS_WORK_PRODUCT,
             BASIS_DISCLOSABLE_FILING, BASIS_NON_PRIVILEGED_REGULATORY}
    assert PRIVILEGE_CLASS, "the classification table must not be empty"
    for event, basis in PRIVILEGE_CLASS.items():
        assert basis in valid, f"{event} maps to an unknown basis {basis!r}"


def test_each_basis_rolls_into_exactly_one_set():
    for basis in (BASIS_PRIVILEGED_LEGAL, BASIS_WORK_PRODUCT,
                  BASIS_DISCLOSABLE_FILING, BASIS_NON_PRIVILEGED_REGULATORY):
        assert basis in _SET_FOR_BASIS
    # The privileged bases roll into the privileged set; the rest into disclosable.
    assert _SET_FOR_BASIS[BASIS_PRIVILEGED_LEGAL] == SET_PRIVILEGED
    assert _SET_FOR_BASIS[BASIS_WORK_PRODUCT] == SET_PRIVILEGED
    assert _SET_FOR_BASIS[BASIS_DISCLOSABLE_FILING] == SET_DISCLOSABLE
    assert _SET_FOR_BASIS[BASIS_NON_PRIVILEGED_REGULATORY] == SET_DISCLOSABLE


def test_the_legal_judgment_events_are_privileged():
    # The materiality / reportability rationale and the determination memos are the
    # post-Capital-One discovery trap: they must be classified privileged legal
    # advice, NOT disclosable.
    for event in ("materiality", "reportability", "determination_record",
                  "legal_hold_attached", "cross_border_resolution"):
        assert PRIVILEGE_CLASS[event] == BASIS_PRIVILEGED_LEGAL
    # The deliberation (reconciliation / negotiation / Challenger) is work-product.
    for event in ("reconciliation", "negotiation", "adversarial_review"):
        assert PRIVILEGE_CLASS[event] == BASIS_WORK_PRODUCT
    # The filings themselves are disclosable.
    assert PRIVILEGE_CLASS["filings"] == BASIS_DISCLOSABLE_FILING


# ---- unit layer: the split over a real run ----------------------------------

def test_filings_land_in_the_disclosable_set():
    # Every default capture produces filings; they must be disclosable.
    for mode in DEFAULT_MODES:
        rec = privilege_record(_packet(mode))
        disclosable_events = {i["event"] for i in rec["disclosable"]}
        assert "filings" in disclosable_events, f"{mode}: filings must be disclosable"
        for i in rec["disclosable"]:
            assert i["privilege_set"] == SET_DISCLOSABLE


def test_amendment_reconciliation_is_work_product_and_privileged():
    # The amendment run carries the agent-to-agent reconciliation: attorney
    # work-product, withheld in the privileged set.
    rec = privilege_record(_packet("amendment"))
    priv_events = {i["event"]: i for i in rec["privileged"]}
    assert "reconciliation" in priv_events
    assert priv_events["reconciliation"]["basis"] == BASIS_WORK_PRODUCT
    assert priv_events["reconciliation"]["privilege_set"] == SET_PRIVILEGED


def test_privileged_set_never_leaks_into_the_disclosable_set():
    # The whole point: counsel hands the disclosable set to a regulator without
    # waiving privilege. No privileged-basis artifact may appear in the disclosable
    # bucket, and no disclosable-basis artifact in the privileged bucket.
    for mode in DEFAULT_MODES + ("submit",):
        path = DATA / f"packet-{mode}.json"
        if not path.exists():
            continue
        rec = privilege_record(json.loads(path.read_text(encoding="utf-8")))
        for i in rec["disclosable"]:
            assert i["privilege_set"] == SET_DISCLOSABLE
            assert i["basis"] in (BASIS_DISCLOSABLE_FILING,
                                  BASIS_NON_PRIVILEGED_REGULATORY), (
                f"{mode}: privileged basis {i['basis']} leaked into disclosable")
        for i in rec["privileged"]:
            assert i["privilege_set"] == SET_PRIVILEGED
            assert i["basis"] in (BASIS_PRIVILEGED_LEGAL, BASIS_WORK_PRODUCT), (
                f"{mode}: disclosable basis {i['basis']} leaked into privileged")


def test_synthetic_packet_with_a_determination_memo_is_withheld():
    # A packet carrying a reportability determination memo must place that memo in
    # the privileged set, never in the disclosable set handed to a regulator.
    packet = {
        "reportability": {"regimes": [
            {"regime": "NIS2", "reportable": True, "rationale": "significant impact",
             "determination": {"standard": "NIS2 significant", "factors": [
                 {"name": "records", "value": "2.1M", "fact_field": "records_affected"}]}},
        ]},
        "filings": [{"regime": "NIS2", "text": "NIS2 filing prose"}],
    }
    rec = privilege_record(packet)
    priv_events = {i["event"] for i in rec["privileged"]}
    disc_events = {i["event"] for i in rec["disclosable"]}
    assert "reportability" in priv_events
    assert "determination_record" in priv_events
    assert "reportability" not in disc_events
    assert "determination_record" not in disc_events
    assert "filings" in disc_events


def test_verdict_counts_the_two_sets():
    rec = privilege_record(_packet("amendment"))
    assert rec["disclosable_count"] == len(rec["disclosable"])
    assert rec["privileged_count"] == len(rec["privileged"])
    assert "DISCLOSABLE set" in rec["verdict"]
    assert "PRIVILEGED set" in rec["verdict"]


def test_banner_travels_with_the_record():
    rec = privilege_record(_packet("amendment"))
    assert rec["banner"] == PRIVILEGE_BANNER
    assert "PRIVILEGED AND CONFIDENTIAL" in rec["banner"]


def test_empty_packet_yields_no_designation():
    # A bare packet with no classifiable artifact produces {} so the renderer omits
    # the section cleanly.
    assert privilege_record({}) == {}
    assert designate({}).items == ()


# ---- derived: no LLM surface, no run-log mutation, deterministic -------------

def test_module_exposes_no_llm_or_nondeterminism_surface():
    src = inspect.getsource(privilege_mod)
    for token in ("llm_complete", "draft_filing", "openai", "httpx", "api_key",
                  "datetime.now", "time.time", "random.", "uuid", "requests",
                  "log.append", "RunLog", ".save("):
        assert token not in src, f"privilege module must not reference {token!r}"


def test_derivation_does_not_mutate_the_packet():
    packet = _packet("amendment")
    before = json.dumps(packet, sort_keys=True)
    designate(packet)
    privilege_record(packet)
    after = json.dumps(packet, sort_keys=True)
    assert before == after


def test_designation_is_deterministic_across_two_derivations():
    packet = _packet("amendment")
    a = privilege_record(packet)
    b = privilege_record(packet)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---- render layer -----------------------------------------------------------

def test_packet_html_renders_the_privilege_split():
    from floor.packet import _render_html
    packet = _packet("amendment")
    packet["privilege"] = privilege_record(packet)
    html = _render_html(packet)
    assert "Privilege / work-product designation" in html
    assert "Disclosable set" in html
    assert "Privileged set" in html
    assert "PRIVILEGED AND CONFIDENTIAL" in html


# ---- guard layer: the sealed captures are byte-for-byte unchanged ------------

# The four DEFAULT sealed captures, pinned by both their on-disk run-log file sha
# and the signed run-log sha256 the detached signature was taken over. The
# privilege designation is derived at packet render time and never enters the
# hashed run-log, so both must be byte-for-byte unchanged. A regression that pushes
# privilege into the log moves these and fails here.
_SEALED_SHAS = {
    "normal": (
        "89dae1455e3719996036ff4fc671755894003ef44b3938f3b9dc597aa54226f3",
        "89dae1455e3719996036ff4fc671755894003ef44b3938f3b9dc597aa54226f3"),
    "inject_contradiction": (
        "f1f2223aa57b4bace83bf3fcfc5886e2a657d86f15b5d9ed0762646142e34e98",
        "f1f2223aa57b4bace83bf3fcfc5886e2a657d86f15b5d9ed0762646142e34e98"),
    "chaos": (
        "303c437140df55fc6694780d6b54715921e9eed017eb8b9c4a348907b268b520",
        "303c437140df55fc6694780d6b54715921e9eed017eb8b9c4a348907b268b520"),
    "amendment": (
        "0ca07fb0a1f975a84de67966d2724137210c4b7ede1b5ddde96a53650d0c8bbc",
        "0ca07fb0a1f975a84de67966d2724137210c4b7ede1b5ddde96a53650d0c8bbc"),
}


def test_sealed_run_log_shas_unchanged_by_this_derive_only_feature():
    for mode in DEFAULT_MODES:
        jsonl = DATA / f"run-inc-8842-{mode}.jsonl"
        sig = json.loads((DATA / f"run-inc-8842-{mode}.jsonl.sig.json")
                         .read_text(encoding="utf-8"))
        file_sha = hashlib.sha256(jsonl.read_bytes()).hexdigest()
        expected_file_sha, expected_signed_sha = _SEALED_SHAS[mode]
        assert file_sha == expected_file_sha, (
            f"{mode}: on-disk run-log bytes changed; the privilege feature must be "
            f"render-only and never touch the sealed log")
        assert sig["sha256"] == expected_signed_sha, (
            f"{mode}: signed run-log sha changed; privilege must never enter the "
            f"hashed run-log")
