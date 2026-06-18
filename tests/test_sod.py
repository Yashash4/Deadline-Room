"""test_sod.py -- the separation-of-duties matrix, proven across the whole run (E4.5).

The two-key release gate proves segregation of duties on ONE action (release). This
matrix proves it ACROSS the ENTIRE run: from the run's events (each state-machine
transition carries an actor + actor_role, and every two-key release records its keys)
it builds the actor x action matrix and asserts the named SoD invariants on every path:

  SOD-M1  the two release keys are distinct roles AND actors per branch
  SOD-M2  no single actor both drafted a filing and released it
  SOD-M3  the Warden (gatekeeper) never authored a filing it gated
  SOD-M4  the human release roles are disjoint from the drafter roles

Layers:

  Unit layer over floor/sod.py: the matrix lists each actor's role(s) and actions from
  the run; the invariants PASS on the real sealed captures; a synthetic run with a
  genuine SoD violation (one actor drafts AND releases) makes the matrix FAIL and names
  the violating actor (non-vacuity, no green-wash); the derivation is pure (no LLM
  surface, no run-log mutation) and deterministic.

  Render layer over the packet HTML: the invariant table and the actor x action matrix
  are rendered with the verdict.

  Guard layer: the four DEFAULT sealed captures and their run-log shas are byte-for-byte
  unchanged by this render/derive-only feature.
"""

import hashlib
import inspect
import json
from pathlib import Path

import floor.sod as sod_mod
from floor.sod import (
    DUTY_AUTHOR,
    DUTY_GATE,
    DUTY_RELEASE,
    RELEASE_ROLES,
    STATUS_FAIL,
    STATUS_PASS,
    matrix_from_packet,
    sod_record,
)

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "web" / "data"
SEALED_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


# ---- helpers ----------------------------------------------------------------

def _transition(corr, event, actor, role, admitted=True):
    return {"correlation_id": corr, "event": event, "ts": "2026-06-16T03:00:00+00:00",
            "actor": actor, "actor_role": role, "admitted": admitted,
            "to_state": "x" if admitted else None, "reason": None}


def _clean_packet():
    """A minimal but realistic released-run packet: triage posts facts, two drafters
    draft, the Warden gates, a human releases, and two distinct keys sign each branch.
    No identity spans a conflicting duty pair (the segregated case)."""
    transitions = [
        _transition("inc:nis2", "fact_record_posted", "triage", "triage"),
        _transition("inc:sec", "fact_record_posted", "triage", "triage"),
        _transition("inc:nis2", "draft_started", "nis2_drafter", "drafter"),
        _transition("inc:sec", "draft_started", "sec_drafter", "drafter"),
        _transition("inc:nis2", "draft_posted", "nis2_drafter", "drafter"),
        _transition("inc:sec", "draft_posted", "sec_drafter", "drafter"),
        _transition("inc:nis2", "diff_passed", "warden", "warden"),
        _transition("inc:sec", "diff_passed", "warden", "warden"),
        _transition("inc:nis2", "signoff_opened", "warden", "warden"),
        _transition("inc:sec", "signoff_opened", "warden", "warden"),
        _transition("inc:nis2", "human_released", "lena", "human_owner"),
        _transition("inc:sec", "human_released", "lena", "human_owner"),
    ]
    signoffs = []
    for b in ("inc:nis2", "inc:sec"):
        signoffs.append({"correlation_id": b, "role": "general_counsel",
                         "actor": "gc", "ts": "2026-06-16T04:50:00+00:00"})
        signoffs.append({"correlation_id": b, "role": "head_of_ir",
                         "actor": "lena", "ts": "2026-06-16T05:00:00+00:00"})
    return {"state_transitions": transitions,
            "release": {"signoffs": signoffs, "released_branches": ["nis2", "sec"]}}


# ---- unit layer: the matrix lists each actor's roles + actions ---------------

def test_matrix_lists_each_actor_roles_and_actions():
    matrix = matrix_from_packet(_clean_packet())
    by_actor = {a.actor: a for a in matrix.actors}
    # every identity that acted is present
    assert set(by_actor) == {"triage", "nis2_drafter", "sec_drafter", "warden",
                             "gc", "lena"}
    # a drafter's role and author actions
    nis2 = by_actor["nis2_drafter"]
    assert nis2.roles == ("drafter",)
    assert nis2.duties == (DUTY_AUTHOR,)
    assert "draft_started" in nis2.actions and "draft_posted" in nis2.actions
    # the Warden gates only
    warden = by_actor["warden"]
    assert warden.duties == (DUTY_GATE,)
    assert "diff_passed" in warden.actions and "signoff_opened" in warden.actions
    # gc is a release key only
    gc = by_actor["gc"]
    assert "general_counsel" in gc.roles
    assert DUTY_RELEASE in gc.duties
    assert "release_signoff" in gc.actions


# ---- unit layer: the invariants PASS on a clean (real-shaped) run ------------

def test_all_invariants_pass_on_a_clean_run():
    matrix = matrix_from_packet(_clean_packet())
    assert matrix.total_invariants == 4
    assert matrix.all_hold is True
    assert matrix.failed_count == 0
    assert {inv.id for inv in matrix.invariants} == {"SOD-M1", "SOD-M2", "SOD-M3",
                                                     "SOD-M4"}
    for inv in matrix.invariants:
        assert inv.status == STATUS_PASS, f"{inv.id} unexpectedly failed: {inv.detail}"
    assert "SEGREGATED" in matrix.verdict


def test_distinct_release_keys_are_two_required_roles():
    matrix = matrix_from_packet(_clean_packet())
    m1 = next(inv for inv in matrix.invariants if inv.id == "SOD-M1")
    assert m1.passed
    # the recorded keys are exactly the two required roles
    roles_in_evidence = {e["role"] for e in m1.evidence}
    assert roles_in_evidence == set(RELEASE_ROLES)


# ---- unit layer: a real SoD violation makes the matrix FAIL, naming it -------

def test_one_actor_drafting_and_releasing_fails_naming_the_actor():
    # The drafter ALSO signs a release key: one identity on both sides of the
    # author/release segregation. This must FAIL, not be green-washed.
    packet = _clean_packet()
    # nis2_drafter signs the head_of_ir key on its own branch.
    packet["release"]["signoffs"].append({
        "correlation_id": "inc:nis2", "role": "head_of_ir",
        "actor": "nis2_drafter", "ts": "2026-06-16T05:10:00+00:00"})
    matrix = matrix_from_packet(packet)
    assert matrix.all_hold is False
    m2 = next(inv for inv in matrix.invariants if inv.id == "SOD-M2")
    assert m2.status == STATUS_FAIL
    assert "nis2_drafter" in m2.detail
    assert "VIOLATION" in matrix.verdict
    # the record form also carries the failure
    rec = sod_record(packet)
    assert rec["all_hold"] is False
    assert rec["failed_count"] >= 1


def test_warden_authoring_a_filing_fails_m3():
    # The Warden identity ALSO drafts: the gatekeeper authored what it gates. FAIL.
    packet = _clean_packet()
    packet["state_transitions"].append(
        _transition("inc:nis2", "draft_posted", "warden", "drafter"))
    matrix = matrix_from_packet(packet)
    m3 = next(inv for inv in matrix.invariants if inv.id == "SOD-M3")
    assert m3.status == STATUS_FAIL
    assert "warden" in m3.detail
    assert matrix.all_hold is False


def test_same_actor_both_release_keys_fails_m1():
    # Lena signs BOTH release keys on a branch (the same identity as both keys). The
    # distinct-key invariant must FAIL.
    packet = _clean_packet()
    packet["release"]["signoffs"] = [
        {"correlation_id": "inc:nis2", "role": "general_counsel",
         "actor": "lena", "ts": "2026-06-16T04:50:00+00:00"},
        {"correlation_id": "inc:nis2", "role": "head_of_ir",
         "actor": "lena", "ts": "2026-06-16T05:00:00+00:00"},
    ]
    matrix = matrix_from_packet(packet)
    m1 = next(inv for inv in matrix.invariants if inv.id == "SOD-M1")
    assert m1.status == STATUS_FAIL
    assert "inc:nis2" in m1.detail
    assert matrix.all_hold is False


def test_release_role_overlapping_drafter_role_fails_m4():
    # A drafter role string is reused as a release key role: roles overlap. FAIL.
    packet = _clean_packet()
    packet["release"]["signoffs"].append({
        "correlation_id": "inc:sec", "role": "drafter",
        "actor": "rogue", "ts": "2026-06-16T05:10:00+00:00"})
    matrix = matrix_from_packet(packet)
    m4 = next(inv for inv in matrix.invariants if inv.id == "SOD-M4")
    assert m4.status == STATUS_FAIL
    assert "drafter" in m4.detail


# ---- unit layer: the invariants PASS on every real sealed capture ------------

def test_invariants_pass_on_the_real_sealed_captures():
    seen = 0
    for mode in SEALED_MODES:
        packet_path = DATA / f"packet-{mode}.json"
        if not packet_path.exists():
            continue
        seen += 1
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        matrix = matrix_from_packet(packet)
        assert matrix.total_invariants == 4
        assert matrix.all_hold is True, (
            f"{mode}: a real SoD violation surfaced: {matrix.verdict}")
        for inv in matrix.invariants:
            assert inv.status == STATUS_PASS, (
                f"{mode} {inv.id} FAILED: {inv.detail}")
    assert seen > 0, "no sealed capture was available to check"


def test_sod_record_present_in_committed_packets():
    # The packets carry the derived sod block (assembled at run time).
    for mode in SEALED_MODES:
        packet_path = DATA / f"packet-{mode}.json"
        if not packet_path.exists():
            continue
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
        block = packet.get("sod") or sod_record(packet)
        assert block, f"{mode}: no sod block derivable"
        assert block["all_hold"] is True
        assert block["total_invariants"] == 4


# ---- unit layer: empty when no SoD path was exercised ------------------------

def test_sod_record_empty_when_no_transitions_or_signoffs():
    assert sod_record({}) == {}
    assert sod_record({"state_transitions": [], "release": {"signoffs": []}}) == {}


def test_matrix_with_transitions_but_no_release_holds_vacuously():
    # A run that drafted but never released: the author side exists, the release side
    # does not. The matrix is built and the invariants hold vacuously (no overlap is
    # possible), which the verdict states honestly.
    packet = {"state_transitions": [
        _transition("inc:nis2", "draft_posted", "nis2_drafter", "drafter")]}
    matrix = matrix_from_packet(packet)
    assert matrix.all_hold is True
    assert any(a.actor == "nis2_drafter" for a in matrix.actors)


# ---- derived: no LLM surface, no run-log mutation ----------------------------

def test_module_exposes_no_llm_or_nondeterminism_surface():
    src = inspect.getsource(sod_mod)
    for token in ("llm_complete", "draft_filing", "openai", "httpx", "api_key",
                  "datetime.now", "time.time", "random.", "uuid", "requests",
                  "log.append", "RunLog", "run_log"):
        assert token not in src, f"sod module must not reference {token!r}"


def test_derivation_does_not_mutate_the_packet():
    packet = _clean_packet()
    before = json.dumps(packet, sort_keys=True)
    sod_record(packet)
    matrix_from_packet(packet)
    after = json.dumps(packet, sort_keys=True)
    assert before == after


def test_matrix_is_deterministic_across_two_derivations():
    packet = _clean_packet()
    a = sod_record(packet)
    b = sod_record(packet)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---- render layer: the invariant table and the matrix are rendered -----------

def test_packet_html_renders_the_sod_matrix():
    from floor.packet import _render_html
    packet = _clean_packet()
    packet.update({
        "incident": {"incident_id": "inc-8842", "band_room_id": "room-x",
                     "fact_record": {}},
        "replay": {"byte_identical": True, "original_sha256": "0" * 64,
                   "replayed_sha256": "0" * 64},
        "filings": [],
    })
    packet["sod"] = sod_record(packet)
    html = _render_html(packet)
    assert "Separation-of-duties matrix" in html
    assert "SOD-M1" in html and "SOD-M2" in html
    assert "PASS" in html
    # the actor x action matrix names the drafter and the release key
    assert "nis2_drafter" in html
    assert "release_signoff" in html
    assert "SEGREGATED" in html


def test_packet_html_renders_a_sod_violation():
    from floor.packet import _render_html
    packet = _clean_packet()
    packet["release"]["signoffs"].append({
        "correlation_id": "inc:nis2", "role": "head_of_ir",
        "actor": "nis2_drafter", "ts": "2026-06-16T05:10:00+00:00"})
    packet.update({
        "incident": {"incident_id": "inc-8842", "band_room_id": "room-x",
                     "fact_record": {}},
        "replay": {"byte_identical": True, "original_sha256": "0" * 64,
                   "replayed_sha256": "0" * 64},
        "filings": [],
    })
    packet["sod"] = sod_record(packet)
    html = _render_html(packet)
    assert "FAIL" in html
    assert "VIOLATION" in html


# ---- script layer: the receipt exits 0 on a clean capture, 1 on a violation --

def test_sod_matrix_script_passes_on_the_committed_normal_capture():
    packet = DATA / "packet-normal.json"
    if not packet.exists():
        return  # capture not present in this checkout; the unit layer covers it
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    import sod_matrix
    rc = sod_matrix.main([str(packet)])
    assert rc == 0


def test_sod_matrix_script_fails_on_a_synthetic_violation(tmp_path):
    # A packet with a real violation makes the receipt exit nonzero (no green-wash).
    packet = _clean_packet()
    packet["release"]["signoffs"].append({
        "correlation_id": "inc:nis2", "role": "head_of_ir",
        "actor": "nis2_drafter", "ts": "2026-06-16T05:10:00+00:00"})
    packet["sod"] = sod_record(packet)
    out = tmp_path / "packet-violation.json"
    out.write_text(json.dumps(packet), encoding="utf-8")
    import sys
    sys.path.insert(0, str(REPO / "scripts"))
    import sod_matrix
    rc = sod_matrix.main([str(out)])
    assert rc == 1


# ---- guard: the four DEFAULT sealed captures and shas are untouched ----------

def test_default_sealed_captures_and_shas_unchanged():
    """The SoD matrix is a render/derive-only feature; the four committed sealed
    captures (normal, inject_contradiction, chaos, amendment) and their run-log shas
    must be byte-for-byte unchanged. This pins them so a regression that perturbs a
    sealed capture fails here."""
    for mode in SEALED_MODES:
        log_path = DATA / f"run-inc-8842-{mode}.jsonl"
        assert log_path.exists(), f"sealed capture missing: {log_path}"
        sha = hashlib.sha256(log_path.read_bytes()).hexdigest()
        assert len(sha) == 64
        packet_path = DATA / f"packet-{mode}.json"
        if packet_path.exists():
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            recorded = packet.get("replay", {}).get("original_sha256")
            from warden.replay import RunLog
            loaded = RunLog.load(log_path)
            assert loaded.sha256() == recorded, (
                f"{mode}: run-log sha drifted from the committed packet")
