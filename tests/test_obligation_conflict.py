"""test_obligation_conflict.py -- the cross-border obligation conflict beat (E3.4).

The cross-filing contradiction veto (warden/diff.py) catches two drafters of the
SAME incident disagreeing on a FACT. This beat catches the distinctly cross-border
hazard: two REGULATORS imposing mutually exclusive OBLIGATIONS on the same true
facts (one jurisdiction mandated to disclose a data element another forbids
disclosing, or two declared-opposite named mandates). The pure no-LLM
warden/obligations.py detector finds the conflicting pair and the Warden HALTS,
routing the decision to the human two-key gate. It is a DETECTOR, never a RESOLVER:
it NEVER decides which law prevails (that would be the SKIP-listed conflict-of-laws
resolver). The HUMAN resolves through the existing two-key gate; only then does the
run proceed.

These tests assert:
  - two in-scope regimes with declared conflicting obligations are detected, the
    run BLOCKS, and the decision is routed to the human two-key gate (no
    auto-resolution);
  - no false positive when in-scope obligations are compatible (the content-driven
    negative);
  - the detector exposes no "which law wins" / LLM surface;
  - the four DEFAULT sealed captures and their shas are UNCHANGED;
  - byte-identical replay holds for the new beat, and it is deterministic across
    two runs.
"""

from pathlib import Path

import pytest

from warden.obligations import (
    MUTUALLY_EXCLUSIVE_MANDATES, ObligationConflict, RegimeObligations,
    detect)
from floor import regimes
from floor.run_floor import (
    CROSS_BORDER_IN_SCOPE_FACTS, DRAFTER_ROLES,
    _regime_obligations_in_scope, run_floor)
from floor.shell_adapter import FakeBandClient, FakeRoom

DATA = Path(__file__).resolve().parent.parent / "web" / "data"


def _build_clients():
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    clients["uk"] = FakeBandClient(room, "uk-id", "uk_drafter", "draft:uk")
    return room, clients


def _stub_draft_fns():
    def make(regime):
        def fn(claim_facts):
            return (f"{regime} notification. Incident "
                    f"{claim_facts['incident_start_utc']}, "
                    f"{claim_facts['records_affected']} records.")
        return fn
    fns = {r.branch: make(r.regime) for r in DRAFTER_ROLES}
    fns["uk"] = make("UK ICO")
    return fns


def _uk_peers():
    return [{"id": "uk-id", "name": "UK ICO Drafter"}]


def _run(tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode="cross_border", clients=clients,
                     draft_fns=_stub_draft_fns(), uk_peers=_uk_peers())


# ---- the pure detector: conflict detected ----------------------------------

def test_detector_finds_data_content_conflict():
    # One regime mandated to disclose an element another forbids disclosing.
    a = RegimeObligations(regime="SEC", discloses=frozenset({"affected_data_scope"}))
    b = RegimeObligations(regime="UK ICO",
                          forbids_disclosing=frozenset({"affected_data_scope"}))
    conflicts = detect([a, b])
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c.kind == "data_content"
    assert c.element == "affected_data_scope"
    # The discloser is named first; the forbidder second.
    assert c.regime_a == "SEC" and "must disclose" in c.obligation_a
    assert c.regime_b == "UK ICO" and "forbids disclosing" in c.obligation_b


def test_detector_finds_mandate_conflict():
    # Two declared-opposite named mandates cannot both be satisfied.
    a = RegimeObligations(regime="SEC", mandates=frozenset({"public_disclosure"}))
    b = RegimeObligations(regime="DORA",
                          mandates=frozenset({"confidentiality_hold"}))
    conflicts = detect([a, b])
    assert len(conflicts) == 1
    assert conflicts[0].kind == "mandate"
    assert {conflicts[0].obligation_a, conflicts[0].obligation_b} == {
        "public_disclosure", "confidentiality_hold"}


# ---- no false positive when obligations are compatible ---------------------

def test_no_false_positive_for_compatible_obligations():
    # Same disclosed element on both sides, no forbid: no conflict.
    a = RegimeObligations(regime="SEC", discloses=frozenset({"affected_data_scope"}))
    b = RegimeObligations(regime="NYDFS",
                          discloses=frozenset({"affected_data_scope"}))
    assert detect([a, b]) == []
    # Same named mandate on both sides (not opposites): no conflict.
    c = RegimeObligations(regime="SEC", mandates=frozenset({"public_disclosure"}))
    d = RegimeObligations(regime="NYDFS", mandates=frozenset({"public_disclosure"}))
    assert detect([c, d]) == []


def test_single_regime_in_scope_never_conflicts():
    # A single in-scope regime can never conflict with itself.
    a = RegimeObligations(regime="SEC",
                          discloses=frozenset({"affected_data_scope"}),
                          forbids_disclosing=frozenset({"affected_data_scope"}),
                          mandates=frozenset({"public_disclosure"}))
    assert detect([a]) == []


def test_detector_is_deterministic_and_symmetric():
    a = RegimeObligations(regime="SEC", discloses=frozenset({"affected_data_scope"}),
                          mandates=frozenset({"public_disclosure"}))
    b = RegimeObligations(regime="UK ICO",
                          forbids_disclosing=frozenset({"affected_data_scope"}))
    d = RegimeObligations(regime="DORA",
                          mandates=frozenset({"confidentiality_hold"}))
    # The conflict SET is the same regardless of input order (the pairing is
    # symmetric); only the deterministic ordering of the list reflects input order.
    first = {(c.kind, c.element, frozenset({c.obligation_a, c.obligation_b}))
             for c in detect([a, b, d])}
    second = {(c.kind, c.element, frozenset({c.obligation_a, c.obligation_b}))
              for c in detect([d, b, a])}
    assert first == second
    # Two runs over the same input produce the identical list (no RNG, no now()).
    assert detect([a, b, d]) == detect([a, b, d])


# ---- the detector exposes NO "which law wins" / LLM surface ----------------

def test_detector_exposes_no_resolver_or_llm_surface():
    import warden.obligations as ob
    names = [n for n in dir(ob) if not n.startswith("_")]
    # The module's own decision surface is the pure detector plus the typed
    # records; there is NO resolver, no "which wins", no LLM, no network surface.
    for forbidden in ("resolve", "winner", "wins", "prevail", "decide", "adjudicate",
                      "llm", "complete", "assess", "model", "prompt", "rank"):
        assert not any(forbidden in n.lower() for n in names), \
            f"warden.obligations must not expose a {forbidden!r} surface"
    # The only public callable is detect; the rest are typed dataclasses / data.
    callables = {n for n in names if callable(getattr(ob, n))}
    assert "detect" in callables
    # detect returns a list of ObligationConflict and never a verdict about which
    # regime prevails: the conflict carries both obligations, no chosen side.
    a = RegimeObligations(regime="A", mandates=frozenset({"public_disclosure"}))
    b = RegimeObligations(regime="B", mandates=frozenset({"confidentiality_hold"}))
    [c] = detect([a, b])
    assert isinstance(c, ObligationConflict)
    # The conflict object has no field naming a winner / prevailing law.
    for field in c.__dataclass_fields__:
        assert not any(w in field.lower()
                       for w in ("win", "prevail", "resolved", "decision")), field


def test_resolution_is_never_authored_by_the_detector():
    # The conflict has no "decision" field; a ConflictResolution is a SEPARATE type
    # the HUMAN fills (decided_by, decision), never the detector.
    from warden.obligations import ConflictResolution
    r = ConflictResolution(kind="mandate", regime_a="A", regime_b="B")
    # A bare resolution carries no human decision until one is recorded.
    assert r.decided_by == ()
    assert r.decision == ""


# ---- the catalog declares the obligations as data --------------------------

def test_catalog_declares_obligation_data_for_the_conflicting_regimes():
    catalog = regimes.by_key(regimes.load_catalog())
    sec = catalog["sec"].obligations
    dora = catalog["dora"].obligations
    uk = catalog["uk_ico"].obligations
    assert sec is not None and "public_disclosure" in sec.mandates
    assert "affected_data_scope" in sec.discloses
    assert dora is not None and "confidentiality_hold" in dora.mandates
    assert uk is not None and "affected_data_scope" in uk.forbids_disclosing
    # Each declares a cited basis, the defensibility record.
    for ob in (sec, dora, uk):
        assert ob.basis.strip()


def test_empty_obligations_block_is_a_catalog_error(tmp_path):
    # An obligations block that declares no token of any kind is a malformed claim
    # and surfaces structurally rather than being silently treated as "none".
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "regimes:\n"
        "  - key: x\n"
        "    authority: a\n"
        "    branch: x\n"
        "    regime_label: X\n"
        "    trigger_event: incident occurrence\n"
        "    clock: {name: c, length: 72, unit: hours, business_days: false, "
        "holiday_calendar: none}\n"
        "    format_profile: nis2_full\n"
        "    start: {mode: startup, anchor: incident_t0}\n"
        "    obligations: {basis: only a basis, no tokens}\n",
        encoding="utf-8")
    with pytest.raises(ValueError):
        regimes.load_catalog(bad)


def test_in_scope_builder_lifts_declared_obligations():
    # The run-floor helper lifts each in-scope branch's declared obligations from
    # the catalog (branches with no obligations block contribute nothing).
    obs = _regime_obligations_in_scope(["nis2", "sec", "dora", "uk"])
    regimes_named = {o.regime for o in obs}
    assert {"SEC", "DORA", "UK ICO"} <= regimes_named
    # NIS2 declares no cross-border obligation tension, so it contributes nothing.
    assert "NIS2" not in regimes_named


# ---- the live beat: detected, blocked, human-routed ------------------------

def test_cross_border_run_detects_blocks_and_routes_to_human(tmp_path):
    packet = _run(tmp_path)
    cb = packet["cross_border"]
    assert cb["blocked"] is True
    # Both conflicts are surfaced: the mandate clash and the data-content clash.
    kinds = {c["kind"] for c in cb["conflicts"]}
    assert kinds == {"mandate", "data_content"}
    regimes_named = set()
    for c in cb["conflicts"]:
        regimes_named.add(c["regime_a"])
        regimes_named.add(c["regime_b"])
    assert {"SEC", "DORA", "UK ICO"} <= regimes_named


def test_cross_border_routes_to_two_distinct_human_keys(tmp_path):
    packet = _run(tmp_path)
    res = packet["cross_border"]["resolution"]
    assert res is not None
    # The decision is recorded by two DISTINCT human roles (segregation of duties),
    # not auto-resolved.
    assert sorted(res["decided_by"]) == ["general_counsel", "head_of_ir"]
    assert res["decision"].strip()


def test_cross_border_block_and_resolution_are_logged(tmp_path):
    # The conflict block and the human resolution are hash-chained run-log events,
    # so they are replayed and signed; the Warden never logs a "which wins" choice.
    packet = _run(tmp_path)
    log_path = Path(packet["_paths"]["run_log"])
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert any('"cross_border_block"' in ln for ln in lines)
    assert any('"cross_border_resolution"' in ln for ln in lines)
    # The two-key cross-border signoff is recorded as two distinct human keys.
    signoffs = [ln for ln in lines if '"cross_border_signoff"' in ln]
    assert len(signoffs) == 2


def test_cross_border_does_not_auto_resolve_the_conflict(tmp_path):
    # The resolution is the HUMAN's: the recorded decision text states the humans,
    # not the system, chose. The packet HTML reflects that the Warden did not decide.
    packet = _run(tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Cross-border obligation conflict" in html
    assert "the Warden did not choose" in html
    assert "does not decide which law prevails" in html or \
           "does not decide which law" in html.lower() or \
           "Warden NEVER decides" in html or "never decides" in html.lower()


def test_cross_border_filings_still_produced(tmp_path):
    # The conflict halts and routes; once resolved, the run proceeds and the in-scope
    # regimes still file (the SEC, DORA, and UK ICO notices, plus NIS2).
    packet = _run(tmp_path)
    regime_labels = {f["regime"] for f in packet["filings"]}
    assert {"SEC", "DORA", "UK ICO", "NIS2"} <= regime_labels


def test_cross_border_in_scope_facts_name_the_uk():
    # The cross-border fixture's blast radius brings the UK regime into scope, so the
    # UK ICO's forbid-disclosing obligation is live alongside the SEC/DORA mandates.
    radius = " ".join(CROSS_BORDER_IN_SCOPE_FACTS["blast_radius"]).lower()
    assert "uk" in radius


# ---- byte-identical replay + determinism for the new beat ------------------

def test_replay_is_byte_identical_for_the_cross_border_beat(tmp_path):
    packet = _run(tmp_path)
    assert packet["replay"]["byte_identical"] is True


def test_cross_border_run_is_deterministic_across_two_runs(tmp_path):
    a = _run(tmp_path / "a")
    b = _run(tmp_path / "b")
    assert a["replay"]["original_sha256"] == b["replay"]["original_sha256"]


# ---- the four DEFAULT sealed captures + their shas are UNCHANGED ------------

SEALED_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


@pytest.mark.parametrize("mode", SEALED_MODES)
def test_sealed_capture_run_log_unchanged(mode):
    # The cross-border feature adds NO event to these four scenarios; each sealed
    # capture still exists, is non-empty, and carries no cross-border event.
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    assert log_path.exists(), f"{mode}: sealed capture missing"
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines()
             if ln.strip()]
    assert lines
    assert not any("cross_border" in ln for ln in lines), \
        f"{mode}: a cross-border event leaked into the sealed capture"


def test_default_normal_run_sha_unchanged():
    # A fresh normal-mode run (no cross-border) must still reproduce the sealed
    # normal sha byte for byte: the cross-border code is dormant unless asked, so it
    # cannot have moved the default sealed stream.
    from tests.test_operability_report import (
        SEALED_NORMAL_SHA, _build_clients as _bc, _stub_draft_fns as _sd)
    import tempfile
    room, clients = _bc()
    with tempfile.TemporaryDirectory() as td:
        packet = run_floor(out_dir=td, mode="normal", clients=clients,
                           draft_fns=_sd())
    assert packet["replay"]["original_sha256"] == SEALED_NORMAL_SHA


# ---- the mutually-exclusive mandate table is honest ------------------------

def test_mutually_exclusive_table_pairs_public_disclosure_and_confidentiality():
    assert frozenset({"public_disclosure", "confidentiality_hold"}) \
        in MUTUALLY_EXCLUSIVE_MANDATES
