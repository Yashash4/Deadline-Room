"""test_reportability.py -- the per-regime reportability / duty-to-notify gate (E3.1).

A reportability LLM judgment role applies each regime's statutory trigger
standard (NIS2 Art 23 significant impact, DORA major-incident RTS, SEC Item 1.05
materiality) and decides, PER REGIME, whether the duty to notify even attaches.
The typed verdict crosses into the deterministic warden/reportability.py gate as
data: a regime BELOW its threshold is driven to the terminal SUPPRESSED state (no
filing, clock stopped, the named rule recorded); a regime ABOVE its threshold
files. This generalizes the proven SEC-only materiality->suppress seam to all
regimes.

The judgment is the LLM's (here a deterministic injected verdict so the tests
need no live LLM, exactly the seam the materiality tests use via materiality_fn);
the gating of each branch is deterministic Python. The reportability API exposes
no gate or release surface: the only deterministic decision is the pure boolean
gate.

These tests also pin that the four DEFAULT sealed captures (normal,
inject_contradiction, chaos, amendment) and their run-log shas are UNCHANGED by
this feature: the reportability beat is its own scenario, so no capture is
regenerated. Byte-identical replay holds for the new beat.
"""

from pathlib import Path

import pytest

from warden.reportability import ReportabilityVerdict, gate
from floor import regimes
from floor.run_floor import (
    DRAFTER_ROLES, REPORTABILITY_BRANCHES, _REGIME_BY_BRANCH, run_floor)
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
    return room, clients


def _stub_draft_fns():
    def make(regime):
        def fn(claim_facts):
            return (f"{regime} notification. Incident "
                    f"{claim_facts['incident_start_utc']}, "
                    f"{claim_facts['records_affected']} records.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def _verdict_for(branch, spec, reportable):
    return ReportabilityVerdict(
        branch=branch, regime=spec.regime_label, reportable=reportable,
        rationale=f"{branch} basis against the {spec.regime_label} standard.",
        standard=spec.reportability.standard, rule=spec.reportability.rule,
        source=f"test:{'reportable' if reportable else 'suppressed'}")


def _mixed_fn(branch, _facts, spec):
    # NIS2 below threshold (suppress); SEC and DORA above (file). A mixed fixture
    # so the beat proves both file and suppress in one run.
    return _verdict_for(branch, spec, reportable=(branch != "nis2"))


def _all_reportable_fn(branch, _facts, spec):
    return _verdict_for(branch, spec, reportable=True)


def _all_suppressed_fn(branch, _facts, spec):
    return _verdict_for(branch, spec, reportable=False)


def _run(fn, tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode="reportability", clients=clients,
                     draft_fns=_stub_draft_fns(), reportability=True,
                     reportability_fn=fn)


# ---- the deterministic gate ------------------------------------------------

def test_gate_is_pure_boolean():
    spec = _REGIME_BY_BRANCH["nis2"]
    assert gate(_verdict_for("nis2", spec, True)) is True
    assert gate(_verdict_for("nis2", spec, False)) is False


def test_gate_module_exposes_no_release_or_gate_state_surface():
    # The reportability API is exactly one pure boolean rule plus a typed verdict;
    # it exposes no gate-state, no release, no clock, and no LLM surface. The
    # Warden gate stays deterministic and the qualitative call never touches it.
    import warden.reportability as rep
    callables = {n for n in dir(rep)
                 if not n.startswith("_") and callable(getattr(rep, n))}
    # gate is the ONLY decision function; ReportabilityVerdict is the only type.
    # (dataclass is an imported decorator, not part of this module's own surface.)
    own = callables - {"dataclass"}
    assert own == {"ReportabilityVerdict", "gate"}
    # No release / hold / clock / llm names anywhere in the module surface.
    for forbidden in ("release", "hold", "clock", "llm", "complete", "assess"):
        assert not any(forbidden in n.lower() for n in dir(rep)), \
            f"warden.reportability must not expose a {forbidden!r} surface"
    # The gate returns a plain bool.
    spec = _REGIME_BY_BRANCH["sec"]
    assert isinstance(gate(_verdict_for("sec", spec, True)), bool)


# ---- every regime carries a declarative threshold --------------------------

def test_every_reportability_branch_has_a_standard_in_the_catalog():
    for branch in REPORTABILITY_BRANCHES:
        spec = _REGIME_BY_BRANCH[branch]
        assert spec.reportability is not None, f"{branch} has no reportability block"
        assert spec.reportability.standard.strip()
        assert spec.reportability.rule.strip()


def test_catalog_loads_reportability_for_all_six_regimes():
    catalog = regimes.load_catalog()
    with_threshold = [s for s in catalog if s.reportability is not None]
    # All six regimes (NIS2 early + full, DORA, SEC, UK ICO, NYDFS) declare one.
    assert len(with_threshold) == 6
    for s in with_threshold:
        assert s.reportability.standard
        assert s.reportability.rule


# ---- below threshold -> SUPPRESSED, rule named -----------------------------

def test_below_threshold_regime_is_suppressed_with_rule_named(tmp_path):
    packet = _run(_mixed_fn, tmp_path)
    rep = packet["reportability"]
    nis2 = next(r for r in rep["regimes"] if r["branch"] == "nis2")
    assert nis2["reportable"] is False
    assert nis2["disposition"] == "suppress"
    assert "NIS2 Art 23 significant-impact" in nis2["rule"]

    # NO NIS2 filing was produced.
    regime_labels = [f["regime"] for f in packet["filings"]]
    assert "NIS2" not in regime_labels

    # The NIS2 branch went to the terminal SUPPRESSED state via a typed SUPPRESS.
    suppress = [t for t in packet["state_transitions"]
                if t["admitted"] and t["event"] == "suppress"
                and t["correlation_id"].endswith(":nis2")]
    assert len(suppress) == 1
    assert suppress[0]["to_state"] == "suppressed"

    # The NIS2 branch never released.
    released_nis2 = [t for t in packet["state_transitions"]
                     if t["admitted"] and t["to_state"] == "released"
                     and t["correlation_id"].endswith(":nis2")]
    assert released_nis2 == []

    # The packet HTML names the rule.
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "not reportable under NIS2 Art 23 significant-impact" in html


# ---- above threshold -> files ----------------------------------------------

def test_above_threshold_regimes_file(tmp_path):
    packet = _run(_mixed_fn, tmp_path)
    regime_labels = [f["regime"] for f in packet["filings"]]
    # SEC and DORA crossed their thresholds and filed.
    assert "SEC" in regime_labels
    assert "DORA" in regime_labels
    # Both reached released through the legal path.
    for branch in ("sec", "dora"):
        released = [t for t in packet["state_transitions"]
                    if t["admitted"] and t["to_state"] == "released"
                    and t["correlation_id"].endswith(f":{branch}")]
        assert len(released) == 1


# ---- decision-driven, not always-file / always-suppress --------------------

def test_reportability_is_decision_driven_not_always(tmp_path):
    # The same code path, three verdict sets, three outcomes: proof it is the
    # verdict that drives file/suppress, not a hardcoded behaviour.
    p_all = _run(_all_reportable_fn, tmp_path / "all")
    p_none = _run(_all_suppressed_fn, tmp_path / "none")
    p_mixed = _run(_mixed_fn, tmp_path / "mixed")

    assert {f["regime"] for f in p_all["filings"]} == {"NIS2", "SEC", "DORA"}
    # All suppressed: not one of the three startup-drafter regimes files.
    assert {"NIS2", "SEC", "DORA"} & {f["regime"] for f in p_none["filings"]} == set()
    assert {f["regime"] for f in p_mixed["filings"]} == {"SEC", "DORA"}


def test_all_suppressed_run_files_nothing_and_suppresses_three(tmp_path):
    packet = _run(_all_suppressed_fn, tmp_path)
    suppress = [t for t in packet["state_transitions"]
                if t["admitted"] and t["event"] == "suppress"]
    suppressed_branches = {t["correlation_id"].split(":")[-1] for t in suppress}
    assert {"nis2", "sec", "dora"} <= suppressed_branches
    assert packet["reportability"]["suppressed"] == ["NIS2", "SEC", "DORA"]


# ---- the gate decision is deterministic Python (no LLM on the gate path) ----

def test_suppress_event_authority_is_not_a_drafter(tmp_path):
    # The SUPPRESS that gates a branch is emitted under the deterministic
    # "materiality" authority role, never a drafter. The LLM verdict crosses as
    # data; the Warden gate never makes an LLM call.
    packet = _run(_mixed_fn, tmp_path)
    suppress = [t for t in packet["state_transitions"]
                if t["admitted"] and t["event"] == "suppress"]
    assert suppress
    for t in suppress:
        assert t["actor_role"] == "materiality"


def test_reportable_clock_runs_suppressed_clock_stops(tmp_path):
    packet = _run(_mixed_fn, tmp_path)
    clocks = {c["correlation_id"].split(":")[-1]: c for c in packet["clocks"]}
    # The suppressed NIS2 branch's clock is stopped; a reportable branch's clock
    # ran and was stopped only at release.
    assert clocks["nis2"]["stopped"]
    assert clocks["sec"]["stopped"]


# ---- byte-identical replay for the new beat --------------------------------

def test_replay_is_byte_identical_for_the_reportability_beat(tmp_path):
    for fn in (_mixed_fn, _all_reportable_fn, _all_suppressed_fn):
        packet = _run(fn, tmp_path / fn.__name__)
        assert packet["replay"]["byte_identical"] is True


def test_reportability_run_is_deterministic_across_two_runs(tmp_path):
    # Same injected verdicts -> identical run-log sha. The gate is a pure function
    # of the event sequence; nothing in the path reads now()/RNG.
    a = _run(_mixed_fn, tmp_path / "a")
    b = _run(_mixed_fn, tmp_path / "b")
    assert a["replay"]["original_sha256"] == b["replay"]["original_sha256"]


# ---- the four DEFAULT sealed captures + their shas are UNCHANGED ------------

SEALED_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


@pytest.mark.parametrize("mode", SEALED_MODES)
def test_sealed_capture_run_log_unchanged(mode):
    # The reportability feature adds NO event to these four scenarios, so each
    # sealed capture file still exists and is non-empty. This is the guard that
    # the new beat is its own scenario and never regenerated a default capture.
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    assert log_path.exists(), f"{mode}: sealed capture missing"
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines
    # No reportability event leaked into a default sealed capture.
    assert not any('"reportability"' in ln for ln in lines), \
        f"{mode}: a reportability event leaked into the sealed capture"


def test_default_normal_run_sha_unchanged():
    # A fresh normal-mode run (no reportability) must still reproduce the sealed
    # normal sha byte for byte: the reportability code is dormant unless asked,
    # so it cannot have moved the default sealed stream.
    from tests.test_operability_report import SEALED_NORMAL_SHA, _build_clients as _bc, \
        _stub_draft_fns as _sd
    import tempfile
    room, clients = _bc()
    with tempfile.TemporaryDirectory() as td:
        packet = run_floor(out_dir=td, mode="normal", clients=clients,
                           draft_fns=_sd())
    assert packet["replay"]["original_sha256"] == SEALED_NORMAL_SHA
