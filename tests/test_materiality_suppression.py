"""test_materiality_suppression.py -- the SEC materiality branch.

A materiality LLM judgment role applies the SEC "substantial likelihood"
materiality test and decides whether the SEC 4-business-day clock is even
triggered. If "not material", the Warden drives the SEC branch to the terminal
SUPPRESSED state and no SEC filing is produced. If material, the SEC branch
proceeds normally.

Two fixtures prove this is not an always-suppress gimmick:
  - material:     SEC proceeds, files, releases.
  - not material: SEC suppressed (terminal), no filing, clock stopped.

The suppression DECISION is the LLM's (here a deterministic injected verdict so
the test has no network); the Warden's gating of the branch is deterministic.
"""

from pathlib import Path

from warden.materiality import MaterialityVerdict, gate
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom


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


def _material_verdict(_facts):
    return MaterialityVerdict("sec", True,
                              "Millions of regulated records across core banking; "
                              "a reasonable investor would consider it important.",
                              source="test:material")


def _immaterial_verdict(_facts):
    return MaterialityVerdict("sec", False,
                              "Twelve cafeteria menu records, contained, no "
                              "regulated data; not material.",
                              source="test:immaterial")


def _run(verdict_fn, tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                     draft_fns=_stub_draft_fns(), materiality=True,
                     materiality_fn=verdict_fn)


# ---- the deterministic gate ------------------------------------------------

def test_gate_is_pure_boolean():
    assert gate(MaterialityVerdict("sec", True, "x")) is True
    assert gate(MaterialityVerdict("sec", False, "x")) is False


# ---- material: SEC proceeds ------------------------------------------------

def test_material_sec_files_and_releases(tmp_path):
    packet = _run(_material_verdict, tmp_path)
    assert packet["materiality"]["material"] is True
    assert packet["materiality"]["disposition"] == "proceed"
    regimes = [f["regime"] for f in packet["filings"]]
    assert "SEC" in regimes
    # the SEC branch reached released through the legal path
    released = [t for t in packet["state_transitions"]
                if t["admitted"] and t["to_state"] == "released"
                and t["correlation_id"].endswith(":sec")]
    assert len(released) == 1
    # no SUPPRESS event fired
    assert not any(t["event"] == "suppress" for t in packet["state_transitions"])


# ---- not material: SEC suppressed ------------------------------------------

def test_immaterial_sec_suppressed_no_filing(tmp_path):
    packet = _run(_immaterial_verdict, tmp_path)
    assert packet["materiality"]["material"] is False
    assert packet["materiality"]["disposition"] == "suppress"
    # NO SEC filing was produced
    regimes = [f["regime"] for f in packet["filings"]]
    assert "SEC" not in regimes
    # the SEC branch went to the terminal SUPPRESSED state via a typed SUPPRESS
    suppress = [t for t in packet["state_transitions"]
                if t["admitted"] and t["event"] == "suppress"
                and t["correlation_id"].endswith(":sec")]
    assert len(suppress) == 1
    assert suppress[0]["to_state"] == "suppressed"
    # the SEC branch never released
    released_sec = [t for t in packet["state_transitions"]
                    if t["admitted"] and t["to_state"] == "released"
                    and t["correlation_id"].endswith(":sec")]
    assert released_sec == []


def test_immaterial_other_branches_still_file(tmp_path):
    # suppressing SEC must not stop NIS2 and DORA
    packet = _run(_immaterial_verdict, tmp_path)
    regimes = [f["regime"] for f in packet["filings"]]
    assert "NIS2" in regimes
    assert "DORA" in regimes
    assert packet["replay"]["byte_identical"] is True


def test_suppression_is_decision_driven_not_always(tmp_path):
    # The same code path, two different verdicts, two different outcomes: proof it
    # is the verdict that drives suppression, not a hardcoded always-suppress.
    p_material = _run(_material_verdict, tmp_path / "a")
    p_immaterial = _run(_immaterial_verdict, tmp_path / "b")
    assert "SEC" in [f["regime"] for f in p_material["filings"]]
    assert "SEC" not in [f["regime"] for f in p_immaterial["filings"]]


def test_immaterial_html_shows_suppressed(tmp_path):
    packet = _run(_immaterial_verdict, tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "SEC: suppressed, not material" in html
