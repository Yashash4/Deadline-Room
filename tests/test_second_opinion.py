"""test_second_opinion.py -- the two-model materiality cross-check.

The SEC Item 1.05 materiality call is the single most load-bearing LLM judgment in
the product: it decides whether an entire statutory branch is even drafted. The
opt-in second-opinion path runs that judgment on TWO independent open Featherless
families and reconciles their typed verdicts with a pure-Python rule before the
EXISTING deterministic gate runs:

  agree    -> that boolean flows to the gate, agreement recorded as corroboration.
  disagree -> conservative, safe-by-construction: proceed (treat as material) and
              escalate to a human; the branch is NOT suppressed pending review.

The reconcile (warden/second_opinion.py) makes no network call and is fully
replayable given the two booleans. The deterministic gate (warden/materiality.py)
is untouched: it still consumes one MaterialityVerdict. These tests use the
injection seam, so no live model call is needed.
"""

from pathlib import Path

from warden.materiality import MaterialityVerdict, gate
from warden.second_opinion import SecondOpinionResult, reconcile
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom


# ---- fixtures --------------------------------------------------------------

def _material(source):
    return MaterialityVerdict(
        "sec", True,
        "Millions of regulated records across core banking; a reasonable investor "
        "would consider it important.",
        source=source)


def _immaterial(source):
    return MaterialityVerdict(
        "sec", False,
        "Twelve cafeteria menu records, contained, no regulated data; not material.",
        source=source)


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


# ---- 1. agreement on material ---------------------------------------------

def test_reconcile_agree_material():
    primary = _material("featherless:deepseek-ai/DeepSeek-V3.2")
    second = _material("featherless:MiniMaxAI/MiniMax-M2.7")
    result = reconcile(primary, second)
    assert isinstance(result, SecondOpinionResult)
    assert result.agreement == "agree"
    assert result.escalated is False
    assert result.verdict.material is True
    # both models named in the reconciled source, for the audit record
    assert "DeepSeek-V3.2" in result.verdict.source
    assert "MiniMax-M2.7" in result.verdict.source
    assert "two independent open models concurred" in result.verdict.memo.lower()
    # the existing deterministic gate consumes the single reconciled verdict
    assert gate(result.verdict) is True


# ---- 2. agreement on immaterial -------------------------------------------

def test_reconcile_agree_immaterial():
    primary = _immaterial("featherless:deepseek-ai/DeepSeek-V3.2")
    second = _immaterial("featherless:MiniMaxAI/MiniMax-M2.7")
    result = reconcile(primary, second)
    assert result.agreement == "agree"
    assert result.escalated is False
    assert result.verdict.material is False
    # SEC still suppresses through the UNCHANGED gate
    assert gate(result.verdict) is False


# ---- 3. disagreement: conservative proceed + escalation -------------------

def test_reconcile_disagree_escalates_and_proceeds():
    primary = _material("featherless:deepseek-ai/DeepSeek-V3.2")
    second = _immaterial("featherless:MiniMaxAI/MiniMax-M2.7")
    result = reconcile(primary, second)
    assert result.agreement == "disagree"
    assert result.escalated is True
    # conservative: proceed (do NOT suppress) even though one model said immaterial
    assert result.verdict.material is True
    assert gate(result.verdict) is True
    # both original memos preserved for the human reviewer
    assert "Millions of regulated records" in result.verdict.memo
    assert "cafeteria menu records" in result.verdict.memo
    assert "escalated to human" in result.verdict.memo.lower()


# ---- 4. reconcile is pure and deterministic (same in -> same out, no net) --

def test_reconcile_is_pure_and_deterministic():
    primary = _material("featherless:deepseek-ai/DeepSeek-V3.2")
    second = _immaterial("featherless:MiniMaxAI/MiniMax-M2.7")
    a = reconcile(primary, second)
    b = reconcile(primary, second)
    # identical inputs produce byte-identical reconciled verdicts
    assert a.verdict == b.verdict
    assert a.agreement == b.agreement
    assert a.escalated == b.escalated
    # order-symmetry of the conservative rule: swapping which model is primary
    # still proceeds and still escalates (the SAFE direction does not depend on
    # which model dissented)
    c = reconcile(second, primary)
    assert c.verdict.material is True
    assert c.escalated is True


# ---- full floor: disagreement does not suppress, packet shows escalation ---

def test_disagree_floor_run_does_not_suppress_and_packet_shows_escalation(tmp_path):
    def two_opinions(_facts):
        return (_material("featherless:deepseek-ai/DeepSeek-V3.2"),
                _immaterial("featherless:MiniMaxAI/MiniMax-M2.7"))

    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns(), materiality=True,
                       second_opinion=True, second_opinion_fn=two_opinions)

    # the reconciled verdict is material -> SEC is NOT suppressed and DOES file
    assert packet["materiality"]["material"] is True
    assert packet["materiality"]["disposition"] == "proceed"
    assert "SEC" in [f["regime"] for f in packet["filings"]]
    assert not any(t["event"] == "suppress" for t in packet["state_transitions"])

    # both opinions are carried in the packet as visible evidence
    so = packet["materiality"]["second_opinion"]
    assert so["agreement"] == "disagree"
    assert so["escalated"] is True
    assert so["primary_material"] is True
    assert so["second_material"] is False
    assert "DeepSeek-V3.2" in so["primary_model"]
    assert "MiniMax-M2.7" in so["second_model"]

    # the rendered packet shows the disagreement / escalation banner
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "DISAGREE" in html
    assert "escalated to human" in html
    assert "NOT suppressed" in html
    # no em/en dashes leaked into the rendered artifact
    assert "—" not in html
    assert "–" not in html

    # replay stays byte-identical with the second-opinion events logged
    assert packet["replay"]["byte_identical"] is True


def test_agree_floor_run_records_corroboration(tmp_path):
    def two_opinions(_facts):
        return (_material("featherless:deepseek-ai/DeepSeek-V3.2"),
                _material("featherless:MiniMaxAI/MiniMax-M2.7"))

    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns(), materiality=True,
                       second_opinion=True, second_opinion_fn=two_opinions)
    so = packet["materiality"]["second_opinion"]
    assert so["agreement"] == "agree"
    assert so["escalated"] is False
    assert packet["materiality"]["material"] is True
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "AGREE" in html
    assert "concurred" in html
    assert "—" not in html and "–" not in html
