"""The deterministic grounding scorer and the judge-runnable grounding receipt.

The scorer (floor/grounding.py) is the eval harness around the drafting LLM. It
is a SCORER, never a gate, so these tests pin three things:

  1. A grounded filing scores high / passes; a filing with an invented number,
     date, or breach actor is flagged.
  2. The scorer is pure and deterministic: same inputs, same output, no network.
  3. The inline-citation validator catches a citation to a nonexistent field.

Plus the load-bearing invariant: the grounding result never changes a gate
decision. The release path is driven entirely by the deterministic Warden and
the two-key gate; the grounding score is attached to the packet as a receipt and
read by nothing that gates.
"""

import json
import subprocess
import sys
from pathlib import Path

from floor.grounding import (
    score_filing, score_filings, validate_citations, strip_citations)

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "web" / "data"
REPORT_SCRIPT = REPO_ROOT / "scripts" / "grounding_report.py"

FACTS = {
    "incident_id": "inc-8842",
    "incident_start_utc": "2026-06-16T02:14:00+00:00",
    "records_affected": 48211,
    "attacker": "LockBit 3.0",
    "containment": "partially_contained",
    "systems": ["core banking ledger", "customer KYC store"],
    "data_categories": ["name", "address", "account_number"],
    "regulated_entity": "Meridian Trust Bank N.V.",
    "competent_authority": "national CSIRT (NIS2)",
}

GROUNDED_FILING = (
    "On 16 June 2026 at 02:14 UTC, Meridian Trust Bank N.V. detected a breach by "
    "the LockBit 3.0 ransomware group affecting the core banking ledger. "
    "Approximately 48,211 records were affected. The incident remains partially "
    "contained, and notification is filed within 72 hours under Article 23.\n\n"
    "[CLAIMS]\nbranch=nis2\nincident_start_utc=2026-06-16T02:14:00+00:00\n"
    "records_affected=48211\nattacker=LockBit 3.0\n"
    "containment=partially_contained\n[/CLAIMS]"
)


# --- 1. grounded passes, invented facts are flagged -------------------------
def test_grounded_filing_scores_perfect_and_passes():
    r = score_filing(GROUNDED_FILING, FACTS, branch="nis2")
    assert r.total > 0
    assert r.grounded == r.total
    assert r.score == 1.0
    assert r.passes(1.0)
    assert r.ungrounded == []


def test_invented_record_count_is_flagged():
    poisoned = GROUNDED_FILING.replace("48,211", "9,500,000")
    r = score_filing(poisoned, FACTS, branch="nis2")
    assert not r.passes(1.0)
    kinds = {u.kind for u in r.ungrounded}
    assert "number" in kinds
    assert any("9,500,000" == u.span for u in r.ungrounded)


def test_invented_date_is_flagged():
    poisoned = GROUNDED_FILING.replace("16 June 2026", "11 August 2026")
    r = score_filing(poisoned, FACTS, branch="nis2")
    assert not r.passes(1.0)
    assert any(u.kind == "date" for u in r.ungrounded)


def test_invented_breach_actor_is_flagged():
    poisoned = GROUNDED_FILING.replace("LockBit 3.0", "BlackMatter 4.2")
    r = score_filing(poisoned, FACTS, branch="nis2")
    assert not r.passes(1.0)
    assert any(u.kind == "named_entity" and "BlackMatter" in u.span
               for u in r.ungrounded)


def test_statutory_numbers_and_regulatory_nouns_are_not_flagged():
    # "72 hours", "Article 23", year 2026: all legitimate regulatory prose, never
    # flagged. Only count-shaped numbers and the named breach actor are scored.
    r = score_filing(GROUNDED_FILING, FACTS, branch="nis2")
    flagged = {u.span for u in r.ungrounded}
    assert "72" not in flagged
    assert "23" not in flagged
    assert "Article 23" not in flagged
    assert "2026" not in flagged


def test_claims_block_is_not_scored():
    # The [CLAIMS] block carries the canonical record count as a bare integer; it
    # is the Warden's deterministic envelope, not LLM prose, so it must not enter
    # the faithfulness score. A filing whose ONLY large number is inside the
    # claims block has no count-shaped span in the prose.
    prose_only = (
        "An incident occurred and was contained. Notification follows.\n\n"
        "[CLAIMS]\nbranch=nis2\nincident_start_utc=2026-06-16T02:14:00+00:00\n"
        "records_affected=9999999\nattacker=LockBit 3.0\n"
        "containment=partially_contained\n[/CLAIMS]")
    r = score_filing(prose_only, FACTS, branch="nis2")
    assert all(u.span != "9999999" for u in r.ungrounded)


# --- 2. purity / determinism ------------------------------------------------
def test_scorer_is_deterministic():
    a = score_filing(GROUNDED_FILING, FACTS, branch="nis2").as_dict()
    b = score_filing(GROUNDED_FILING, FACTS, branch="nis2").as_dict()
    assert a == b


def test_score_filings_does_not_mutate_inputs():
    filings = [{"regime": "NIS2", "text": GROUNDED_FILING}]
    snapshot = json.dumps(filings)
    score_filings(filings, FACTS)
    assert json.dumps(filings) == snapshot


def test_amended_filing_grounds_against_amended_record():
    amended_text = (
        "Records affected revised to 2,100,000 [field: records_affected].\n\n"
        "[CLAIMS]\nbranch=sec\nincident_start_utc=2026-06-16T02:14:00+00:00\n"
        "records_affected=2100000\nattacker=LockBit 3.0\n"
        "containment=contained\n[/CLAIMS]")
    # Against the ORIGINAL record the revised figure is flagged.
    r_orig = score_filing(amended_text, FACTS, branch="sec")
    assert not r_orig.passes(1.0)
    # Against the AMENDED record it is grounded.
    amended = dict(FACTS, records_affected=2_100_000)
    r_amend = score_filing(amended_text, amended, branch="sec")
    assert r_amend.passes(1.0)


# --- 3. inline citation validation ------------------------------------------
def test_citation_to_existing_field_is_valid():
    text = ("48,211 records were affected [field: records_affected]. "
            "The actor was LockBit 3.0 [field: attacker].")
    c = validate_citations(text, FACTS)
    assert c.all_valid
    assert set(c.valid) == {"records_affected", "attacker"}
    assert c.invalid == []


def test_citation_to_nonexistent_field_is_caught():
    text = "The breach exposed crypto wallets [field: crypto_wallets]."
    c = validate_citations(text, FACTS)
    assert not c.all_valid
    assert "crypto_wallets" in c.invalid


def test_strip_citations_removes_tags_but_keeps_prose_and_claims():
    text = ("48,211 records affected [field: records_affected].\n\n"
            "[CLAIMS]\nbranch=nis2\n[/CLAIMS]")
    stripped = strip_citations(text)
    assert "[field:" not in stripped
    assert "48,211 records affected" in stripped
    assert "[CLAIMS]" in stripped


# --- the load-bearing invariant: grounding never gates ----------------------
def test_grounding_result_never_changes_a_gate_decision():
    # A poisoned filing (ungrounded) and a clean filing must produce IDENTICAL
    # gate behavior, because the gate path does not read the grounding score. We
    # assert structurally: the grounding API surface exposes only a score, the
    # flagged spans, and as_dict; it exposes no method that blocks, releases, or
    # advances a transition.
    r = score_filing(GROUNDED_FILING.replace("48,211", "9,500,000"), FACTS)
    public = {name for name in dir(r) if not name.startswith("_")}
    forbidden = {"gate", "block", "release", "admit", "transition", "suppress",
                 "stop", "advance"}
    assert public & forbidden == set()


def test_grounding_packet_block_carries_no_release_authority():
    # The packet's grounding block is data only: a threshold, the per-filing
    # rows, and an all_pass flag. The release decision lives in packet["release"]
    # and the state_transitions, never in packet["grounding"].
    from floor.grounding import score_filings as sf
    rows = sf([{"regime": "NIS2", "text": GROUNDED_FILING}], FACTS)
    assert isinstance(rows, list)
    for row in rows:
        assert set(row) >= {"branch", "score", "grounded", "total", "ungrounded"}
        assert "released" not in row
        assert "admitted" not in row


# --- the judge-runnable receipt --------------------------------------------
def test_grounding_report_script_passes_on_the_clean_run():
    proc = subprocess.run([sys.executable, str(REPORT_SCRIPT)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "VERDICT: PASS" in proc.stdout
    assert "FLAGGED (good)" in proc.stdout


def test_poisoned_fixture_is_caught_by_the_scorer():
    fixture_path = DATA / "grounding-poisoned-fixture.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    fr = fixture["incident"]["fact_record"]
    caught_any = False
    for f in fixture["filings"]:
        r = score_filing(f["text"], fr, branch=f.get("regime", ""))
        if not r.passes(1.0):
            caught_any = True
    assert caught_any, "the poisoned fixture must be flagged by the scorer"
