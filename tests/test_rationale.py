"""test_rationale.py -- the deterministic decision-rationale ledger (E9.1).

ONE source of truth for the plain-English "why" behind every Warden decision. The
room post (run_floor _warden_announce), the Examiner Packet ("Decision rationale"
section + the transition table's why column), and the web copy (deriveGate) all
read floor/rationale.py, so the three read the same bytes instead of three
hand-typed strings.

Layers:

  Coverage layer: every protocol Event has a governing rule, and every rule has a
  template, so a new gate cannot ship without a rationale.

  Identity layer: the room text == the packet text == the web text for a decision
  (the contradiction block and the amendment block), byte for byte.

  Driving-fact layer: the rationale names the EXACT driving fact value (the
  conflicting field's two values, the revised figure, the recorded claims).

  Render-time layer: the ledger is derived from the assembled packet, never
  appended to the hashed run-log; a fresh normal FakeBand run reproduces the
  sealed sha 89dae145 with byte-identical replay.
"""

import inspect
import json
from pathlib import Path

import floor.rationale as rationale_mod
from floor import rationale
from floor.packet import _render_html
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom
from warden.diff import Conflict
from warden.state_machine import Event

# The sealed normal-mode run-log sha (canonical-LF). A fresh normal run MUST
# reproduce this byte for byte; if the rationale ever leaked into the hashed
# run-log this would move. This is exactly the regression this file pins.
SEALED_NORMAL_SHA = (
    "89dae1455e3719996036ff4fc671755894003ef44b3938f3b9dc597aa54226f3")


# ---- a self-contained FakeBand run (no network, no LLM) ---------------------

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
            return (f"{regime} mandatory notification. Records "
                    f"{claim_facts['records_affected']} attacker "
                    f"{claim_facts['attacker']}. Test stub.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def _run(mode, tmp_path):
    _, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode=mode, clients=clients,
                     draft_fns=_stub_draft_fns())


# The amendment beat needs a live reconciliation characterization (an LLM call the
# offline stub does not provide), so the amendment-mode packet is read from the
# bundled capture and its decision-rationale ledger is derived at test time
# exactly as the packet assembly derives it (rationale_record over the assembled
# packet). This is the same render-time derive the live run performs.
DATA = Path(__file__).resolve().parents[1] / "web" / "data"


def _amendment_packet():
    packet = json.loads((DATA / "packet-amendment.json").read_text(encoding="utf-8"))
    packet["decision_rationale"] = rationale.rationale_record(packet)
    return packet


# ---- coverage layer: no gate ships without a rationale ----------------------

def test_every_event_has_a_governing_rule():
    # A new Event in the protocol state machine must declare its governing rule
    # here, or this fails. That is the "a new gate cannot ship without a
    # rationale" guarantee.
    for event in Event:
        assert event in rationale.EVENT_RULE, (
            f"Event {event.value} has no governing rule in rationale.EVENT_RULE")


def test_every_rule_id_referenced_has_a_template():
    # Every kind named in EVENT_RULE must resolve to a RuleTemplate with a
    # non-empty id and template.
    for kind in rationale.EVENT_RULE.values():
        assert kind in rationale.RULES, f"no RuleTemplate for kind {kind}"
    for kind, tmpl in rationale.RULES.items():
        assert tmpl.rule_id, f"{kind}: empty rule_id"
        assert tmpl.template, f"{kind}: empty template"


def test_every_constructor_kind_has_a_template():
    # Each constructor builds a known kind; assert every RULES kind is reachable.
    built_kinds = {
        rationale.diff_green(2).kind,
        rationale.diff_blocked(
            Conflict("records_affected", "sec", 1, "nis2", 2)).kind,
        rationale.diff_resolved("sec", "incident_start_utc", "x", 3).kind,
        rationale.release_key1("gc", "general_counsel", "SEC").kind,
        rationale.release_key2("lena", "ciso", "SEC", 3).kind,
        rationale.dedup_dropped("SEC", "duplicate_dropped").kind,
        rationale.liveness_dead("SEC", 3, 2).kind,
        rationale.liveness_recovered("SEC").kind,
        rationale.amend_blocked("records_affected", 1, 2, "SEC and NIS2", "r").kind,
        rationale.draft_recorded("SEC", {
            "incident_start_utc": "2026-06-20T02:14:00+00:00",
            "records_affected": 1, "attacker": "lockbit",
            "containment": "partially_contained"}).kind,
    }
    assert built_kinds == set(rationale.RULES.keys()), (
        "a RULES template is unreachable from any constructor")


# ---- driving-fact layer: the rationale names the EXACT value ----------------

def test_block_rationale_names_the_exact_conflicting_values():
    c = Conflict("incident_start_utc", "sec",
                 "2026-06-20T02:14:00+00:00", "nis2",
                 "2026-06-20T01:14:00+00:00")
    r = rationale.diff_blocked(c)
    assert r.rule_id == "WARDEN-RULE-CONTRADICTION-VETO"
    # both exact values appear verbatim, named with the field
    assert "incident_start_utc" in r.plain_why
    assert "2026-06-20T02:14:00+00:00" in r.plain_why
    assert "2026-06-20T01:14:00+00:00" in r.plain_why
    assert "SEC" in r.plain_why and "NIS2" in r.plain_why


def test_amend_rationale_names_the_exact_revised_figure():
    r = rationale.amend_blocked("records_affected", 21000, 84000,
                                "@SEC Drafter and @NIS2 Drafter", "no concur yet")
    # the exact old and new figures, thousands-grouped, are named
    assert "21,000" in r.plain_why
    assert "84,000" in r.plain_why
    assert "no concur yet" in r.plain_why


def test_draft_recorded_names_the_recorded_claim_values():
    r = rationale.draft_recorded("DORA", {
        "incident_start_utc": "2026-06-20T02:14:00+00:00",
        "records_affected": 21000,
        "attacker": "lockbit",
        "containment": "partially_contained"})
    assert "2026-06-20T02:14:00+00:00" in r.plain_why
    assert "21,000" in r.plain_why
    assert "lockbit" in r.plain_why
    assert "partially_contained" in r.plain_why


def test_explain_dispatches_on_conflict_and_rejects_unknown():
    c = Conflict("records_affected", "sec", 1, "nis2", 2)
    assert rationale.explain(c).kind == "diff_blocked"
    try:
        rationale.explain(object())
    except TypeError:
        pass
    else:
        raise AssertionError("explain must reject an undescribable object")


# ---- the packet ledger derives from the assembled packet --------------------

def test_packet_carries_the_rationale_ledger_on_a_normal_run(tmp_path):
    packet = _run("normal", tmp_path)
    ledger = packet.get("decision_rationale")
    assert ledger, "the normal packet must carry a decision_rationale ledger"
    # a clean run records the green diff with a named filing count
    assert "diff_green" in ledger
    g = ledger["diff_green"]
    assert g["rule_id"] == "WARDEN-RULE-DIFF-GREEN"
    assert g["plain_why"]


def test_block_ledger_present_on_a_contradiction_run(tmp_path):
    packet = _run("inject_contradiction", tmp_path)
    ledger = packet["decision_rationale"]
    assert "diff_blocked" in ledger, (
        "a contradiction run must record the block rationale")
    why = ledger["diff_blocked"]["plain_why"]
    # the exact conflicting field is named in the derived block rationale
    assert "incident_start_utc" in why
    assert ledger["diff_blocked"]["rule_id"] == "WARDEN-RULE-CONTRADICTION-VETO"


def test_amend_ledger_present_on_an_amendment_run():
    packet = _amendment_packet()
    ledger = packet["decision_rationale"]
    assert "amend_blocked" in ledger, (
        "an amendment run must record the amendment-block rationale")
    assert ledger["amend_blocked"]["rule_id"] == "WARDEN-RULE-AMEND-GUARD"


# ---- identity layer: room text == packet text == web text -------------------

def test_room_packet_web_block_text_are_the_same_bytes(tmp_path):
    # The contradiction block: the Warden posted rationale.diff_blocked(c0), the
    # packet's ledger entry is built from the same conflict, and the web reads the
    # same ledger entry. Assert the three are byte-identical.
    packet = _run("inject_contradiction", tmp_path)
    ledger = packet["decision_rationale"]
    packet_why = ledger["diff_blocked"]["plain_why"]

    # Web: the web reads packet.decision_rationale[kind].plain_why verbatim (see
    # web/app.js rationaleWhy), so the web bytes are the ledger bytes.
    web_app = (Path(__file__).resolve().parents[1] / "web" / "app.js").read_text(
        encoding="utf-8")
    assert 'rationaleWhy(p, "diff_blocked")' in web_app, (
        "the web gate panel must read the diff_blocked rationale from the ledger")

    # Room: rebuild the room post from the first conflict the packet recorded; it
    # is the same constructor the run_floor announce site calls.
    first = packet["diff"]["blocked_conflicts"][0]
    conflict = rationale_mod._parse_human_conflict(first)
    assert conflict is not None
    room_why = rationale.diff_blocked(conflict).plain_why
    assert room_why == packet_why, "room block text != packet block text"


def test_room_packet_web_amend_text_are_the_same_bytes():
    packet = _amendment_packet()
    ledger = packet["decision_rationale"]
    packet_why = ledger["amend_blocked"]["plain_why"]
    rec = packet["reconciliation"]

    web_app = (Path(__file__).resolve().parents[1] / "web" / "app.js").read_text(
        encoding="utf-8")
    assert 'rationaleWhy(p, "amend_blocked")' in web_app, (
        "the web gate panel must read the amend_blocked rationale from the ledger")

    reopened = rec.get("reopened_branches") or []
    branch_list = " and ".join(b.upper() for b in reopened) or "the reopened branches"
    room_why = rationale.amend_blocked(
        rec["fact_key"], rec["old_value"], rec["new_value"],
        branch_list, rec["block_reason"]).plain_why
    assert room_why == packet_why, "room amend text != packet amend text"


# ---- render-time layer: the packet HTML renders the rationale ---------------

def test_packet_html_renders_the_rationale_section_and_why_column(tmp_path):
    packet = _run("inject_contradiction", tmp_path)
    html = _render_html(packet)
    assert "Decision rationale" in html
    assert "Why (plain English)" in html  # the transition table's new column
    # the block plain_why is rendered into the HTML, escaped
    why = packet["decision_rationale"]["diff_blocked"]["plain_why"]
    assert why.split("=")[0] in html  # the leading text is present verbatim


def test_rationale_module_is_pure_no_io_no_llm():
    # The module must make no network / LLM / now() calls. Assert its source has
    # no obvious I/O imports or time-of-day reads.
    src = inspect.getsource(rationale_mod)
    for forbidden in ("requests", "open(", "datetime.now", "time.time", "urllib",
                      "httpx", "LiveBand"):
        assert forbidden not in src, f"rationale.py must not use {forbidden}"


# ---- the critical guard: the rationale does NOT move the sha or break replay -

def test_rationale_does_not_change_run_log_sha(tmp_path):
    # The whole point: the rationale is assembled OUT-OF-LOG at render time, so a
    # fresh normal run reproduces the SEALED capture sha byte-for-byte. If the
    # rationale ever leaked into the hashed run-log this fails.
    packet = _run("normal", tmp_path)
    assert packet["replay"]["original_sha256"] == SEALED_NORMAL_SHA
    assert packet["replay"]["byte_identical"] is True


def test_replay_byte_identical_with_rationale(tmp_path):
    from warden.replay import RunLog, replay
    packet = _run("normal", tmp_path)
    loaded = RunLog.load(Path(packet["_paths"]["run_log"]))
    assert replay(loaded).sha256() == packet["replay"]["original_sha256"]
    assert loaded.to_jsonl() == replay(loaded).to_jsonl()


def test_run_log_jsonl_carries_no_rationale_key(tmp_path):
    # Belt and suspenders: the literal run-log bytes carry no rationale text.
    packet = _run("normal", tmp_path)
    raw = Path(packet["_paths"]["run_log"]).read_text(encoding="utf-8")
    assert "plain_why" not in raw
    assert "decision_rationale" not in raw
    assert "WARDEN-RULE-" not in raw
    # the JSON sidecar, by contrast, DOES carry it (it is render-time output)
    sidecar = json.loads(
        Path(packet["_paths"]["json"]).read_text(encoding="utf-8"))
    assert "decision_rationale" in sidecar
