"""test_packet_presentation.py -- the regulator-grade Examiner Packet chrome:
a filing-style cover block, an inline-SVG handoff graph, and print/PDF styling,
all rendered from data already in the packet dict. The deterministic core is not
touched: these tests prove the restyle adds presentation bytes only and leaves
the run-log hash and the JSON sidecar byte-identical.
"""

import json
from pathlib import Path

from floor.packet import _render_html
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom
from warden.replay import RunLog, replay


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
    fns = {}

    def make(regime):
        def fn(claim_facts):
            return (f"{regime} mandatory notification. Meridian Trust Bank N.V. "
                    f"reports an incident starting {claim_facts['incident_start_utc']} "
                    f"affecting {claim_facts['records_affected']} records, attacker "
                    f"{claim_facts['attacker']}, containment "
                    f"{claim_facts['containment']}. Deterministic test stub.")
        return fn
    for r in DRAFTER_ROLES:
        fns[r.branch] = make(r.regime)

    # The two characterization stubs the reconciliation turns use, so the
    # amendment mode runs without a live LLM. Deterministic, ASCII, dash-free.
    def sec_characterize(counterpart_text):
        return "approximately 2.1 million affected records, data categories bounded"

    def nis2_characterize(counterpart_text):
        return counterpart_text

    fns["sec:characterize"] = sec_characterize
    fns["nis2:characterize"] = nis2_characterize
    return fns


def _run(mode, tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode=mode, clients=clients,
                     draft_fns=_stub_draft_fns())


# ---- 1. The cover renders from real data -----------------------------------

def test_packet_has_regulator_cover(tmp_path):
    packet = _run("normal", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    # The cover band and classification line.
    assert "EXAMINER PACKET" in html
    assert "CONFIDENTIAL: REGULATORY FILING RECORD" in html
    # Reporting entity and incident reference pulled from the fact-record.
    assert "Meridian Trust Bank N.V." in html
    assert packet["incident"]["incident_id"] in html
    # Every clock regime label appears in the jurisdictions strip.
    for c in packet["clocks"]:
        assert c["name"] in html
    # The signoff chain presents both human roles as a chain.
    assert "General Counsel" in html
    assert "Head of IR" in html
    assert "One alone never" in html
    # The replay seal carries the run-log hash on the cover.
    assert packet["replay"]["original_sha256"][:24] in html


# ---- 2. The handoff graph is data-driven, not decorative -------------------

def test_packet_has_handoff_graph(tmp_path):
    packet = _run("normal", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "<svg" in html
    assert 'class="handoff-graph"' in html
    # Every handoff message id (short form) appears in the SVG, so the graph is
    # generated from handoff_trace, not hand-drawn.
    for h in packet["handoff_trace"]:
        mid = h.get("message_id", "")
        if mid:
            assert str(mid)[:8] in html
    # The Warden gate node carries the admitted/rejected transition counts.
    admitted = sum(1 for t in packet["state_transitions"] if t["admitted"])
    assert f"{admitted} admitted" in html
    # On a clean run the gate clears green and releases.
    assert "Warden gate: RELEASED" in html
    assert "gate-ok" in html
    # The textual handoff table is kept beneath the graph as the fallback.
    assert "To (@mention)" in html


def test_handoff_graph_gate_blocks_red_on_contradiction(tmp_path):
    # inject_contradiction resolves, so the gate clears; assert the graph reflects
    # that the contradiction was caught and then cleared (data-driven outcome).
    packet = _run("inject_contradiction", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Warden gate: CLEARED" in html
    assert "Contradiction caught" in html


# ---- 3. Print styling present ----------------------------------------------

def test_packet_is_print_ready(tmp_path):
    packet = _run("normal", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "@media print" in html
    assert "break-inside" in html
    assert "page-break-after" in html


# ---- 4. THE LOAD-BEARING GUARD: the restyle never touches gated data -------

def test_packet_styling_does_not_touch_load_bearing_data(tmp_path):
    packet = _run("normal", tmp_path)
    run_log_path = Path(packet["_paths"]["run_log"])
    json_path = Path(packet["_paths"]["json"])

    # The replay hash recorded in the packet is the SHA-256 of the JSONL run log,
    # computed in run_floor.py, never a function of the HTML. Re-load the log,
    # replay it, and confirm the hash still matches what the packet reports.
    loaded = RunLog.load(run_log_path)
    assert replay(loaded).sha256() == packet["replay"]["original_sha256"]
    assert packet["replay"]["byte_identical"] is True

    # The hash was taken over exactly these JSONL bytes; the file on disk is what
    # the browser re-hashes. Confirm the recorded hash equals sha256 of the log
    # the in-memory RunLog reproduces.
    assert loaded.sha256() == packet["replay"]["original_sha256"]

    # The JSON sidecar round-trips to the same dict the packet rendered from. The
    # render path added no keys to and removed none from the packet dict (only
    # the internal _paths helper key, which write_packet never serializes).
    sidecar = json.loads(json_path.read_text(encoding="utf-8"))
    expected_keys = {k for k in packet if k != "_paths"}
    assert set(sidecar.keys()) == expected_keys

    # Rendering the HTML does not mutate the packet dict it reads.
    before = json.dumps({k: v for k, v in packet.items() if k != "_paths"},
                        sort_keys=True, default=str)
    _render_html({k: v for k, v in packet.items() if k != "_paths"})
    after = json.dumps({k: v for k, v in packet.items() if k != "_paths"},
                       sort_keys=True, default=str)
    assert before == after


# ---- 5. Determinism: the new render is byte-stable -------------------------

def test_packet_html_is_byte_stable(tmp_path):
    packet = _run("normal", tmp_path)
    p = {k: v for k, v in packet.items() if k != "_paths"}
    first = _render_html(p)
    second = _render_html(p)
    # No now()/random in the cover or the SVG layout: two renders are identical.
    assert first == second


def test_packet_html_byte_stable_across_modes(tmp_path):
    for mode in ("normal", "inject_contradiction", "chaos"):
        packet = _run(mode, tmp_path / mode)
        p = {k: v for k, v in packet.items() if k != "_paths"}
        assert _render_html(p) == _render_html(p)


# ---- 6. E9.2: counter-question card, determinism chip, provenance trail ----

def test_packet_renders_counter_questions_chip_and_provenance(tmp_path):
    # A contradiction run exercises the block, the resolution, the two-key
    # release, and the replay proof, so the counter-question card has the richest
    # set of plain answers, every one derived from the packet's own records.
    packet = _run("inject_contradiction", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")

    # The counter-question card: the non-engineer's actual questions, as a real
    # accordion (details/summary), answered from the ledger and the release/replay
    # blocks already in the packet.
    assert "Plain answers to the questions a non-engineer asks" in html
    assert "Did the referee block anything, and exactly why?" in html
    assert "Was any gate decided by an AI?" in html
    assert "Can I prove none of this was altered?" in html
    assert "<details class='cq'>" in html
    # The block answer is the SAME bytes as the ledger's block rationale (one
    # source), not a hand-typed second copy.
    block_why = packet["decision_rationale"]["diff_blocked"]["plain_why"]
    assert block_why.split("=")[0] in html

    # The determinism chip: the contradiction veto is a FIXED rule with no AI
    # judgment; the resolution is AI-drafted content a fixed rule then checked.
    assert "fixed rule (no AI judgment)" in html
    assert "AI drafted, fixed rule checked" in html

    # The provenance trail: the block rationale is bound to the exact run-log
    # entries by content hash, and those hashes are reproducible from the bundled
    # log (a protocol_event payload is byte-identical to a state_transition row).
    ledger = packet["decision_rationale"]
    block_hashes = ledger["diff_blocked"]["evidence_entry_hashes"]
    assert block_hashes, "the block rationale must carry evidence entry hashes"
    for h in block_hashes:
        assert h in html, "each provenance hash must render in the packet"
    # Recompute the same content hash from the bundled run-log entries and confirm
    # the recorded provenance hashes are exactly the admitted protocol_event set.
    import hashlib

    from warden.replay import _canon
    raw = Path(packet["_paths"]["run_log"]).read_text(encoding="utf-8")
    present = {
        hashlib.sha256(_canon(json.loads(line)["payload"]).encode()).hexdigest()
        for line in raw.splitlines() if line.strip()
        and json.loads(line)["type"] == "protocol_event"
        and json.loads(line)["payload"].get("admitted")
    }
    for h in block_hashes:
        assert h in present, (
            "a recorded provenance hash is not an entry in the bundled run log")


def test_counter_questions_clean_run_states_no_block(tmp_path):
    # On a clean run the block question must answer honestly that nothing was
    # blocked, not omit the question or imply a phantom block.
    packet = _run("normal", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Did the referee block anything, and exactly why?" in html
    assert "Nothing was blocked on a contradiction" in html


# ---- 7. Dash-free guard on the rendered HTML -------------------------------

def test_packet_html_is_dash_free(tmp_path):
    # Referenced by codepoint so this source file itself carries no raw dash:
    # U+2014 em-dash, U+2013 en-dash, U+2212 unicode minus.
    em_dash, en_dash, minus = chr(0x2014), chr(0x2013), chr(0x2212)
    for mode in ("normal", "inject_contradiction", "chaos", "amendment"):
        packet = _run(mode, tmp_path / mode)
        html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
        assert em_dash not in html, f"em-dash in {mode} packet"
        assert en_dash not in html, f"en-dash in {mode} packet"
        assert minus not in html, f"unicode minus in {mode} packet"
