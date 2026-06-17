"""Structured run telemetry + the operability / SLO block (E1.6).

These prove the operability narrative an SRE / enterprise judge asks for, and
prove it is gated so the trust spine is untouched:

  - the operability block renders with the per-regime deadline MARGIN, and each
    margin equals deadline minus filed-at from the deterministic clock math;
  - the nearest-deadline, the SLO line, the per-phase timings, and the
    throughput / reliability counts are all present and correct;
  - a clock that never filed (the NIS2 early-warning clock the run does not stop)
    is reported as running with no fabricated margin;
  - a trivial run renders a clean, zeroed block (nothing notable, nothing faked);
  - CRITICALLY adding the telemetry does NOT change the run-log sha and does NOT
    break byte-identical replay: the block is computed entirely OUT-OF-LOG, so a
    fresh normal run reproduces the SEALED capture sha byte-for-byte, and the
    rendered packet HTML carries the SLO without any glyph leaking.

No live network and no LLM: injected FakeBand clients and stub drafters, exactly
the harness test_full_floor.py uses.
"""

from __future__ import annotations

from datetime import timezone
from pathlib import Path

from floor.run_floor import (
    DRAFTER_ROLES, TS_DIFF, TS_DRAFT, TS_FACTS, TS_RELEASE, run_floor)
from floor.shell_adapter import FakeBandClient, FakeRoom
from floor.telemetry import RunTelemetry
from warden.clocks import ClockEngine, parse_ts

# The sealed normal-mode capture sha. A fresh normal run MUST reproduce this byte
# for byte; if the operability block ever leaked into the hashed run-log this
# would move, which is exactly the regression this pins.
SEALED_NORMAL_SHA = (
    "89dae1455e3719996036ff4fc671755894003ef44b3938f3b9dc597aa54226f3")


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
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode=mode, clients=clients,
                     draft_fns=_stub_draft_fns())


# ---- the block renders and carries margins ---------------------------------

def test_operability_block_present_on_normal_run(tmp_path):
    packet = _run("normal", tmp_path)
    op = packet.get("operability")
    assert op is not None
    assert op["mode"] == "normal"
    assert op["slo_line"]
    assert op["deadline_margins"]
    assert op["phase_timings"]


def test_deadline_margin_equals_deadline_minus_filed_at(tmp_path):
    # The margin must equal the deterministic clock math exactly: for every clock
    # that filed, margin_hours == (deadline - stopped_at) in hours. The release
    # moment for the three drafter branches is TS_RELEASE.
    packet = _run("normal", tmp_path)
    op = packet["operability"]
    filed = {m["clock"]: m for m in op["deadline_margins"] if m["filed"]}
    assert filed, "at least the released branches must carry a filed margin"
    release = parse_ts(TS_RELEASE)
    for m in filed.values():
        deadline = parse_ts(m["deadline_utc"])
        expected = round((deadline - release).total_seconds() / 3600.0, 2)
        assert m["margin_hours"] == expected
        assert m["filed_utc"] == release.isoformat()
        assert m["breached"] is False


def test_known_run_margin_numbers(tmp_path):
    # Pin the exact margin numbers for the normal run so a future clock-math change
    # is caught. NIS2/DORA full clocks (72h from T0 02:14) filed at 05:00 on the
    # SAME day, so 69.23h of margin; SEC (4 business days to June 23) has 187.00h.
    packet = _run("normal", tmp_path)
    op = packet["operability"]
    by_clock = {m["clock"]: m for m in op["deadline_margins"]}
    assert by_clock["NIS2 full notification (72h)"]["margin_hours"] == 69.23
    assert by_clock["DORA major-incident (72h)"]["margin_hours"] == 69.23
    assert by_clock["SEC 8-K (4 business days)"]["margin_hours"] == 187.0
    # The SEC June 23 deadline is the pinned demo invariant.
    assert by_clock["SEC 8-K (4 business days)"]["deadline_utc"].startswith(
        "2026-06-23")
    assert op["min_filed_margin_hours"] == 69.23
    assert op["any_breached"] is False


def test_unfiled_clock_reports_running_not_a_fake_margin(tmp_path):
    # The NIS2 early-warning clock is started but the run never stops it. It must
    # be reported as running with NO margin, never a fabricated zero.
    packet = _run("normal", tmp_path)
    op = packet["operability"]
    early = next(m for m in op["deadline_margins"]
                 if m["clock"] == "NIS2 early warning (24h)")
    assert early["filed"] is False
    assert early["filed_utc"] is None
    assert early["margin_hours"] is None
    assert early["breached"] is False


def test_nearest_deadline_is_earliest_clock(tmp_path):
    packet = _run("normal", tmp_path)
    op = packet["operability"]
    nearest = op["nearest_deadline"]
    deadlines = [m["deadline_utc"] for m in op["deadline_margins"]]
    assert nearest["deadline_utc"] == min(deadlines)
    # On the normal run the nearest deadline is the 24h NIS2 early warning.
    assert nearest["clock"] == "NIS2 early warning (24h)"


def test_phase_timings_match_protocol_timestamps(tmp_path):
    packet = _run("normal", tmp_path)
    phases = {p["phase"]: p for p in packet["operability"]["phase_timings"]}
    assert phases["drafting"]["start"] == TS_FACTS
    assert phases["drafting"]["end"] == TS_DRAFT
    assert phases["contradiction_round_trip"]["start"] == TS_DRAFT
    assert phases["contradiction_round_trip"]["end"] == TS_DIFF
    assert phases["two_key_release"]["end"] == TS_RELEASE


def test_throughput_and_reliability_counts(tmp_path):
    packet = _run("normal", tmp_path)
    op = packet["operability"]
    assert op["throughput"]["filings"] == 3
    assert op["throughput"]["released"] == 3
    assert op["throughput"]["diff_conflicts"] == 0
    # A clean offline run touches no network and kills nothing.
    assert op["reliability"]["recovered_retries"] == 0
    assert op["reliability"]["duplicates_dropped"] == 0
    assert op["reliability"]["chaos_events"] == 0
    assert op["reliability"]["rejected_transitions"] == 0


def test_chaos_run_reports_duplicate_dropped_in_operability(tmp_path):
    # The chaos beat drops exactly one duplicate; the operability block surfaces it
    # in the reliability counters and the chaos-event tally.
    packet = _run("chaos", tmp_path)
    rel = packet["operability"]["reliability"]
    assert rel["duplicates_dropped"] == 1
    assert rel["chaos_events"] >= 1


# ---- the SLO line ----------------------------------------------------------

def test_slo_line_states_margin_and_zero_breaches(tmp_path):
    packet = _run("normal", tmp_path)
    slo = packet["operability"]["slo_line"]
    assert "3 filings landed" in slo
    assert "69.23h of statutory margin" in slo
    assert "0 breach(es)" in slo
    assert "byte-identical" in slo


def test_slo_line_on_packet_cover(tmp_path):
    packet = _run("normal", tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "OPERABILITY SLO" in html
    assert "8d. Operability and statutory-margin SLO" in html
    assert "Per-regime deadline margin" in html


# ---- the renderer is clean on a trivial / empty block ----------------------

def test_render_operability_empty_is_blank():
    from floor.packet import _render_operability
    assert _render_operability({}) == ""
    assert _render_operability(None) == ""


def test_render_operability_trivial_run_is_clean():
    # A run with nothing notable (no filings, no breaches, no clocks): the block
    # renders the SLO line and a zeroed throughput row, nothing fabricated.
    from floor.packet import _render_operability
    trivial = RunTelemetry(mode="normal")
    trivial.finalize(ClockEngine(), [])
    out = _render_operability(trivial.operability_block())
    assert "Operability and statutory-margin SLO" in out
    assert "No filing landed on this run" in out
    # No clocks: no margin table, no phase table, just the SLO and the zeroed row.
    assert "Per-regime deadline margin" not in out
    # No forbidden glyphs ever leak into the rendered receipt. The em/en dashes
    # are written as escapes so this file carries no raw glyph and needs no
    # hygiene-gate allowlist exception.
    assert chr(0x2014) not in out and chr(0x2013) not in out


# ---- the critical guard: telemetry does NOT move the sha or break replay ----

def test_operability_does_not_change_run_log_sha(tmp_path):
    # The whole point: the operability block is derived OUT-OF-LOG, so a fresh
    # normal run with the telemetry in place reproduces the SEALED capture sha
    # byte-for-byte. If the block ever leaked into the hashed run-log this fails.
    packet = _run("normal", tmp_path)
    assert packet["replay"]["original_sha256"] == SEALED_NORMAL_SHA
    assert packet["replay"]["byte_identical"] is True


def test_replay_byte_identical_with_telemetry(tmp_path):
    packet = _run("normal", tmp_path)
    from warden.replay import RunLog, replay
    loaded = RunLog.load(Path(packet["_paths"]["run_log"]))
    # Replay through a fresh state machine reproduces the sealed bytes and sha.
    assert replay(loaded).sha256() == packet["replay"]["original_sha256"]
    assert loaded.to_jsonl() == replay(loaded).to_jsonl()


def test_run_log_jsonl_contains_no_operability_key(tmp_path):
    # Belt and suspenders: assert the literal run-log bytes carry no telemetry. The
    # operability block, the margins, and the SLO line must appear NOWHERE in the
    # hashed JSONL; they live only in the packet render.
    packet = _run("normal", tmp_path)
    jsonl = Path(packet["_paths"]["run_log"]).read_text(encoding="utf-8")
    assert "operability" not in jsonl
    assert "margin_hours" not in jsonl
    assert "slo_line" not in jsonl


# ---- the margin math is independent of timezone presentation ---------------

def test_margin_uses_utc_instants(tmp_path):
    # The clock deadline and filed-at are stored as UTC instants; the margin is a
    # pure instant difference, so it is invariant to display zone. Confirm the
    # parsed instants are tz-aware UTC.
    packet = _run("normal", tmp_path)
    op = packet["operability"]
    filed = next(m for m in op["deadline_margins"] if m["filed"])
    assert parse_ts(filed["deadline_utc"]).tzinfo == timezone.utc
    assert parse_ts(filed["filed_utc"]).tzinfo == timezone.utc
