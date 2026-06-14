"""The SEC Item 1.05 four-business-day clock must anchor on the MATERIALITY
DETERMINATION moment, not on incident occurrence (T0).

SEC Form 8-K Item 1.05 starts its clock when the registrant DETERMINES the
incident is material, not when it occurred or was discovered (adopting release
33-11216; CorpFin guidance, May 21 2024). NYDFS already anchors at its
determination/recruit moment; this proves the SEC clock now does the same.

The determination constant is fixed on 2026-06-16 so the resulting deadline still
lands on Tue 2026-06-23 (the Juneteenth + weekend skip), byte for byte unchanged
from the prior occurrence-anchored run: only the anchor SOURCE and the
trigger_event label change, never the demo date. These tests pin both halves:
the anchor moved off T0, AND the deadline date is preserved.

They also pin the trigger_event label per regime, so the Examiner Packet reads
each clock honestly: SEC from materiality determination, NIS2 from awareness,
DORA from occurrence, the runtime recruits from their determination/awareness
moment.
"""

from pathlib import Path

from floor.run_floor import (
    DRAFTER_ROLES, INCIDENT_T0, TS_SEC_DETERMINATION, run_floor)
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
            return (f"{regime} mandatory notification. Meridian Trust Bank N.V. "
                    f"reports an incident starting {claim_facts['incident_start_utc']} "
                    f"affecting {claim_facts['records_affected']} records, attacker "
                    f"{claim_facts['attacker']}, containment "
                    f"{claim_facts['containment']}. Deterministic test stub.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def _run(tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                     draft_fns=_stub_draft_fns())


def _clock(packet, name_fragment):
    for c in packet["clocks"]:
        if name_fragment in c["name"]:
            return c
    raise AssertionError(f"no clock matching {name_fragment!r} in {packet['clocks']}")


def test_sec_clock_anchors_on_determination_not_t0(tmp_path):
    packet = _run(tmp_path)
    sec = _clock(packet, "SEC 8-K")
    # The constant is deliberately later than T0, never at occurrence.
    assert sec["started"] == TS_SEC_DETERMINATION
    assert sec["started"] != INCIDENT_T0
    assert TS_SEC_DETERMINATION > INCIDENT_T0  # determination is after occurrence


def test_sec_deadline_date_unchanged_at_june_23(tmp_path):
    # The byte-identical guard: re-anchoring on the determination moment must NOT
    # move the demo deadline. It still lands on Tue 2026-06-23 (Juneteenth +
    # weekend skip), exactly as the occurrence-anchored run produced.
    packet = _run(tmp_path)
    sec = _clock(packet, "SEC 8-K")
    assert sec["deadline"].startswith("2026-06-23")


def test_sec_trigger_event_is_materiality_determination(tmp_path):
    packet = _run(tmp_path)
    sec = _clock(packet, "SEC 8-K")
    assert sec["trigger_event"] == "materiality determination"


def test_nis2_and_dora_trigger_events_labelled_honestly(tmp_path):
    packet = _run(tmp_path)
    early = _clock(packet, "NIS2 early warning")
    full = _clock(packet, "NIS2 full notification")
    dora = _clock(packet, "DORA major-incident")
    # NIS2 Article 23: both the 24h and 72h run from "becoming aware".
    assert early["trigger_event"] == "becoming aware"
    assert full["trigger_event"] == "becoming aware"
    # DORA is anchored at occurrence today and labelled as such (no overclaim).
    assert dora["trigger_event"] == "incident occurrence"
    # Their timing is untouched: still 24h / 72h from T0.
    assert early["started"] == INCIDENT_T0
    assert full["started"] == INCIDENT_T0
    assert dora["started"] == INCIDENT_T0


def test_packet_renders_trigger_event_column_and_chips(tmp_path):
    packet = _run(tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "Trigger event" in html  # the statutory clocks table column
    assert "trigger: materiality determination" in html  # the cover chip
    assert "trigger: becoming aware" in html


def test_replay_byte_identical_with_determination_anchor(tmp_path):
    # The anchor change is a fixed constant, so replay stays byte-identical.
    packet = _run(tmp_path)
    assert packet["replay"]["byte_identical"] is True
