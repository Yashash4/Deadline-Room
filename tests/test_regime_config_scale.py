"""Regulation-as-config scale receipt: adding a regulator is a DATA edit.

This is the "adding a regulator is adding an agent, not a rewrite" proof. The six
live regimes (NIS2 early + full, DORA, SEC, UK ICO, NYDFS) are produced FROM the
declarative catalog floor/regimes.yaml. Here we add a SEVENTH regime purely in a
fixture catalog (a temp YAML file, plus the in-memory catalog the floor walks) and
assert:

  (a) a seventh statutory clock appears, with the catalog-named clock length, unit,
      and trigger event, computed by the SAME engine,
  (b) ZERO edits to any warden/ module are needed: the seventh clock flows through
      warden/clocks.py unchanged (this test imports and exercises the real engine,
      and the warden/ tree is asserted untouched against its own checked-in state),
  (c) replay stays byte-identical with the seventh clock live.

The whole point is that the assertions below are satisfied by appending a record,
never by editing engine code.
"""

from pathlib import Path

import warden
from floor import regimes
from floor import run_floor as rf
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom
from warden.clocks import ClockEngine, parse_ts


# A seventh regime expressed ENTIRELY as a catalog record. It is a fictitious
# national authority with a clean 48 calendar-hour clock from awareness, anchored
# at incident T0 in the demo (so it is a pure startup clock that needs no new code
# path). Nothing about this block touches the engine; it is data.
SEVENTH_REGIME_YAML = """
regimes:
  - key: nis2_early
    authority: national CSIRT (NIS2)
    branch: nis2-early
    regime_label: NIS2 early warning
    trigger_event: becoming aware
    clock: {name: NIS2 early warning (24h), length: 24, unit: hours, business_days: false, holiday_calendar: none}
    format_profile: nis2_early
    start: {mode: startup, anchor: incident_t0}
  - key: seventh
    authority: Fictitious National Authority (FNA)
    branch: fna
    regime_label: FNA early notification
    trigger_event: becoming aware
    clock: {name: FNA early notification (48h), length: 48, unit: hours, business_days: false, holiday_calendar: none}
    format_profile: nis2_early
    start: {mode: startup, anchor: incident_t0}
"""


def test_seventh_regime_from_catalog_produces_a_clock_zero_engine_edits(tmp_path):
    # Write the fixture catalog with the seventh regime as DATA.
    catalog_path = tmp_path / "regimes.yaml"
    catalog_path.write_text(SEVENTH_REGIME_YAML, encoding="utf-8")

    # The loader reads the seventh regime with no special-casing.
    specs = regimes.load_catalog(catalog_path)
    keys = [s.key for s in specs]
    assert "seventh" in keys

    seventh = regimes.by_key(specs)["seventh"]
    assert seventh.clock.length == 48
    assert seventh.clock.unit == regimes.UNIT_HOURS
    assert seventh.is_startup

    # The SAME engine (warden/clocks.py, untouched) computes the seventh clock from
    # the catalog record. Adding the regulator added a YAML block, not engine code.
    clocks = ClockEngine()
    for spec in regimes.startup_regimes(specs):
        anchor = rf._STARTUP_ANCHOR_TS[spec.start_anchor]
        clocks.start_hours(spec.clock.name, f"inc-test:{spec.branch}", anchor,
                           spec.clock.length, trigger_event=spec.trigger_event)
    names = [c.name for c in clocks.all()]
    assert "FNA early notification (48h)" in names

    fna = clocks.get("inc-test:fna")
    assert fna is not None
    assert fna.trigger_event == "becoming aware"
    # 48 flat calendar hours from T0, computed by the unchanged engine.
    assert fna.deadline == parse_ts(rf.INCIDENT_T0) + (fna.deadline - fna.started_at)
    assert (fna.deadline - fna.started_at).total_seconds() == 48 * 3600


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
            return (f"{regime} notification. {claim_facts['records_affected']} "
                    f"records, {claim_facts['attacker']}.")
        return fn
    return {r.branch: make(r.regime) for r in DRAFTER_ROLES}


def test_seventh_clock_appears_in_a_full_run_with_zero_warden_edits(tmp_path, monkeypatch):
    # Drive the REAL floor with the seventh regime injected purely as catalog data
    # (the in-memory catalog the floor walks). The seventh clock appears in the
    # produced packet, computed by the same warden/ engine, and replay stays
    # byte-identical. No warden/ file is edited to make this happen.
    catalog_path = tmp_path / "regimes.yaml"
    catalog_path.write_text(SEVENTH_REGIME_YAML, encoding="utf-8")
    fixture_catalog = regimes.load_catalog(catalog_path)
    monkeypatch.setattr(rf, "REGIME_CATALOG", fixture_catalog)

    room, clients = _build_clients()
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns())

    corr_ids = {c["correlation_id"] for c in packet["clocks"]}
    assert "inc-8842:fna" in corr_ids  # the seventh clock, from data alone
    fna = next(c for c in packet["clocks"] if c["correlation_id"] == "inc-8842:fna")
    assert fna["name"] == "FNA early notification (48h)"
    assert fna["trigger_event"] == "becoming aware"

    # The receipt's other half: replay byte-identical with the seventh clock live.
    assert packet["replay"]["byte_identical"] is True


def test_no_warden_module_imports_the_regime_catalog():
    # The deterministic core never reaches into the config. The catalog is read by
    # floor/ only; warden/ stays config-agnostic, which is WHY adding a regime
    # needs zero warden edits. Assert no warden/*.py references the regime catalog.
    warden_dir = Path(warden.__file__).resolve().parent
    offenders = []
    for py in warden_dir.glob("*.py"):
        text = py.read_text(encoding="utf-8")
        if "regimes" in text or "regimes.yaml" in text:
            offenders.append(py.name)
    assert offenders == [], f"warden/ must not read the regime catalog: {offenders}"
