"""test_lead_authority.py -- GDPR Art 56 lead-supervisory-authority routing (E3.6).

Cross-border GDPR is not "file N independent notices to N data-protection
authorities". Under GDPR Article 56(1), where a personal-data breach concerns
cross-border processing, the supervisory authority of the controller's MAIN
ESTABLISHMENT is the LEAD supervisory authority (the single point of contact); the
other in-scope member states' authorities are "concerned" authorities (Art 4(22))
reached THROUGH the lead under the Art 60 cooperation procedure, not filed to
independently. This is a PURE DETERMINISTIC routing decision (no LLM, no judgment):
given the controller's main establishment + the in-scope EU member states, the
correct lead and concerned authorities are a data-driven lookup.

These tests assert:
  - for a given main establishment + a set of in-scope EU states, the correct lead
    SA and concerned SAs are returned per Art 56;
  - a single-state case has a trivial lead and NO concerned authorities;
  - the routing is deterministic + data-driven (no LLM / resolver surface);
  - the main-establishment rule is honored even if it is not in the in-scope set;
  - missing authority data surfaces structurally (not silently dropped);
  - the live cross-border beat renders the lead/concerned routing in the packet;
  - the four DEFAULT sealed captures and their shas are UNCHANGED;
  - byte-identical replay holds for the beat.
"""

from pathlib import Path

import pytest

from floor import regimes
from floor.lead_authority import (
    AuthorityRouting, LeadRouting, SupervisoryAuthority, resolve)
from floor.run_floor import (
    CONTROLLER, EU_SUPERVISORY_AUTHORITIES, DRAFTER_ROLES, run_floor)
from floor.shell_adapter import FakeBandClient, FakeRoom

DATA = Path(__file__).resolve().parent.parent / "web" / "data"


# A small honest fixture map, independent of the catalog, for the pure-routing
# tests (the catalog is exercised separately below).
_AUTHORITIES = {
    "IE": SupervisoryAuthority("IE", "Irish DPC", "Ireland"),
    "DE": SupervisoryAuthority("DE", "German BfDI", "Germany"),
    "FR": SupervisoryAuthority("FR", "French CNIL", "France"),
    "NL": SupervisoryAuthority("NL", "Dutch AP", "Netherlands"),
}


# ---- the pure routing: correct lead + concerned per Art 56 -----------------

def test_lead_is_the_main_establishment_authority():
    routing = resolve("IE", ["IE", "DE", "FR"], _AUTHORITIES)
    assert routing.lead.member_state == "IE"
    assert routing.lead.authority == "Irish DPC"
    assert routing.lead.role == "lead"
    # The others are concerned, in sorted member-state order, never the lead.
    assert [a.member_state for a in routing.concerned] == ["DE", "FR"]
    assert all(a.role == "concerned" for a in routing.concerned)
    assert routing.cross_border is True


def test_lead_changes_with_the_main_establishment():
    # Same in-scope set, different main establishment -> different lead. The lead is
    # ALWAYS the main establishment, never a fixed authority.
    de = resolve("DE", ["IE", "DE", "FR"], _AUTHORITIES)
    assert de.lead.member_state == "DE"
    assert [a.member_state for a in de.concerned] == ["FR", "IE"]


def test_main_establishment_forced_into_scope_when_absent():
    # The controller's own member state is by definition concerned by its own
    # breach: even if the in-scope list omits it, it is the lead and not a duplicate
    # concerned entry.
    routing = resolve("IE", ["DE", "FR"], _AUTHORITIES)
    assert routing.lead.member_state == "IE"
    assert [a.member_state for a in routing.concerned] == ["DE", "FR"]
    assert "IE" not in [a.member_state for a in routing.concerned]


# ---- single-state case: trivial lead, no concerned ------------------------

def test_single_state_has_trivial_lead_and_no_concerned():
    routing = resolve("IE", ["IE"], _AUTHORITIES)
    assert routing.lead.member_state == "IE"
    assert routing.concerned == ()
    assert routing.cross_border is False
    assert "No one-stop-shop split" in routing.human()


def test_single_state_when_only_main_establishment_in_scope():
    # An empty in-scope list still resolves to the main establishment as the sole
    # (trivial) lead with no concerned authorities.
    routing = resolve("FR", [], _AUTHORITIES)
    assert routing.lead.member_state == "FR"
    assert routing.concerned == ()
    assert routing.cross_border is False


# ---- determinism + data-driven, no LLM surface ----------------------------

def test_routing_is_deterministic_and_order_independent():
    a = resolve("IE", ["DE", "FR", "NL"], _AUTHORITIES)
    b = resolve("IE", ["NL", "FR", "DE"], _AUTHORITIES)
    # Same lead, same concerned set, in the same sorted order regardless of input
    # order: no RNG, no now(), byte-stable.
    assert a.lead == b.lead
    assert a.concerned == b.concerned
    assert resolve("IE", ["DE", "FR"], _AUTHORITIES) == \
        resolve("IE", ["DE", "FR"], _AUTHORITIES)


def test_module_exposes_no_resolver_or_llm_surface():
    import floor.lead_authority as la
    names = [n for n in dir(la) if not n.startswith("_")]
    # The module is a pure ROUTING lookup: no LLM, no judgment, no "which wins".
    for forbidden in ("llm", "model", "prompt", "assess", "judge", "winner",
                      "wins", "prevail", "network", "client", "now", "random"):
        assert not any(forbidden in n.lower() for n in names), \
            f"floor.lead_authority must not expose a {forbidden!r} surface"
    # The only public FUNCTION defined in this module is resolve; the rest are typed
    # dataclasses. There is no second behavioral surface (the imported `dataclass`
    # decorator is not defined here).
    import inspect
    functions = {n for n in names
                 if inspect.isfunction(getattr(la, n))
                 and getattr(getattr(la, n), "__module__", "") == la.__name__}
    assert functions == {"resolve"}
    # resolve returns a LeadRouting of typed AuthorityRouting records, never a
    # verdict about which authority "wins".
    routing = resolve("IE", ["DE"], _AUTHORITIES)
    assert isinstance(routing, LeadRouting)
    assert isinstance(routing.lead, AuthorityRouting)


# ---- missing authority data surfaces structurally -------------------------

def test_missing_main_establishment_authority_raises():
    with pytest.raises(ValueError):
        resolve("ES", ["IE", "ES"], _AUTHORITIES)


def test_missing_in_scope_authority_raises():
    with pytest.raises(ValueError):
        resolve("IE", ["IE", "ES"], _AUTHORITIES)


def test_empty_main_establishment_raises():
    with pytest.raises(ValueError):
        resolve("", ["IE"], _AUTHORITIES)


# ---- the catalog declares the controller + the SA map as data --------------

def test_catalog_declares_controller_and_authorities():
    controller = regimes.load_controller()
    assert controller.main_establishment == "IE"
    assert controller.name.strip()
    authorities = regimes.load_supervisory_authorities()
    # The honest set covers the main establishment + the in-scope states.
    assert {"IE", "DE", "FR", "NL"} <= set(authorities)
    for state, spec in authorities.items():
        assert spec.member_state == state
        assert spec.authority.strip() and spec.country.strip()


def test_run_floor_loaded_controller_and_authorities_match_catalog():
    # The run_floor module-level data is lifted straight from the catalog.
    assert CONTROLLER.main_establishment == "IE"
    assert set(EU_SUPERVISORY_AUTHORITIES) >= {"IE", "DE", "FR", "NL"}


def test_catalog_routing_matches_pure_routing():
    # Resolving through the real catalog data (the Irish main establishment, the
    # four in-scope states) yields the Irish DPC as lead and the other three as
    # concerned, in sorted order.
    routing = resolve(CONTROLLER.main_establishment, ["IE", "DE", "FR", "NL"],
                      EU_SUPERVISORY_AUTHORITIES)
    assert routing.lead.member_state == "IE"
    assert [a.member_state for a in routing.concerned] == ["DE", "FR", "NL"]


def test_duplicate_authority_in_catalog_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "controller: {name: X, main_establishment: IE}\n"
        "eu_supervisory_authorities:\n"
        "  - {member_state: IE, authority: a, country: Ireland}\n"
        "  - {member_state: IE, authority: b, country: Ireland}\n"
        "regimes:\n"
        "  - key: x\n"
        "    authority: a\n"
        "    branch: x\n"
        "    regime_label: X\n"
        "    trigger_event: incident occurrence\n"
        "    clock: {name: c, length: 72, unit: hours, business_days: false, "
        "holiday_calendar: none}\n"
        "    format_profile: nis2_full\n"
        "    start: {mode: startup, anchor: incident_t0}\n",
        encoding="utf-8")
    with pytest.raises(ValueError):
        regimes.load_supervisory_authorities(bad)


# ---- the live beat renders the routing -------------------------------------

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


def _run(tmp_path):
    room, clients = _build_clients()
    return run_floor(out_dir=str(tmp_path), mode="cross_border", clients=clients,
                     draft_fns=_stub_draft_fns(),
                     uk_peers=[{"id": "uk-id", "name": "UK ICO Drafter"}])


def test_cross_border_run_resolves_lead_authority(tmp_path):
    packet = _run(tmp_path)
    la = packet["cross_border"]["lead_authority"]
    assert la is not None
    assert la["main_establishment"] == "IE"
    assert "Irish Data Protection Commission" in la["lead"]["authority"]
    assert la["cross_border"] is True
    concerned = [a["member_state"] for a in la["concerned"]]
    assert concerned == ["DE", "FR", "NL"]
    assert "IE" not in concerned


def test_cross_border_packet_renders_lead_and_concerned(tmp_path):
    packet = _run(tmp_path)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "GDPR Art 56 one-stop-shop routing" in html
    assert "Article 56(1)" in html
    assert "Irish Data Protection Commission" in html
    # The concerned authorities are named and the routing is "not N independent".
    assert "concerned authorit" in html
    assert "not as 4 independent filings" in html


def test_lead_authority_routing_is_logged(tmp_path):
    packet = _run(tmp_path)
    log_path = Path(packet["_paths"]["run_log"])
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert any('"lead_authority_routing"' in ln for ln in lines)


# ---- byte-identical replay for the beat ------------------------------------

def test_replay_is_byte_identical_for_the_lead_authority_beat(tmp_path):
    packet = _run(tmp_path)
    assert packet["replay"]["byte_identical"] is True


def test_routing_is_deterministic_across_two_runs(tmp_path):
    a = _run(tmp_path / "a")
    b = _run(tmp_path / "b")
    assert a["replay"]["original_sha256"] == b["replay"]["original_sha256"]


# ---- the four DEFAULT sealed captures + their shas are UNCHANGED ------------

SEALED_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


@pytest.mark.parametrize("mode", SEALED_MODES)
def test_sealed_capture_carries_no_lead_authority_event(mode):
    # The lead-authority routing adds NO event to these four scenarios; each sealed
    # capture still exists, is non-empty, and carries no lead_authority event.
    log_path = DATA / f"run-inc-8842-{mode}.jsonl"
    assert log_path.exists(), f"{mode}: sealed capture missing"
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines()
             if ln.strip()]
    assert lines
    assert not any("lead_authority" in ln for ln in lines), \
        f"{mode}: a lead-authority event leaked into the sealed capture"


def test_default_normal_run_sha_unchanged():
    # A fresh normal-mode run (no cross-border) must still reproduce the sealed
    # normal sha byte for byte: the lead-authority code is dormant unless asked.
    from tests.test_operability_report import (
        SEALED_NORMAL_SHA, _build_clients as _bc, _stub_draft_fns as _sd)
    import tempfile
    room, clients = _bc()
    with tempfile.TemporaryDirectory() as td:
        packet = run_floor(out_dir=td, mode="normal", clients=clients,
                           draft_fns=_sd())
    assert packet["replay"]["original_sha256"] == SEALED_NORMAL_SHA
