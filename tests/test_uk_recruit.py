"""test_uk_recruit.py -- the content-driven UK ICO runtime recruit.

Triage's fact-record carries a blast radius. ONLY when that blast radius names a
UK subsidiary does the Warden discover the UK ICO Drafter over the live peer list
(token-match) and recruit it at runtime, starting a fifth statutory clock at the
RECRUIT moment (not at incident T0). When the blast radius does not touch the UK,
no recruit happens, which proves the behavior is content-driven, not hardcoded.
"""

from pathlib import Path

from floor.recruit import (
    UK_ICO_TARGET, find_peer, jurisdiction_in_blast_radius, peer_id)
from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom


UK_PEER = {"id": "uk-ico-agent-id", "name": "UK ICO Drafter",
           "handle": "uk_ico_drafter"}


def _build_clients(with_uk_in_directory: bool):
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    # the UK drafter exists in the directory (discoverable) but is NOT in the room
    clients["uk"] = FakeBandClient(room, UK_PEER["id"], "uk_drafter", "draft:uk")
    if with_uk_in_directory:
        room.directory.append(UK_PEER)
    return room, clients


def _stub_draft_fns():
    def make(regime):
        def fn(claim_facts):
            return (f"{regime} notification. {claim_facts['records_affected']} "
                    f"records, {claim_facts['attacker']}.")
        return fn
    fns = {r.branch: make(r.regime) for r in DRAFTER_ROLES}
    fns["uk"] = make("UK ICO")
    return fns


# ---- the pure content + discovery helpers ----------------------------------

def test_blast_radius_match_is_content_check():
    uk_facts = {"blast_radius": ["EU: HQ", "UK: London subsidiary"]}
    eu_facts = {"blast_radius": ["EU: HQ only"]}
    assert jurisdiction_in_blast_radius(uk_facts, "UK") is True
    assert jurisdiction_in_blast_radius(eu_facts, "UK") is False
    assert jurisdiction_in_blast_radius({}, "UK") is False


def test_find_peer_token_match():
    peers = [{"id": "a", "name": "DORA Drafter"},
             {"id": "b", "name": "UK ICO Drafter"}]
    p = find_peer(peers, UK_ICO_TARGET.name_tokens)
    assert p is not None
    assert peer_id(p) == "b"
    assert find_peer([{"id": "a", "name": "DORA Drafter"}],
                     UK_ICO_TARGET.name_tokens) is None


# ---- end to end: UK in scope -> recruit fires ------------------------------

def test_uk_in_scope_recruits_and_starts_fifth_clock(tmp_path):
    room, clients = _build_clients(with_uk_in_directory=True)
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns(), uk_recruit=True)
    rec = packet["recruit"]
    assert rec["recruited"] is True
    assert rec["peer_id"] == UK_PEER["id"]
    # the UK 72h clock started at the recruit moment, NOT incident T0
    assert rec["clock_started_at"] == "2026-06-16T03:40:00+00:00"
    # there are now FIVE clocks (the four T0 clocks + the late UK clock)
    assert len(packet["clocks"]) == 5
    uk_clock = [c for c in packet["clocks"] if c["correlation_id"] == "inc-8842:uk"]
    assert len(uk_clock) == 1
    assert uk_clock[0]["started"] == "2026-06-16T03:40:00+00:00"
    # the UK filing is in the packet, marked recruited at runtime
    uk_filing = [f for f in packet["filings"] if f["regime"] == "UK ICO"]
    assert len(uk_filing) == 1
    assert uk_filing[0]["recruited_at_runtime"] is True


def test_uk_recruit_event_in_handoff_trace(tmp_path):
    room, clients = _build_clients(with_uk_in_directory=True)
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns(), uk_recruit=True)
    kinds = [(h["from"], h["to"], h["kind"]) for h in packet["handoff_trace"]]
    assert ("Warden", "UK ICO Drafter", "runtime_recruit") in kinds
    # the recruited drafter is now a room participant
    assert UK_PEER["id"] in room.participants


def test_uk_branch_released_via_two_keys(tmp_path):
    room, clients = _build_clients(with_uk_in_directory=True)
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns(), uk_recruit=True)
    # the UK branch reaches released, and carries two distinct human sign-offs
    released = [t for t in packet["state_transitions"]
                if t["admitted"] and t["to_state"] == "released"
                and t["correlation_id"] == "inc-8842:uk"]
    assert len(released) == 1
    uk_signoffs = [s for s in packet["release"]["signoffs"]
                   if s["correlation_id"] == "inc-8842:uk"]
    assert sorted(s["role"] for s in uk_signoffs) == ["general_counsel", "head_of_ir"]


# ---- end to end: UK NOT in scope -> no recruit (the content-driven proof) --

def test_uk_not_in_scope_does_not_recruit(tmp_path):
    # The default canonical fact-record's blast radius names only the EU entity.
    # We force the no-UK fixture by NOT adding UK to the blast radius: run_floor's
    # uk_recruit path uses UK_IN_SCOPE_FACTS, so to prove the negative we drive the
    # recruit phase against an EU-only blast radius via the peer-absence path.
    room, clients = _build_clients(with_uk_in_directory=True)
    # Override: post the recruit with an EU-only fact-record by patching the
    # module's UK_IN_SCOPE_FACTS for this run is intrusive; instead assert the
    # helper-level negative which the live phase delegates to.
    from floor import run_floor as rf
    eu_only = {**rf.CANONICAL_FACTS, "blast_radius": ["EU: HQ only"]}
    assert jurisdiction_in_blast_radius(eu_only, "UK") is False


def test_no_recruit_when_blast_radius_excludes_uk(tmp_path, monkeypatch):
    # Drive the FULL floor with uk_recruit=True but a blast radius that does NOT
    # name the UK: the recruit must NOT fire, and there must be only four clocks.
    from floor import run_floor as rf
    eu_only = {**rf.CANONICAL_FACTS, "blast_radius": ["EU: Meridian Trust Bank N.V."]}
    monkeypatch.setattr(rf, "UK_IN_SCOPE_FACTS", eu_only)
    room, clients = _build_clients(with_uk_in_directory=True)
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns(), uk_recruit=True)
    rec = packet["recruit"]
    assert rec["recruited"] is False
    assert rec["in_scope"] is False
    # only the four T0 clocks; no fifth UK clock
    assert len(packet["clocks"]) == 4
    assert all(c["correlation_id"] != "inc-8842:uk" for c in packet["clocks"])
    # no UK filing, and the UK agent was never added to the room
    assert "UK ICO" not in [f["regime"] for f in packet["filings"]]
    assert UK_PEER["id"] not in room.participants


def test_recruit_replay_byte_identical(tmp_path):
    room, clients = _build_clients(with_uk_in_directory=True)
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns(), uk_recruit=True)
    assert packet["replay"]["byte_identical"] is True


def test_recruit_html_shows_fifth_clock_and_event(tmp_path):
    room, clients = _build_clients(with_uk_in_directory=True)
    packet = run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                       draft_fns=_stub_draft_fns(), uk_recruit=True)
    html = Path(packet["_paths"]["html"]).read_text(encoding="utf-8")
    assert "UK ICO runtime recruit" in html
    assert "late-started fifth clock" in html
