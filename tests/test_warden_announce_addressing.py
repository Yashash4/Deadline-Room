"""test_warden_announce_addressing.py -- regression guard on every Warden room post.

The Warden narrates its deterministic decisions IN the Band room via
_warden_announce. Live Band imposes two hard constraints on a message that the
in-process FakeRoom now mirrors: a message must mention at least one participant
(minItems: 1), and a sender may NOT mention itself (HTTP 422
cannot_mention_self). A Warden visibility post whose mentions resolve to an empty
or self-only list is therefore a real crash on a live run, even though the gating
decision behind it is correct.

This guard runs every mode that announces (normal, inject_contradiction, chaos,
amendment, reportability, cross_border, affected_party) and asserts that EVERY
message the Warden posts addresses at least one NON-Warden participant. It locks
out the whole class of bug where an announce falls back to a self-mention because
its specific addressee was empty (e.g. a conflict whose drafters were
runtime-recruited and carry no startup id, or the affected-party beat that posted
before its drafter joined). The mentions on these posts are trace-only visibility,
never part of the hashed run-log, so this assertion does not touch replay or any
sealed sha.
"""

import pytest

from warden.high_risk import HighRiskVerdict
from warden.materiality import MaterialityVerdict
from warden.reportability import ReportabilityVerdict
from floor.run_floor import (
    AFFECTED_PARTY_BRANCH, DRAFTER_ROLES, run_floor)
from floor.shell_adapter import FakeBandClient, FakeRoom

WARDEN_ID = "warden-id"


def _build_clients(*, with_uk=False, with_affected_party=False):
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, WARDEN_ID, "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    if with_uk:
        clients["uk"] = FakeBandClient(room, "uk-id", "uk_drafter", "draft:uk")
    if with_affected_party:
        clients[AFFECTED_PARTY_BRANCH] = FakeBandClient(
            room, "ds-id", "data_subject_drafter",
            f"draft:{AFFECTED_PARTY_BRANCH}")
    return room, clients


def _draft_fns(*, with_uk=False, with_affected_party=False, characterize=False):
    def make(regime):
        def fn(claim_facts):
            return (f"{regime} notification. Incident "
                    f"{claim_facts['incident_start_utc']}, "
                    f"{claim_facts['records_affected']} records.")
        return fn
    fns = {r.branch: make(r.regime) for r in DRAFTER_ROLES}
    if with_uk:
        fns["uk"] = make("UK ICO")
    if with_affected_party:
        def ds_fn(notice_facts):
            return ("GDPR Art 34 communication to data subjects. Incident "
                    f"{notice_facts['incident_start_utc']}, "
                    f"{notice_facts['records_affected']} individuals affected.")
        fns[AFFECTED_PARTY_BRANCH] = ds_fn
    if characterize:
        fns["sec:characterize"] = lambda x: "approximately 2.1 million records."
        fns["nis2:characterize"] = lambda x: "approximately 2.1 million records."
    return fns


def _high_risk_fn(_facts, spec):
    return HighRiskVerdict(
        high_risk=True,
        rationale="Exposed account numbers create a high risk to individuals.",
        standard=spec.high_risk.standard, rule=spec.high_risk.rule,
        source="test:high_risk")


def _not_high_risk_fn(_facts, spec):
    return HighRiskVerdict(
        high_risk=False,
        rationale="Contained and encrypted; no realistic high risk.",
        standard=spec.high_risk.standard, rule=spec.high_risk.rule,
        source="test:not_high_risk")


def _materiality_not_material(_facts):
    return MaterialityVerdict(
        branch="sec", material=False, memo="Below the substantial-likelihood bar.",
        source="test:not_material")


def _reportability_mixed(branch, _facts, spec):
    # NIS2 suppressed, the rest file: exercises both the suppress and file paths.
    return ReportabilityVerdict(
        branch=branch, regime=spec.regime_label, reportable=(branch != "nis2"),
        rationale=f"{branch} basis.",
        standard=spec.reportability.standard, rule=spec.reportability.rule,
        source="test:mixed")


def _uk_peers():
    return [{"id": "uk-id", "name": "UK ICO Drafter"}]


def _warden_posts(room):
    """Every message the Warden posted into the room, in order. The Warden is the
    only sender whose posts are the visibility announces under test."""
    return [m for m in room.messages if m["sender"] == WARDEN_ID]


def _assert_every_warden_post_addresses_a_nonwarden(room, mode):
    posts = _warden_posts(room)
    assert posts, f"mode {mode!r}: the Warden posted nothing to assert on"
    for m in posts:
        mentions = m["mentions"]
        head = m["content"].splitlines()[0] if m["content"] else ""
        # Never empty: live Band requires at least one mention.
        assert mentions, (
            f"mode {mode!r}: Warden post with NO mentions (live Band minItems:1) "
            f"-> {head!r}")
        # Never the Warden's own id alone (or at all): live Band rejects a
        # self-mention. At least one addressee must be a non-Warden participant.
        non_warden = [x for x in mentions if x != WARDEN_ID]
        assert non_warden, (
            f"mode {mode!r}: Warden post addresses only itself "
            f"(cannot_mention_self) -> {head!r}")
        assert WARDEN_ID not in mentions, (
            f"mode {mode!r}: Warden post mentions its own id {WARDEN_ID!r} "
            f"(live Band rejects cannot_mention_self) -> {head!r}")


# ---- one assertion per announcing mode -------------------------------------

def test_normal_warden_posts_address_a_nonwarden(tmp_path):
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
              draft_fns=_draft_fns())
    _assert_every_warden_post_addresses_a_nonwarden(room, "normal")


def test_contradiction_warden_posts_address_a_nonwarden(tmp_path):
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="inject_contradiction", clients=clients,
              draft_fns=_draft_fns())
    _assert_every_warden_post_addresses_a_nonwarden(room, "inject_contradiction")


def test_chaos_warden_posts_address_a_nonwarden(tmp_path):
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="chaos", clients=clients,
              draft_fns=_draft_fns())
    _assert_every_warden_post_addresses_a_nonwarden(room, "chaos")


def test_amendment_warden_posts_address_a_nonwarden(tmp_path):
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="amendment", clients=clients,
              draft_fns=_draft_fns(characterize=True))
    _assert_every_warden_post_addresses_a_nonwarden(room, "amendment")


def test_reportability_warden_posts_address_a_nonwarden(tmp_path):
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="reportability", clients=clients,
              draft_fns=_draft_fns(), reportability=True,
              reportability_fn=_reportability_mixed)
    _assert_every_warden_post_addresses_a_nonwarden(room, "reportability")


def test_materiality_suppress_warden_posts_address_a_nonwarden(tmp_path):
    # The SEC materiality SUPPRESS path is a distinct deterministic decision that
    # also narrates; run it on the clean base to cover its announces.
    room, clients = _build_clients()
    run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
              draft_fns=_draft_fns(), materiality=True,
              materiality_fn=_materiality_not_material)
    _assert_every_warden_post_addresses_a_nonwarden(room, "materiality")


def test_cross_border_warden_posts_address_a_nonwarden(tmp_path):
    room, clients = _build_clients(with_uk=True)
    run_floor(out_dir=str(tmp_path), mode="cross_border", clients=clients,
              draft_fns=_draft_fns(with_uk=True), uk_peers=_uk_peers())
    _assert_every_warden_post_addresses_a_nonwarden(room, "cross_border")


def test_affected_party_required_warden_posts_address_a_nonwarden(tmp_path):
    room, clients = _build_clients(with_affected_party=True)
    run_floor(out_dir=str(tmp_path), mode="affected_party", clients=clients,
              draft_fns=_draft_fns(with_affected_party=True, characterize=True),
              affected_party=True, high_risk_fn=_high_risk_fn)
    _assert_every_warden_post_addresses_a_nonwarden(room, "affected_party_required")


def test_affected_party_not_required_warden_posts_address_a_nonwarden(tmp_path):
    # The not-required path posts the Art 34 not-required record with no
    # affected-party drafter in the room: it must still address the active
    # regulator drafters, never itself.
    room, clients = _build_clients(with_affected_party=True)
    run_floor(out_dir=str(tmp_path), mode="affected_party", clients=clients,
              draft_fns=_draft_fns(with_affected_party=True, characterize=True),
              affected_party=True, high_risk_fn=_not_high_risk_fn)
    _assert_every_warden_post_addresses_a_nonwarden(
        room, "affected_party_not_required")


# ---- the FakeRoom now enforces the live self-mention rejection -------------

def test_fake_room_rejects_a_self_mention():
    # The guard that makes the offline suite catch this class of bug: posting with
    # the sender in its own mentions raises, exactly as live Band returns 422
    # cannot_mention_self. Without this, a self-mention announce would post
    # silently in the fake and the green suite would hide a live crash.
    room = FakeRoom()
    with pytest.raises(ValueError, match="cannot_mention_self"):
        room.post("warden-id", "decision", ["warden-id"])
    # A mixed list that includes the sender is still a self-mention and rejected.
    with pytest.raises(ValueError, match="cannot_mention_self"):
        room.post("warden-id", "decision", ["nis2-id", "warden-id"])
    # Addressing only non-senders is fine.
    mid = room.post("warden-id", "decision", ["nis2-id"])
    assert mid


# ---- the helper refuses a self-mention by construction ---------------------

def test_warden_announce_refuses_a_self_only_addressee(tmp_path):
    # Drive _warden_announce directly with a self-only mention and no registered
    # fallback: it must refuse rather than emit a self-mention that crashes live.
    from floor import run_floor as rf
    from floor.run_floor import StepTrace
    from warden.replay import RunLog

    rf.ROOM_ADDRESSING.reset(WARDEN_ID)  # no non-Warden participants registered
    room = FakeRoom()
    warden = FakeBandClient(room, WARDEN_ID, "warden", "warden")
    warden.create_chat("room")
    trace = StepTrace(RunLog())
    with pytest.raises(RuntimeError, match="no non-Warden addressee"):
        rf._warden_announce(warden, trace, "Warden decision text",
                            mentions=[WARDEN_ID])
    # With a non-Warden participant registered, the same call addresses it.
    rf.ROOM_ADDRESSING.reset(WARDEN_ID)
    rf.ROOM_ADDRESSING.register("nis2-id")
    mid = rf._warden_announce(warden, trace, "Warden decision text",
                              mentions=[WARDEN_ID])
    posted = [m for m in room.messages if m["id"] == mid][0]
    assert posted["mentions"] == ["nis2-id"]
