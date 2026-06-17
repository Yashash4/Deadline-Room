"""Runtime agent recruit: content-driven discovery of a regulator drafter.

The "Internet of Agents" beat. Triage's fact-record carries a blast radius (the
set of jurisdictions and subsidiaries an incident actually touches). The room is
NOT pre-wired with every possible regulator. When, and ONLY when, the blast radius
reveals a jurisdiction whose regulator is not already in the room, the Warden
discovers that regulator's drafter agent at runtime over the live Band peer list
and recruits it into the incident room.

Discovery is a token-match over /agent/peers (the live API exposes only a
not_in_chat filter, no role/jurisdiction filter), so we match the peer whose
name/handle contains the regulator's token. The recruit is add_participant on the
live API. The recruited drafter's statutory clock starts at the MOMENT OF RECRUIT,
not at incident T0, because the obligation attaches when the jurisdiction enters
scope.

This module is pure orchestration over the Band client surface; it makes no LLM
call. Whether a recruit happens is decided by the blast-radius content, never
hardcoded: a blast radius that does not touch the jurisdiction produces no
recruit, which the no-UK fixture proves.
"""

from __future__ import annotations

from dataclasses import dataclass

from floor import regimes


@dataclass(frozen=True)
class RecruitTarget:
    """A regulator drafter that MAY be recruited if its jurisdiction is in scope."""
    jurisdiction: str        # the blast-radius token that triggers it, e.g. "UK"
    branch: str              # protocol branch, e.g. "uk"
    regime: str              # human regime label, e.g. "UK ICO"
    name_tokens: tuple[str, ...]  # tokens to match a peer's name/handle on
    clock_name: str          # statutory clock label
    clock_hours: int         # statutory window in hours from the recruit moment
    # The statutory event the clock is anchored on, rendered next to the clock in
    # the Examiner Packet. The recruit moment is the faithful proxy: for the UK
    # ICO it stands in for "became aware a UK personal-data breach is in scope",
    # for NYDFS it is the moment of determination. Defaulted so any future target
    # that omits it still constructs.
    trigger_event: str = "determination (recruit moment)"
    # The real filing field skeleton (floor/formats.py id) the recruited drafter
    # fills. Defaulted so any future target that omits it still constructs.
    format_profile: str = ""
    # The IANA zone the recruited regulator reads its deadline in (Europe/London
    # for the UK ICO, America/New_York for NYDFS). RENDER-ONLY: the stored deadline
    # stays a UTC instant and the packet derives the local wall-clock from it.
    # Defaulted so any future target that omits it still constructs.
    display_timezone: str = ""


def target_from_spec(spec: "regimes.RegimeSpec") -> RecruitTarget:
    """Build a RecruitTarget from a recruit-mode regime record in the catalog, so
    the UK and NYDFS targets are produced FROM floor/regimes.yaml rather than from
    hardcoded constants. The values are exactly the prior constants, so the live
    behaviour and demo clocks are byte-identical."""
    if not spec.is_recruit:
        raise ValueError(f"regime {spec.key} is not a recruit-mode regime")
    return RecruitTarget(
        jurisdiction=spec.recruit_jurisdiction,
        branch=spec.branch,
        regime=spec.regime_label,
        name_tokens=spec.recruit_name_tokens,
        clock_name=spec.clock.name,
        clock_hours=spec.clock.length,
        trigger_event=spec.trigger_event,
        format_profile=spec.format_profile,
        display_timezone=spec.clock.display_timezone,
    )


# The recruit targets are produced FROM the declarative catalog. The UK ICO
# Drafter is recruited only when a UK subsidiary is in the blast radius (its 72h
# GDPR personal-data-breach clock starts at recruit time, anchored on awareness);
# the NYDFS Drafter only when a New York licensed entity is in scope (a flat 72
# CALENDAR-hour 500.17(a)(1) notice from the determination/recruit moment, no
# business-day or holiday arithmetic). Both flow through the same recruit seam.
_CATALOG = regimes.by_key(regimes.load_catalog())
UK_ICO_TARGET = target_from_spec(_CATALOG["uk_ico"])
NYDFS_TARGET = target_from_spec(_CATALOG["nydfs"])


def jurisdiction_in_blast_radius(fact_record: dict, jurisdiction: str) -> bool:
    """True iff the fact-record's blast radius names the jurisdiction. Pure
    content check over the canonical fact-record Triage posted. Case-insensitive,
    matches the jurisdiction token against each blast-radius entry."""
    radius = fact_record.get("blast_radius", []) or []
    tok = jurisdiction.strip().lower()
    for entry in radius:
        if tok in str(entry).strip().lower():
            return True
    return False


def find_peer(peers: list, name_tokens: tuple[str, ...]) -> dict | None:
    """Token-match a peer (an agent NOT yet in the room) by name/handle.

    /agent/peers exposes only a not_in_chat filter, so role/jurisdiction matching
    is our own token-match here. Returns the first peer whose name or handle
    contains ALL the given tokens (lowercased), or None. A peer is a dict with at
    least an id and a name/handle; we read whatever identity fields are present."""
    for peer in peers:
        if not isinstance(peer, dict):
            continue
        haystack = " ".join(
            str(peer.get(k, "")) for k in ("name", "handle", "title", "id")
        ).lower()
        if all(tok.lower() in haystack for tok in name_tokens):
            return peer
    return None


def peer_id(peer: dict) -> str:
    """Extract the agent UUID from a peer record, tolerating id/agent_id/uuid."""
    for k in ("id", "agent_id", "uuid", "participant_id"):
        v = peer.get(k)
        if v:
            return str(v)
    return ""
