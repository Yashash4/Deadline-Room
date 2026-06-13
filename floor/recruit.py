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


@dataclass(frozen=True)
class RecruitTarget:
    """A regulator drafter that MAY be recruited if its jurisdiction is in scope."""
    jurisdiction: str        # the blast-radius token that triggers it, e.g. "UK"
    branch: str              # protocol branch, e.g. "uk"
    regime: str              # human regime label, e.g. "UK ICO"
    name_tokens: tuple[str, ...]  # tokens to match a peer's name/handle on
    clock_name: str          # statutory clock label
    clock_hours: int         # statutory window in hours from the recruit moment


# The UK ICO Drafter. Recruited only when a UK subsidiary is in the blast radius.
# Its 72h GDPR personal-data-breach clock starts at recruit time.
UK_ICO_TARGET = RecruitTarget(
    jurisdiction="UK",
    branch="uk",
    regime="UK ICO",
    name_tokens=("uk", "ico"),
    clock_name="UK ICO / GDPR personal-data breach (72h)",
    clock_hours=72,
)


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
