"""GDPR Article 56 lead-supervisory-authority (one-stop-shop) routing.

Cross-border GDPR is not "file N independent notices to N data-protection
authorities". Under GDPR Article 56(1), where a personal-data breach concerns
cross-border processing, the supervisory authority of the controller's MAIN
ESTABLISHMENT is the LEAD supervisory authority and is competent to act as the
single point of contact; the other supervisory authorities whose member states
are concerned are "concerned supervisory authorities" (Art 4(22)) and are reached
THROUGH the lead, which coordinates under the cooperation procedure (Art 60). The
primary Art 33 breach notification is filed to the lead; the concerned authorities
receive it through the lead rather than as independent filings.

This module is the pure, deterministic ROUTING decision that GDPR Art 56 prescribes:
given the controller's main-establishment member state and the set of EU member
states actually in scope for the incident (both already on hand from the catalog
and the fact-record's blast radius), it identifies the ONE lead supervisory
authority and lists the concerned ones. There is NO LLM, no judgment, no network,
no now()/RNG here: the routing is a function of declared data only, so it replays
byte-for-byte exactly like the rest of the deterministic core. It NEVER gates,
blocks, releases, or clocks anything; it RENDERS the correct cross-border routing
the room would otherwise get wrong by treating every EU authority as independent.

The honest catalog of supervisory authorities (the small set covering the entity's
establishment and the in-scope states) is declared as DATA in floor/regimes.yaml
under `eu_supervisory_authorities`, lifted into the typed `SupervisoryAuthority`
records this module consumes. This module reads no file itself; the caller passes
the already-lifted authority map and the in-scope states in.

The main-establishment rule (Art 56(1)) is the SINGLE source of the lead; this
module never invents a lead from anything but the declared main establishment, and
if the main establishment's authority is not in the in-scope set the routing
surfaces that structurally rather than silently picking a different lead.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SupervisoryAuthority:
    """One EU member state's data-protection supervisory authority, lifted from the
    catalog. `member_state` is the ISO-style member-state token the routing keys on
    (e.g. "IE", "DE", "FR", "NL"); `authority` is the authority's name (the Irish
    DPC, the German BfDI, the French CNIL, the Dutch AP); `country` is the
    human-readable country label rendered for the examiner. The comparison is a
    plain token match on `member_state`, so the routing is a pure lookup."""
    member_state: str
    authority: str
    country: str


@dataclass(frozen=True)
class AuthorityRouting:
    """One supervisory authority's role in the Art 56 routing for this incident.

    `role` is "lead" (the single Art 56(1) lead from the main establishment) or
    "concerned" (an Art 4(22) concerned authority reached through the lead). The
    record carries the authority's identity so the packet renders the routing
    without re-walking the catalog."""
    member_state: str
    authority: str
    country: str
    role: str


@dataclass(frozen=True)
class LeadRouting:
    """The resolved GDPR Art 56 one-stop-shop routing for one incident.

    `main_establishment` is the controller's main-establishment member state (the
    Art 56(1) basis for the lead). `lead` is the single lead supervisory authority;
    `concerned` is the ordered list of concerned authorities reached through it.
    `cross_border` is True when more than one EU member state is in scope (the
    one-stop-shop applies); a single-state incident has the trivial lead and no
    concerned authorities, which `cross_border` False records. `routing` is the
    full per-authority list (lead first, then concerned) for rendering. The Warden
    never reads this: it RENDERS the routing, it gates nothing."""
    main_establishment: str
    lead: AuthorityRouting
    concerned: tuple[AuthorityRouting, ...]
    cross_border: bool

    @property
    def routing(self) -> tuple[AuthorityRouting, ...]:
        return (self.lead, *self.concerned)

    def human(self) -> str:
        """A one-line, examiner-facing summary of the routing."""
        if not self.concerned:
            return (
                f"Single EU member state in scope ({self.lead.country}); the "
                f"{self.lead.authority} receives the Art 33 notification directly. "
                f"No one-stop-shop split (no concerned authorities).")
        concerned = "; ".join(f"{a.authority} ({a.country})" for a in self.concerned)
        return (
            f"Main establishment in {self.lead.country}: GDPR Art 56(1) lead "
            f"supervisory authority is the {self.lead.authority}. Concerned "
            f"authorities reached through the lead: {concerned}. The primary Art 33 "
            f"notification is filed to the lead, not as independent notices.")


def resolve(main_establishment: str,
            in_scope_member_states: list[str],
            authorities: dict[str, SupervisoryAuthority]) -> LeadRouting:
    """Resolve the GDPR Art 56 lead / concerned routing, deterministically.

    `main_establishment` is the controller's main-establishment member-state token
    (the Art 56(1) basis for the single lead). `in_scope_member_states` is the set
    of EU member states actually in scope for the incident (from the blast radius);
    order is normalized here so the routing is byte-stable regardless of input
    order. `authorities` is the declared member-state -> SupervisoryAuthority map.

    The lead is ALWAYS the authority of the main establishment (Art 56(1)); the
    main establishment is forced into the in-scope set if absent (the controller's
    own member state is by definition concerned by its own breach), so the lead is
    always well-defined. Every OTHER in-scope state's authority is a concerned
    authority, in sorted member-state order. A single in-scope state yields the
    trivial lead and no concerned authorities (cross_border False).

    Pure: the result is a function of the three declared inputs only. No LLM, no
    network, no now()/RNG. Raises if the main establishment, or any in-scope state,
    has no declared authority (a missing authority is a catalog gap, surfaced
    structurally rather than silently dropped)."""
    main = main_establishment.strip().upper()
    if not main:
        raise ValueError("main_establishment is required for Art 56 routing")
    if main not in authorities:
        raise ValueError(
            f"main establishment {main!r} has no declared supervisory authority; "
            f"add it to eu_supervisory_authorities in the catalog")

    # Normalize the in-scope set: upper-cased tokens, the main establishment always
    # included (the controller's own member state is concerned by its own breach),
    # de-duplicated, sorted for byte-stable order.
    in_scope = {s.strip().upper() for s in in_scope_member_states if s.strip()}
    in_scope.add(main)
    for state in sorted(in_scope):
        if state not in authorities:
            raise ValueError(
                f"in-scope member state {state!r} has no declared supervisory "
                f"authority; add it to eu_supervisory_authorities in the catalog")

    lead_sa = authorities[main]
    lead = AuthorityRouting(
        member_state=lead_sa.member_state, authority=lead_sa.authority,
        country=lead_sa.country, role="lead")
    concerned = tuple(
        AuthorityRouting(
            member_state=authorities[state].member_state,
            authority=authorities[state].authority,
            country=authorities[state].country, role="concerned")
        for state in sorted(in_scope) if state != main)
    return LeadRouting(
        main_establishment=main, lead=lead, concerned=concerned,
        cross_border=bool(concerned))
