"""test_global_catalog_recruit.py -- the global-catalog (E3.7) recruit proof.

The global catalog adds real, cited breach-notification regimes across APAC and
LATAM (India DPDP, Singapore PDPA, Australia NDB, Canada OSFI, Brazil LGPD, South
Korea PIPA). Each is a recruit-mode regime: its clock starts ONLY when its
jurisdiction is named in the incident's blast radius, exactly the content-driven
recruit seam the UK ICO and NYDFS clocks already proved out.

These tests prove that seam over the new jurisdictions, using the SAME primitives
the production recruit phase (floor/run_floor._recruit_phase) composes:
jurisdiction_in_blast_radius (the content check), find_peer (token-match
discovery), target_from_spec (the RecruitTarget built from the catalog record),
and the unchanged ClockEngine / business-day walker (clock starts at the recruit
moment, not incident T0). An APAC nexus recruits India + Singapore; a LATAM nexus
recruits Brazil and starts its genuine business-day clock against the Brazilian
national holiday calendar. A blast radius that does NOT name a jurisdiction
produces no recruit, the content-driven negative.

No warden/ control logic is edited to make any of this work: a new jurisdiction is
a catalog record plus the same recruit primitives.
"""

from datetime import timedelta

from floor import regimes
from floor.recruit import (
    find_peer, jurisdiction_in_blast_radius, peer_id, target_from_spec)
from warden.clocks import (
    ClockEngine, add_business_days, is_business_day, parse_ts)


_SPECS = regimes.by_key(regimes.load_catalog())

# The discoverable drafter peers (NOT yet in the room) for the new jurisdictions,
# the same shape the live /agent/peers list returns.
APAC_PEERS = [
    {"id": "dora-agent", "name": "DORA Drafter"},
    {"id": "india-agent", "name": "India DPDP Drafter", "handle": "india_dpdp"},
    {"id": "singapore-agent", "name": "Singapore PDPC Drafter",
     "handle": "singapore_pdpc"},
    {"id": "australia-agent", "name": "Australia OAIC Drafter",
     "handle": "australia_oaic"},
    {"id": "korea-agent", "name": "South Korea PIPC Drafter",
     "handle": "korea_pipc"},
]
LATAM_PEERS = [
    {"id": "brazil-agent", "name": "Brazil ANPD Drafter", "handle": "brazil_anpd"},
    {"id": "canada-agent", "name": "Canada OSFI Drafter", "handle": "canada_osfi"},
]


def _target(key):
    return target_from_spec(_SPECS[key])


# ---- the content check: a jurisdiction in the blast radius drives the recruit ---

def test_apac_blast_radius_names_india_and_singapore():
    facts = {"blast_radius": [
        "EU: HQ",
        "IN: Meridian Trust India Pvt Ltd (Mumbai subsidiary)",
        "SG: Meridian Trust Singapore office",
    ]}
    assert jurisdiction_in_blast_radius(facts, "IN") is True
    assert jurisdiction_in_blast_radius(facts, "SG") is True
    # A jurisdiction NOT in the radius does not recruit (content-driven negative).
    assert jurisdiction_in_blast_radius(facts, "KR") is False
    assert jurisdiction_in_blast_radius(facts, "AU") is False


def test_latam_blast_radius_names_brazil():
    facts = {"blast_radius": ["EU: HQ", "BR: Meridian Trust Brasil Ltda (Sao Paulo)"]}
    assert jurisdiction_in_blast_radius(facts, "BR") is True
    assert jurisdiction_in_blast_radius(facts, "IN") is False


# ---- discovery: the recruited drafter is token-matched among peers -------------

def test_find_peer_token_match_for_new_jurisdictions():
    for key, peers in (("india_dpdp", APAC_PEERS), ("singapore_pdpa", APAC_PEERS),
                       ("australia_ndb", APAC_PEERS), ("korea_pipa", APAC_PEERS),
                       ("brazil_lgpd", LATAM_PEERS), ("canada_osfi", LATAM_PEERS)):
        target = _target(key)
        peer = find_peer(peers, target.name_tokens)
        assert peer is not None, f"{key} drafter not discovered by token-match"
        assert peer_id(peer), f"{key} discovered peer has no id"
    # A peer list missing the target's tokens discovers nothing.
    assert find_peer([{"id": "x", "name": "DORA Drafter"}],
                     _target("india_dpdp").name_tokens) is None


# ---- end to end (recruit primitives): APAC nexus recruits India + Singapore ----

def test_apac_nexus_recruits_india_and_singapore_clocks_at_recruit_moment():
    facts = {"blast_radius": [
        "EU: Meridian Trust Bank N.V.",
        "IN: Meridian Trust India Pvt Ltd",
        "SG: Meridian Trust Singapore Branch",
    ]}
    # The recruit moment: the obligation attaches when the jurisdiction enters
    # scope, so the clock anchors HERE, not at incident T0 (2026-06-16T02:14).
    recruit_ts = "2026-06-16T03:45:00+00:00"
    engine = ClockEngine()

    recruited = []
    for key in ("india_dpdp", "singapore_pdpa"):
        target = _target(key)
        assert jurisdiction_in_blast_radius(facts, target.jurisdiction)
        peer = find_peer(APAC_PEERS, target.name_tokens)
        assert peer is not None
        # 72 flat calendar hours from the recruit moment for both APAC regimes.
        c = engine.start_hours(target.clock_name, f"inc-apac:{target.branch}",
                               recruit_ts, target.clock_hours,
                               trigger_event=target.trigger_event,
                               display_tz=target.display_timezone)
        recruited.append((key, c))

    # Both APAC clocks started at the recruit moment, NOT incident T0.
    t0 = parse_ts("2026-06-16T02:14:00+00:00")
    for key, c in recruited:
        assert c.started_at == parse_ts(recruit_ts), key
        assert c.started_at != t0, key
        assert c.deadline == parse_ts(recruit_ts) + timedelta(hours=72), key

    # The India clock answers to the Data Protection Board of India; the Singapore
    # clock to the PDPC. The catalog carried both, the recruit started both.
    assert _SPECS["india_dpdp"].authority.startswith("Data Protection Board of India")
    assert _SPECS["singapore_pdpa"].authority.startswith(
        "Personal Data Protection Commission (PDPC)")


def test_apac_nexus_does_not_recruit_australia_when_absent():
    # Australia is in the catalog but NOT in this incident's blast radius, so it is
    # not recruited: the recruit is content-driven, never hardcoded to "all APAC".
    facts = {"blast_radius": ["EU: HQ", "IN: India subsidiary"]}
    target = _target("australia_ndb")
    assert jurisdiction_in_blast_radius(facts, target.jurisdiction) is False


# ---- end to end: LATAM nexus recruits Brazil, a genuine business-day clock ------

def test_latam_nexus_recruits_brazil_business_day_clock_at_recruit_moment():
    facts = {"blast_radius": [
        "EU: Meridian Trust Bank N.V.",
        "BR: Meridian Trust Brasil Ltda (Sao Paulo subsidiary)",
    ]}
    target = _target("brazil_lgpd")
    assert jurisdiction_in_blast_radius(facts, target.jurisdiction)
    peer = find_peer(LATAM_PEERS, target.name_tokens)
    assert peer is not None

    # Brazil LGPD is a 3-BUSINESS-day clock (Regulation CD/ANPD 15/2024), the
    # deliberate contrast with the calendar-hour APAC clocks: it skips weekends AND
    # Brazilian national holidays via the BR_FEDERAL calendar. Recruit on Tuesday
    # 2026-06-16; three business days lands on Friday 2026-06-19.
    recruit_ts = "2026-06-16T12:00:00+00:00"
    started = parse_ts(recruit_ts)
    spec = _SPECS["brazil_lgpd"]
    assert spec.clock.business_days is True
    assert spec.clock.holiday_calendar == "BR_FEDERAL"
    deadline = add_business_days(started, spec.clock.length,
                                 calendar=spec.clock.holiday_calendar)
    assert deadline.date().isoformat() == "2026-06-19"
    assert deadline.strftime("%A") == "Friday"
    assert is_business_day(deadline.date(), "BR_FEDERAL")


def test_brazil_clock_skips_a_brazilian_national_holiday():
    # Recruit on Thursday 2026-04-02. April 3 is Sexta-feira Santa (Good Friday, a
    # Brazilian national holiday); the next two business days are Mon Apr 6 and Tue
    # Apr 7, so the third business day is Wed Apr 8. A naive +3-calendar-days clock
    # would say Apr 5 (a Sunday). The BR_FEDERAL calendar makes the difference.
    started = parse_ts("2026-04-02T12:00:00+00:00")
    deadline = add_business_days(started, 3, calendar="BR_FEDERAL")
    assert deadline.date().isoformat() == "2026-04-08"
    assert deadline.strftime("%A") == "Wednesday"


def test_canada_osfi_recruits_with_24h_clock():
    # Canada OSFI (Guideline B-13 incident reporting): a flat 24 calendar hours from
    # the incident, the tightest clock in the catalog. Recruited from a North-America
    # nexus, anchored at the recruit moment.
    facts = {"blast_radius": ["CA: Meridian Trust Canada (OSFI-regulated)"]}
    target = _target("canada_osfi")
    assert jurisdiction_in_blast_radius(facts, target.jurisdiction)
    recruit_ts = "2026-06-16T12:00:00+00:00"
    engine = ClockEngine()
    c = engine.start_hours(target.clock_name, "inc-na:canada", recruit_ts,
                           target.clock_hours, trigger_event=target.trigger_event,
                           display_tz=target.display_timezone)
    assert c.deadline == parse_ts(recruit_ts) + timedelta(hours=24)
    assert _SPECS["canada_osfi"].authority.startswith(
        "Office of the Superintendent of Financial Institutions")
