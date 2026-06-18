"""Regulation-as-config loader: the declarative regime catalog made live.

`floor/regimes.yaml` holds one record per statutory reporting regime (authority,
trigger event, clock rule, business-day-vs-calendar, holiday calendar, format
profile, and how the clock starts). This module reads that file and yields typed
`RegimeSpec` records the existing engine consumes, so the six live regimes (NIS2
early + full, DORA, SEC, UK ICO, NYDFS) are produced FROM the data rather than
from hardcoded constants.

The contract that makes this a safe refactor: the values produced here are
exactly the constants the floor used before. A startup clock named in the catalog
produces the same clock the old `clocks.start_*` call site produced; a recruit
regime produces the same `RecruitTarget` the old module-level constant produced.
Adding a seventh regime is appending one YAML block, which is the scale receipt.

This module is pure data plumbing. It makes no LLM call and touches nothing in
warden/. It is read by floor/run_floor.py (to start the startup clocks and walk
the recruit targets) and by floor/recruit.py (to expose UK_ICO_TARGET /
NYDFS_TARGET from the catalog).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_CATALOG_PATH = Path(__file__).resolve().parent / "regimes.yaml"

# Clock start modes.
START_STARTUP = "startup"
START_RECRUIT = "recruit"
# A post-release obligation (the affected-party / GDPR Art 34 communication to
# data subjects). It is NOT a regulator filing and its clock does NOT start when
# the floor opens or at a jurisdiction recruit: it starts at the regulator RELEASE
# moment ("without undue delay" runs from then), and only if the high-risk gate
# requires a communication to the affected individuals. So it is neither a startup
# nor a recruit regime; startup_regimes / recruit_regimes both exclude it, and the
# affected-party phase starts its clock explicitly at the release timestamp.
START_POST_RELEASE = "post_release"

# Startup-clock anchors (which fixed timestamp a startup clock counts from).
ANCHOR_INCIDENT_T0 = "incident_t0"
ANCHOR_MATERIALITY_DETERMINATION = "materiality_determination"
# The affected-party (Art 34) clock anchors at the regulator RELEASE moment, not
# at occurrence or determination: the "without undue delay" communication to data
# subjects runs from when the regulator filings are released.
ANCHOR_RELEASE_MOMENT = "release_moment"

# Clock units.
UNIT_HOURS = "hours"
UNIT_BUSINESS_DAYS = "business_days"


@dataclass(frozen=True)
class ClockSpec:
    """The statutory clock rule for one regime, lifted from the catalog.

    `holiday_calendar` is the named holiday-calendar id a business-day clock counts
    against (warden.clocks.HOLIDAY_CALENDARS: US_FEDERAL, UK_BANK, DE_FEDERAL,
    EU_TARGET); a calendar-hour clock names "none". `display_timezone` is the IANA
    zone the regulator reads the deadline in (render-only; the stored deadline
    stays a UTC instant)."""
    name: str
    length: int
    unit: str
    business_days: bool
    holiday_calendar: str
    display_timezone: str = ""


@dataclass(frozen=True)
class ReportabilitySpec:
    """The declarative reportability / duty-to-notify threshold for one regime.

    `standard` is the statutory trigger standard the regime applies to decide
    whether the incident must be reported at all (NIS2 significant impact, DORA
    major incident, GDPR Art 33 risk to rights and freedoms, NYDFS material harm,
    SEC Item 1.05 materiality). The qualitative CALL against this standard is an
    LLM judgment (floor/reportability.py); the deterministic
    warden/reportability.py gate then suppresses a regime below the threshold or
    files one above it. `rule` is the short human-readable rule label rendered in
    the Examiner Packet when a regime is suppressed."""
    standard: str
    rule: str


@dataclass(frozen=True)
class ExpertProfileSpec:
    """The regime-expert substance for one regime (E5.6).

    `statutory_standard` is the legal test the filing must satisfy; `factors` are
    the named elements the regulator weighs; `failure_modes` are the common ways a
    filing for this regime falls short. floor/drafter.py threads this into the
    drafter SYSTEM prompt exactly the way a FormatProfile is threaded, so the model
    reasons in regime-specific terms and emits an OPTIONAL fenced rationale block.
    It changes ONLY the human-readable prose: the [CLAIMS] block the Warden diffs is
    attached after sanitization and is never affected, and the rationale is
    out-of-log, so the sealed run-log shas and byte-identical replay are
    untouched."""
    statutory_standard: str
    factors: tuple[str, ...] = ()
    failure_modes: tuple[str, ...] = ()


@dataclass(frozen=True)
class HighRiskSpec:
    """The declarative GDPR Art 34 high-risk threshold for the affected-party
    (data-subject) communication track.

    `standard` is the statutory standard applied to decide whether the breach is
    "likely to result in a HIGH RISK to the rights and freedoms of natural persons"
    (the Art 34 trigger to communicate the breach to the affected individuals,
    which is a higher bar than the Art 33 duty owed to the supervisory authority).
    The qualitative CALL against this standard is an LLM judgment
    (floor/high_risk.py); the deterministic warden/high_risk.py gate then requires
    a communication when high risk attaches or records it not-required otherwise.
    `rule` is the short human-readable rule label rendered in the Examiner Packet
    when no communication to data subjects is required."""
    standard: str
    rule: str


@dataclass(frozen=True)
class ObligationSpec:
    """The declarative cross-border obligation attributes for one regime (E3.4).

    The typed obligation data the pure no-LLM warden/obligations.py detector reads
    for the regimes actually in scope, to find any mutually exclusive pair across
    jurisdictions. `discloses` is the data elements the regime is MANDATED to put in
    its notice; `forbids_disclosing` is the data elements its law FORBIDS
    disclosing; `mandates` is the named obligation tags it asserts (a tag and its
    declared opposite cannot both be satisfied). Each is a tuple of plain lowercase
    tokens. `basis` is the cited statutory basis, rendered for the examiner and
    never gated on. The detector reports conflicts; it never decides which law
    prevails (that is the human two-key gate's call)."""
    discloses: tuple[str, ...] = ()
    forbids_disclosing: tuple[str, ...] = ()
    mandates: tuple[str, ...] = ()
    basis: str = ""


@dataclass(frozen=True)
class ControllerSpec:
    """The regulated entity's GDPR establishment data (E3.6).

    `name` is the controller; `main_establishment` is the member-state token (IE,
    DE, FR, NL) where it has its main establishment in the EU, which under GDPR
    Article 56(1) determines the LEAD supervisory authority for cross-border
    processing. Pure declarative data: the deterministic floor/lead_authority.py
    routing reads it, it gates nothing."""
    name: str
    main_establishment: str


@dataclass(frozen=True)
class SupervisoryAuthoritySpec:
    """One EU member state's data-protection supervisory authority (E3.6).

    `member_state` is the ISO-style token the Art 56 routing keys on; `authority`
    is the authority's name (filed to as lead, or copied through the lead as
    concerned); `country` is the human-readable label rendered for the examiner.
    Pure declarative data read by floor/lead_authority.py; it gates nothing."""
    member_state: str
    authority: str
    country: str


@dataclass(frozen=True)
class RegimeSpec:
    """One regime record from the catalog, in typed form.

    `recruit_jurisdiction` / `recruit_name_tokens` are populated only for
    recruit-mode regimes (UK, NYDFS); they are the blast-radius token and the
    peer name-match tokens the runtime recruit uses.

    `corpus_tags` (E3.11) are the stable human-citation chunk ids in the regulation
    corpus (floor/corpus/, built into floor/corpus/index.json) that GROUND this
    regime: the statutory passages the regime's filing draws on and cites. They are
    reference-data pointers, never gated on; the E5.9 retriever uses them to fetch
    the real text to inject, and scripts/build_corpus.py asserts every tag resolves
    to a real chunk so a wrong or stale citation surfaces at build time."""
    key: str
    authority: str
    branch: str
    regime_label: str
    trigger_event: str
    clock: ClockSpec
    format_profile: str
    start_mode: str
    start_anchor: str | None = None
    recruit_jurisdiction: str | None = None
    recruit_name_tokens: tuple[str, ...] = ()
    reportability: ReportabilitySpec | None = None
    obligations: ObligationSpec | None = None
    high_risk: HighRiskSpec | None = None
    corpus_tags: tuple[str, ...] = ()
    expert_profile: ExpertProfileSpec | None = None

    @property
    def is_startup(self) -> bool:
        return self.start_mode == START_STARTUP

    @property
    def is_recruit(self) -> bool:
        return self.start_mode == START_RECRUIT

    @property
    def is_post_release(self) -> bool:
        return self.start_mode == START_POST_RELEASE


def _parse_regime(record: dict) -> RegimeSpec:
    clock = record["clock"]
    start = record.get("start", {})
    recruit = record.get("recruit", {})
    clock_spec = ClockSpec(
        name=clock["name"],
        length=int(clock["length"]),
        unit=clock["unit"],
        business_days=bool(clock["business_days"]),
        holiday_calendar=clock["holiday_calendar"],
        display_timezone=str(clock.get("display_timezone", "")),
    )
    reportability = record.get("reportability")
    reportability_spec = None
    if reportability is not None:
        # A reportability block, when present, must carry BOTH the standard and
        # the rule. A half-specified block is a catalog error, surfaced
        # structurally rather than silently treated as "no threshold".
        standard = " ".join(str(reportability["standard"]).split())
        reportability_spec = ReportabilitySpec(
            standard=standard,
            rule=str(reportability["rule"]),
        )
    high_risk = record.get("high_risk")
    high_risk_spec = None
    if high_risk is not None:
        # A high_risk block, when present, must carry BOTH the standard and the
        # rule (the affected-party / Art 34 track). A half-specified block is a
        # catalog error, surfaced structurally rather than silently treated as
        # "no threshold".
        high_risk_standard = " ".join(str(high_risk["standard"]).split())
        high_risk_spec = HighRiskSpec(
            standard=high_risk_standard,
            rule=str(high_risk["rule"]),
        )
    obligations = record.get("obligations")
    obligations_spec = None
    if obligations is not None:
        # An obligations block, when present, declares the typed cross-border
        # obligation attributes (E3.4). Tokens are lowercased so the pure detector
        # compares plain set elements. A bare/empty block (no obligation token of
        # any kind) is a catalog error, surfaced structurally: declaring the block
        # at all is a claim that the regime carries a cross-border tension.
        obligations_spec = ObligationSpec(
            discloses=_token_tuple(obligations.get("discloses")),
            forbids_disclosing=_token_tuple(obligations.get("forbids_disclosing")),
            mandates=_token_tuple(obligations.get("mandates")),
            basis=" ".join(str(obligations.get("basis", "")).split()),
        )
        if not (obligations_spec.discloses or obligations_spec.forbids_disclosing
                or obligations_spec.mandates):
            raise ValueError(
                f"regime {record['key']} declares an empty obligations block; an "
                f"obligations block must carry at least one of discloses, "
                f"forbids_disclosing, or mandates")
    expert = record.get("expert_profile")
    expert_spec = None
    if expert is not None:
        # An expert_profile block, when present, must carry a statutory_standard and
        # at least one factor: a profile with no standard or no factors is a catalog
        # error (declaring the block at all is a claim the regime carries
        # regime-expert substance), surfaced structurally rather than silently
        # treated as "no expert profile".
        standard = " ".join(str(expert["statutory_standard"]).split())
        factors = _phrase_tuple(expert.get("factors"))
        failure_modes = _phrase_tuple(expert.get("failure_modes"))
        if not standard or not factors:
            raise ValueError(
                f"regime {record['key']} declares an expert_profile that is missing "
                f"a statutory_standard or factors; both are required")
        expert_spec = ExpertProfileSpec(
            statutory_standard=standard,
            factors=factors,
            failure_modes=failure_modes,
        )
    return RegimeSpec(
        key=record["key"],
        authority=record["authority"],
        branch=record["branch"],
        regime_label=record["regime_label"],
        trigger_event=record["trigger_event"],
        clock=clock_spec,
        format_profile=record["format_profile"],
        start_mode=start["mode"],
        start_anchor=start.get("anchor"),
        recruit_jurisdiction=recruit.get("jurisdiction"),
        recruit_name_tokens=tuple(recruit.get("name_tokens", ())),
        reportability=reportability_spec,
        obligations=obligations_spec,
        high_risk=high_risk_spec,
        corpus_tags=_corpus_tags(record.get("corpus_tags")),
        expert_profile=expert_spec,
    )


def _corpus_tags(value) -> tuple[str, ...]:
    """Normalize a YAML corpus_tags list into a tuple of chunk-id strings, in the
    declared order, preserving the citation punctuation verbatim (the ids carry
    parentheses, slashes, and dots). None or an empty list yields the empty tuple.
    A non-string entry is a catalog error surfaced structurally."""
    if not value:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"corpus_tags must be a list, got {type(value).__name__}")
    out: list[str] = []
    for v in value:
        s = str(v).strip()
        if s:
            out.append(s)
    return tuple(out)


def _token_tuple(value) -> tuple[str, ...]:
    """Normalize a YAML obligation list into a tuple of lowercase tokens, in the
    declared order. None or an empty list yields the empty tuple."""
    if not value:
        return ()
    return tuple(str(v).strip().lower() for v in value if str(v).strip())


def _phrase_tuple(value) -> tuple[str, ...]:
    """Normalize a YAML list of human phrases (expert-profile factors and failure
    modes) into a tuple of whitespace-collapsed strings, in the declared order,
    preserving the original casing and punctuation. None or an empty list yields the
    empty tuple. A non-list value is a catalog error surfaced structurally."""
    if not value:
        return ()
    if not isinstance(value, list):
        raise ValueError(
            f"expected a list of phrases, got {type(value).__name__}")
    out: list[str] = []
    for v in value:
        s = " ".join(str(v).split())
        if s:
            out.append(s)
    return tuple(out)


def load_catalog(path: str | Path | None = None) -> list[RegimeSpec]:
    """Read the regime catalog file and return the typed regime records in file
    order. Raises if the file is missing or a record is malformed (a regime that
    cannot be parsed must surface structurally, never be silently skipped)."""
    p = Path(path) if path is not None else _CATALOG_PATH
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    regimes = data.get("regimes") if isinstance(data, dict) else None
    if not regimes:
        raise ValueError(f"regime catalog {p} has no 'regimes' list")
    return [_parse_regime(r) for r in regimes]


def by_key(specs: list[RegimeSpec]) -> dict[str, RegimeSpec]:
    return {s.key: s for s in specs}


def expert_profile_for(
        key: str, path: str | Path | None = None) -> ExpertProfileSpec | None:
    """Resolve the regime-expert profile a regime declares in floor/regimes.yaml,
    by regime key, or None if that regime declares none (E5.6). Raises if the key
    names no regime, so a caller typo surfaces structurally."""
    specs = by_key(load_catalog(path))
    try:
        return specs[key].expert_profile
    except KeyError as e:
        raise KeyError(f"unknown regime key: {key!r}") from e


def load_controller(path: str | Path | None = None) -> ControllerSpec:
    """Read the regulated entity's GDPR establishment data from the catalog (E3.6).

    Returns the typed ControllerSpec the Art 56 routing reads. Raises if the
    `controller` block, or either required field, is missing: a half-specified
    controller is a catalog error surfaced structurally, never silently treated as
    "no main establishment"."""
    p = Path(path) if path is not None else _CATALOG_PATH
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    controller = data.get("controller") if isinstance(data, dict) else None
    if not controller:
        raise ValueError(f"regime catalog {p} has no 'controller' block")
    name = str(controller["name"]).strip()
    main = str(controller["main_establishment"]).strip().upper()
    if not name or not main:
        raise ValueError(
            f"controller in {p} must declare both name and main_establishment")
    return ControllerSpec(name=name, main_establishment=main)


def load_supervisory_authorities(
        path: str | Path | None = None) -> dict[str, SupervisoryAuthoritySpec]:
    """Read the EU supervisory-authority map from the catalog (E3.6).

    Returns a member-state-token -> SupervisoryAuthoritySpec dict the Art 56 routing
    keys on. Raises if the block is missing, a record is half-specified, or a
    member-state token is declared twice (a duplicate is an ambiguous catalog error,
    surfaced structurally rather than silently overwriting)."""
    p = Path(path) if path is not None else _CATALOG_PATH
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    records = data.get("eu_supervisory_authorities") if isinstance(data, dict) else None
    if not records:
        raise ValueError(
            f"regime catalog {p} has no 'eu_supervisory_authorities' list")
    out: dict[str, SupervisoryAuthoritySpec] = {}
    for record in records:
        state = str(record["member_state"]).strip().upper()
        authority = str(record["authority"]).strip()
        country = str(record["country"]).strip()
        if not state or not authority or not country:
            raise ValueError(
                f"supervisory authority record in {p} must declare member_state, "
                f"authority, and country")
        if state in out:
            raise ValueError(
                f"member state {state!r} declared twice in "
                f"eu_supervisory_authorities")
        out[state] = SupervisoryAuthoritySpec(
            member_state=state, authority=authority, country=country)
    return out


def startup_regimes(specs: list[RegimeSpec]) -> list[RegimeSpec]:
    """The regimes whose clocks start when the floor opens (NIS2 early + full,
    DORA, SEC), in catalog order."""
    return [s for s in specs if s.is_startup]


def recruit_regimes(specs: list[RegimeSpec]) -> list[RegimeSpec]:
    """The regimes whose clocks start at a runtime recruit (UK ICO, NYDFS), in
    catalog order."""
    return [s for s in specs if s.is_recruit]
