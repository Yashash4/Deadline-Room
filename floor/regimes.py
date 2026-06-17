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

# Startup-clock anchors (which fixed timestamp a startup clock counts from).
ANCHOR_INCIDENT_T0 = "incident_t0"
ANCHOR_MATERIALITY_DETERMINATION = "materiality_determination"

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
class RegimeSpec:
    """One regime record from the catalog, in typed form.

    `recruit_jurisdiction` / `recruit_name_tokens` are populated only for
    recruit-mode regimes (UK, NYDFS); they are the blast-radius token and the
    peer name-match tokens the runtime recruit uses."""
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

    @property
    def is_startup(self) -> bool:
        return self.start_mode == START_STARTUP

    @property
    def is_recruit(self) -> bool:
        return self.start_mode == START_RECRUIT


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
    )


def _token_tuple(value) -> tuple[str, ...]:
    """Normalize a YAML obligation list into a tuple of lowercase tokens, in the
    declared order. None or an empty list yields the empty tuple."""
    if not value:
        return ()
    return tuple(str(v).strip().lower() for v in value if str(v).strip())


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


def startup_regimes(specs: list[RegimeSpec]) -> list[RegimeSpec]:
    """The regimes whose clocks start when the floor opens (NIS2 early + full,
    DORA, SEC), in catalog order."""
    return [s for s in specs if s.is_startup]


def recruit_regimes(specs: list[RegimeSpec]) -> list[RegimeSpec]:
    """The regimes whose clocks start at a runtime recruit (UK ICO, NYDFS), in
    catalog order."""
    return [s for s in specs if s.is_recruit]
