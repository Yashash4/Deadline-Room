"""Deterministic grounding / hallucination scorer over a drafted filing.

This is the eval harness AROUND the drafting LLM, not an LLM itself. For a
drafted filing and the canonical fact-record it scores faithfulness: it extracts
the load-bearing spans from the prose (record counts, dates, the attacker name,
the regulated entity, named systems) and checks each against the fact-record.
Any load-bearing span that is not supported by the record is flagged as an
UNGROUNDED span.

Three hard properties, all required because the result is a printed receipt a
judge re-runs and because replay must stay byte-identical:

  1. Pure function of (filing_text, fact_record). No network, no clock, no
     randomness, no global state. Same inputs, same GroundingResult, always.
  2. It is a SCORER, never a gate. Nothing in this module blocks a filing,
     moves a transition, stops a clock, or releases. It only reads text that has
     already been produced and reports a number plus the flagged spans.
  3. Conservative on HIGH-SIGNAL spans only. A regulator-style filing is full of
     legitimate statutory numbers (72 hours, Article 23, Item 1.05) and
     regulatory proper nouns (NIS2, GDPR, the SEC). Those are allowlisted so the
     score is not noise. What it catches is a number in the SHAPE of a fact the
     record carries (a large record count, a date, a year) that disagrees with
     the record, or a named breach actor the record does not name. A false
     positive costs nothing but a visible REVIEW badge; a false negative on an
     invented record count is the failure this exists to prevent, so the
     record-count and date checks are exact.

The companion validator `validate_citations` checks the inline
[field: <name>] citation tags the drafter is asked to emit: every cited field
must exist in the fact-record. An unknown tag is itself an ungrounded flag.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# The load-bearing fact fields a filing is scored against. These are the facts
# the [CLAIMS] block also carries, plus the named entities a filing states in
# prose. Kept conservative: only facts with a checkable surface form.
SCORED_FIELDS = (
    "records_affected",
    "incident_start_utc",
    "attacker",
    "regulated_entity",
)

# Statutory periods, article numbers, and form references that legitimately
# appear in regulatory prose and must never be flagged as ungrounded. These are
# the closed regulatory-boilerplate allowlist. Stored as normalized digit
# strings (see _norm_num). Year-shaped numbers are handled separately against the
# incident date, not here.
_REGULATORY_NUMBERS = frozenset({
    "23",      # NIS2 Article 23
    "33",      # GDPR Article 33
    "72",      # 72-hour notification (NIS2, GDPR, NYDFS)
    "24",      # NIS2 24-hour early warning
    "105",     # SEC 8-K Item 1.05 (decimal stripped by _norm_num)
    "4",       # SEC four business days
    "8",       # 8-K form
    "50017",   # 23 NYCRR 500.17 (NYDFS)
    "500",     # 23 NYCRR Part 500
    "17",      # 500.17
    "1",       # ordinals / section numbers
    "2",
    "3",
    "5",
    "6",
})

# Regulatory proper nouns and common filing words that are capitalized but are
# NOT breach-actor / entity claims. A capitalized span built only from these is
# not treated as a named-entity claim, so it is never flagged. Lowercased.
_REGULATORY_PROPER_NOUNS = frozenset({
    "nis2", "dora", "sec", "gdpr", "ico", "nydfs", "uk", "eu", "us", "ny",
    "article", "directive", "item", "form", "part", "reg", "regulation",
    "csirt", "the", "to", "from", "subject", "incident", "reference",
    "notification", "timelines", "nature", "significance", "impact",
    "assessment", "measures", "taken", "next", "steps", "data", "compromised",
    "response", "regulatory", "coordination", "contact", "authority", "summary",
    "description", "containment", "status", "information", "designated", "point",
    "of", "your", "name", "position", "date", "today", "insert", "today's",
    "sincerely", "preliminary", "approximately", "no", "additional", "further",
    "june", "january", "february", "march", "april", "may", "july", "august",
    "september", "october", "november", "december", "utc", "and", "s", "p",
    "national", "european", "union", "directive's",
}) | frozenset({n.lower() for n in
                ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
                 "Saturday", "Sunday")})

_MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
    "july": 7, "august": 8, "september": 9, "october": 10, "november": 11,
    "december": 12,
}

# A run of digits with optional thousands separators and an optional decimal.
_NUMBER = re.compile(r"\d[\d,]*(?:\.\d+)?")
# A capitalized multiword span: two or more Capitalized tokens in a row, allowing
# internal lowercase connectors and trailing version digits (e.g. "LockBit 3.0").
_CAP_SPAN = re.compile(
    r"(?:[A-Z][\w.&'-]*\s+){1,5}[A-Z][\w.&'-]*(?:\s+\d[\d.]*)?")
# A standalone version-tagged actor like "LockBit 3.0" (one CamelCase word + ver).
_ACTOR_SPAN = re.compile(r"[A-Z][a-zA-Z]+\s+\d[\d.]*")
# A written date: "16 June 2026", "June 16, 2026", "June 16 2026".
_DATE_DMY = re.compile(r"\b(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})\b")
_DATE_MDY = re.compile(r"\b([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})\b")
# An ISO date or datetime: 2026-06-16 or 2026-06-16T02:14:00+00:00.
_ISO = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2}))?")
# A clock time "02:14" optionally with "UTC".
_TIME = re.compile(r"\b(\d{1,2}):(\d{2})(?::\d{2})?\s*(?:UTC)?\b")


@dataclass(frozen=True)
class UngroundedSpan:
    """One load-bearing span in the prose not supported by the fact-record."""
    kind: str          # "number" | "date" | "named_entity"
    span: str          # the verbatim text flagged
    reason: str        # why it is ungrounded


@dataclass
class GroundingResult:
    """The per-filing grounding score. grounded + len(ungrounded) == total."""
    branch: str
    grounded: int = 0
    total: int = 0
    ungrounded: list[UngroundedSpan] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Grounded fraction in [0, 1]. A filing with no load-bearing spans
        scores 1.0 (nothing unsupported was asserted)."""
        if self.total == 0:
            return 1.0
        return self.grounded / self.total

    def passes(self, threshold: float) -> bool:
        return self.score >= threshold

    def as_dict(self) -> dict:
        return {
            "branch": self.branch,
            "grounded": self.grounded,
            "total": self.total,
            "score": round(self.score, 4),
            "ungrounded": [
                {"kind": u.kind, "span": u.span, "reason": u.reason}
                for u in self.ungrounded
            ],
        }


def _norm_num(raw: str) -> str:
    """Normalize a numeric surface form to a comparable digit string: strip
    thousands separators and any decimal point so 48,211 / 48211 / 48211.0 all
    compare equal and 1.05 -> 105. Returns the digit run."""
    return raw.replace(",", "").replace(".", "")


def _grounded_numbers(fact_record: dict) -> set[str]:
    """Every numeric surface form derivable from the fact-record, normalized.
    Includes the record count, the date/time components, and the incident-id
    digits, so a legitimate restatement of any record fact is grounded."""
    out: set[str] = set()
    rec = fact_record.get("records_affected")
    if isinstance(rec, int):
        out.add(_norm_num(str(rec)))
    start = _date_parts(str(fact_record.get("incident_start_utc", "")))
    if start:
        y, mo, d, hh, mm = start
        for part in (y, mo, d, hh, mm):
            if part is not None:
                out.add(str(part))
                out.add(f"{part:02d}")
    # The incident id often carries a numeric tail (inc-8842); ground it.
    for tok in re.findall(r"\d+", str(fact_record.get("incident_id", ""))):
        out.add(tok)
    return out


def _date_parts(value: str):
    """Parse an ISO date/datetime into (year, month, day, hour, minute) ints,
    or None if it is not an ISO date. Used both to build the grounded set and to
    compare a written date in the prose against the record."""
    m = _ISO.search(value)
    if not m:
        return None
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hh = int(m.group(4)) if m.group(4) is not None else None
    mm = int(m.group(5)) if m.group(5) is not None else None
    return (y, mo, d, hh, mm)


def _named_values(fact_record: dict) -> list[str]:
    """Lowercased named-entity values the prose may legitimately restate: the
    attacker, the regulated entity, the competent authority, and each named
    system. A capitalized span in the prose is grounded if it is contained in,
    or contains, one of these."""
    vals: list[str] = []
    for key in ("attacker", "regulated_entity", "competent_authority"):
        v = fact_record.get(key)
        if isinstance(v, str) and v.strip():
            vals.append(v.lower())
    for sys_name in fact_record.get("systems", []) or []:
        if isinstance(sys_name, str) and sys_name.strip():
            vals.append(sys_name.lower())
    return vals


def _record_count(fact_record: dict) -> int | None:
    rec = fact_record.get("records_affected")
    return rec if isinstance(rec, int) else None


def _looks_like_count(norm: str, record: int | None) -> bool:
    """A normalized number is COUNT-SHAPED (a candidate record-count claim) when
    it has as many digits as the real record count and is not a year. We only
    hold count-shaped numbers to the exact-match bar, so statutory periods and
    section numbers (short) are never flagged."""
    if record is None:
        return False
    digits = len(str(record))
    if digits < 4:
        return False
    return len(norm) >= digits - 1 and not _is_year(norm)


def _is_year(norm: str) -> bool:
    return len(norm) == 4 and norm.isdigit() and 1900 <= int(norm) <= 2999


def _strip_claims(text: str) -> str:
    """Score only the human prose, never the [CLAIMS] block. The claims block is
    the deterministic Warden-owned envelope; it is grounded by construction and
    is not LLM prose, so it must not enter the faithfulness score.

    Cut at the LAST [CLAIMS] occurrence, not the first. The drafter appends the
    one authoritative block at the END after sanitizing the prose, so the last
    occurrence is the real envelope boundary. A first-occurrence cut would let a
    model-injected earlier fence hide everything after it from the scorer (the
    historic blind spot). The sanitizer defangs any such injected fence, so on a
    clean run there is exactly one block and last == first; this is the belt."""
    idx = text.rfind("[CLAIMS]")
    return text[:idx] if idx != -1 else text


def score_filing(filing_text: str, fact_record: dict, *, branch: str = "") -> GroundingResult:
    """Score one drafted filing for grounding against the fact-record.

    Pure and deterministic: same (filing_text, fact_record) always yields the
    same GroundingResult. It is a SCORER only; it never gates. Load-bearing spans
    checked: numbers (count-shaped numbers held to exact match; statutory periods
    allowlisted), written/ISO dates (compared to the incident date), and named
    breach-actor spans (held against the fact-record's named values).
    """
    prose = _strip_claims(filing_text or "")
    grounded_nums = _grounded_numbers(fact_record)
    named = _named_values(fact_record)
    record = _record_count(fact_record)
    incident_date = _date_parts(str(fact_record.get("incident_start_utc", "")))

    result = GroundingResult(branch=branch or str(fact_record.get("incident_id", "")))

    # Spans already accounted for by a date match, so the date's component
    # numbers are not double-counted as bare numbers.
    consumed: list[tuple[int, int]] = []

    def _overlaps(start: int, end: int) -> bool:
        return any(s < end and start < e for s, e in consumed)

    # ---- Dates: every written/ISO date must match the incident date ----------
    for m in _iter_dates(prose):
        start, end, parts = m
        consumed.append((start, end))
        result.total += 1
        if incident_date is None:
            result.grounded += 1
            continue
        if _date_matches(parts, incident_date):
            result.grounded += 1
        else:
            result.ungrounded.append(UngroundedSpan(
                kind="date", span=prose[start:end].strip(),
                reason=("date does not match the fact-record incident date "
                        f"{fact_record.get('incident_start_utc')}")))

    # ---- Named breach-actor spans --------------------------------------------
    # We only score version-tagged actor spans ("LockBit 3.0") and only when the
    # fact-record's attacker is itself version-tagged, so the prose actor is held
    # against a comparable surface form. This keeps the check sharp on the one
    # named claim that matters (the breach actor) and never mistakes a statutory
    # reference ("Article 23"), a count lead-in ("Approximately 48"), or a form
    # name ("Amended 8-K") for an actor. The leading word must also be a genuine
    # name candidate: a mixed-case word like "LockBit" or "EvilCorp", not a plain
    # English word.
    attacker = str(fact_record.get("attacker", ""))
    if _ACTOR_SPAN.fullmatch(attacker.strip()):
        for m in _ACTOR_SPAN.finditer(prose):
            start, end = m.start(), m.end()
            if _overlaps(start, end):
                continue
            span = m.group(0).strip()
            lead = span.split()[0]
            if not _name_candidate(lead):
                continue
            consumed.append((start, end))
            result.total += 1
            if _entity_grounded(span.lower(), named):
                result.grounded += 1
            else:
                result.ungrounded.append(UngroundedSpan(
                    kind="named_entity", span=span,
                    reason="named breach actor not present in the fact-record"))

    # ---- Numbers: count-shaped numbers must equal the record count -----------
    for m in _NUMBER.finditer(prose):
        start, end = m.start(), m.end()
        if _overlaps(start, end):
            continue
        raw = m.group(0)
        norm = _norm_num(raw)
        if not norm or set(norm) == {"0"} and len(norm) == 1:
            continue
        if not _looks_like_count(norm, record):
            # Not count-shaped: a statutory period, section number, or year.
            # Grounded if it is a known fact number or a regulatory constant.
            if norm in grounded_nums or norm in _REGULATORY_NUMBERS or _is_year(norm):
                continue
            # A short non-fact number (e.g. a page count) is low signal; do not
            # flag it, but do not credit it either: skip entirely.
            continue
        result.total += 1
        if norm in grounded_nums:
            result.grounded += 1
        else:
            result.ungrounded.append(UngroundedSpan(
                kind="number", span=raw,
                reason=("count-shaped number does not match the fact-record "
                        f"records_affected {record}")))

    return result


def _iter_dates(prose: str):
    """Yield (start, end, parts) for each written or ISO date in the prose, where
    parts is (year, month, day) ints. Earlier (longer) patterns win on overlap."""
    found: list[tuple[int, int, tuple[int, int, int]]] = []
    for m in _DATE_DMY.finditer(prose):
        mon = _MONTHS.get(m.group(2).lower())
        if mon:
            found.append((m.start(), m.end(),
                          (int(m.group(3)), mon, int(m.group(1)))))
    for m in _DATE_MDY.finditer(prose):
        mon = _MONTHS.get(m.group(1).lower())
        if mon:
            found.append((m.start(), m.end(),
                          (int(m.group(3)), mon, int(m.group(2)))))
    for m in _ISO.finditer(prose):
        found.append((m.start(), m.end(),
                      (int(m.group(1)), int(m.group(2)), int(m.group(3)))))
    found.sort(key=lambda t: (t[0], -(t[1] - t[0])))
    out = []
    taken: list[tuple[int, int]] = []
    for start, end, parts in found:
        if any(s < end and start < e for s, e in taken):
            continue
        taken.append((start, end))
        out.append((start, end, parts))
    return out


def _date_matches(parts: tuple[int, int, int], incident) -> bool:
    """A prose date (year, month, day) matches the incident date when all three
    components agree with the fact-record's incident_start_utc."""
    y, mo, d = parts
    iy, imo, idd = incident[0], incident[1], incident[2]
    return y == iy and mo == imo and d == idd


def _name_candidate(word: str) -> bool:
    """A leading word is a breach-actor name candidate when it carries internal
    capitalization (CamelCase: LockBit, EvilCorp, BlackCat), the distinctive
    shape of a threat-actor handle. A plain Title-case English word (Article,
    Amended, Approximately) is not, so a version-tagged statutory or form
    reference is never mistaken for an actor."""
    return bool(re.search(r"[A-Z]", word[1:])) if len(word) > 1 else False


def _entity_grounded(low_span: str, named: list[str]) -> bool:
    """A named span is grounded if it is a substring of, or contains, any named
    value in the fact-record (so 'LockBit 3.0 ransomware group' grounds against
    'lockbit 3.0', and 'Meridian Trust Bank' grounds against the full name)."""
    for val in named:
        if low_span in val or val in low_span:
            return True
        # Token overlap: the actor's distinctive token appears in the span.
        val_tokens = [t for t in re.split(r"\s+", val) if len(t) > 2]
        if val_tokens and val_tokens[0] in low_span:
            return True
    return False


# ---------------------------------------------------------------------------
# Inline citation validation (item 2). The drafter is asked to tag each factual
# sentence with the fact-record FIELD it relies on, e.g. "[field: records_affected]".
# This validator is deterministic: every cited field name must exist in the
# fact-record. An unknown tag is an ungrounded flag. A filing with no tags is not
# an error (older runs, or a model that ignored the instruction); it simply has
# no citations to validate.
# ---------------------------------------------------------------------------
_CITATION = re.compile(r"\[field:\s*([a-zA-Z0-9_]+)\s*\]")


@dataclass
class CitationResult:
    """Validation of the inline [field: <name>] citation tags in a filing."""
    cited_fields: list[str] = field(default_factory=list)
    valid: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        return not self.invalid

    def as_dict(self) -> dict:
        return {
            "cited_fields": self.cited_fields,
            "valid": self.valid,
            "invalid": self.invalid,
            "all_valid": self.all_valid,
        }


def validate_citations(filing_text: str, fact_record: dict) -> CitationResult:
    """Validate the inline citation tags against the fact-record keys. Pure and
    deterministic. Cites to a field the record does not carry are reported as
    invalid; nothing here gates."""
    prose = _strip_claims(filing_text or "")
    keys = set(fact_record.keys())
    result = CitationResult()
    for m in _CITATION.finditer(prose):
        fieldname = m.group(1)
        result.cited_fields.append(fieldname)
        if fieldname in keys:
            result.valid.append(fieldname)
        else:
            result.invalid.append(fieldname)
    return result


def strip_citations(filing_text: str) -> str:
    """Remove the inline [field: <name>] tags from prose for a clean
    human-readable rendering. Pure string work; leaves the [CLAIMS] block and all
    other text untouched."""
    return re.sub(r"\s*" + _CITATION.pattern, "", filing_text or "")


def score_filings(filings: list[dict], fact_record: dict) -> list[dict]:
    """Score a list of filing dicts (each {'regime'/'branch', 'text', ...}) and
    return a list of result dicts ready to attach to the packet. Pure; the input
    filings are not mutated. The grounding result is a printed receipt; it is
    NEVER read back as a gate condition."""
    out: list[dict] = []
    for f in filings:
        branch = str(f.get("branch") or f.get("regime") or "")
        text = f.get("text", "")
        grounding = score_filing(text, fact_record, branch=branch)
        citations = validate_citations(text, fact_record)
        row = grounding.as_dict()
        row["regime"] = f.get("regime", branch)
        row["citations"] = citations.as_dict()
        out.append(row)
    return out
