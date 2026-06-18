"""The examiner's first auto-screen: a machine-readable per-regime completeness sheet.

An examiner does not read prose first. The intake system auto-screens a STRUCTURED
submission before any human looks at it: for each regime, every mandated field the
form requires is checked PRESENT / EMPTY / NOT-APPLICABLE against the EXACT mandated
field labels the form defines (floor/formats.py, FormatProfile.fields), and the
result is the green/amber completeness matrix that is literally the examiner's first
screen. A single empty mandated field is a guaranteed deficiency notice.

This module produces that sheet. Per regime it resolves the FormatProfile the filing
fills (from the declarative regime catalog, the same catalog that drives the clocks),
reads the labelled sections out of the drafted filing PROSE, and for each mandated
field returns a typed FieldStatus -> {label, status, evidence}. An overall
complete/incomplete verdict per regime falls straight out of the per-field statuses.

What it is, precisely:

  A PURE DERIVED RENDER over the assembled packet. It reads the SAME labelled
  sections the deficiency completeness screen and the submission export read (the
  exact mandated field label followed by a colon, then the prose up to the next
  blank line), with the field citations stripped and the Warden-owned [CLAIMS] block
  removed first. A field is PRESENT iff its mandated label occurs in the prose with a
  genuinely non-empty body, EMPTY otherwise. A regime with a profile but no filing in
  the packet (e.g. a suppressed regime) yields a sheet whose every field is
  NOT-APPLICABLE: the duty did not attach, so the form is not owed.

  Deterministic and no-trust-core: zero LLM calls, no now(), no randomness. The same
  packet always derives the byte-identical sheet. It reads the packet dict only; it
  never enters the hashed run-log, never gates a Warden transition, never clocks or
  counts anything inside the core. It is an examiner-side READ over the Warden's
  output, exactly like the deficiency screen and the grounding receipt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from floor.formats import FormatProfile, format_profile_for
from floor.grounding import strip_citations
from floor.regimes import load_catalog

# The three intake dispositions, named so the packet and the receipt branch on the
# code rather than a free string. PRESENT: the mandated field is filled. EMPTY: the
# form requires it and it is missing or blank (a deficiency at intake). NA: the form
# itself is not owed for this regime in this incident (the duty did not attach), so
# no field is expected.
STATUS_PRESENT = "PRESENT"
STATUS_EMPTY = "EMPTY"
STATUS_NA = "NA"

# How many characters of a present field's body to carry as evidence on the sheet.
# Enough to identify the section, short enough to keep the matrix readable. The
# full prose stays in the filing block; this is the intake-screen snippet.
_EVIDENCE_LEN = 120

# The fenced [CLAIMS] envelope the drafter appends below its prose. It is the
# Warden-owned deterministic block, not part of the examiner's form, so it is
# removed before the labelled sections are read (the same cut the deficiency screen
# and the submission export make).
_CLAIMS_BLOCK = re.compile(r"\[CLAIMS\].*", re.DOTALL)

# Regime-label / branch token -> format profile id, built once from the SAME
# declarative regime catalog that drives the clocks. This is the regulation-as-config
# spine: the mandated-field matrix is generated from the same catalog that anchors
# the statutory deadlines. Both the branch token (the stable key a filing carries)
# and the regime label are indexed, lower-cased, so a filing matches on either.
def _build_profile_index() -> dict[str, str]:
    index: dict[str, str] = {}
    for spec in load_catalog():
        index[spec.branch.strip().lower()] = spec.format_profile
        index[spec.regime_label.strip().lower()] = spec.format_profile
    return index


_PROFILE_ID_INDEX = _build_profile_index()


@dataclass(frozen=True)
class FieldStatus:
    """One mandated field's intake disposition on the completeness sheet.

    label    the EXACT mandated field label from the form (formats.py).
    status   STATUS_PRESENT / STATUS_EMPTY / STATUS_NA.
    evidence a short human-readable basis: the present field's body snippet, or the
             reason the field is empty / not applicable. Never the full prose.
    """
    label: str
    status: str
    evidence: str

    @property
    def present(self) -> bool:
        return self.status == STATUS_PRESENT

    def as_dict(self) -> dict:
        return {"label": self.label, "status": self.status, "evidence": self.evidence}


@dataclass(frozen=True)
class CompletenessSheet:
    """The per-regime completeness sheet: the examiner's first auto-screen.

    regime       the regime label the filing was drafted under (e.g. "SEC").
    form_title   the form the mandated fields are drawn from (formats.py).
    cover_tag    the form's cover tag (the rule the mandated fields enforce).
    applicable   True when a filing for this regime exists in the packet (the duty
                 attached); False when the profile applies but no filing was made
                 (every field is then NA).
    fields       the per-mandated-field statuses, in form order.
    """
    regime: str
    form_title: str
    cover_tag: str
    applicable: bool
    fields: tuple[FieldStatus, ...]

    @property
    def total(self) -> int:
        return len(self.fields)

    @property
    def present_count(self) -> int:
        return sum(1 for f in self.fields if f.status == STATUS_PRESENT)

    @property
    def empty_count(self) -> int:
        return sum(1 for f in self.fields if f.status == STATUS_EMPTY)

    @property
    def na_count(self) -> int:
        return sum(1 for f in self.fields if f.status == STATUS_NA)

    @property
    def complete(self) -> bool:
        """COMPLETE iff the form applies and every mandated field is PRESENT. A sheet
        for a regime whose duty did not attach (applicable False) is NOT complete: it
        is not owed, which the verdict states separately, but it is not a passed
        intake screen either."""
        return self.applicable and self.empty_count == 0 and self.present_count > 0

    @property
    def verdict(self) -> str:
        """The one-line intake verdict the matrix shows as its first screen."""
        if not self.applicable:
            return "NOT APPLICABLE (no filing owed for this regime)"
        if self.complete:
            return f"COMPLETE ({self.present_count}/{self.total} mandated fields present)"
        return (f"INCOMPLETE ({self.empty_count} of {self.total} mandated field"
                f"{'' if self.empty_count == 1 else 's'} empty)")

    def as_dict(self) -> dict:
        """A JSON-serializable view for the Examiner Packet. Stable key order so the
        packet render and any guard see identical bytes."""
        return {
            "regime": self.regime,
            "form_title": self.form_title,
            "cover_tag": self.cover_tag,
            "applicable": self.applicable,
            "complete": self.complete,
            "verdict": self.verdict,
            "present_count": self.present_count,
            "empty_count": self.empty_count,
            "na_count": self.na_count,
            "total": self.total,
            "fields": [f.as_dict() for f in self.fields],
        }


def _filing_prose(filing: dict) -> str:
    """The filing's human PROSE with the field citations stripped and the
    Warden-owned [CLAIMS] block removed, ready for the labelled-section read. The
    same recipe the deficiency screen and the submission export use, so all three
    read the examiner's form identically."""
    text = strip_citations(filing.get("text", "") or "")
    return _CLAIMS_BLOCK.sub("", text).strip()


def _field_body(prose: str, label: str) -> str:
    """The body the filing prose carries for one mandated field label, or "" when
    the field is absent or empty.

    Each mandated field is written as its own labelled section: the exact field
    label followed by a colon, then the field prose up to the next blank line (the
    section boundary). Deterministic string work, matched case-insensitively on the
    label (a drafter may title-case a heading) with a genuinely non-empty body
    required. This mirrors floor/deficiency._field_present and
    floor/submission._field_body so the intake screen and the export agree."""
    needle = label.lower() + ":"
    haystack = prose.lower()
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            return ""
        after = prose[idx + len(needle):]
        body = after.split("\n\n", 1)[0].strip()
        if body:
            return body
        start = idx + len(needle)


def _evidence_snippet(body: str) -> str:
    """A single-line evidence snippet for a present field: the body collapsed to one
    line and truncated. Deterministic; identifies the section without dumping the
    full prose into the matrix."""
    flat = " ".join(body.split())
    if len(flat) <= _EVIDENCE_LEN:
        return flat
    return flat[:_EVIDENCE_LEN].rstrip() + "..."


def _profile_id_for_filing(filing: dict) -> str:
    """The format profile id a filing fills, resolved from the regime catalog by the
    filing's branch token (preferred, the stable key) or its regime label. "" when
    neither resolves (the filing names no known regime form)."""
    branch = str(filing.get("branch", "")).strip().lower()
    if branch and branch in _PROFILE_ID_INDEX:
        return _PROFILE_ID_INDEX[branch]
    regime = str(filing.get("regime", "")).strip().lower()
    if regime in _PROFILE_ID_INDEX:
        return _PROFILE_ID_INDEX[regime]
    # Last resort: a regime label that CONTAINS a known key (e.g. "uk ico" contains
    # "uk"). Match the longest key to avoid a short token grabbing the wrong form.
    for key in sorted(_PROFILE_ID_INDEX, key=len, reverse=True):
        if key and key in regime:
            return _PROFILE_ID_INDEX[key]
    return ""


def sheet_for_filing(filing: dict) -> CompletenessSheet | None:
    """The completeness sheet for one drafted filing, or None when the filing names
    no known regime form (so no mandated-field set exists to screen against).

    Pure derived: it resolves the FormatProfile from the catalog, reads the labelled
    sections from the filing prose, and marks each mandated field PRESENT / EMPTY. The
    filing is applicable by construction (it exists), so no field is NA here."""
    pid = _profile_id_for_filing(filing)
    if not pid:
        return None
    profile = format_profile_for(pid)
    prose = _filing_prose(filing)
    statuses: list[FieldStatus] = []
    for f in profile.fields:
        body = _field_body(prose, f.label)
        if body:
            statuses.append(FieldStatus(
                label=f.label, status=STATUS_PRESENT,
                evidence=_evidence_snippet(body)))
        else:
            statuses.append(FieldStatus(
                label=f.label, status=STATUS_EMPTY,
                evidence="mandated field absent or empty in the filing prose"))
    return CompletenessSheet(
        regime=str(filing.get("regime", "")) or profile.form_title,
        form_title=profile.form_title,
        cover_tag=profile.cover_tag,
        applicable=True,
        fields=tuple(statuses))


def na_sheet_for_profile(profile: FormatProfile, regime: str) -> CompletenessSheet:
    """A NOT-APPLICABLE sheet for a regime whose form applies in principle but for
    which no filing was made in this incident (e.g. a regime suppressed below its
    reporting threshold). Every mandated field is NA: the duty did not attach, so the
    form is not owed and nothing is expected to be filled."""
    statuses = tuple(
        FieldStatus(label=f.label, status=STATUS_NA,
                    evidence="no filing owed: the reporting duty did not attach")
        for f in profile.fields)
    return CompletenessSheet(
        regime=regime, form_title=profile.form_title, cover_tag=profile.cover_tag,
        applicable=False, fields=statuses)


def sheets_for_packet(packet: dict) -> list[CompletenessSheet]:
    """The per-regime completeness sheets for an assembled packet, in filing order.

    One sheet per drafted filing that names a known regime form. Pure derived over
    packet["filings"]: it reads the labelled sections from each filing's prose and
    marks every mandated field PRESENT / EMPTY against the form's exact mandated field
    labels. A filing naming no known form is skipped (no mandated-field set to screen
    against). No LLM, no now(); the same packet derives the byte-identical sheets."""
    sheets: list[CompletenessSheet] = []
    for filing in packet.get("filings", []):
        sheet = sheet_for_filing(filing)
        if sheet is not None:
            sheets.append(sheet)
    return sheets


def packet_complete(sheets: list[CompletenessSheet]) -> bool:
    """The overall intake verdict over the applicable sheets: True iff at least one
    regime is owed a filing and every owed (applicable) regime is COMPLETE. A run with
    no applicable filing is not 'complete' (nothing was screened)."""
    applicable = [s for s in sheets if s.applicable]
    if not applicable:
        return False
    return all(s.complete for s in applicable)


def completeness_record(packet: dict) -> dict:
    """The packet-ready completeness block: the per-regime sheets plus the overall
    intake verdict, JSON-serializable. Empty (None-equivalent) handling is the
    caller's: this returns {} when the packet carries no screenable filing so the
    renderer can omit the section cleanly."""
    sheets = sheets_for_packet(packet)
    if not sheets:
        return {}
    return {
        "sheets": [s.as_dict() for s in sheets],
        "all_complete": packet_complete(sheets),
        "regimes_screened": [s.regime for s in sheets],
    }
