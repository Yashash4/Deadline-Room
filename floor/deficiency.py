"""Modeled regulator intake review: the deficiency / rejection loop.

A real filing does not vanish into the regulator the moment it is released.
An intake desk RECEIVES it and runs a completeness screen: every mandated field
the form requires must be present and non-empty. If one is missing the desk does
not silently drop the filing, it issues a DEFICIENCY NOTICE naming the defective
field, and the filer must cure it (re-draft the missing element, re-file) before
the desk re-checks and accepts. This module models that intake review.

What is modeled, and what is honest about it:

  The review here is a DETERMINISTIC FIELD-COMPLETENESS SCREEN, exactly the
  automated intake completeness check a real desk runs first (EDGAR's automated
  8-K intake, the ICO and NIS2 CSIRT structured portals, the NYDFS intake). It
  walks the EXACT mandated field labels already defined per regime in
  floor/formats.py (FormatProfile.fields) and confirms each labelled section is
  present and non-empty in the filing prose. No LLM decides deficiency: a field
  is deficient iff its mandated label is absent from the prose or carries no
  content. That is a typed rule over text, not a judgment.

  The regulator is an HONEST STUB. It is a MODELED intake desk, not a real
  government endpoint. It assigns NO accession number, NO receipt number, and NO
  fabricated government acknowledgement: a real submission receipt is something
  only the actual authority issues, and inventing one would be dishonest. The
  ACCEPTED verdict means "this filing passes the modeled intake completeness
  screen", stated as exactly that. The MODELED_CAVEAT below says so on every
  verdict the packet renders.

Where this sits relative to the Warden: OUTSIDE the deterministic trust core.
The Warden's gate (warden/state_machine.py) is the FILER's referee; this review
is the EXAMINER's verdict on the released artifact. The review never gates a
Warden transition, never enters the hashed run-log, and never clocks or counts
anything inside the core. It is a pure read over filing text. The CURE rides the
existing FACT_AMENDED reopen seam in floor/run_floor.py: on a deficiency the
Warden reopens the branch (released -> amending), the drafter re-drafts the cited
element, re-files (amending -> draft_submitted -> ... -> released), and this
review re-runs over the cured filing and ACCEPTS. The Warden gate that drives the
reopen and the re-release stays deterministic and makes zero LLM calls; only the
drafter's re-draft prose is the model's.
"""

from __future__ import annotations

from dataclasses import dataclass

from floor.formats import FormatProfile
from floor.grounding import strip_citations

# The honest caveat that rides every verdict. The modeled regulator is an intake
# completeness screen, not a real government endpoint: it never invents a receipt.
MODELED_CAVEAT = (
    "Modeled regulator intake completeness screen, not a real government "
    "endpoint. ACCEPTED means the filing passes the per-regime mandated-field "
    "completeness check; no accession or receipt number is assigned (only the "
    "actual authority issues one)."
)

# Deficiency severity. A missing mandated field is a hard intake defect: the
# automated screen rejects the filing back to the filer for a corrected
# resubmission. There is one severity today (the completeness screen is binary
# per field); it is typed so a future check that warns without rejecting has a
# place to land without changing this one's meaning.
SEVERITY_REJECT = "reject"

# The single deficiency code this completeness screen raises: a mandated field is
# missing or empty in the filing prose. Typed so the notice reads like a real
# intake rejection ("MISSING_MANDATORY_FIELD") and so a reader can branch on the
# code rather than parse the human reason string.
CODE_MISSING_FIELD = "MISSING_MANDATORY_FIELD"


@dataclass(frozen=True)
class Deficiency:
    """One typed defect the modeled regulator found at intake: a mandated field
    that the form requires is missing or empty in the filing prose.

    code            the typed defect class (CODE_MISSING_FIELD).
    regime          the regime whose form the filing fills (e.g. "SEC").
    deficient_field the exact mandated field label from the form (formats.py).
    severity        SEVERITY_REJECT: the screen rejects the filing for a cure.
    reason          the human-readable rejection sentence, the way a real notice
                    reads ("Item 1.05 mandates the Timing of the incident field;
                    it is absent from the filing.")."""
    code: str
    regime: str
    deficient_field: str
    severity: str
    reason: str

    def human(self) -> str:
        return f"[{self.code}] {self.regime}: {self.deficient_field}: {self.reason}"


@dataclass(frozen=True)
class RegulatorVerdict:
    """The modeled regulator's intake verdict on one released filing.

    accepted        True iff every mandated field is present and non-empty.
    regime          the regime the filing was filed under.
    form_title      the form the completeness screen checked against.
    deficiencies    the typed defects found; empty iff accepted.
    caveat          the honest modeled-stub caveat (MODELED_CAVEAT).
    """
    accepted: bool
    regime: str
    form_title: str
    deficiencies: tuple[Deficiency, ...]
    caveat: str = MODELED_CAVEAT

    @property
    def stamp(self) -> str:
        """The one-line intake stamp a packet renders: ACCEPTED FOR FILING when
        the screen passes, or DEFICIENCY NOTICE with the count when it does not."""
        if self.accepted:
            return "ACCEPTED FOR FILING"
        n = len(self.deficiencies)
        plural = "" if n == 1 else "s"
        return f"DEFICIENCY NOTICE ({n} defect{plural})"

    def as_dict(self) -> dict:
        """A JSON-serializable view for the Examiner Packet. Stable key order so
        the packet render and any replay guard see identical bytes."""
        return {
            "accepted": self.accepted,
            "regime": self.regime,
            "form_title": self.form_title,
            "stamp": self.stamp,
            "deficiencies": [
                {"code": d.code, "regime": d.regime,
                 "deficient_field": d.deficient_field,
                 "severity": d.severity, "reason": d.reason}
                for d in self.deficiencies
            ],
            "caveat": self.caveat,
        }


def _field_present(prose: str, label: str) -> bool:
    """True iff the mandated field `label` appears as a labelled section in the
    prose AND carries non-empty content.

    The drafter writes each mandated field as its own labelled section: the exact
    field label followed by a colon, then the prose for that field (the contract
    in floor/formats.prompt_for). So a field is PRESENT iff its label, followed by
    a colon, occurs in the prose with at least one non-whitespace character after
    the colon and before the next line that is empty or the [CLAIMS] block.

    Deterministic string work only: same (prose, label) always yields the same
    answer. No LLM, no fuzzy match. The label is matched case-insensitively (a
    drafter may title-case a heading) but the body must be genuinely non-empty.
    """
    needle = label.lower() + ":"
    haystack = prose.lower()
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx == -1:
            return False
        after = prose[idx + len(needle):]
        # The content for this field is everything up to a blank line (the section
        # boundary the drafter writes between labelled sections). If anything
        # non-whitespace sits there, the field is present and filled.
        body = after.split("\n\n", 1)[0]
        if body.strip():
            return True
        start = idx + len(needle)


def review(profile: FormatProfile, filing_text: str, regime: str) -> RegulatorVerdict:
    """Run the modeled regulator intake completeness screen over one filing.

    Deterministic and pure: it walks the profile's mandated field labels in order
    and returns a typed DeficiencyNotice (a RegulatorVerdict carrying one or more
    Deficiency rows) when any mandated field is missing or empty, or an ACCEPTED
    verdict when every mandated field is present and filled. No LLM decides the
    verdict; it is a field-completeness rule over the filing prose.

    The prose checked is the human filing text with field citations stripped and
    the [CLAIMS] block (the Warden-owned deterministic envelope, not part of the
    examiner's form) removed, so the screen reads exactly the labelled sections an
    intake desk reads.
    """
    prose = strip_citations(filing_text or "")
    cut = prose.rfind("[CLAIMS]")
    if cut != -1:
        prose = prose[:cut]

    deficiencies: list[Deficiency] = []
    for f in profile.fields:
        if not _field_present(prose, f.label):
            deficiencies.append(Deficiency(
                code=CODE_MISSING_FIELD,
                regime=regime,
                deficient_field=f.label,
                severity=SEVERITY_REJECT,
                reason=(
                    f"{profile.cover_tag} mandates the \"{f.label}\" field; it "
                    f"is absent or empty in the filing. {f.instruction}"),
            ))

    return RegulatorVerdict(
        accepted=not deficiencies,
        regime=regime,
        form_title=profile.form_title,
        deficiencies=tuple(deficiencies),
    )
