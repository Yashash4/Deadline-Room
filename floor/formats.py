"""Real per-regime filing field skeletons.

The drafter no longer gets a generic "keep the structure a regulator expects"
instruction. Each regime carries a FORMAT PROFILE drawn from the actual form: the
real labelled fields an examiner expects to see. The LLM writes prose INTO those
labelled slots; it does not invent the structure. The result reads examiner-
authored when a judge pauses the frame.

This is deterministic template text. It changes only the human-readable filing
prose. The structured [CLAIMS] block the Warden parses (floor/claims.py) is
unchanged and untouched here, so the contradiction diff and every deterministic
gate are unaffected. The Warden still makes zero LLM calls.

Each profile is a FormatProfile: a form title + cover tag, and an ordered list of
mandated fields with a short instruction telling the drafter what belongs in each
slot. `format_profile_for(profile_id)` resolves the id carried by a regime in
floor/regimes.yaml. `render_skeleton(profile)` produces the labelled field
heading list the drafter fills, and `prompt_for(profile)` produces the field
instructions injected into the drafter's system prompt.

Sources for the field sets:
  SEC 8-K Item 1.05: the four mandated content elements (material aspects of the
    nature, scope, and timing of the incident; the material impact or reasonably
    likely material impact, including on financial condition and results of
    operations) under the Item 1.05 cover tag.
  NIS2 Article 23(4): the early-warning fields (suspected unlawful/malicious act
    flag, possible cross-border impact flag) and the 72h notification fields
    (initial severity and impact assessment, indicators of compromise).
  DORA Article 19 + RTS: the major-incident notification fields keyed to the
    classification criteria (clients/counterparts affected, duration/downtime,
    geographical spread, data losses, economic impact, criticality of services).
  UK GDPR Article 33(3): nature of the breach; categories and approximate number
    of data subjects and records; likely consequences; measures taken or proposed.
  NYDFS 23 NYCRR 500.17(a)(1): the electronic notice fields (covered entity,
    nature of the cybersecurity event, determination time, systems affected).
  GDPR Article 34(2): the communication TO THE DATA SUBJECT (the affected
    individuals, not the regulator) when the breach is likely to result in a high
    risk. Art 34(2) requires the communication to describe in clear and plain
    language the nature of the breach and to carry at least the same information
    Art 33(3)(b)-(d) requires: the contact point, the likely consequences, and the
    measures taken or proposed (including measures the individual can take to
    protect themselves).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FormatField:
    """One mandated field in a regulator's form: a labelled slot plus the short
    instruction telling the drafter what prose belongs in it."""
    label: str
    instruction: str


@dataclass(frozen=True)
class FormatProfile:
    """A real per-regime filing skeleton: a form title, an optional cover tag
    (e.g. the EDGAR Item 1.05 tag), and the ordered mandated fields.

    cover_fields is the OPTIONAL ordered list of the EDGAR cover-page header
    labels a form carries above its item body (registrant name, the commission
    file number, the 8-K event date, the item heading). It is empty for the
    regimes that do not have an EDGAR-style cover page; only the SEC 8-K profile
    populates it, so the deterministic EDGAR export (floor/exports_edgar.py) can
    render the real Form 8-K cover skeleton. It is render/export-time metadata: it
    never enters the hashed run-log, the [CLAIMS] block, or any deterministic
    gate, so byte-identical replay and every sealed sha are untouched."""
    profile_id: str
    form_title: str
    cover_tag: str
    fields: tuple[FormatField, ...]
    cover_fields: tuple[str, ...] = ()


# The real EDGAR Form 8-K cover-page header labels, in the order they appear at
# the top of the form above Item 1.05. These are the registrant-identifying
# fields an examiner reads first on every 8-K. They drive the deterministic
# EDGAR-shaped export's cover block (floor/exports_edgar.py); the prose drafter
# never sees them (the LLM fills the four mandated content elements below).
SEC_8K_COVER_FIELDS = (
    "Name of registrant as specified in its charter",
    "State or other jurisdiction of incorporation",
    "Commission file number",
    "Date of report (date of earliest event reported)",
    "Item 1.05 Material Cybersecurity Incidents",
)

SEC_8K = FormatProfile(
    profile_id="sec_8k",
    form_title="Form 8-K, Item 1.05 Material Cybersecurity Incidents",
    cover_tag="Item 1.05 Material Cybersecurity Incidents",
    # The four mandated Item 1.05 content elements, in the order the rule states
    # them: the registrant must describe the material aspects of the nature, the
    # scope, and the timing of the incident, and the material impact or reasonably
    # likely material impact on the registrant (including on its financial
    # condition and results of operations). 17 CFR 229.105 / Form 8-K Item 1.05.
    fields=(
        FormatField(
            "Nature of the incident",
            "State the material aspects of the NATURE of the cybersecurity "
            "incident from the fact-record (what occurred, the threat actor, the "
            "systems and data categories involved)."),
        FormatField(
            "Scope of the incident",
            "State the material aspects of the SCOPE of the incident from the "
            "fact-record (the number of records affected and the breadth across "
            "systems). Do not speculate beyond the fact-record."),
        FormatField(
            "Timing of the incident",
            "State the material aspects of the TIMING of the incident from the "
            "fact-record (when it began, when it was discovered, and the current "
            "containment status as of a stated time)."),
        FormatField(
            "Material impact or reasonably likely material impact",
            "State the material impact, or reasonably likely material impact, on "
            "the registrant, including on financial condition and results of "
            "operations. Do not speculate beyond the fact-record."),
    ),
    cover_fields=SEC_8K_COVER_FIELDS,
)

NIS2_EARLY = FormatProfile(
    profile_id="nis2_early",
    form_title="NIS2 Article 23 early warning",
    cover_tag="Article 23(4)(a) early warning",
    fields=(
        FormatField(
            "Suspected unlawful or malicious act",
            "State whether the significant incident is suspected to be caused by "
            "unlawful or malicious acts (yes/no with a one-line basis)."),
        FormatField(
            "Possible cross-border impact",
            "State whether the incident could have a cross-border impact "
            "(yes/no with the affected jurisdictions if any)."),
        FormatField(
            "Initial description",
            "Give a brief initial description of the significant incident from the "
            "fact-record, sufficient for the early warning."),
    ),
)

NIS2_FULL = FormatProfile(
    profile_id="nis2_full",
    form_title="NIS2 Article 23 incident notification",
    cover_tag="Article 23(4)(b) incident notification",
    fields=(
        FormatField(
            "Initial severity and impact assessment",
            "Give the initial assessment of the significant incident, including "
            "its severity and impact, from the fact-record."),
        FormatField(
            "Indicators of compromise",
            "List the indicators of compromise known so far (attacker, affected "
            "systems) from the fact-record."),
        FormatField(
            "Suspected unlawful or malicious act and cross-border impact",
            "Confirm the suspected-malicious and possible-cross-border findings "
            "carried from the early warning."),
    ),
)

DORA = FormatProfile(
    profile_id="dora",
    form_title="DORA Article 19 major ICT-related incident report",
    cover_tag="Major incident notification (Article 19, RTS classification)",
    fields=(
        FormatField(
            "Clients, financial counterparts, and transactions affected",
            "State the number and type of clients or financial counterparts "
            "affected, with affected-record counts from the fact-record."),
        FormatField(
            "Duration and service downtime",
            "State the incident duration and any service downtime from the "
            "fact-record."),
        FormatField(
            "Geographical spread and critical services affected",
            "State the geographical spread and which critical or important "
            "functions were affected (e.g. core banking ledger)."),
        FormatField(
            "Data losses and economic impact",
            "State any data losses and the economic impact, confined to what the "
            "fact-record supports."),
    ),
)

ICO_ART33 = FormatProfile(
    profile_id="ico_art33",
    form_title="UK GDPR Article 33 personal data breach notification to the ICO",
    cover_tag="Article 33(3) personal data breach notification",
    fields=(
        FormatField(
            "Nature of the breach",
            "Describe the nature of the personal data breach from the "
            "fact-record."),
        FormatField(
            "Categories and approximate number of data subjects and records",
            "State the categories and approximate number of data subjects "
            "concerned and of personal data records concerned."),
        FormatField(
            "Likely consequences",
            "Describe the likely consequences of the personal data breach."),
        FormatField(
            "Measures taken or proposed",
            "Describe the measures taken or proposed to address the breach and "
            "mitigate its possible adverse effects."),
    ),
)

NYDFS_50017 = FormatProfile(
    profile_id="nydfs_50017",
    form_title="NYDFS 23 NYCRR 500.17(a) notice of a cybersecurity event",
    cover_tag="Section 500.17(a)(1) notice to the superintendent",
    fields=(
        FormatField(
            "Covered entity and reporting basis",
            "Identify the covered entity and the reporting basis under "
            "500.17(a)(1)."),
        FormatField(
            "Nature of the cybersecurity event",
            "Describe the nature of the cybersecurity event from the "
            "fact-record."),
        FormatField(
            "Systems and information affected",
            "State the systems and categories of information affected."),
        FormatField(
            "Determination and notification timing",
            "State when the covered entity determined a reportable event occurred "
            "and that notice is given within 72 hours of that determination."),
    ),
)

GDPR_ART34 = FormatProfile(
    profile_id="gdpr_art34",
    form_title="GDPR Article 34 communication of a personal data breach to the data subject",
    cover_tag="Article 34(2) communication to the data subject",
    fields=(
        FormatField(
            "Nature of the breach in clear and plain language",
            "Describe, in clear and plain language addressed to the affected "
            "individual, the nature of the personal data breach from the "
            "fact-record."),
        FormatField(
            "Contact point for more information",
            "State the name and contact details of the data protection officer or "
            "other contact point where the individual can obtain more information."),
        FormatField(
            "Likely consequences for the individual",
            "Describe the likely consequences of the personal data breach for the "
            "affected individual, confined to what the fact-record supports."),
        FormatField(
            "Measures taken and steps the individual can take",
            "Describe the measures taken or proposed to address the breach and "
            "mitigate its adverse effects, and the steps the individual can take to "
            "protect themselves."),
    ),
)

_PROFILES = {
    p.profile_id: p
    for p in (SEC_8K, NIS2_EARLY, NIS2_FULL, DORA, ICO_ART33, NYDFS_50017,
              GDPR_ART34)
}


def format_profile_for(profile_id: str) -> FormatProfile:
    """Resolve the format profile a regime names in floor/regimes.yaml. Raises on
    an unknown id so a catalog typo surfaces structurally."""
    try:
        return _PROFILES[profile_id]
    except KeyError as e:
        raise KeyError(f"unknown format profile: {profile_id!r}") from e


def render_skeleton(profile: FormatProfile) -> str:
    """The labelled field headings of a profile, as the empty skeleton an examiner
    expects, for reference and tests."""
    lines = [f"{profile.form_title}", f"Cover: {profile.cover_tag}", ""]
    for i, f in enumerate(profile.fields, 1):
        lines.append(f"{i}. {f.label}:")
    return "\n".join(lines)


def prompt_for(profile: FormatProfile) -> str:
    """The field-by-field instruction block injected into a drafter's prompt so
    the model writes prose INTO the real labelled slots, in order, under the form
    title and cover tag. Deterministic text; the model fills the slots."""
    lines = [
        f"Structure the filing as a {profile.form_title}.",
        f"Open with the cover tag line: {profile.cover_tag}.",
        "Then write each of the following mandated fields as its own short "
        "labelled section, using the exact field label followed by a colon, in "
        "this order:",
    ]
    for i, f in enumerate(profile.fields, 1):
        lines.append(f"  {i}. {f.label}: {f.instruction}")
    return "\n".join(lines)
