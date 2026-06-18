"""Deterministic EDGAR-shaped Form 8-K Item 1.05 export plus Inline-XBRL tagging.

The Examiner Packet already carries the structured facts a Form 8-K Item 1.05
filing rests on: the canonical fact-record, the SEC drafter's typed [CLAIMS]
(records affected, incident start, attacker, containment), and the SEC statutory
clock (the materiality-determination anchor that is the Item 1.05 period of
report, and the four-business-day deadline). This module turns those facts into
two artifacts the SEC's own machine-readable intake expects:

  to_edgar_8k(packet) -> dict
      the real Form 8-K cover-page header (registrant name, jurisdiction of
      incorporation, commission file number, the date of the earliest event
      reported, the Item 1.05 heading) plus the four mandated Item 1.05 content
      elements (the material aspects of the nature, the scope, and the timing of
      the incident, and the material impact or reasonably likely material impact
      on the registrant). The body text is the SEC drafter's PROSE (the LLM wrote
      it); the STRUCTURE and the cover fields are deterministic from the facts.

  to_edgar_ixbrl(packet) -> str
      a well-formed Inline-XBRL (iXBRL) fragment that tags the Item 1.05 facts
      with the SEC's real Cybersecurity Disclosure (CYD) taxonomy concepts under
      the http://xbrl.sec.gov/cyd/2024 namespace: the material cybersecurity
      incident text block, the nature/scope/timing text block, and the material
      impact text block, dimensioned by the MaterialCybersecurityIncidentAxis with
      a custom member that identifies this incident, exactly as the CYD taxonomy
      guide specifies (more than one incident may be reported on a single 8-K, so
      each is a member on that axis).

Honesty posture (the same posture as the planned EDGAR / STIX exports): this is an
EDGAR-SHAPED export of the real fields and the real CYD concept names, NOT a filed
EDGAR submission. There is no fabricated EDGAR accession number; the filer fields
that are not in the fact-record are marked as a deployment placeholder rather than
invented. The CYD element names, the namespace, the iXBRL structure, and the Item
1.05 element set are real and verifiable against the SEC taxonomy guide.

Determinism: every value comes from the packet (CANONICAL_FACTS + the SEC claims +
the SEC clock row). There is NO LLM call and NO wall-clock read (no now()), so the
same packet renders byte-identical EDGAR + iXBRL every time. This is a render-time
DERIVED transform: it reads the packet, never the hashed run-log, and writes
nothing back into it, so the run-log sha, byte-identical replay, and every sealed
capture are untouched.

Sources for the CYD concept set:
  SEC Cybersecurity Disclosure (CYD) taxonomy, 2024 (xbrl.sec.gov/cyd/2024). The
  Item 1.05 incident concepts are Text Block concepts dimensioned by the
  MaterialCybersecurityIncidentAxis (a custom member identifies the incident,
  because more than one incident can be reported on a single 8-K). Form 8-K Item
  1.05 / 17 CFR 229.105 for the mandated content elements.
"""

from __future__ import annotations

import re
from xml.sax.saxutils import escape, quoteattr

from floor.formats import SEC_8K
from floor.grounding import strip_citations

# The fenced [CLAIMS] envelope the drafter appends below its prose. The EDGAR body
# is the human-readable filing, so the structured claims block is stripped out of
# it before tagging (the typed facts are read from packet.diff.final_claims, not
# re-parsed from the prose). Pure string removal; leaves the prose untouched.
_CLAIMS_BLOCK = re.compile(r"\n*\[CLAIMS\].*?\[/CLAIMS\]\s*", re.DOTALL)

# The real SEC CYD taxonomy namespace + the iXBRL / XBRL instance namespaces the
# fragment declares. These are the published, stable identifiers, not invented.
CYD_NAMESPACE = "http://xbrl.sec.gov/cyd/2024"
IX_NAMESPACE = "http://www.xbrl.org/2013/inlineXBRL"
XBRLI_NAMESPACE = "http://www.xbrl.org/2003/instance"
XBRLDI_NAMESPACE = "http://xbrl.org/2006/xbrldi"

# The real CYD concept (element) names used to tag a Form 8-K Item 1.05 material
# cybersecurity incident. Each is a Text Block concept; the dimensioning axis
# carries a custom member that identifies the incident.
CYD_INCIDENT_TEXT_BLOCK = "MaterialCybersecurityIncidentTextBlock"
CYD_NATURE_SCOPE_TIMING_TEXT_BLOCK = (
    "MaterialCybersecurityIncidentNatureScopeTimingTextBlock")
CYD_MATERIAL_IMPACT_TEXT_BLOCK = (
    "MaterialCybersecurityIncidentMaterialImpactOrReasonablyLikelyMaterialImpactTextBlock")
CYD_INCIDENT_AXIS = "MaterialCybersecurityIncidentAxis"

# The SEC clock's correlation id and human name, used to locate the SEC clock row
# in the packet so the period of report and the deadline come from the same
# deterministic clock math the rest of the packet renders.
_SEC_CORR_SUFFIX = ":sec"

# Honest placeholders for the EDGAR filer fields that are NOT in the incident
# fact-record. They are clearly marked, never invented, so the export stays
# truthful: a real deployment supplies the registrant's actual CIK / file number.
_FILER_PLACEHOLDER = "[to be supplied by filer at submission]"


class EdgarExportError(ValueError):
    """The packet does not carry the SEC facts an Item 1.05 export needs (no SEC
    claims, or no SEC clock row). Raised so a missing input surfaces structurally
    rather than producing a silently empty or malformed export."""


def _sec_clock_row(packet: dict) -> dict:
    """The SEC statutory clock row from the packet, located by its correlation-id
    suffix. Raises EdgarExportError if the SEC clock is absent (e.g. the SEC branch
    was suppressed and no 8-K is owed)."""
    for c in packet.get("clocks", []):
        if str(c.get("correlation_id", "")).endswith(_SEC_CORR_SUFFIX):
            return c
    raise EdgarExportError(
        "no SEC clock row in the packet; an EDGAR 8-K Item 1.05 export needs the "
        "SEC materiality-determination anchor and deadline")


def _sec_claims(packet: dict) -> dict:
    """The SEC branch's final reconciled claims from the packet diff block. Raises
    EdgarExportError if absent (the SEC branch never produced a filing)."""
    final = (packet.get("diff", {}) or {}).get("final_claims", {}) or {}
    claims = final.get("sec")
    if not claims:
        raise EdgarExportError(
            "no SEC claims in the packet diff.final_claims; an EDGAR 8-K Item 1.05 "
            "export needs the SEC drafter's typed claims")
    return claims


def _sec_filing_prose(packet: dict) -> str:
    """The SEC drafter's filing PROSE, citations stripped, from the packet filings
    list. Empty string if the SEC filing carried no prose (the structure still
    renders from the typed facts)."""
    for f in packet.get("filings", []):
        regime = str(f.get("regime", "")).strip().lower()
        branch = str(f.get("branch", "")).strip().lower()
        if regime == "sec" or branch == "sec":
            text = _CLAIMS_BLOCK.sub("", f.get("text", "") or "")
            return strip_citations(text).strip()
    return ""


def _event_date(sec_clock: dict) -> str:
    """The Form 8-K 'date of earliest event reported': the calendar date of the
    SEC materiality-determination anchor, which is when the Item 1.05 obligation
    attaches and the four-business-day clock starts. Derived from the clock's
    started instant (UTC date), so it is deterministic from the packet."""
    started = str(sec_clock.get("started", ""))
    # The started instant is an ISO-8601 UTC timestamp (e.g. 2026-06-16T02:31:...);
    # the EDGAR event date is its calendar date.
    return started[:10] if len(started) >= 10 else started


def _incident_member_local_name(incident_id: str) -> str:
    """A deterministic, schema-safe custom member local name identifying this
    incident on the MaterialCybersecurityIncidentAxis. The CYD taxonomy reports
    each incident as a custom member on that axis (more than one incident may be
    on a single 8-K). We derive it from the incident id so it is stable and
    traceable: 'inc-8842' -> 'Inc8842Member'."""
    token = re.sub(r"[^A-Za-z0-9]", "", str(incident_id))
    if not token:
        token = "Incident"
    if token[0].isdigit():
        token = "Incident" + token
    return token[:1].upper() + token[1:] + "Member"


def to_edgar_8k(packet: dict) -> dict:
    """Build the EDGAR-shaped Form 8-K Item 1.05 structure from the packet.

    Returns a dict with the real cover-page header fields, the Item 1.05 heading,
    and the four mandated content elements (nature, scope, timing, material
    impact). The body of each content element is the SEC drafter's prose (the LLM
    wrote it); the cover fields and the element labels are deterministic from the
    facts. Honest: filer fields not in the fact-record are marked as a deployment
    placeholder, and there is no fabricated EDGAR accession number.

    Pure and deterministic: every value is read from the packet, no LLM, no now().
    """
    incident = packet.get("incident", {}) or {}
    fact = incident.get("fact_record", {}) or {}
    incident_id = incident.get("incident_id", "") or fact.get("incident_id", "")
    sec_clock = _sec_clock_row(packet)
    claims = _sec_claims(packet)
    prose = _sec_filing_prose(packet)

    registrant = fact.get("regulated_entity", "") or _FILER_PLACEHOLDER
    event_date = _event_date(sec_clock)

    cover = {
        "Name of registrant as specified in its charter": registrant,
        "State or other jurisdiction of incorporation": _FILER_PLACEHOLDER,
        "Commission file number": _FILER_PLACEHOLDER,
        "Central Index Key (CIK)": _FILER_PLACEHOLDER,
        "Date of report (date of earliest event reported)": event_date,
    }

    # The four mandated Item 1.05 content elements, keyed by the real field labels
    # the tightened SEC_8K profile carries. The prose body is the drafter's text;
    # when no prose is present (a structure-only export) the element still appears
    # with an empty body so the mandated set is complete and checkable.
    elements = [{"label": f.label, "instruction": f.instruction, "body": prose}
                for f in SEC_8K.fields]

    return {
        "form_type": "8-K",
        "item": "1.05",
        "item_heading": SEC_8K.cover_tag,
        "form_title": SEC_8K.form_title,
        "period_of_report": event_date,
        "cover": cover,
        "cover_field_order": list(SEC_8K.cover_fields),
        "content_elements": elements,
        "facts": {
            "incident_id": incident_id,
            "incident_start_utc": claims.get("incident_start_utc", ""),
            "records_affected": claims.get("records_affected"),
            "attacker": claims.get("attacker", ""),
            "containment": claims.get("containment", ""),
            "materiality_determination_utc": sec_clock.get("started", ""),
            "statutory_deadline_utc": sec_clock.get("deadline", ""),
        },
        # Honesty: state plainly that this is an EDGAR-shaped export of the real
        # fields, not a filed submission. No accession number is invented.
        "edgar_accession_number": None,
        "export_note": (
            "EDGAR-shaped Form 8-K Item 1.05 export of the real mandated fields. "
            "This is not a filed EDGAR submission: no accession number is assigned "
            "and the filer-identifying fields marked as placeholders are supplied "
            "by the registrant at submission. The Item 1.05 content elements and "
            "the CYD/iXBRL tagging use the real SEC concept names."),
    }


def _ix_text(concept: str, context_ref: str, body: str) -> str:
    """One Inline-XBRL nonNumeric fact: the concept tagged against a context. The
    body is XML-escaped. Text Block concepts carry the escape="false" hint per the
    iXBRL spec for rich-text blocks; we emit plain escaped text so the fragment is
    well-formed and the tagged value round-trips."""
    return (
        f'<ix:nonNumeric name="cyd:{concept}" '
        f'contextRef={quoteattr(context_ref)}>'
        f'{escape(body)}'
        f'</ix:nonNumeric>')


def to_edgar_ixbrl(packet: dict) -> str:
    """Build a well-formed Inline-XBRL fragment tagging the Form 8-K Item 1.05
    facts with the real SEC CYD taxonomy concepts.

    The fragment declares the iXBRL, XBRL instance, XBRL dimensions, and CYD
    namespaces; defines a context dimensioned by the MaterialCybersecurityIncident
    axis with a custom member identifying this incident; and tags three Text Block
    concepts: the overall material-cybersecurity-incident block, the
    nature/scope/timing block, and the material-impact block. Every value is
    deterministic from the packet (no LLM, no now()), so the same packet renders a
    byte-identical fragment.

    The fragment is a self-contained, parseable XML element (it parses under
    xml.etree.ElementTree), which is what scripts/verify_edgar.py and the tests
    assert. A full iXBRL DOCUMENT embeds this inside the filing's XHTML <body>; the
    fragment is the tagging payload.
    """
    edgar = to_edgar_8k(packet)
    facts = edgar["facts"]
    incident_id = facts.get("incident_id", "") or "incident"
    member_local = _incident_member_local_name(incident_id)
    member_qname = f"cyd:{member_local}"
    context_id = "C-" + re.sub(r"[^A-Za-z0-9]", "-", str(incident_id)) or "C-incident"
    event_date = edgar["period_of_report"]

    # The three Item 1.05 content bodies the text blocks tag. The nature/scope/
    # timing block carries the three nature/scope/timing content elements; the
    # impact block carries the material-impact element; the overall incident block
    # carries the whole Item 1.05 prose. When prose is absent, a deterministic
    # fact-derived summary is tagged so the fragment is never empty.
    elements = {e["label"]: e["body"] for e in edgar["content_elements"]}
    nst_body = "\n\n".join(
        f"{label}: {elements.get(label, '')}".strip()
        for label in ("Nature of the incident", "Scope of the incident",
                      "Timing of the incident"))
    impact_label = "Material impact or reasonably likely material impact"
    impact_body = elements.get(impact_label, "")
    overall_body = (elements.get("Nature of the incident", "")
                    or _fact_summary(facts))
    if not nst_body.strip().endswith((":", "")) and not any(
            elements.get(lbl) for lbl in (
                "Nature of the incident", "Scope of the incident",
                "Timing of the incident")):
        nst_body = _fact_summary(facts)
    if not impact_body:
        impact_body = ("The registrant is assessing the material impact, or "
                       "reasonably likely material impact, of the incident on its "
                       "financial condition and results of operations.")

    lines = [
        f'<ix:header xmlns:ix={quoteattr(IX_NAMESPACE)} '
        f'xmlns:xbrli={quoteattr(XBRLI_NAMESPACE)} '
        f'xmlns:xbrldi={quoteattr(XBRLDI_NAMESPACE)} '
        f'xmlns:cyd={quoteattr(CYD_NAMESPACE)}>',
        '  <ix:references>',
        '    <link:schemaRef xmlns:link="http://www.xbrl.org/2003/linkbase" '
        'xmlns:xlink="http://www.w3.org/1999/xlink" xlink:type="simple" '
        'xlink:href="https://xbrl.sec.gov/cyd/2024/cyd-2024.xsd"/>',
        '  </ix:references>',
        '  <ix:resources>',
        f'    <xbrli:context id={quoteattr(context_id)}>',
        '      <xbrli:entity>',
        # The CIK is a filer-identifying field not in the incident fact-record. We
        # emit the EDGAR zero-CIK placeholder (0000000000) rather than invent one,
        # keeping the export honest; a real deployment supplies the registrant CIK.
        '        <xbrli:identifier scheme="http://www.sec.gov/CIK">'
        '0000000000</xbrli:identifier>',
        '        <xbrli:segment>',
        f'          <xbrldi:explicitMember dimension="cyd:{CYD_INCIDENT_AXIS}">'
        f'{escape(member_qname)}</xbrldi:explicitMember>',
        '        </xbrli:segment>',
        '      </xbrli:entity>',
        '      <xbrli:period>',
        f'        <xbrli:instant>{escape(event_date)}</xbrli:instant>',
        '      </xbrli:period>',
        '    </xbrli:context>',
        '  </ix:resources>',
        '</ix:header>',
    ]
    header = "\n".join(lines)

    body_facts = "\n".join([
        f'  {_ix_text(CYD_INCIDENT_TEXT_BLOCK, context_id, overall_body)}',
        f'  {_ix_text(CYD_NATURE_SCOPE_TIMING_TEXT_BLOCK, context_id, nst_body)}',
        f'  {_ix_text(CYD_MATERIAL_IMPACT_TEXT_BLOCK, context_id, impact_body)}',
    ])

    return (
        f'<ix:fragment xmlns:ix={quoteattr(IX_NAMESPACE)} '
        f'xmlns:cyd={quoteattr(CYD_NAMESPACE)} '
        f'form="8-K" item="1.05" period-of-report={quoteattr(event_date)}>\n'
        f'{header}\n'
        f'{body_facts}\n'
        f'</ix:fragment>')


def _fact_summary(facts: dict) -> str:
    """A deterministic one-line incident summary from the typed facts, used as the
    tagged body when the SEC filing carried no prose (a structure-only export).
    Pure string assembly from the packet facts."""
    records = facts.get("records_affected")
    records_txt = f"{records:,}" if isinstance(records, int) else str(records)
    return (
        f"A material cybersecurity incident affecting {records_txt} records, "
        f"beginning {facts.get('incident_start_utc', '')}, attributed to "
        f"{facts.get('attacker', '')}, was determined material on "
        f"{facts.get('materiality_determination_utc', '')}. Containment status: "
        f"{facts.get('containment', '')}.")
