"""End-to-end verifiable submission pipeline: export, stubbed validating endpoint, sealed receipt.

The Examiner Packet proves a CORRECT FILING was drafted, reconciled, and released.
It does not yet prove the filing was SUBMITTED and accepted. This module closes
that loop, honestly. After the two-key release, for each regime in scope:

  1. EXPORT a machine-readable submission artifact in the regulator's own shape.
     SEC reuses the EDGAR-shaped Form 8-K Item 1.05 export (floor/exports_edgar.py);
     the other regimes get a structured per-regime payload built from the EXACT
     mandated field labels in floor/formats.py plus the reconciled [CLAIMS] facts.
     The transform is a deterministic read of the packet: no LLM, no now().

  2. SUBMIT the artifact to an honestly-STUBBED regulator endpoint. `submit(payload,
     regime)` runs a DETERMINISTIC required-field completeness/contract validation
     (every mandated field must be present and non-empty: real validation, not
     theater) and returns a typed SubmissionReceipt, or a typed SubmissionRejection
     when a mandated field is missing.

  3. SEAL the receipt: the caller logs a `submission_receipt` run-log event so the
     filed receipt is hash-chained, replayed, and signed. The signature then attests
     the filed OUTCOME (this exact artifact was submitted and accepted with this
     receipt), not just the drafted filing.

HONESTY POSTURE (mandatory, stated on every receipt and rendered in the packet):
this is a MODELED submission channel, a local in-process stub. The submission
FORMAT and the field-contract VALIDATION are real; the network hop to the actual
regulator is modeled. The filing id is a "modeled accession-style id" derived
deterministically from the artifact bytes: it is clearly NOT a real EDGAR accession
number, and no government acknowledgement is fabricated. A production deployment
swaps StubRegulatorEndpoint for an authenticated EDGAR / CSIRT-portal / ICO
connector behind the SAME interface.

DETERMINISM (the sealed path has no nondeterminism): the artifact is canonicalized
to bytes with sorted keys and no whitespace; the artifact sha256 and the modeled
filing id are pure functions of those bytes; the accepted-at timestamp is a fixed
value the caller supplies (a derived run timestamp, never now()). So the same packet
submits to a byte-identical receipt every time, and replay over the submit beat's
run log is byte-identical.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from floor.exports_edgar import to_edgar_8k
from floor.formats import FormatProfile, format_profile_for
from floor.grounding import strip_citations

# The honest caveat that travels with every submission receipt and rejection. The
# format and the validation are real; the channel is modeled. The filing id is a
# modeled accession-style id, never a real EDGAR accession number.
MODELED_CHANNEL_CAVEAT = (
    "Modeled submission channel (local stub), not a live regulator endpoint. The "
    "submission FORMAT and the required-field contract validation are real; the "
    "network hop to the actual regulator is modeled. The filing id is a modeled "
    "accession-style id derived from the artifact bytes, not a real EDGAR accession "
    "number, and no government acknowledgement is fabricated."
)

# The typed submission status values. A receipt is ACCEPTED; a rejection is
# REJECTED. Kept as named constants so the packet and the verifier branch on the
# code, not a free string.
STATUS_ACCEPTED = "accepted"
STATUS_REJECTED = "rejected"

# The fenced [CLAIMS] envelope the drafter appends below its prose. The submission
# artifact is built from the typed facts and the labelled filing sections, so the
# Warden-owned claims block is stripped from the prose before the fields are read.
_CLAIMS_BLOCK = re.compile(r"\[CLAIMS\].*?\[/CLAIMS\]\s*", re.DOTALL)


class SubmissionError(ValueError):
    """A submission could not be built or submitted because a required input is
    absent (no filing for the regime, or no format profile). Raised so a missing
    input surfaces structurally rather than producing a silently empty submission."""


@dataclass(frozen=True)
class SubmissionReceipt:
    """The modeled regulator's filed receipt for one accepted submission.

    regime            the regime the artifact was filed under (e.g. "SEC").
    channel           the modeled channel id the artifact was submitted on.
    modeled_filing_id the modeled accession-style filing id, derived from the
                      artifact bytes. CLEARLY NOT a real EDGAR accession number.
    accepted_at       the accepted-at timestamp the caller supplied (a fixed,
                      derived run timestamp, never now()), so the receipt is
                      deterministic and the sealed event replays byte-identically.
    artifact_sha256   the sha256 of the canonical submission artifact bytes; a
                      verifier recomputes this from the artifact and confirms the
                      receipt attests THIS exact artifact.
    status            STATUS_ACCEPTED.
    validated_fields  the mandated field labels the contract validation confirmed
                      present and non-empty, in order.
    stub_endpoint     True: this is a modeled local stub, stated plainly.
    caveat            the honest modeled-channel caveat (MODELED_CHANNEL_CAVEAT).
    """
    regime: str
    channel: str
    modeled_filing_id: str
    accepted_at: str
    artifact_sha256: str
    status: str = STATUS_ACCEPTED
    validated_fields: tuple[str, ...] = ()
    stub_endpoint: bool = True
    caveat: str = MODELED_CHANNEL_CAVEAT

    @property
    def accepted(self) -> bool:
        return self.status == STATUS_ACCEPTED

    @property
    def stamp(self) -> str:
        """The one-line filed stamp a packet renders for an accepted submission."""
        return f"FILED (modeled): {self.modeled_filing_id}"

    def as_dict(self) -> dict:
        """A JSON-serializable view for the run-log event and the Examiner Packet.
        Stable key order so the sealed event and any replay guard see identical
        bytes."""
        return {
            "status": self.status,
            "regime": self.regime,
            "channel": self.channel,
            "modeled_filing_id": self.modeled_filing_id,
            "accepted_at": self.accepted_at,
            "artifact_sha256": self.artifact_sha256,
            "validated_fields": list(self.validated_fields),
            "stub_endpoint": self.stub_endpoint,
            "caveat": self.caveat,
        }


@dataclass(frozen=True)
class SubmissionRejection:
    """The modeled regulator's rejection for one submission that failed the
    required-field contract. No filing id is assigned: the artifact was not filed.

    regime           the regime the artifact would have been filed under.
    channel          the modeled channel the artifact was submitted on.
    missing_fields   the mandated field labels the contract validation found
                     missing or empty, in order. Non-empty by definition.
    status           STATUS_REJECTED.
    stub_endpoint    True: this is a modeled local stub, stated plainly.
    caveat           the honest modeled-channel caveat (MODELED_CHANNEL_CAVEAT).
    """
    regime: str
    channel: str
    missing_fields: tuple[str, ...]
    status: str = STATUS_REJECTED
    stub_endpoint: bool = True
    caveat: str = MODELED_CHANNEL_CAVEAT

    @property
    def accepted(self) -> bool:
        return False

    @property
    def stamp(self) -> str:
        n = len(self.missing_fields)
        plural = "" if n == 1 else "s"
        return f"REJECTED (modeled): {n} missing mandated field{plural}"

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "regime": self.regime,
            "channel": self.channel,
            "missing_fields": list(self.missing_fields),
            "stub_endpoint": self.stub_endpoint,
            "caveat": self.caveat,
        }


@dataclass(frozen=True)
class SubmissionArtifact:
    """A machine-readable submission artifact ready for the stubbed endpoint.

    regime      the regime the artifact is filed under.
    channel     the modeled channel id (e.g. "EDGAR-8K-modeled").
    form_title  the human form title (from the format profile).
    fields      ordered (label, body) pairs for every mandated field of the form.
                A body is "" when the filing left that mandated section empty; the
                endpoint's contract validation rejects on an empty mandated body.
    payload     the full structured submission object (header + fields + facts) the
                endpoint validates and the receipt's sha is taken over.

    The artifact canonicalizes to bytes deterministically (`canonical_bytes`):
    sorted keys, no whitespace, the same recipe the run log uses, so the artifact
    sha256 and the modeled filing id are byte-stable across runs."""
    regime: str
    channel: str
    form_title: str
    fields: tuple[tuple[str, str], ...]
    payload: dict = field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        """The canonical artifact bytes: the payload encoded with sorted keys and
        no whitespace (the run log's own canonicalization recipe). The artifact
        sha256 and the modeled filing id are pure functions of these bytes."""
        return json.dumps(
            self.payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def artifact_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def as_dict(self) -> dict:
        """A JSON-serializable view for the Examiner Packet."""
        return {
            "regime": self.regime,
            "channel": self.channel,
            "form_title": self.form_title,
            "fields": [{"label": label, "body": body} for label, body in self.fields],
            "payload": self.payload,
            "artifact_sha256": self.artifact_sha256(),
        }


# The modeled channel id per regime: a stable, clearly-modeled identifier so the
# receipt names the channel the artifact was submitted on without pretending to be
# a real portal. Regimes not listed fall back to a generic modeled channel id.
_CHANNEL_BY_REGIME = {
    "SEC": "EDGAR-8K-modeled",
    "NIS2": "NIS2-CSIRT-modeled",
    "ICO": "ICO-breach-portal-modeled",
}


def _channel_for(regime: str) -> str:
    return _CHANNEL_BY_REGIME.get(regime.upper(), f"{regime.lower()}-portal-modeled")


def _modeled_filing_id(regime: str, artifact_sha: str) -> str:
    """A deterministic modeled accession-style filing id, derived from the regime
    and the artifact sha256. Shaped to READ like an accession id (a dashed,
    segmented token) so a reader recognizes the slot, but explicitly prefixed
    MODELED- so no one mistakes it for a real EDGAR accession number. Pure function
    of the inputs: the same artifact always yields the same id, so the sealed
    receipt event replays byte-identically.

    Example: 'MODELED-SEC-1a2b3c4d5e6f'. A real EDGAR accession number has the
    form 0001234567-26-000123 and is issued only by EDGAR; this is not that, and
    the caveat says so."""
    token = artifact_sha[:12]
    return f"MODELED-{regime.upper()}-{token}"


def _filing_prose_for(packet: dict, regime: str, branch: str) -> str:
    """The drafter's filing PROSE for a regime, citations stripped and the [CLAIMS]
    block removed, from the packet filings list. Matched by the regime label OR the
    branch token (a recruited filing names its regime as e.g. "UK ICO" while its
    branch is "uk", so the branch is the stable key). Empty string when no filing
    matches (the structured fields still render from the typed facts)."""
    target_regime = regime.strip().lower()
    target_branch = branch.strip().lower()
    for f in packet.get("filings", []):
        f_regime = str(f.get("regime", "")).strip().lower()
        f_branch = str(f.get("branch", "")).strip().lower()
        # Match on the exact regime label, the branch token, or a regime label that
        # contains the branch / regime token (e.g. "uk ico" contains "ico" / "uk").
        if (f_regime == target_regime or f_branch == target_branch
                or (f_branch == "" and (target_regime in f_regime
                                        or target_branch in f_regime))):
            text = _CLAIMS_BLOCK.sub("", f.get("text", "") or "")
            return strip_citations(text).strip()
    return ""


def _field_body(prose: str, label: str) -> str:
    """The body the filing prose carries for one mandated field label, or "" when
    the field is absent or empty.

    The drafter writes each mandated field as its own labelled section: the exact
    field label followed by a colon, then the field prose up to the next blank line
    (the section boundary). Deterministic string work, matched case-insensitively
    on the label (a drafter may title-case a heading) with a genuinely non-empty
    body required. This mirrors the deficiency completeness screen so the export and
    the intake check read the labelled sections the same way."""
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


def _reconciled_facts(packet: dict, branch: str) -> dict:
    """The branch's final reconciled claims from the packet diff block, or {} when
    absent. These are the post-reconciliation, post-amendment facts the filing
    rests on, so the submission artifact carries the SAME values the contradiction
    diff agreed on."""
    final = (packet.get("diff", {}) or {}).get("final_claims", {}) or {}
    return final.get(branch, {}) or {}


def build_submission(packet: dict, regime: str, *, branch: str | None = None,
                     profile_id: str | None = None) -> SubmissionArtifact:
    """Build the machine-readable submission artifact for one regime from the packet.

    SEC reuses the EDGAR-shaped Form 8-K Item 1.05 export (floor/exports_edgar.py):
    the artifact payload IS the EDGAR object, and the mandated fields are its Item
    1.05 content elements. The other regimes get a structured payload keyed by the
    EXACT mandated field labels in floor/formats.py, each carrying the body the
    drafter wrote for that labelled section, plus a header (regime, channel, form
    title) and the reconciled typed facts.

    Pure and deterministic: every value is read from the packet (the filings prose,
    the reconciled claims, the format profile). No LLM, no now(). Raises
    SubmissionError when the regime has no filing or no format profile."""
    regime_u = regime.upper()
    branch = branch or regime.lower()
    channel = _channel_for(regime_u)

    if regime_u == "SEC":
        # The SEC artifact is the EDGAR-shaped Form 8-K Item 1.05 export reused
        # wholesale: the same structured object floor/exports_edgar.py produces. Its
        # content elements are the mandated Item 1.05 fields the endpoint validates.
        edgar = to_edgar_8k(packet)
        fields = tuple(
            (el["label"], (el.get("body") or "").strip())
            for el in edgar.get("content_elements", [])
        )
        payload = {
            "regime": regime_u,
            "channel": channel,
            "form_type": edgar.get("form_type", "8-K"),
            "item": edgar.get("item", "1.05"),
            "form_title": edgar.get("form_title", ""),
            "period_of_report": edgar.get("period_of_report", ""),
            "cover": edgar.get("cover", {}),
            "content_elements": [
                {"label": label, "body": body} for label, body in fields
            ],
            "facts": edgar.get("facts", {}),
        }
        return SubmissionArtifact(
            regime=regime_u, channel=channel,
            form_title=edgar.get("form_title", ""), fields=fields, payload=payload)

    # The non-SEC regimes: a structured payload keyed by the real mandated field
    # labels in floor/formats.py. The field body is the drafter's labelled section.
    pid = profile_id or _profile_id_for_regime(regime_u)
    if not pid:
        raise SubmissionError(
            f"no format profile known for regime {regime!r}; a structured "
            f"submission needs the per-regime mandated field labels")
    profile: FormatProfile = format_profile_for(pid)
    prose = _filing_prose_for(packet, regime, branch)
    fields = tuple((f.label, _field_body(prose, f.label)) for f in profile.fields)
    facts = _reconciled_facts(packet, branch)
    payload = {
        "regime": regime_u,
        "channel": channel,
        "form_title": profile.form_title,
        "cover_tag": profile.cover_tag,
        "fields": [{"label": label, "body": body} for label, body in fields],
        "facts": {
            "incident_start_utc": facts.get("incident_start_utc", ""),
            "records_affected": facts.get("records_affected"),
            "attacker": facts.get("attacker", ""),
            "containment": facts.get("containment", ""),
        },
    }
    return SubmissionArtifact(
        regime=regime_u, channel=channel, form_title=profile.form_title,
        fields=fields, payload=payload)


# Regime -> format profile id for the structured (non-SEC) submission payloads.
# Lifted to a small map here so build_submission resolves the labels for the
# in-scope regimes without a regimes.yaml round-trip.
_PROFILE_ID_BY_REGIME = {
    "NIS2": "nis2_full",
    "ICO": "ico_art33",
    "DORA": "dora",
    "NYDFS": "nydfs_50017",
}


def _profile_id_for_regime(regime: str) -> str:
    return _PROFILE_ID_BY_REGIME.get(regime.upper(), "")


class StubRegulatorEndpoint:
    """An honestly-stubbed regulator submission endpoint.

    It is a MODELED local channel, not a real government portal. What it does is
    REAL: it runs a deterministic required-field completeness/contract validation
    over the submission artifact (every mandated field must be present and
    non-empty) and returns a typed receipt or rejection. What is MODELED: the
    network hop to the actual regulator. The filing id it assigns is a modeled
    accession-style id derived from the artifact bytes, never a real accession
    number, and it fabricates no government acknowledgement.

    A production deployment swaps this class for an authenticated EDGAR /
    CSIRT-portal / ICO connector behind the SAME `submit(artifact, accepted_at)`
    interface. The contract validation stays; only the channel changes."""

    def submit(self, artifact: SubmissionArtifact, accepted_at: str
               ) -> SubmissionReceipt | SubmissionRejection:
        """Validate the artifact against the regime's required-field contract and
        return a typed receipt (accepted) or rejection (a mandated field is empty).

        `accepted_at` is the caller-supplied accepted-at timestamp: a fixed, derived
        run timestamp (never now()), so the receipt is deterministic and the sealed
        event replays byte-identically. The artifact sha256 and the modeled filing id
        are pure functions of the artifact bytes."""
        missing = tuple(label for label, body in artifact.fields if not body.strip())
        if missing:
            return SubmissionRejection(
                regime=artifact.regime, channel=artifact.channel,
                missing_fields=missing)
        artifact_sha = artifact.artifact_sha256()
        return SubmissionReceipt(
            regime=artifact.regime,
            channel=artifact.channel,
            modeled_filing_id=_modeled_filing_id(artifact.regime, artifact_sha),
            accepted_at=accepted_at,
            artifact_sha256=artifact_sha,
            validated_fields=tuple(label for label, _ in artifact.fields),
        )


def submit(artifact: SubmissionArtifact, regime: str, accepted_at: str,
           endpoint: StubRegulatorEndpoint | None = None
           ) -> SubmissionReceipt | SubmissionRejection:
    """Submit one artifact to the (default stub) regulator endpoint and return the
    typed receipt or rejection.

    The endpoint runs the deterministic required-field contract validation; a
    complete artifact yields a SubmissionReceipt whose artifact_sha256 matches the
    artifact and whose modeled_filing_id is derived from those bytes, an incomplete
    artifact yields a SubmissionRejection naming the empty mandated fields. The
    `regime` argument is validated against the artifact so a caller cannot submit an
    artifact under the wrong regime label.

    `endpoint` lets a production deployment inject a real channel adapter behind the
    same interface; the default is the honest local stub."""
    if artifact.regime.upper() != regime.upper():
        raise SubmissionError(
            f"regime mismatch: artifact is {artifact.regime!r}, submit asked for "
            f"{regime!r}")
    endpoint = endpoint or StubRegulatorEndpoint()
    return endpoint.submit(artifact, accepted_at)


def verify_receipt(receipt: dict, artifact: dict) -> tuple[bool, str]:
    """Independently verify a sealed submission receipt against its artifact.

    Recomputes the artifact sha256 from the artifact's canonical bytes and confirms
    it matches the receipt's `artifact_sha256` (the receipt attests THIS exact
    artifact), confirms the receipt was ACCEPTED, and confirms the modeled filing id
    is derived from those same bytes (so the id cannot be swapped for another
    artifact's). Returns (ok, detail) where detail names the locus on failure.

    This is the check scripts/verify_submission.py runs; it reads the receipt and
    the artifact dicts as they were sealed, recomputes the sha from the artifact
    payload, and never trusts the recorded sha."""
    if receipt.get("status") != STATUS_ACCEPTED:
        return False, f"receipt status is {receipt.get('status')!r}, not accepted"
    payload = artifact.get("payload")
    if not isinstance(payload, dict):
        return False, "artifact carries no payload to recompute the sha over"
    recomputed = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    recorded = receipt.get("artifact_sha256", "")
    if recomputed != recorded:
        return False, (
            f"artifact sha mismatch: recomputed {recomputed[:16]} != receipt "
            f"{str(recorded)[:16]} (the receipt does not attest this artifact)")
    regime = receipt.get("regime", "")
    expected_id = _modeled_filing_id(regime, recomputed)
    if receipt.get("modeled_filing_id") != expected_id:
        return False, (
            f"modeled filing id {receipt.get('modeled_filing_id')!r} is not derived "
            f"from this artifact (expected {expected_id!r})")
    # The count of validated fields: the receipt's validated_fields when present
    # (the packet-rendered receipt carries it), else the artifact's mandated fields
    # (the sealed log receipt omits it, so fall back to the artifact the contract ran
    # over). Either way it is the number of mandated fields the contract validated.
    validated = receipt.get("validated_fields")
    field_count = len(validated) if validated else len(artifact.get("fields") or [])
    return True, (
        f"artifact sha {recomputed[:16]} matches the receipt; {field_count} "
        f"mandated field(s) validated; modeled filing id {expected_id} derived from "
        f"the artifact bytes")
