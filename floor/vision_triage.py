"""Vision triage of a breach screenshot (E5.7 part 3).

A production gateway can point a VISION model at the first artifact of an
incident, a screenshot of a ransom note, a SIEM alert panel, a defacement, and
extract a first-pass set of breach facts to seed the war room. This module does
exactly that, and then holds the model's output to the SAME deterministic bars
every other LLM output on the floor must clear.

Three hard properties, because vision output is the least trustworthy input we
take:

  1. ADVISORY ONLY. The extracted fields NEVER gate, clock, release, or enter the
     canonical fact-record or the hashed [CLAIMS]. They are a triage suggestion a
     human (or a later deterministic step) confirms. Nothing here moves a
     transition.

  2. GATED by a deterministic validator BEFORE it is shown. The model emits a
     fenced [VISION] block of typed key=value lines; a pure validator parses it,
     type-checks each field, and rejects a malformed or out-of-schema extraction.
     A field that does not pass the validator is dropped, never surfaced as a fact.

  3. CLEARED by the grounding scorer BEFORE [CLAIMS]. The validated extraction is
     rendered as advisory prose and scored by floor.grounding.score_filing against
     the canonical fact-record. An extracted value that disagrees with the record
     (a hallucinated record count, a wrong date) is flagged as UNGROUNDED and the
     triage is marked NOT cleared, so a vision hallucination is caught loudly
     before it can seed anything.

The live vision call is NEVER on the default or test path. Live providers are
unreliable (the Band room cap, the held Featherless slot, the flaky AI/ML
gateway), so triage_from_cache() reads a COMMITTED cached response honestly
labeled source=live|illustrative, exactly like the E5.2 caches. A live call is
available via triage_live() for an operator who has a key and accepts the
latency, but no default path and no test ever blocks on it.

Out-of-log by construction: the triage result rides the trace like
recovered_retries and never enters the hashed run-log, and vision triage is only
run when a caller asks for it, so the offline suite and replay stay
byte-identical.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path

from floor import grounding
from floor.drafter import DEFAULT_PROVIDER, llm_complete, sanitize_llm_text

# The fence the vision extraction is wrapped in. It is NOT a Warden control
# envelope: it carries no gated value and never feeds the diff, a clock, or a
# release. It is deliberately not a [CLAIMS]/[RECONCILE]/[CHALLENGE]/[MATERIALITY]
# fence, so the drafter sanitizer leaves it intact while still defanging any real
# control fence a model emits.
VISION_OPEN = "[VISION]"
VISION_CLOSE = "[/VISION]"

# The advisory fields the triage is allowed to extract, and the type each must
# parse to. Anything outside this schema is dropped by the validator: the model
# cannot widen the advisory surface, only fill these slots.
#   records_affected -> int (the count a screenshot might show)
#   incident_date    -> an ISO yyyy-mm-dd date string
#   attacker         -> a short free-text actor name
#   regulated_entity -> a short free-text entity name
_VISION_SCHEMA = ("records_affected", "incident_date", "attacker", "regulated_entity")

# The fixture image and its committed cached response live beside the code so the
# default and test paths are keyless and never block on a live vision call.
_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
FIXTURE_IMAGE = _FIXTURE_DIR / "vision_breach_screenshot.png"
CACHE_FILE = _FIXTURE_DIR / "vision_triage_cache.json"

# A default vision-capable model for the optional live path. The cached path needs
# no model. Kept as a named id so an operator can override it.
DEFAULT_VISION_MODEL = "gemini-3.5-flash"


class VisionTriageError(RuntimeError):
    pass


@dataclass
class VisionExtraction:
    """The validated, advisory extraction from a breach screenshot. Every field is
    a suggestion, never a canonical fact."""
    fields: dict = field(default_factory=dict)      # only validator-passing fields
    rejected: list[str] = field(default_factory=list)  # raw lines the validator dropped
    source: str = ""                                # "live" | "illustrative"
    model: str = ""

    def as_advisory_prose(self) -> str:
        """Render the validated extraction as advisory prose the grounding scorer
        can score against the fact-record. Plain ASCII, no control fence, no
        [CLAIMS] block: it is deliberately scoreable as prose only."""
        if not self.fields:
            return "Vision triage extracted no advisory fields from the screenshot."
        bits = []
        if "records_affected" in self.fields:
            bits.append(f"approximately {self.fields['records_affected']} records affected")
        if "incident_date" in self.fields:
            bits.append(f"incident date {self.fields['incident_date']}")
        if "attacker" in self.fields:
            bits.append(f"the named actor is {self.fields['attacker']}")
        if "regulated_entity" in self.fields:
            bits.append(f"the regulated entity is {self.fields['regulated_entity']}")
        return ("Advisory vision triage of the breach screenshot suggests "
                + ", ".join(bits) + ".")


@dataclass
class VisionTriageResult:
    """The full triage outcome: the validated extraction, the grounding score of
    its advisory prose against the canonical fact-record, and whether it CLEARED
    (validator passed AND the grounding scorer flagged nothing). cleared == False
    means a human must look before any extracted value is trusted."""
    extraction: VisionExtraction
    grounding: grounding.GroundingResult
    cleared: bool

    def as_dict(self) -> dict:
        """The out-of-log record for the packet. Read at packet time, never written
        into the hashed run-log JSONL."""
        return {
            "source": self.extraction.source,
            "model": self.extraction.model,
            "advisory": True,
            "cleared": self.cleared,
            "fields": dict(self.extraction.fields),
            "rejected_lines": list(self.extraction.rejected),
            "grounding": self.grounding.as_dict(),
            "advisory_prose": self.extraction.as_advisory_prose(),
        }


def _coerce(field_name: str, raw: str):
    """Type-coerce one raw extracted value to the schema type, or raise ValueError
    so the validator drops the line. Pure: no network, no clock."""
    value = raw.strip()
    if not value:
        raise ValueError("empty value")
    if field_name == "records_affected":
        cleaned = value.replace(",", "").replace(".", "")
        if not cleaned.isdigit():
            raise ValueError(f"records_affected not an integer: {raw!r}")
        return int(cleaned)
    if field_name == "incident_date":
        parts = grounding._date_parts(value)  # reuse the ISO date parser
        if parts is None:
            raise ValueError(f"incident_date not an ISO date: {raw!r}")
        y, mo, d = parts[0], parts[1], parts[2]
        return f"{y:04d}-{mo:02d}-{d:02d}"
    # attacker / regulated_entity: short free text, capped so a model cannot smuggle
    # a paragraph (or an injected instruction) into an advisory field.
    if len(value) > 80:
        raise ValueError(f"{field_name} too long")
    return value


def validate_extraction(raw_block: str) -> tuple[dict, list[str]]:
    """Deterministically validate a raw [VISION] block body into (fields, rejected).

    Parses one key=value per line, keeps only keys in the schema whose value
    type-coerces cleanly, and returns the kept fields plus the raw lines it
    dropped. Pure and deterministic; same input always yields the same output. A
    line with an unknown key, a bad type, or an out-of-range value is REJECTED, so
    a malformed extraction can never be surfaced as a fact. On a duplicate key the
    last valid line wins."""
    fields: dict = {}
    rejected: list[str] = []
    for raw in raw_block.splitlines():
        line = raw.strip()
        if not line:
            continue
        key, sep, value = line.partition("=")
        key = key.strip().lower()
        if not sep or key not in _VISION_SCHEMA:
            rejected.append(line)
            continue
        try:
            fields[key] = _coerce(key, value)
        except ValueError:
            rejected.append(line)
    return fields, rejected


def _parse_vision_block(text: str) -> str:
    """Extract the inner body of the [VISION] fence, or "" if absent/malformed.
    Tolerant: no block, an unclosed block, or the close before the open return ""."""
    start = text.find(VISION_OPEN)
    if start == -1:
        return ""
    inner_start = start + len(VISION_OPEN)
    end = text.find(VISION_CLOSE, inner_start)
    if end == -1:
        return ""
    return text[inner_start:end].strip()


def triage_response(raw_model_text: str, fact_record: dict, *,
                    source: str, model: str) -> VisionTriageResult:
    """Turn a raw vision-model response (live or cached) into a fully validated,
    grounding-scored, advisory VisionTriageResult.

    The pipeline is deterministic from here on: sanitize the model text (defang any
    control fence it tried to plant), pull the [VISION] block, validate + type-coerce
    each field, render the validated fields as advisory prose, and score that prose
    with the grounding oracle against the canonical fact-record. cleared is True iff
    the validator kept at least one field AND the grounding scorer flagged nothing.
    Pure of the network; the only LLM-touching step is producing raw_model_text,
    which the cached path does without a call."""
    text = sanitize_llm_text(raw_model_text or "")
    block = _parse_vision_block(text)
    fields, rejected = validate_extraction(block)
    extraction = VisionExtraction(
        fields=fields, rejected=rejected, source=source, model=model)
    score = grounding.score_filing(
        extraction.as_advisory_prose(), fact_record, branch="vision")
    cleared = bool(fields) and not score.ungrounded
    return VisionTriageResult(extraction=extraction, grounding=score, cleared=cleared)


def load_cache() -> dict:
    """Load the committed vision-triage cache (the raw model response, honestly
    labeled source=live|illustrative). Raises VisionTriageError if it is missing or
    malformed, so a broken cache surfaces structurally rather than silently
    skipping triage."""
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise VisionTriageError(f"vision-triage cache unreadable: {e}") from e


def triage_from_cache(fact_record: dict) -> VisionTriageResult:
    """Run vision triage from the COMMITTED cache, never a live call. This is the
    default and test path: it blocks on no network and is reproducible. The cache
    holds the raw model response and its honest source label; the validation and
    grounding are recomputed live here (always real), so only the raw model output
    is cached, exactly like the E5.2 caches."""
    cache = load_cache()
    raw = cache.get("raw_response", "")
    source = cache.get("source", "illustrative")
    model = cache.get("model", "")
    return triage_response(raw, fact_record, source=source, model=model)


def _encode_image(image_path: Path) -> str:
    """Base64 data-URL encode the fixture image for an OpenAI-compatible image
    part. Raises VisionTriageError if the image is missing."""
    try:
        data = image_path.read_bytes()
    except OSError as e:
        raise VisionTriageError(f"vision fixture image missing: {e}") from e
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _vision_messages(image_data_url: str) -> list[dict]:
    """The OpenAI-compatible chat messages for the vision call: a system prompt
    bounding the extraction to the advisory schema, and a user message carrying the
    image part plus the [VISION] block instruction."""
    fields = ", ".join(_VISION_SCHEMA)
    system = (
        "You are a breach-triage assistant reading the FIRST screenshot of a "
        "security incident (a ransom note, an alert panel, or a defacement). "
        "Extract ONLY what the image visibly shows. Do not guess. Your output is "
        "ADVISORY and will be checked against the authoritative record, so an "
        "invented value is worse than an omitted one."
    )
    user_text = (
        "Read the breach screenshot and emit ONE fenced block, exactly "
        f"{VISION_OPEN} on its own line, then one line per visible fact of the "
        f"form key=value using ONLY these keys: {fields}. Use an integer for "
        "records_affected and an ISO yyyy-mm-dd date for incident_date. Omit any "
        f"key the image does not clearly show. Close with {VISION_CLOSE} on its "
        "own line. Emit nothing else."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": [
            {"type": "text", "text": user_text},
            {"type": "image_url", "image_url": {"url": image_data_url}},
        ]},
    ]


def triage_live(fact_record: dict, *, image_path: Path | None = None,
                provider: str = DEFAULT_PROVIDER, model: str = DEFAULT_VISION_MODEL,
                api_key: str | None = None, timeout: int = 60,
                max_attempts: int = 1) -> VisionTriageResult:
    """Run vision triage with a LIVE vision-model call over the fixture image.

    NEVER on the default or test path: live providers are unreliable, so the
    default is triage_from_cache(). An operator who has a key and accepts the
    latency may call this; it makes exactly one chat completion with an image part
    and then runs the same deterministic validate + ground pipeline as the cached
    path. Raises VisionTriageError / DrafterError on a transport or empty-content
    failure (never swallowed). source is labeled "live"."""
    img = image_path or FIXTURE_IMAGE
    image_data_url = _encode_image(img)
    raw = llm_complete(
        provider, model, _vision_messages(image_data_url),
        api_key=api_key, max_tokens=300, temperature=0.0, timeout=timeout,
        max_attempts=max_attempts)
    return triage_response(raw, fact_record, source="live", model=model)
