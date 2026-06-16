"""Adversarial Challenger role: an independent LLM red-team reviewer that sits
BETWEEN a drafter posting its filing and the Warden gating it.

For each drafted filing the Challenger reads the filing prose plus the canonical
fact-record and produces a structured CHALLENGE: a short list of itemized
objections, each naming the load-bearing thing it disputes ("records_affected",
"incident_start_utc", the named breach actor, the severity characterization).
The Challenger posts the challenge into the Band room @mentioning the drafter;
the drafter then REVISES (re-files corrected) or REBUTS (defends). This is a
genuine agent-to-agent critique/defend exchange on camera, the same shape as the
PROPOSE/CONCUR reconciliation and the contradiction round-trip.

The Challenger NEVER gates, counts, clocks, or releases. Its objections are
CONTENT. The deterministic adjudicator (floor/challenge_adjudicate.py) is what
decides which objections are real, by cross-checking each against the existing
pure-Python grounding scorer. The Warden still consumes only the unchanged typed
[CLAIMS] block. So the LLM critiques; Python adjudicates.

The load-bearing structure is a fenced [CHALLENGE]...[/CHALLENGE] block parsed
deterministically (same pattern as [MATERIALITY]), so the adjudicator and packet
never have to interpret an essay. Each objection line is:

    target=<fact_field_or_span_kind>;claim=<verbatim disputed text>;reason=<why>

The Warden never calls this. Only the Challenger process makes this LLM call,
through the shared llm_complete chokepoint so sanitization and bounded retry are
inherited.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from floor.drafter import DrafterError, llm_complete
from floor.grounding import strip_citations
from floor import roster

_BLOCK = re.compile(r"\[CHALLENGE\](.*?)\[/CHALLENGE\]", re.DOTALL)

# The fact-record fields the Challenger may name as the target of an objection.
# A target outside this set (or a free-form span kind) is still parsed and
# carried, but the deterministic adjudicator can only CONFIRM objections whose
# target maps to a grounding-scorer dimension; everything else is OVERTURNED by
# construction, which is exactly the "the Challenger was wrong / unprovable"
# outcome the receipt exists to surface.
TARGET_RECORDS = "records_affected"
TARGET_INCIDENT_START = "incident_start_utc"
TARGET_ATTACKER = "attacker"

_SYSTEM = (
    "You are an independent adversarial reviewer (a red team) for a public "
    "bank's regulatory breach-notification filings. Another agent drafted the "
    "filing below. Your single job is to challenge it: find specific, itemized "
    "objections where the filing's prose is NOT supported by the supplied "
    "fact-record, overstates or misstates a load-bearing fact (the affected "
    "record count, the incident start time, the named breach actor, the "
    "containment or severity characterization), or asserts a number, date, or "
    "name the fact-record does not carry. Be concrete and specific; do not "
    "rubber-stamp. If the filing is faithful, raise no objections. Do NOT rewrite "
    "the filing; only object.\n"
    "End your reply with a fenced block on its own lines, exactly:\n"
    "[CHALLENGE]\n"
    "target=<fact field or what you dispute>;claim=<the verbatim disputed "
    "phrase>;reason=<why it is unsupported>\n"
    "(one such line per objection; if there are no objections, write a single "
    "line: none)\n"
    "[/CHALLENGE]"
)


@dataclass(frozen=True)
class Objection:
    """One itemized Challenger objection, parsed off a [CHALLENGE] line.

    `target` names the load-bearing thing disputed (a fact-record field name, or
    a free-form description). `claim` is the verbatim disputed phrase. `reason`
    is the Challenger's natural-language argument. None of these gate anything;
    they are adjudicated by the deterministic grounding scorer."""
    target: str
    claim: str
    reason: str


@dataclass
class Challenge:
    """The parsed Challenger output for one filing: the prose memo plus the
    itemized objections. The memo is the Challenger's reasoning; the objections
    are the structured, deterministically adjudicable claims."""
    branch: str
    source: str
    memo: str = ""
    objections: list[Objection] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "branch": self.branch,
            "source": self.source,
            "memo": self.memo,
            "objections": [
                {"target": o.target, "claim": o.claim, "reason": o.reason}
                for o in self.objections
            ],
        }


def parse_challenge(text: str, *, branch: str = "", source: str = "") -> Challenge:
    """Parse a Challenger reply into a Challenge. Pure, deterministic string work.

    The memo is the prose above the fenced block; each objection is parsed off a
    `target=...;claim=...;reason=...` line. A "none" body (or an empty block)
    yields zero objections. Raises DrafterError if the fenced block is absent, so
    a malformed Challenger reply surfaces structurally rather than being silently
    treated as zero objections."""
    m = _BLOCK.search(text or "")
    if not m:
        raise DrafterError("challenger reply missing [CHALLENGE] block")
    memo = strip_citations(_BLOCK.sub("", text or "")).strip()
    objections: list[Objection] = []
    for raw in m.group(1).strip().splitlines():
        line = raw.strip()
        if not line or line.lower() == "none":
            continue
        fields = _parse_objection_line(line)
        if fields is None:
            continue
        target, claim, reason = fields
        if not target and not claim:
            continue
        objections.append(Objection(target=target, claim=claim, reason=reason))
    return Challenge(branch=branch, source=source, memo=memo, objections=objections)


def _parse_objection_line(line: str) -> tuple[str, str, str] | None:
    """Parse one `key=value;key=value` objection line into (target, claim,
    reason). Tolerant of missing fields and of a free-form line with no
    recognized keys (treated as a reason-only objection)."""
    parts = {}
    has_kv = False
    for chunk in line.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        key = key.strip().lower()
        if key in ("target", "claim", "reason"):
            parts[key] = value.strip()
            has_kv = True
    if not has_kv:
        # A free-form objection with no key=value structure: keep it as a
        # reason-only objection so a loosely formatted Challenger reply is not
        # silently dropped. It will be OVERTURNED by the adjudicator (no target
        # maps to a grounding dimension), which is the honest outcome.
        return ("", "", line)
    return (parts.get("target", ""), parts.get("claim", ""), parts.get("reason", ""))


def challenge_filing(filing_text: str, fact_record: dict, *, model: str,
                     provider: str = roster.FEATHERLESS, api_key: str | None = None,
                     branch: str = "", max_tokens: int = 600, timeout: int = 90,
                     max_attempts: int = 1) -> Challenge:
    """Run the LLM adversarial review of one drafted filing and return a parsed
    Challenge. The objections are CONTENT, never a gate. Raises DrafterError on a
    transport failure or an unparsable [CHALLENGE] block.

    Only the filing PROSE is shown to the Challenger, never the [CLAIMS] block:
    the challenge is over the human-readable filing the regulator would read, and
    the structured claims envelope is the Warden's deterministic concern, not the
    Challenger's. max_attempts threads to llm_complete (default 1, so offline
    behavior and byte-identical replay are unchanged)."""
    prose = strip_citations(_strip_claims(filing_text or "")).strip()
    user = (
        "Challenge this regulatory breach-notification filing. Object only where "
        "the prose is not supported by the fact-record. Use ONLY these facts as "
        "the ground truth.\n\n"
        f"FACT RECORD (canonical, authoritative):\n{json.dumps(fact_record, indent=2)}\n\n"
        f"FILING PROSE TO CHALLENGE:\n{prose}"
    )
    text = llm_complete(
        provider, model,
        [{"role": "system", "content": _SYSTEM},
         {"role": "user", "content": user}],
        api_key=api_key, max_tokens=max_tokens, temperature=0.2, timeout=timeout,
        max_attempts=max_attempts)
    return parse_challenge(text, branch=branch, source=f"{provider}:{model}")


def _strip_claims(text: str) -> str:
    """Drop the [CLAIMS] block so the Challenger sees only human prose. The claims
    block is the deterministic Warden-owned envelope, not the Challenger's
    concern.

    Cut at the LAST [CLAIMS] occurrence: the drafter appends the one authoritative
    block at the end after sanitizing the prose, so the last occurrence is the
    real boundary. A first-occurrence cut would let a model-injected earlier fence
    blind the Challenger to everything after it. The sanitizer defangs any such
    injected fence, so a clean filing has exactly one block and last == first."""
    idx = text.rfind("[CLAIMS]")
    return text[:idx] if idx != -1 else text
