"""Sub-agent INVESTIGATION: an LLM derivation step that proposes candidate facts
from the fact-record, and a PURE deterministic verifier that admits only the
candidates the frozen Warden core (the statutory clocks and the reportability /
high-risk threshold rules) independently confirms (E9.7).

The problem this solves. A drafter, given the raw fact-record, can REASON ITS WAY
to facts the record does not state outright: that the NIS2 full-notification
deadline lands at a specific instant (counting the 72-hour window from the
becoming-aware timestamp), or that the GDPR Article 34 communication-to-data-
subject duty is triggered (a high-risk derivation over the record). Those derived
facts are useful: they sharpen the drafting prompt. But an LLM derivation is a
GUESS until something deterministic checks it. A model that miscounts the window,
or over-reads the high-risk bar, would otherwise feed a WRONG derived fact into a
regulated filing.

So this module is two halves with a hard boundary between them:

  1. The LLM half (propose_candidates / a propose_fn seam): proposes a list of
     CandidateFact records. Each is a structured guess: kind (a deadline, or a
     duty trigger), the regime it concerns, the field it derives, the value the
     model computed, and the model's short basis. This is the qualitative,
     derivation-shaped work an LLM is good at, exactly like the materiality and
     reportability JUDGMENTS elsewhere.

  2. The deterministic half (verify_derivation, a PURE function): recomputes EACH
     candidate against the SAME frozen Warden core the rest of the system gates
     on. A deadline candidate is recomputed with warden.clocks.ClockEngine (the
     identical statutory-clock engine the live clocks use); a trigger candidate is
     recomputed with a pure threshold predicate over the fact-record. The
     candidate is ADMITTED only when the recompute AGREES with the model's claimed
     value, and REJECTED (with the recomputed value recorded for the audit trail)
     when it disagrees. The recompute is READ-ONLY over the clocks: it constructs a
     throwaway ClockEngine, reads the resulting deadline instant, and never mutates
     any live clock, the run-log, the chaos fixture, or any sealed capture.

Where the admitted facts go. An admitted derived fact feeds the DRAFTING PROMPT
only (an investigation HINT block the model may rely on, the same posture as the
RAG grounding context). It NEVER enters the [CLAIMS] gate envelope the Warden
diffs: the load-bearing claims block stays exactly the deterministic fact-record
the drafter process attaches, so the Warden's contradiction diff, the sealed
shas, and byte-identical replay are untouched. A derived fact is a prompt aid, not
a gated claim.

The Warden makes ZERO LLM calls here, and this module never gates, blocks,
releases, counts, or clocks anything live: it only RECOMPUTES (read-only) to admit
or reject a model's guess. The whole step is additive and default-off in the
runner, so the four sealed captures and their run-log shas are unchanged.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from warden.clocks import ClockEngine, parse_ts

from floor.drafter import DrafterError, llm_complete
from floor import roster


# The two kinds of candidate fact the investigation derives. A DEADLINE is a
# statutory-clock instant recomputed against warden.clocks; a TRIGGER is a
# duty-to-notify boolean recomputed against a pure threshold predicate. Any other
# kind is rejected structurally (an unverifiable derivation is never admitted).
KIND_DEADLINE = "deadline"
KIND_TRIGGER = "trigger"
CANDIDATE_KINDS = (KIND_DEADLINE, KIND_TRIGGER)


@dataclass(frozen=True)
class CandidateFact:
    """One candidate fact the LLM derivation proposes from the fact-record.

    `kind` is KIND_DEADLINE (a statutory-clock instant) or KIND_TRIGGER (a
    duty-to-notify boolean). `regime` names the regime the derivation concerns
    (e.g. "NIS2", "GDPR Art 34"). `field` names what is derived (e.g.
    "nis2_full_notification_deadline_utc", "gdpr_art34_communication_required").
    `value` is the model's claimed value: for a deadline, an ISO-8601 UTC instant
    string; for a trigger, the string "yes"/"no" (or a bool). `basis` is the
    model's short rationale (audit-trail only, never recomputed against).

    The deterministic recompute fields below let verify_derivation reproduce the
    value from the frozen core WITHOUT trusting the model:
      - for a deadline: `anchor_ts` (the fact-record timestamp the window counts
        from) and `window_hours` (the statutory window length);
      - for a trigger: nothing extra is needed (the predicate reads the
        fact-record directly).
    These are the model's STATED inputs; the verifier recomputes the value from
    them and the fact-record and admits the candidate only if its result matches
    `value`. A candidate that states inputs the verifier cannot reproduce the
    claimed value from is rejected, never admitted on the model's say-so."""
    kind: str
    regime: str
    field: str
    value: str
    basis: str = ""
    anchor_ts: str = ""
    window_hours: int = 0


@dataclass(frozen=True)
class DerivationVerdict:
    """The deterministic verdict for one candidate fact. `confirmed` is the
    load-bearing boolean: True iff the frozen-core recompute AGREES with the
    model's claimed value. `recomputed_value` is what the deterministic core
    actually produced (an ISO instant for a deadline, "yes"/"no" for a trigger),
    recorded whether confirmed or not so a rejection names what the truth was.
    `reason` is a short human-readable explanation for the packet."""
    candidate: CandidateFact
    confirmed: bool
    recomputed_value: str
    reason: str

    @property
    def admitted(self) -> bool:
        return self.confirmed


@dataclass
class InvestigationResult:
    """The outcome of an investigation: every candidate paired with its
    deterministic verdict, partitioned into admitted (confirmed) and rejected.

    `admitted_facts()` returns the {field: value} mapping of CONFIRMED derivations
    only, which is the sole thing that ever reaches the drafting prompt. A rejected
    candidate is recorded for the audit trail and never feeds the prompt."""
    verdicts: list[DerivationVerdict] = field(default_factory=list)

    @property
    def admitted(self) -> list[DerivationVerdict]:
        return [v for v in self.verdicts if v.confirmed]

    @property
    def rejected(self) -> list[DerivationVerdict]:
        return [v for v in self.verdicts if not v.confirmed]

    def admitted_facts(self) -> dict[str, str]:
        """The {field: confirmed value} mapping of admitted derivations, the only
        thing that feeds the drafting prompt. Last field wins on a duplicate, a
        deterministic documented rule."""
        out: dict[str, str] = {}
        for v in self.admitted:
            out[v.candidate.field] = v.recomputed_value
        return out

    def as_dict(self) -> dict:
        """The packet-ready receipt: every candidate, its claimed value, the
        deterministically recomputed value, and whether it was admitted. Pure read;
        never enters the hashed run-log."""
        rows = []
        for v in self.verdicts:
            rows.append({
                "kind": v.candidate.kind,
                "regime": v.candidate.regime,
                "field": v.candidate.field,
                "claimed_value": v.candidate.value,
                "recomputed_value": v.recomputed_value,
                "admitted": v.confirmed,
                "reason": v.reason,
                "basis": v.candidate.basis,
            })
        return {
            "candidates": rows,
            "admitted_count": len(self.admitted),
            "rejected_count": len(self.rejected),
        }


# ---------------------------------------------------------------------------
# The pure threshold predicate for a TRIGGER candidate (GDPR Art 34
# communication-to-data-subject duty). This mirrors the conservative shape of the
# reportability / high-risk gates: the qualitative call is delegated, but the
# RECOMPUTE the verifier runs is a deterministic rule over the fact-record so a
# candidate is admitted only when the record itself supports it.
#
# Art 34 attaches when a personal-data breach is likely to result in a HIGH RISK
# to the rights and freedoms of natural persons. The deterministic proxy: a
# materially large affected-record count AND at least one sensitive data category
# in the record. Both must hold; a small or non-sensitive breach does not clear
# the high-risk bar, so a model that claims the trigger fires on such a record is
# REJECTED by the recompute.
# ---------------------------------------------------------------------------
_HIGH_RISK_RECORDS_THRESHOLD = 1000
_SENSITIVE_DATA_CATEGORIES = frozenset({
    "account_number", "financial", "payment_card", "health", "medical",
    "biometric", "credentials", "password", "ssn", "national_id",
    "government_id", "tax_id",
})


def _recompute_trigger(fact_record: dict) -> bool:
    """Deterministically recompute the GDPR Art 34 communication trigger from the
    fact-record. Pure: no LLM, no clock, no randomness; the same fact-record always
    yields the same boolean. The duty attaches when the affected-record count is
    materially large AND the record carries at least one sensitive data category."""
    records = fact_record.get("records_affected")
    if not isinstance(records, int) or records < _HIGH_RISK_RECORDS_THRESHOLD:
        return False
    categories = fact_record.get("data_categories") or []
    if not isinstance(categories, (list, tuple)):
        return False
    return any(str(c).strip().lower() in _SENSITIVE_DATA_CATEGORIES
               for c in categories)


def _norm_trigger_value(value) -> bool | None:
    """Normalize a claimed trigger value to a bool, or None if unparsable. Accepts
    the bools True/False and the strings yes/no/true/false/required/not_required."""
    if isinstance(value, bool):
        return value
    token = str(value).strip().lower()
    if token in ("yes", "true", "required", "1"):
        return True
    if token in ("no", "false", "not_required", "0"):
        return False
    return None


def verify_derivation(candidate: CandidateFact, fact_record: dict) -> DerivationVerdict:
    """Recompute ONE candidate fact against the frozen deterministic Warden core and
    return a verdict admitting it only if the recompute agrees with the model's
    claimed value. PURE and READ-ONLY: it constructs throwaway objects (a fresh
    ClockEngine for a deadline), reads the result, and never mutates any live clock,
    the run-log, the chaos fixture, or any sealed capture. No LLM call happens here.

    Two kinds:

      KIND_DEADLINE: recompute the statutory deadline instant by counting the
        candidate's stated window (`window_hours`) from its stated anchor timestamp
        (`anchor_ts`) with the SAME warden.clocks engine the live clocks use. The
        candidate is admitted iff the model's claimed `value` parses to the same UTC
        instant. A miscounted window is rejected, with the true instant recorded.

      KIND_TRIGGER: recompute the duty-to-notify boolean with the pure threshold
        predicate over the fact-record. The candidate is admitted iff the model's
        claimed `value` (yes/no) matches the recomputed boolean. An over-read
        trigger is rejected, with the true boolean recorded.

    Any other kind, or a deadline candidate whose stated inputs do not reproduce
    its claimed value, is REJECTED: an unverifiable derivation is never admitted."""
    if candidate.kind == KIND_DEADLINE:
        return _verify_deadline(candidate)
    if candidate.kind == KIND_TRIGGER:
        return _verify_trigger(candidate, fact_record)
    return DerivationVerdict(
        candidate=candidate, confirmed=False, recomputed_value="",
        reason=(f"unverifiable candidate kind {candidate.kind!r}: only "
                f"{', '.join(CANDIDATE_KINDS)} are deterministically recomputable"))


def _verify_deadline(candidate: CandidateFact) -> DerivationVerdict:
    if not candidate.anchor_ts or candidate.window_hours <= 0:
        return DerivationVerdict(
            candidate=candidate, confirmed=False, recomputed_value="",
            reason=("deadline candidate is missing a positive window or an anchor "
                    "timestamp, so it cannot be recomputed"))
    try:
        # A throwaway engine: this is read-only against the frozen clock logic, it
        # never touches the live ClockEngine the run uses.
        engine = ClockEngine()
        clock = engine.start_hours(
            candidate.field, candidate.field, candidate.anchor_ts,
            candidate.window_hours, trigger_event="becoming aware")
        recomputed = clock.deadline
    except (ValueError, KeyError) as exc:
        return DerivationVerdict(
            candidate=candidate, confirmed=False, recomputed_value="",
            reason=f"deadline recompute failed: {exc}")
    recomputed_iso = recomputed.isoformat()
    try:
        claimed = parse_ts(candidate.value)
    except ValueError:
        return DerivationVerdict(
            candidate=candidate, confirmed=False, recomputed_value=recomputed_iso,
            reason=("claimed deadline is not a parsable ISO-8601 instant; the "
                    f"deterministic recompute gives {recomputed_iso}"))
    if claimed == recomputed:
        return DerivationVerdict(
            candidate=candidate, confirmed=True, recomputed_value=recomputed_iso,
            reason=(f"the {candidate.window_hours}-hour window from "
                    f"{candidate.anchor_ts} deterministically lands on "
                    f"{recomputed_iso}, matching the derivation"))
    return DerivationVerdict(
        candidate=candidate, confirmed=False, recomputed_value=recomputed_iso,
        reason=("the derivation claims a deadline the recompute disagrees with: "
                f"the {candidate.window_hours}-hour window from "
                f"{candidate.anchor_ts} lands on {recomputed_iso}, not "
                f"{candidate.value}"))


def _verify_trigger(candidate: CandidateFact, fact_record: dict) -> DerivationVerdict:
    recomputed = _recompute_trigger(fact_record)
    recomputed_value = "yes" if recomputed else "no"
    claimed = _norm_trigger_value(candidate.value)
    if claimed is None:
        return DerivationVerdict(
            candidate=candidate, confirmed=False, recomputed_value=recomputed_value,
            reason=("claimed trigger value is not parsable as yes/no; the "
                    f"deterministic recompute gives {recomputed_value}"))
    if claimed == recomputed:
        return DerivationVerdict(
            candidate=candidate, confirmed=True, recomputed_value=recomputed_value,
            reason=(f"the {candidate.regime} threshold predicate over the "
                    f"fact-record deterministically yields {recomputed_value}, "
                    "matching the derivation"))
    return DerivationVerdict(
        candidate=candidate, confirmed=False, recomputed_value=recomputed_value,
        reason=(f"the derivation claims {candidate.value!r} but the "
                f"{candidate.regime} threshold predicate over the fact-record "
                f"deterministically yields {recomputed_value}"))


def investigate(fact_record: dict, candidates: list[CandidateFact]) -> InvestigationResult:
    """Run verify_derivation over every candidate and return the partitioned result.
    Pure and deterministic: the same (fact_record, candidates) always yields the same
    InvestigationResult. Admits only confirmed derivations; records the rest for the
    audit trail. Nothing here gates, clocks, or writes the run-log."""
    result = InvestigationResult()
    for candidate in candidates:
        result.verdicts.append(verify_derivation(candidate, fact_record))
    return result


# ---------------------------------------------------------------------------
# The LLM derivation half. propose_candidates asks a model to derive candidate
# facts from the record and returns parsed CandidateFact records. It is the
# qualitative half; verify_derivation is the deterministic gate on its output. A
# propose_fn injection seam keeps the offline suite and replay LLM-free, exactly
# like reportability_fn / materiality_fn elsewhere.
# ---------------------------------------------------------------------------
_INVESTIGATE_OPEN = "[DERIVATION]"
_INVESTIGATE_CLOSE = "[/DERIVATION]"
_BLOCK = re.compile(r"\[DERIVATION\](.*?)\[/DERIVATION\]", re.DOTALL)

_SYSTEM = (
    "You are an investigation sub-agent for a regulated breach-reporting team. "
    "From the canonical fact-record you DERIVE candidate facts the record does not "
    "state outright but that follow from it: a statutory notification DEADLINE "
    "(the instant a fixed-hour window lands on, counting from a fact-record "
    "timestamp), or a duty-to-notify TRIGGER (whether a named obligation is "
    "engaged). You state each derivation's inputs explicitly so a deterministic "
    "checker can recompute it; you NEVER assert a derived fact the inputs do not "
    "support. Emit ONLY a fenced block, exactly:\n"
    "[DERIVATION]\n"
    "kind=deadline|trigger;regime=<name>;field=<name>;value=<value>;"
    "anchor_ts=<iso or blank>;window_hours=<int or 0>;basis=<short reason>\n"
    "(one line per candidate)\n"
    "[/DERIVATION]"
)


def parse_candidates(text: str) -> list[CandidateFact]:
    """Parse the fenced [DERIVATION] block from a model reply into CandidateFact
    records. Pure deterministic string work. Tolerant: no block, an unclosed block,
    or the close before the open all return []. Within the block, only lines that
    name a recognized kind and a field are kept; a malformed line is dropped so a
    bad derivation never becomes a candidate. The field names mirror the
    CandidateFact fields; an unknown key on a line is ignored."""
    m = _BLOCK.search(text or "")
    if not m:
        return []
    out: list[CandidateFact] = []
    for raw in m.group(1).strip().splitlines():
        line = raw.strip()
        if not line:
            continue
        fields: dict[str, str] = {}
        for part in line.split(";"):
            key, sep, value = part.partition("=")
            if sep:
                fields[key.strip().lower()] = value.strip()
        kind = fields.get("kind", "")
        field_name = fields.get("field", "")
        if kind not in CANDIDATE_KINDS or not field_name:
            continue
        window = fields.get("window_hours", "0")
        try:
            window_hours = int(window) if window else 0
        except ValueError:
            window_hours = 0
        out.append(CandidateFact(
            kind=kind, regime=fields.get("regime", ""), field=field_name,
            value=fields.get("value", ""), basis=fields.get("basis", ""),
            anchor_ts=fields.get("anchor_ts", ""), window_hours=window_hours))
    return out


def propose_candidates(fact_record: dict, *, model: str,
                       provider: str = roster.FEATHERLESS,
                       api_key: str | None = None, max_tokens: int = 400,
                       timeout: int = 90, max_attempts: int = 1) -> list[CandidateFact]:
    """Run the LLM derivation step over the fact-record and return parsed candidate
    facts. The qualitative half only: the returned candidates are GUESSES that
    verify_derivation must confirm before any reach a prompt. Raises DrafterError on
    transport failure; an empty / unparsable block yields no candidates (an
    investigation that derives nothing is valid, not an error)."""
    user = (
        "Derive candidate facts from this canonical fact-record. Use ONLY these "
        "facts. State each derivation's inputs so a deterministic checker can "
        "recompute it.\n\nFACT RECORD (canonical):\n"
        f"{json.dumps(fact_record, indent=2)}"
    )
    try:
        text = llm_complete(
            provider, model,
            [{"role": "system", "content": _SYSTEM},
             {"role": "user", "content": user}],
            api_key=api_key, max_tokens=max_tokens, temperature=0.1,
            timeout=timeout, max_attempts=max_attempts)
    except DrafterError:
        raise
    return parse_candidates(text)
