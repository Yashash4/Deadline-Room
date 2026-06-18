"""The examiner's cross-filing consistency assertion sheet (E4.3).

When the same incident is filed to SEC, ICO, NIS2, DORA, and NYDFS, the examiner
CROSS-READS the filings. If the 8-K says 48,211 records and the Article 33 notice
says a different number, or the incident_start differs across filings, that is a
referral. The contradiction veto (warden/diff.py) catches the BLOCKING field-level
conflicts internally and refuses to release on one. This sheet is the inverse,
positive face the examiner actually wants: the affirmative ATTESTATION that the
load-bearing facts are IDENTICAL across all N filings, with each shared value shown
ONCE and a per-fact CONSISTENT / CONFLICT status, plus an overall "all N filings
consistent across M load-bearing facts" verdict.

What it is, precisely:

  A PURE DERIVED render over the already-reconciled claims the packet carries
  (packet["diff"]["final_claims"], the per-branch canonical fact claims the diff
  produced). Per load-bearing fact (incident_start_utc, records_affected, attacker,
  containment) it groups the filings by their canonical value, attests the single
  agreed value when they all match, and marks the fact CONFLICT (showing both sides)
  when they do not. The CONSISTENT / CONFLICT decision is computed through the SAME
  canonicalization the contradiction veto uses (warden/diff.py: all timestamps
  normalized to UTC, attacker run through the alias table, containment a closed
  enum), so a timezone-equivalent value ("02:14 CET" vs "01:14 UTC") is still
  CONSISTENT, exactly like the veto, and a genuine conflict surfaces the same
  Conflict the veto blocked on.

  Deterministic and no-trust-core: zero LLM calls, no now(), no randomness. The same
  claims always derive the byte-identical sheet. It reads the packet dict only; it
  never enters the hashed run-log, never gates a Warden transition, never clocks or
  counts anything inside the core. It is an examiner-side READ over the Warden's
  output, exactly like the completeness screen (E4.2) and the grounding receipt.
"""

from __future__ import annotations

from dataclasses import dataclass

from warden.diff import FactClaims, diff_claims

# The load-bearing facts an examiner cross-reads across the filing set, keyed by the
# EXACT canonical field names warden/diff.py's FactClaims.canonical() emits, in a
# fixed order so the sheet and the render see identical bytes. These are the same
# four fields the contradiction veto diffs; the consistency sheet is the veto's
# positive face over the same canonical values.
LOAD_BEARING_FACTS: tuple[str, ...] = (
    "incident_start_utc",
    "records_affected",
    "attacker",
    "containment",
)

# Human-readable labels for the load-bearing facts, for the examiner-facing sheet.
_FACT_LABELS: dict[str, str] = {
    "incident_start_utc": "Incident start (UTC)",
    "records_affected": "Records affected",
    "attacker": "Attacker",
    "containment": "Containment status",
}

# The two per-fact dispositions, named so the packet and the receipt branch on the
# code rather than a free string. CONSISTENT: every filing asserts the same canonical
# value for this fact. CONFLICT: at least two filings assert different canonical
# values (the same condition the contradiction veto blocks on).
STATUS_CONSISTENT = "CONSISTENT"
STATUS_CONFLICT = "CONFLICT"

# Branch token -> regime label, built once from the SAME declarative regime catalog
# that drives the clocks and the completeness sheet. The claims are keyed by branch
# (the stable key); the examiner reads regime labels, so the sheet names each filing
# by its regime label when one resolves, falling back to the upper-cased branch.
from floor.regimes import load_catalog  # noqa: E402


def _build_branch_label_index() -> dict[str, str]:
    index: dict[str, str] = {}
    for spec in load_catalog():
        index[spec.branch.strip().lower()] = spec.regime_label
    return index


_BRANCH_LABEL_INDEX = _build_branch_label_index()


def _filing_label(branch: str) -> str:
    """The examiner-facing filing name for a branch token: its regime label from the
    catalog, or the upper-cased branch when the catalog does not name it."""
    key = str(branch).strip().lower()
    return _BRANCH_LABEL_INDEX.get(key, str(branch).upper())


@dataclass(frozen=True)
class FactAgreement:
    """One load-bearing fact's cross-filing agreement on the consistency sheet.

    fact         the canonical field name (e.g. "records_affected").
    label        the examiner-facing label for the fact.
    status       STATUS_CONSISTENT / STATUS_CONFLICT.
    agreed_value the single value every filing asserts when CONSISTENT; None when
                 CONFLICT (there is no single agreed value to attest).
    filings      the regime labels of the filings asserting the agreed value (every
                 in-scope filing when CONSISTENT).
    conflict     when CONFLICT, the pair of disagreeing (filing label, value)
                 tuples the contradiction veto caught; empty when CONSISTENT.
    """
    fact: str
    label: str
    status: str
    agreed_value: object
    filings: tuple[str, ...]
    conflict: tuple[tuple[str, object], ...]

    @property
    def consistent(self) -> bool:
        return self.status == STATUS_CONSISTENT

    def as_dict(self) -> dict:
        return {
            "fact": self.fact,
            "label": self.label,
            "status": self.status,
            "agreed_value": self.agreed_value,
            "filings": list(self.filings),
            "conflict": [{"filing": f, "value": v} for f, v in self.conflict],
        }


@dataclass(frozen=True)
class ConsistencySheet:
    """The cross-filing consistency assertion sheet: the affirmative attestation that
    the load-bearing facts are identical across the filing set.

    filings    the regime labels of the filings cross-read, in claim order.
    facts      the per-load-bearing-fact agreements, in LOAD_BEARING_FACTS order.
    """
    filings: tuple[str, ...]
    facts: tuple[FactAgreement, ...]

    @property
    def filing_count(self) -> int:
        return len(self.filings)

    @property
    def fact_count(self) -> int:
        return len(self.facts)

    @property
    def conflict_count(self) -> int:
        return sum(1 for f in self.facts if f.status == STATUS_CONFLICT)

    @property
    def consistent(self) -> bool:
        """CONSISTENT iff at least two filings were cross-read and every load-bearing
        fact agrees. A single filing has nothing to cross-read against, so it is not
        an attested cross-filing consistency (the verdict says so separately)."""
        return self.filing_count >= 2 and self.conflict_count == 0

    @property
    def verdict(self) -> str:
        """The one-line examiner verdict the sheet stamps."""
        if self.filing_count < 2:
            return ("NOT CROSS-READ (a single filing; cross-filing consistency needs "
                    "two or more filings)")
        if self.consistent:
            return (f"CONSISTENT: all {self.filing_count} filings report the same "
                    f"value on every one of the {self.fact_count} load-bearing facts")
        return (f"CONFLICT: {self.conflict_count} of {self.fact_count} load-bearing "
                f"fact{'' if self.conflict_count == 1 else 's'} disagree across the "
                f"{self.filing_count} filings")

    def as_dict(self) -> dict:
        """A JSON-serializable view for the Examiner Packet. Stable key order so the
        packet render and any guard see identical bytes."""
        return {
            "filings": list(self.filings),
            "filing_count": self.filing_count,
            "fact_count": self.fact_count,
            "conflict_count": self.conflict_count,
            "consistent": self.consistent,
            "verdict": self.verdict,
            "facts": [f.as_dict() for f in self.facts],
        }


def _canonical_by_branch(claims_by_branch: dict) -> dict[str, dict]:
    """Canonicalize each branch's claim through warden/diff.py, the SAME
    canonicalization the contradiction veto applies, so a timezone-equivalent value
    is the same canonical value (and thus CONSISTENT). A FactClaims is canonicalized
    via its .canonical(); an already-canonical dict (the packet's final_claims) is
    taken as-is (it was produced by the same .canonical())."""
    canon: dict[str, dict] = {}
    for branch, claim in claims_by_branch.items():
        if isinstance(claim, FactClaims):
            canon[branch] = claim.canonical()
        else:
            canon[branch] = dict(claim)
    return canon


def consistency_from_claims(claims_by_branch: dict) -> ConsistencySheet:
    """The consistency sheet over a set of per-branch claims (raw FactClaims or the
    already-canonical final_claims dicts).

    Pure derived: it canonicalizes each branch's claim through warden/diff.py and, per
    load-bearing fact, groups the filings by their canonical value. When every filing
    shares one value the fact is CONSISTENT and that single value is attested; when
    they do not, the fact is CONFLICT and the disagreeing pair the contradiction veto
    caught is shown. The CONFLICT set is reconciled with diff_claims so the sheet's
    conflicts are exactly the veto's conflicts (a timezone-equivalent value is never a
    false conflict)."""
    branches = list(claims_by_branch.keys())
    canon = _canonical_by_branch(claims_by_branch)
    labels = tuple(_filing_label(b) for b in branches)

    # The conflicting fields the contradiction veto would catch over these same
    # claims, computed through the exact veto canonicalization (FactClaims.canonical
    # within diff_claims), so the sheet's CONFLICT verdict matches the veto's BLOCK.
    fact_claims = [c for c in claims_by_branch.values() if isinstance(c, FactClaims)]
    conflicted_fields: set[str] = set()
    if len(fact_claims) == len(branches) and fact_claims:
        for conflict in diff_claims(fact_claims):
            conflicted_fields.add(conflict.field)

    facts: list[FactAgreement] = []
    for fact in LOAD_BEARING_FACTS:
        # Group the filings by the canonical value they assert for this fact, in
        # first-seen order so the agreement is deterministic.
        groups: list[tuple[object, list[str]]] = []
        for branch in branches:
            value = canon[branch].get(fact)
            for gv, members in groups:
                if gv == value:
                    members.append(_filing_label(branch))
                    break
            else:
                groups.append((value, [_filing_label(branch)]))

        # CONFLICT when the canonical values disagree across filings. When raw
        # FactClaims were supplied we trust diff_claims (the veto) as the authority;
        # otherwise (canonical dicts only) more than one value group is the conflict.
        if fact_claims and len(fact_claims) == len(branches):
            is_conflict = fact in conflicted_fields
        else:
            is_conflict = len(groups) > 1

        if not is_conflict:
            agreed_value = groups[0][0] if groups else None
            facts.append(FactAgreement(
                fact=fact, label=_FACT_LABELS.get(fact, fact),
                status=STATUS_CONSISTENT, agreed_value=agreed_value,
                filings=tuple(labels), conflict=()))
        else:
            # Show the two disagreeing sides (the first member of the first two
            # distinct value groups), the same pair the veto's Conflict named.
            pair = tuple(
                (members[0], gv) for gv, members in groups[:2])
            facts.append(FactAgreement(
                fact=fact, label=_FACT_LABELS.get(fact, fact),
                status=STATUS_CONFLICT, agreed_value=None,
                filings=tuple(labels), conflict=pair))

    return ConsistencySheet(filings=labels, facts=tuple(facts))


def consistency_record(packet: dict) -> dict:
    """The packet-ready cross-filing consistency block: the per-fact agreement plus
    the overall verdict, JSON-serializable.

    Pure derived over packet["diff"]["final_claims"], the per-branch canonical claims
    the diff already reconciled (the source of truth for consistency). Returns {} when
    the packet carries fewer than two filings' claims (nothing to cross-read), so the
    renderer can omit the section cleanly. No LLM, no now(); the same packet derives
    the byte-identical block."""
    final_claims = (packet.get("diff", {}) or {}).get("final_claims", {}) or {}
    if len(final_claims) < 2:
        return {}
    sheet = consistency_from_claims(final_claims)
    return sheet.as_dict()
