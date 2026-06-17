"""Cross-border obligation-conflict detector (the international contradiction beat).

The cross-filing contradiction veto (warden/diff.py) catches two drafters of the
SAME incident disagreeing on a FACT (records count, incident_start). This module
catches a DIFFERENT, distinctly cross-border hazard: two REGULATORS imposing
mutually exclusive OBLIGATIONS on the same true facts. One jurisdiction requires
disclosing a data element another jurisdiction forbids disclosing; or two named
obligations cannot both be satisfied at once (a public-disclosure mandate against
a confidentiality / law-enforcement hold).

This is the SAME posture as the fact-contradiction veto: the Warden DETECTS the
conflict deterministically and HALTS, routing the decision to the human two-key
gate. It is a DETECTOR, never a RESOLVER. It does NOT reason about which law wins
(that would be the SKIP-listed conflict-of-laws resolver, a research project that
pulls legal reasoning toward the Warden). It only finds the conflicting pair,
names both regulators and both opposed obligations, and stops. The human resolves
through the existing release gate; the system never picks a side.

Obligations are declared as DATA in the floor's declarative regulator catalog and
lifted into the typed RegimeObligations below: each in-scope regulator carries a
small typed set of obligation attributes that can genuinely conflict. The
detection is pure Python over that declared data, no LLM, no network, no
now()/RNG, so it replays byte-for-byte exactly like the diff. This module reads
no config file itself; the caller passes the already-lifted obligation data in.

Two conflict kinds, both genuine cross-border tensions:

  data-content conflict   regime A's `discloses` set (a data element it is
                          MANDATED to put in its notice) intersects regime B's
                          `forbids_disclosing` set (a data element B's law forbids
                          disclosing). The same incident's notices to the two
                          regulators cannot both comply: one must carry an element
                          the other forbids. Real example: a US disclosure duty
                          pushing toward fuller detail against an EU
                          data-minimization rule that forbids carrying that detail.

  mandate conflict        regime A asserts a named obligation that is the declared
                          opposite of a named obligation regime B asserts (e.g.
                          SEC Item 1.05 `public_disclosure` against a DORA / law
                          enforcement `confidentiality_hold`). The two mandates are
                          mutually exclusive: satisfying one breaches the other.

Both are surfaced ONLY when both regulators are actually in scope for the
incident. A single-regulator run, or two whose obligations are compatible,
produces no conflict (the content-driven negative), exactly like a clean diff.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# The declared-opposite pairs of named mandate tags. A regime asserting one tag
# and another in-scope regime asserting its declared opposite cannot both be
# satisfied. This table states ONLY that the two are mutually exclusive; it makes
# NO judgment about which one prevails (that is the human's call, never this
# module's). The pairs are symmetric: (a, b) and (b, a) are the same conflict.
MUTUALLY_EXCLUSIVE_MANDATES: frozenset[frozenset[str]] = frozenset({
    frozenset({"public_disclosure", "confidentiality_hold"}),
})


def _opposed(tag_a: str, tag_b: str) -> bool:
    """True iff the two named mandate tags are a declared mutually-exclusive pair."""
    return frozenset({tag_a, tag_b}) in MUTUALLY_EXCLUSIVE_MANDATES


@dataclass(frozen=True)
class RegimeObligations:
    """One in-scope regime's typed obligation attributes, lifted from the catalog.

    `discloses` is the set of data elements the regime is MANDATED to carry in its
    notice. `forbids_disclosing` is the set of data elements the regime's law
    FORBIDS disclosing. `mandates` is the set of named obligation tags the regime
    asserts (e.g. "public_disclosure", "confidentiality_hold"). Every attribute is
    a frozenset of plain lowercase tokens, so the comparison is a pure set
    operation. `basis` is the cited statutory basis, rendered for the examiner and
    never gated on."""
    regime: str
    discloses: frozenset[str] = frozenset()
    forbids_disclosing: frozenset[str] = frozenset()
    mandates: frozenset[str] = frozenset()
    basis: str = ""


@dataclass(frozen=True)
class ObligationConflict:
    """A detected, mutually exclusive obligation pair across two in-scope regulators.

    `kind` is "data_content" (a disclosed element one regime forbids) or "mandate"
    (two declared-opposite named obligations). `element` is the conflicting data
    element for a data-content conflict, or the empty string for a mandate
    conflict. `obligation_a` / `obligation_b` are the human-readable opposed
    obligations. The conflict names BOTH regulators and BOTH obligations and stops:
    it carries no verdict about which one prevails (that is the human's)."""
    kind: str
    regime_a: str
    obligation_a: str
    regime_b: str
    obligation_b: str
    element: str = ""
    basis_a: str = ""
    basis_b: str = ""

    def human(self) -> str:
        if self.kind == "data_content":
            return (
                f"{self.regime_a} is mandated to disclose '{self.element}'; "
                f"{self.regime_b} forbids disclosing '{self.element}'. The two "
                f"notices for the same incident cannot both comply. Routed to the "
                f"human two-key gate; the Warden does not decide which law prevails.")
        return (
            f"{self.regime_a} asserts {self.obligation_a}; {self.regime_b} asserts "
            f"{self.obligation_b}. The two mandates are mutually exclusive. Routed "
            f"to the human two-key gate; the Warden does not decide which law "
            f"prevails.")


def _pair_conflicts(a: RegimeObligations, b: RegimeObligations) -> list[ObligationConflict]:
    """Every conflict between one ordered regime pair (a before b). Deterministic:
    data elements and mandate tags are walked in sorted order so the conflict list
    is byte-stable regardless of set iteration order."""
    conflicts: list[ObligationConflict] = []

    # Data-content conflict: an element a is MANDATED to disclose that b FORBIDS
    # disclosing, in BOTH directions (a discloses / b forbids, and b discloses / a
    # forbids), each reported once with the regime that discloses named first.
    for element in sorted(a.discloses & b.forbids_disclosing):
        conflicts.append(ObligationConflict(
            kind="data_content",
            regime_a=a.regime, obligation_a=f"must disclose '{element}'",
            regime_b=b.regime, obligation_b=f"forbids disclosing '{element}'",
            element=element, basis_a=a.basis, basis_b=b.basis))
    for element in sorted(b.discloses & a.forbids_disclosing):
        conflicts.append(ObligationConflict(
            kind="data_content",
            regime_a=b.regime, obligation_a=f"must disclose '{element}'",
            regime_b=a.regime, obligation_b=f"forbids disclosing '{element}'",
            element=element, basis_a=b.basis, basis_b=a.basis))

    # Mandate conflict: a named obligation a asserts is the declared opposite of a
    # named obligation b asserts. Walk sorted so the order is stable.
    for tag_a in sorted(a.mandates):
        for tag_b in sorted(b.mandates):
            if _opposed(tag_a, tag_b):
                conflicts.append(ObligationConflict(
                    kind="mandate",
                    regime_a=a.regime, obligation_a=tag_a,
                    regime_b=b.regime, obligation_b=tag_b,
                    basis_a=a.basis, basis_b=b.basis))
    return conflicts


def detect(in_scope: list[RegimeObligations]) -> list[ObligationConflict]:
    """Pairwise scan over the in-scope regulators' declared obligations, returning
    every mutually exclusive obligation pair. Empty list == no conflict (green).

    `in_scope` is the list of RegimeObligations for the regulators actually live
    this incident. Pure, deterministic, no LLM: the conflict set is a function of the
    declared obligation DATA only. The scan is ordered (the given order, pairs i<j,
    elements and tags sorted) so the result is byte-stable and replays identically.
    It NEVER decides which obligation prevails; it only reports the conflicting
    pairs for the human two-key gate to resolve."""
    conflicts: list[ObligationConflict] = []
    for i in range(len(in_scope)):
        for j in range(i + 1, len(in_scope)):
            conflicts.extend(_pair_conflicts(in_scope[i], in_scope[j]))
    return conflicts


@dataclass(frozen=True)
class ConflictResolution:
    """The human's recorded decision on one detected obligation conflict.

    The Warden NEVER fills this: it is recorded only when a human, through the
    existing two-key release gate, makes an explicit call. `decided_by` names the
    human role(s) that signed; `decision` is the free-text human direction (which
    way, and why). This is a defensibility artifact a litigator would want, and it
    is the ONLY thing that lets a halted branch proceed."""
    kind: str
    regime_a: str
    regime_b: str
    decided_by: tuple[str, ...] = field(default_factory=tuple)
    decision: str = ""
