"""Cross-draft contradiction diff (the F1 separator, deterministic).

Drafters emit fact claims in a structured envelope we control. The diff
is a checkable Python condition, not LLM mood.

Canonicalization rules (the flag the judge ballots missed):
- All timestamps normalized to UTC before comparison. "02:14 CET" vs
  "01:14 UTC" is AGREEMENT; "02:14" in two zones is CONTRADICTION.
- Attacker attribution lowercased/stripped with an alias table hook.
- Containment status mapped to a closed enum.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .clocks import parse_ts


class Containment(str, Enum):
    NOT_CONTAINED = "not_contained"
    PARTIALLY_CONTAINED = "partially_contained"
    CONTAINED = "contained"
    ERADICATED = "eradicated"


ATTACKER_ALIASES: dict[str, str] = {
    # canonical <- aliases (extend during build; deterministic table, not vibes)
    "lockbit": "lockbit",
    "lockbit 3.0": "lockbit",
    "lockbit3": "lockbit",
}


def canon_attacker(raw: str) -> str:
    key = raw.strip().lower()
    return ATTACKER_ALIASES.get(key, key)


@dataclass(frozen=True)
class FactClaims:
    """The load-bearing facts every filing must agree on."""
    branch: str                 # e.g. "nis2"
    incident_start_ts: str      # any ISO-8601 with offset; normalized to UTC
    records_affected: int
    attacker: str
    containment: Containment

    def canonical(self) -> dict:
        return {
            "incident_start_utc": parse_ts(self.incident_start_ts).isoformat(),
            "records_affected": self.records_affected,
            "attacker": canon_attacker(self.attacker),
            "containment": self.containment.value,
        }


@dataclass(frozen=True)
class Conflict:
    field: str
    branch_a: str
    value_a: object
    branch_b: str
    value_b: object

    def human(self) -> str:
        return (f"{self.branch_a.upper()} says {self.field}={self.value_a}; "
                f"{self.branch_b.upper()} says {self.field}={self.value_b}. Submission blocked.")


def diff_claims(claims: list[FactClaims]) -> list[Conflict]:
    """Pairwise diff over canonicalized load-bearing facts. Empty list == green."""
    conflicts: list[Conflict] = []
    canon = [(c.branch, c.canonical()) for c in claims]
    for i in range(len(canon)):
        for j in range(i + 1, len(canon)):
            ba, fa = canon[i]
            bb, fb = canon[j]
            for fieldname in fa:
                if fa[fieldname] != fb[fieldname]:
                    conflicts.append(Conflict(fieldname, ba, fa[fieldname], bb, fb[fieldname]))
    return conflicts
