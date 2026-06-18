"""Render-time policy / config version stamp (E4.10).

Regulation in this system is configuration: the statutory clocks, the mandated
fields, and the control mapping all come from declarative catalogs
(floor/regimes.yaml, floor/controls.yaml) and the Warden's typed authority table
(warden/state_machine.EVENT_AUTHORITY). When an examiner or an auditor reads a
packet months later, they must know WHICH policy version governed THIS run: a
later edit to a threshold, a mandated field, or a control mapping must not be
silently attributed to an older run. This module derives a stable version stamp
over the exact policy bytes that were loaded, so the packet records its own
governing policy version.

What it is, precisely:

  A PURE DERIVED stamp computed at packet RENDER time. policy_version() reads the
  catalog files' bytes (regimes.yaml, controls.yaml) and a canonical serialization
  of the rule set (the EVENT_AUTHORITY transition-authority map), hashes each to a
  per-component sha256, and folds the per-component shas into one composite
  policy_version sha. The same catalogs and rule set always derive the
  byte-identical stamp; an edit to any one of them moves the composite sha, so a
  reader sees immediately that a different policy governed a different run.

  CRITICAL: this stamp is RENDER-TIME ONLY. It is computed when the packet is
  assembled, attached to the packet for display, and is NEVER written into the
  hashed run-log JSONL. The hashed run-log seals the RUN (the events that
  occurred); the policy version is metadata ABOUT the policy that governed it,
  derived afresh at render time. Folding it into the hashed log would move the
  sealed sha, so it deliberately stays out: the four sealed captures' run-log shas
  and byte-identical replay are completely untouched by this stamp.

  Deterministic and no-trust-core: zero LLM calls, no now(), no randomness. It
  reads the policy files and the rule set only; it never gates a Warden transition,
  never clocks or counts anything inside the core.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from warden.state_machine import EVENT_AUTHORITY

_FLOOR_DIR = Path(__file__).resolve().parent

# The declarative policy catalogs whose bytes define the governing policy: the
# regime catalog (clocks + mandated fields) and the control catalog (the
# named-framework control mapping). Listed by path so the stamp is computed over
# the exact files on disk.
_CATALOG_FILES = (
    ("regimes.yaml", _FLOOR_DIR / "regimes.yaml"),
    ("controls.yaml", _FLOOR_DIR / "controls.yaml"),
)


def _file_sha(path: Path) -> str:
    """The sha256 over a policy file's raw bytes, or "" when the file is absent.
    Pure read; the byte digest is independent of platform line endings only insofar
    as the file's own bytes are, which is the honest thing to stamp: the exact
    governing bytes."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (FileNotFoundError, IsADirectoryError):
        return ""


def _ruleset_canonical() -> str:
    """A canonical, deterministic serialization of the Warden's transition-authority
    rule set (EVENT_AUTHORITY): each event mapped to the SORTED list of role classes
    authorized to emit it. Sorted keys and sorted role lists make the serialization
    byte-stable regardless of dict / set iteration order, so the rule-set sha moves
    only when the authority table actually changes."""
    table = {
        event.value: sorted(roles)
        for event, roles in EVENT_AUTHORITY.items()
    }
    return json.dumps(table, sort_keys=True, separators=(",", ":"))


def _ruleset_sha() -> str:
    """The sha256 over the canonical rule-set serialization."""
    return hashlib.sha256(_ruleset_canonical().encode("utf-8")).hexdigest()


def policy_version() -> dict:
    """The render-time policy / config version stamp.

    Returns the per-component shas (regimes.yaml, controls.yaml, the rule set) and
    a composite policy_version sha that folds them in a fixed order. The same
    catalogs and rule set derive the byte-identical stamp; an edit to any component
    moves the composite. Pure: reads the policy files and the rule set, makes no
    LLM call, no now(), and never writes the run-log.

    This stamp is RENDER-TIME ONLY: it is attached to the packet for display and is
    NEVER folded into the hashed run-log JSONL, so the sealed run-log shas and
    byte-identical replay are untouched."""
    components: dict[str, str] = {}
    for label, path in _CATALOG_FILES:
        components[label] = _file_sha(path)
    components["rule_set"] = _ruleset_sha()

    # The composite policy version: a sha over the per-component shas in a fixed,
    # sorted order, so the composite is stable and moves only when a component
    # moves. The component order is pinned by sorting the labels.
    material = "\n".join(f"{k}={components[k]}" for k in sorted(components))
    composite = hashlib.sha256(material.encode("utf-8")).hexdigest()

    return {
        "policy_version": composite,
        "render_time_only": True,
        "in_hashed_run_log": False,
        "components": [
            {"name": name, "sha256": components[name]}
            for name in sorted(components)
        ],
        "note": (
            "Render-time policy version over the governing catalogs "
            "(regimes.yaml, controls.yaml) and the Warden rule set "
            "(transition-authority table). Derived at packet assembly, NOT folded "
            "into the hashed run-log, so the sealed run-log sha and byte-identical "
            "replay are untouched. An edit to any policy component moves this "
            "composite sha."),
    }


def policy_version_record(packet: dict) -> dict:
    """The packet-ready policy-version block, JSON-serializable.

    The `packet` argument is accepted for a uniform record(...) signature with the
    other derived blocks; the stamp is a pure function of the policy files and the
    rule set on disk, independent of the run, so it is the same for every run that
    loaded the same policy. Render-time only; never enters the hashed run-log."""
    return policy_version()
