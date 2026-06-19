"""Signed portfolio attestation: one receipt over a whole fleet of sealed runs.

A per-run signature proves a SINGLE incident's run-log was not tampered with.
It says nothing about the fleet: an operator standing up a breach-reporting
operations center runs many incidents, and the question an auditor then asks is
not "is run X intact" but "is the WHOLE set of runs intact, and was no run
silently dropped from the record". A bare folder of per-run signatures cannot
answer the second half: delete one run's files and every surviving signature
still verifies, so the absence is invisible.

This module closes that gap with a Merkle root over the chain-heads of every
sealed run. Each run already carries a per-entry chain head (warden/chain.py)
that summarizes its exact ordered, complete sequence. Folding the SORTED set of
those heads into one Merkle root yields a single value that summarizes the whole
fleet: edit one byte of any run and that run's chain head moves, which moves the
root; drop a run and the root is computed over a smaller set, which also moves
it. A signature over that root (warden/portfolio_signing.py, under a DISTINCT
label so it is never confused with a per-run receipt) therefore proves, in one
verification, that the entire fleet is untampered and complete.

READ-ONLY over the sealed captures. This module discovers, re-verifies, and
folds; it never writes a run log or a per-run signature. The per-run sealed bytes
and their signatures stay byte-frozen. A run that fails its own per-run signature
is FLAGGED and excluded from the attested set, never silently folded in, so the
root only ever attests runs that independently verify.

CANONICAL-LF read recipe. The per-run seal is taken over
`path.read_text(encoding="utf-8").encode("utf-8")` (LF-canonical), NOT the raw
on-disk bytes, which on Windows may carry CRLF. Every read here uses that exact
recipe so the recomputed sha and chain head match the sealed signature on every
platform.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from warden.chain import chain_head
from warden.signing import verify_run_log_jsonl


def _canonical_jsonl(path: Path) -> str:
    """The LF-canonical run-log string the per-run seal is taken over.

    The seal is computed from `read_text(encoding="utf-8").encode("utf-8")`, so a
    verifier must read with the SAME recipe (utf-8 decode) rather than the raw
    on-disk bytes, which on Windows may carry CRLF line endings that the sealed
    sha never saw. Returning the decoded string lets the caller both re-verify the
    signature and recompute the chain head from one canonical source."""
    return path.read_text(encoding="utf-8")


def _sha256_of(jsonl: str) -> str:
    """The run-log integrity sha over the LF-canonical bytes, matching the seal."""
    return hashlib.sha256(jsonl.encode("utf-8")).hexdigest()


def _chain_head_of(jsonl: str) -> str:
    """The per-entry chain head over the run log's entries, recomputed read-only
    from the canonical bytes (the same value warden/chain.head_for_log produces
    for a loaded RunLog, derived here straight from the canonical string)."""
    entries = [json.loads(line) for line in jsonl.splitlines() if line.strip()]
    return chain_head(entries)


@dataclass(frozen=True)
class SealedRun:
    """One discovered run and the verdict of re-verifying it.

    `name` is the run-log file name (a stable identifier in the manifest);
    `sha256` and `chain_head` are recomputed from the LF-canonical bytes;
    `signature_valid` records whether the sibling per-run signature verified over
    those recomputed values; `flag` names why a run was excluded when it did not
    verify (empty string when the run is sound). Only runs with
    `signature_valid is True` are folded into the Merkle root."""
    name: str
    log_path: Path
    sig_path: Path
    sha256: str
    chain_head: str
    signature_valid: bool
    flag: str


def _sidecar_for(log_path: Path) -> Path:
    """The detached per-run signature sidecar that sits beside a run log."""
    return log_path.with_suffix(log_path.suffix + ".sig.json")


def load_portfolio(data_dir: str | Path) -> list[SealedRun]:
    """Discover every sealed run under `data_dir` and re-verify each one.

    A run is any `run-*.jsonl` that has a sibling `<name>.sig.json`. For each, the
    LF-canonical bytes are read, the sha256 and chain head are recomputed from
    them, and the sibling per-run signature is re-verified over those recomputed
    values via warden.signing.verify_run_log_jsonl. A run whose signature does NOT
    verify (or whose sidecar is missing or malformed) is returned with
    `signature_valid=False` and a populated `flag`; it is discovered but will be
    excluded from the attested set by `attest_portfolio`. The list is sorted by
    file name so discovery is deterministic regardless of filesystem order."""
    data_path = Path(data_dir)
    runs: list[SealedRun] = []
    for log_path in sorted(data_path.glob("run-*.jsonl")):
        sig_path = _sidecar_for(log_path)
        jsonl = _canonical_jsonl(log_path)
        sha = _sha256_of(jsonl)
        head = _chain_head_of(jsonl)
        if not sig_path.exists():
            runs.append(SealedRun(
                name=log_path.name, log_path=log_path, sig_path=sig_path,
                sha256=sha, chain_head=head, signature_valid=False,
                flag="no per-run signature sidecar found"))
            continue
        try:
            record = json.loads(sig_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            runs.append(SealedRun(
                name=log_path.name, log_path=log_path, sig_path=sig_path,
                sha256=sha, chain_head=head, signature_valid=False,
                flag=f"per-run signature sidecar unreadable: {exc}"))
            continue
        valid = verify_run_log_jsonl(jsonl, record)
        flag = "" if valid else "per-run signature does not verify"
        runs.append(SealedRun(
            name=log_path.name, log_path=log_path, sig_path=sig_path,
            sha256=sha, chain_head=head, signature_valid=valid, flag=flag))
    return runs


def merkle_root(leaves: list[str]) -> str:
    """Fold a list of hex leaf digests into one Merkle root.

    Each leaf is first hashed with a domain-separating `leaf:` prefix; interior
    nodes hash the concatenation of their two children with a `node:` prefix. An
    odd node at any level is promoted (duplicated) rather than hashed against a
    sibling, the standard odd-leaf rule. An empty leaf set folds to the hash of
    the empty string, a stable sentinel. The leaf-vs-node domain separation makes
    a second-preimage collision (passing an interior digest off as a leaf)
    infeasible. Callers pass the leaves already SORTED so the root is a pure
    function of the SET of chain heads, independent of discovery order."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = [
        hashlib.sha256(f"leaf:{leaf}".encode("utf-8")).hexdigest()
        for leaf in leaves
    ]
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(
                hashlib.sha256(
                    f"node:{left}{right}".encode("utf-8")).hexdigest())
        level = nxt
    return level[0]


# ---------------------------------------------------------------------------
# Cross-incident pattern detection (E6.3). A capability impossible from a SINGLE
# run: "is this attacker a repeat offender against us, and did the contradiction
# veto fire on the same field type more than once across our incidents?" Both are
# pure deterministic folds over the SEALED run-log entries, with ZERO LLM near the
# signed object: counting and grouping only, never a generated trend narrative.
# ---------------------------------------------------------------------------


def _entries_of(jsonl: str) -> list[dict]:
    """The run-log entries of one sealed log, parsed read-only from the canonical
    bytes (the same recipe the seal and chain head are taken over)."""
    return [json.loads(line) for line in jsonl.splitlines() if line.strip()]


def _incident_of(correlation_id: str) -> str:
    """The incident id carried in a correlation id. A correlation id is
    `<incident>:<regime>` (e.g. `inc-8842:nis2`), so the incident is the part
    before the first colon. A correlation id without a colon is its own incident
    id. Empty input yields the empty string, which the folds ignore."""
    if not correlation_id:
        return ""
    return correlation_id.split(":", 1)[0]


def _regime_of(correlation_id: str) -> str:
    """The regime branch carried in a correlation id (`<incident>:<regime>`): the
    part after the first colon, empty when the id carries no regime."""
    if not correlation_id or ":" not in correlation_id:
        return ""
    return correlation_id.split(":", 1)[1]


def _conflict_field(conflict: str) -> str:
    """The disputed fact key named in a Warden conflict string, parsed
    deterministically (no LLM). A conflict reads
    `<REGIME> says <field>=<value>; <REGIME> says <field>=<value>. ...`, so the
    field is the token between the first ` says ` and the first `=` after it. A
    string that does not match that shape yields the empty string and is skipped,
    so a future conflict format never silently miscounts."""
    marker = " says "
    start = conflict.find(marker)
    if start < 0:
        return ""
    rest = conflict[start + len(marker):]
    eq = rest.find("=")
    if eq < 0:
        return ""
    return rest[:eq].strip()


def _run_incident_ids(entries: list[dict]) -> set[str]:
    """Every incident id referenced anywhere in a run's entries, drawn from
    correlation ids on the entries that carry them plus any explicit
    `incident_id` payload field. A single sealed run normally references exactly
    one incident; reading the set (not assuming one) keeps the fold correct for a
    multi-incident corpus."""
    found: set[str] = set()
    for entry in entries:
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            continue
        explicit = payload.get("incident_id")
        if isinstance(explicit, str) and explicit:
            found.add(explicit)
        inc = _incident_of(str(payload.get("correlation_id", "")))
        if inc:
            found.add(inc)
    return found


def _run_attacker(entries: list[dict]) -> str:
    """The named threat actor for a run, read from the first entry payload that
    carries an `attacker` field. Returns the empty string when no entry names one
    (the current single-incident captures do not, so the attacker fold reports no
    repeat offender on them). Read-only: this never writes the field."""
    for entry in entries:
        payload = entry.get("payload", {})
        if isinstance(payload, dict):
            value = payload.get("attacker")
            if isinstance(value, str) and value:
                return value
    return ""


def _run_regulated_entity(entries: list[dict]) -> str:
    """The regulated entity (the filer) for a run, read from the first entry
    payload that carries a `regulated_entity` field, empty when none does."""
    for entry in entries:
        payload = entry.get("payload", {})
        if isinstance(payload, dict):
            value = payload.get("regulated_entity")
            if isinstance(value, str) and value:
                return value
    return ""


@dataclass(frozen=True)
class PortfolioInsights:
    """Cross-incident findings folded from the SEALED run logs, no LLM.

    `repeat_offenders` maps each attacker that appears across `>= 2` distinct
    incidents to the SORTED list of those incident ids (the fleet-level question a
    single run cannot answer). `attacker_incident_counts` carries every attacker's
    distinct-incident count for context. `veto_field_recurrence` maps each
    disputed fact key to how many times the contradiction veto (a `diff_blocked`
    protocol event) fired on it across all incidents, so a field type vetoed twice
    is visible. `suppress_by_regime` counts terminal `suppress` dispositions per
    regime. `incidents_by_entity` groups distinct incident ids under each
    regulated entity. Every value is a pure count or grouping; the object carries
    no generated prose, so it is safe to fold next to the signed root."""
    repeat_offenders: dict[str, list[str]]
    attacker_incident_counts: dict[str, int]
    veto_field_recurrence: dict[str, int]
    suppress_by_regime: dict[str, int]
    incidents_by_entity: dict[str, list[str]]


def cross_incident_patterns(runs: list[SealedRun]) -> PortfolioInsights:
    """Fold cross-incident patterns over the ATTESTED sealed runs, deterministically.

    Only runs that passed their per-run signature are folded (a flagged run is
    never counted), so the findings attest the same verified set as the Merkle
    root. The fold is pure counting and grouping over the run-log entries:

      * repeat offenders: distinct incident ids per `attacker`, flagging any
        attacker spanning `>= 2` incidents;
      * field-level veto recurrence: `diff_blocked` protocol events bucketed by
        the disputed fact key (parsed from the matching round's `diff` conflicts),
        across incidents;
      * suppress dispositions per regime (from each `suppress` protocol event's
        correlation id);
      * incidents grouped by regulated entity.

    Same input, same output on every platform: sorted keys, sorted incident lists,
    no `now()`, no randomness, no LLM."""
    attested = sorted(
        (r for r in runs if r.signature_valid), key=lambda r: r.name)

    attacker_incidents: dict[str, set[str]] = defaultdict(set)
    entity_incidents: dict[str, set[str]] = defaultdict(set)
    veto_fields: dict[str, int] = defaultdict(int)
    suppress_regimes: dict[str, int] = defaultdict(int)

    for run in attested:
        entries = _entries_of(_canonical_jsonl(run.log_path))
        incident_ids = _run_incident_ids(entries)
        attacker = _run_attacker(entries)
        entity = _run_regulated_entity(entries)
        if attacker:
            attacker_incidents[attacker].update(incident_ids)
        if entity:
            entity_incidents[entity].update(incident_ids)

        # The disputed fact key for each round, parsed once from the diff entries,
        # so a diff_blocked protocol event can be attributed to its field.
        round_field: dict[object, str] = {}
        for entry in entries:
            if entry.get("type") != "diff":
                continue
            payload = entry.get("payload", {})
            key = payload.get("round", payload.get("phase"))
            for conflict in payload.get("conflicts", []):
                field = _conflict_field(str(conflict))
                if field:
                    round_field.setdefault(key, field)

        sole_field = next(iter(set(round_field.values())), "") \
            if len(set(round_field.values())) == 1 else ""

        for entry in entries:
            if entry.get("type") != "protocol_event":
                continue
            payload = entry.get("payload", {})
            event = payload.get("event")
            if event == "diff_blocked":
                # Attribute the block to the round's disputed field; fall back to
                # the run's single disputed field when the event carries no round.
                field = sole_field
                if not field and len(set(round_field.values())) == 1:
                    field = next(iter(set(round_field.values())), "")
                if field:
                    veto_fields[field] += 1
            elif event == "suppress":
                regime = _regime_of(str(payload.get("correlation_id", "")))
                if regime:
                    suppress_regimes[regime] += 1

    repeat_offenders = {
        attacker: sorted(incidents)
        for attacker, incidents in attacker_incidents.items()
        if len(incidents) >= 2
    }
    attacker_incident_counts = {
        attacker: len(incidents)
        for attacker, incidents in attacker_incidents.items()
    }
    incidents_by_entity = {
        entity: sorted(incidents)
        for entity, incidents in entity_incidents.items()
    }
    return PortfolioInsights(
        repeat_offenders=dict(sorted(repeat_offenders.items())),
        attacker_incident_counts=dict(sorted(attacker_incident_counts.items())),
        veto_field_recurrence=dict(sorted(veto_fields.items())),
        suppress_by_regime=dict(sorted(suppress_regimes.items())),
        incidents_by_entity=dict(sorted(incidents_by_entity.items())),
    )


def insights_dict(insights: PortfolioInsights) -> dict:
    """The canonical, sorted-key dict the insights serialize to inside the signed
    manifest. Mirrors the manifest's own canonicalization so a verifier (Python or
    browser) rebuilds identical bytes and the same digest. Every value is a count
    or a sorted grouping; no field carries generated prose."""
    return {
        "repeat_offenders": {
            k: list(v) for k, v in sorted(insights.repeat_offenders.items())
        },
        "attacker_incident_counts": dict(
            sorted(insights.attacker_incident_counts.items())),
        "veto_field_recurrence": dict(
            sorted(insights.veto_field_recurrence.items())),
        "suppress_by_regime": dict(sorted(insights.suppress_by_regime.items())),
        "incidents_by_entity": {
            k: list(v) for k, v in sorted(insights.incidents_by_entity.items())
        },
    }


def insights_dict_digest(insights_obj: dict) -> str:
    """The sha256 of a canonical insights DICT (sorted keys, no whitespace). Used
    by a verifier that holds the stored insights object straight from a manifest,
    so it can recompute the exact digest the signature folded in without
    rebuilding a `PortfolioInsights`."""
    payload = json.dumps(
        insights_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def insights_digest(insights: PortfolioInsights) -> str:
    """The sha256 of the canonical insights bytes: the value the PORTFOLIO
    signature folds in alongside the root and run count, so editing any finding
    moves this digest, which moves the signed payload, which breaks the
    signature."""
    return insights_dict_digest(insights_dict(insights))


def _canonical_manifest(runs: list[SealedRun]) -> dict:
    """The canonical, sorted manifest the portfolio signature is taken over.

    Lists every attested run by name with its recomputed sha256 and chain head,
    plus the Merkle root over the SORTED chain heads and the run count. Built only
    from runs that passed their per-run signature; flagged runs are excluded so
    the root never attests an unverified run. The dict carries sorted-key data so
    `canonical_manifest_bytes` renders it deterministically."""
    attested = sorted(
        (r for r in runs if r.signature_valid), key=lambda r: r.name)
    heads = sorted(r.chain_head for r in attested)
    insights = cross_incident_patterns(runs)
    return {
        "portfolio_version": "1",
        "run_count": len(attested),
        "portfolio_root": merkle_root(heads),
        "insights": insights_dict(insights),
        "runs": [
            {"name": r.name, "sha256": r.sha256, "chain_head": r.chain_head}
            for r in attested
        ],
    }


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """The exact bytes the canonical manifest renders to: sorted keys, no
    whitespace, UTF-8. Mirrors the run log's own canonicalization so a verifier
    (in Python or a browser) rebuilds identical bytes and recomputes the same
    digest."""
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_digest(manifest: dict) -> str:
    """The sha256 of the canonical manifest bytes: the value the portfolio
    signature ultimately commits to, alongside the root and run count."""
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


@dataclass(frozen=True)
class PortfolioAttestation:
    """The signed roll-up over a fleet of sealed runs.

    `manifest` is the canonical sorted manifest (run count, Merkle root, per-run
    name/sha/head); `root` is its Merkle root over the sorted chain heads;
    `run_count` is the number of ATTESTED runs; `manifest_sha256` is the digest of
    the canonical manifest bytes; `insights` is the cross-incident finding object
    folded into the manifest; `insights_sha256` is its digest, which the portfolio
    signature folds into the signed payload so editing any finding breaks the
    signature; `flagged` carries any discovered runs that failed their per-run
    signature and were therefore excluded, so the exclusion is visible rather than
    silent. The detached portfolio signature is added by
    warden/portfolio_signing.py and stored beside this attestation."""
    manifest: dict
    root: str
    run_count: int
    manifest_sha256: str
    insights: PortfolioInsights
    insights_sha256: str
    attested: list[SealedRun]
    flagged: list[SealedRun]


def attest_portfolio(runs: list[SealedRun]) -> PortfolioAttestation:
    """Build the portfolio attestation over the verified runs.

    Folds a Merkle root over the SORTED chain heads of every run that passed its
    per-run signature, alongside a canonical sorted manifest. Runs that failed
    verification are recorded in `flagged` and excluded from the root, never
    silently included. Pure and deterministic: the same set of sealed runs yields
    the same root and manifest digest on every build and platform."""
    attested = sorted(
        (r for r in runs if r.signature_valid), key=lambda r: r.name)
    flagged = sorted(
        (r for r in runs if not r.signature_valid), key=lambda r: r.name)
    insights = cross_incident_patterns(runs)
    manifest = _canonical_manifest(runs)
    return PortfolioAttestation(
        manifest=manifest,
        root=manifest["portfolio_root"],
        run_count=manifest["run_count"],
        manifest_sha256=manifest_digest(manifest),
        insights=insights,
        insights_sha256=insights_digest(insights),
        attested=attested,
        flagged=flagged,
    )
