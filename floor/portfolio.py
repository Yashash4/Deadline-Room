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


# ---------------------------------------------------------------------------
# Portfolio SLA / throughput roll-up (E6.4). A standing operations center is
# judged on its SLA, not on any single deadline: across EVERY sealed incident,
# the worst-case and median statutory margin, how many filings landed inside a
# near-breach window, how many runs ever breached, and the nearest deadline across
# the whole fleet. Every number is a pure read of the `clock_started` /
# `clock_stopped` entries ALREADY in the sealed run logs (the exact deadline and
# the exact filed-at instant), folded with the same deadline-minus-filed math the
# packet operability block renders. We never re-enter the clock engine and never
# call now(): same captures, same rollup on every platform. The SLA verdict is
# folded into the RANK 1 signed manifest, so editing any rollup number breaks the
# portfolio signature.
# ---------------------------------------------------------------------------

# The near-breach window an operations center watches: a filing that landed with
# less than this many hours of statutory margin is "near breach", a filing that
# landed past its deadline is a breach. 24h is the tightest statutory step in the
# regime set (the NIS2 early warning), so it is the natural near-breach band.
NEAR_BREACH_HOURS = 24.0


def _hours_between(deadline_iso: str, filed_iso: str) -> float:
    """Signed hours from filed-at to deadline (deadline minus filed-at), rounded to
    two decimals, the same recipe floor.telemetry uses for a stable receipt.
    Positive means statutory time remained at filing (margin); negative means the
    deadline was already past (a breach). Pure arithmetic over the two instants
    already recorded in the sealed log; no clock engine, no now()."""
    from datetime import datetime

    delta = datetime.fromisoformat(deadline_iso) - datetime.fromisoformat(filed_iso)
    return round(delta.total_seconds() / 3600.0, 2)


@dataclass(frozen=True)
class FiledMargin:
    """One filed statutory clock and the margin it landed with, read straight from
    the sealed log. `clock` and `correlation_id` identify the deadline; `regime` is
    the branch parsed from the correlation id; `deadline_utc` is the recorded
    deadline; `filed_utc` is the recorded stop instant; `margin_hours` is
    deadline minus filed-at; `breached` is True when the margin is negative. Every
    field derives from a `clock_started` / `clock_stopped` pair in the sealed log."""
    run: str
    clock: str
    correlation_id: str
    regime: str
    deadline_utc: str
    filed_utc: str
    margin_hours: float
    breached: bool


def _run_filed_margins(run_name: str, entries: list[dict]) -> list[FiledMargin]:
    """The filed-clock margins for one run, folded from its `clock_started` /
    `clock_stopped` entries. A `clock_started` carries the clock name and the
    statutory deadline; a matching `clock_stopped` (same correlation id) carries
    the filed-at instant. A clock that started but never stopped never filed and so
    contributes no margin (it is omitted, never a fabricated zero), mirroring the
    packet operability block. Deterministic: sorted by deadline then correlation id
    so the fold reads in statutory order on every platform."""
    started: dict[str, dict] = {}
    stopped: dict[str, str] = {}
    for entry in entries:
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            continue
        etype = entry.get("type")
        if etype == "clock_started":
            corr = str(payload.get("correlation_id", ""))
            if corr:
                started[corr] = payload
        elif etype == "clock_stopped":
            corr = str(payload.get("correlation_id", ""))
            ts = payload.get("ts")
            if corr and isinstance(ts, str):
                stopped[corr] = ts
    margins: list[FiledMargin] = []
    for corr, start in started.items():
        if corr not in stopped:
            continue
        deadline = str(start.get("deadline", ""))
        filed = stopped[corr]
        if not deadline or not filed:
            continue
        margin = _hours_between(deadline, filed)
        margins.append(FiledMargin(
            run=run_name, clock=str(start.get("clock", "")),
            correlation_id=corr, regime=_regime_of(corr),
            deadline_utc=deadline, filed_utc=filed,
            margin_hours=margin, breached=margin < 0))
    margins.sort(key=lambda m: (m.deadline_utc, m.correlation_id))
    return margins


def _run_started_deadlines(entries: list[dict]) -> list[str]:
    """Every statutory deadline a run STARTED a clock on (filed or not), so the
    fleet nearest-deadline is computed over all live clocks, not only filed ones.
    Sorted ascending; deterministic."""
    deadlines: list[str] = []
    for entry in entries:
        if entry.get("type") != "clock_started":
            continue
        payload = entry.get("payload", {})
        if isinstance(payload, dict):
            deadline = payload.get("deadline")
            if isinstance(deadline, str) and deadline:
                deadlines.append(deadline)
    return sorted(deadlines)


def _run_throughput(entries: list[dict]) -> dict:
    """The throughput counts for one run, folded from its protocol events, matching
    the packet operability throughput block exactly: `drafted` is the number of
    distinct regimes that started drafting, `released` (= `filings`) is the number
    of distinct regimes that reached human release, `suppressed` is the count of
    terminal suppress dispositions, and `diff_conflicts` is the count of
    contradiction-veto (`diff_blocked`) events. Pure counting over the sealed log;
    no LLM, no now()."""
    drafted: set[str] = set()
    released: set[str] = set()
    suppressed = 0
    diff_conflicts = 0
    for entry in entries:
        if entry.get("type") != "protocol_event":
            continue
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            continue
        event = payload.get("event")
        corr = str(payload.get("correlation_id", ""))
        regime = _regime_of(corr) or corr
        if event == "draft_started" and regime:
            drafted.add(regime)
        elif event == "human_released" and regime:
            released.add(regime)
        elif event == "suppress":
            suppressed += 1
        elif event == "diff_blocked":
            diff_conflicts += 1
    return {
        "drafted": len(drafted),
        "filings": len(released),
        "released": len(released),
        "suppressed": suppressed,
        "diff_conflicts": diff_conflicts,
    }


@dataclass(frozen=True)
class RunSla:
    """The SLA / throughput summary for one sealed run, folded from its log.

    `name` is the run-log file name; `mode` is the scenario branch parsed from the
    name; `margins` are the filed-clock margins; `throughput` is the per-run count
    block; `filings_landed` is the number of clocks that filed; `min_margin_hours`
    is the tightest margin any filing landed inside (None when nothing filed);
    `breaches` counts clocks that filed past their deadline; `nearest_deadline_utc`
    is the earliest deadline any clock STARTED on (filed or not). Every value is a
    deterministic read of the sealed log."""
    name: str
    mode: str
    margins: list[FiledMargin]
    throughput: dict
    filings_landed: int
    min_margin_hours: float | None
    breaches: int
    nearest_deadline_utc: str | None


def _mode_of(run_name: str) -> str:
    """The scenario mode carried in a run-log file name. A capture is named
    `run-<incident>-<mode>.jsonl` (e.g. `run-inc-8842-chaos.jsonl`), so the mode is
    the final dash-delimited token before the `.jsonl` suffix. A name that does not
    match that shape yields the empty string."""
    stem = run_name
    for suffix in (".jsonl",):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    if "-" not in stem:
        return ""
    return stem.rsplit("-", 1)[1]


def _run_sla(run: SealedRun) -> RunSla:
    """Fold one run's SLA / throughput summary from its sealed log entries."""
    entries = _entries_of(_canonical_jsonl(run.log_path))
    margins = _run_filed_margins(run.name, entries)
    throughput = _run_throughput(entries)
    filed = [m.margin_hours for m in margins]
    started = _run_started_deadlines(entries)
    return RunSla(
        name=run.name,
        mode=_mode_of(run.name),
        margins=margins,
        throughput=throughput,
        filings_landed=len(margins),
        min_margin_hours=min(filed) if filed else None,
        breaches=sum(1 for m in margins if m.breached),
        nearest_deadline_utc=started[0] if started else None,
    )


def _median(values: list[float]) -> float | None:
    """The median of a list of floats, rounded to two decimals for a stable
    receipt. The mean of the two middle values on an even-length list. None on an
    empty list. Pure and deterministic."""
    if not values:
        return None
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return round(ordered[mid], 2)
    return round((ordered[mid - 1] + ordered[mid]) / 2.0, 2)


@dataclass(frozen=True)
class PortfolioSla:
    """The fleet SLA / throughput roll-up across every attested sealed run, no LLM.

    `per_run` is the SORTED per-run SLA summary; `total_filings` is the count of
    filed clocks across the fleet; `total_breaches` is how many filed past their
    deadline; `worst_margin_hours` is the tightest margin any filing in the fleet
    landed inside, and `worst_margin_run` / `worst_margin_clock` name where it
    landed; `median_margin_hours` is the median filed margin across the fleet;
    `near_breach_count` is how many filings landed inside the near-breach window
    (margin under NEAR_BREACH_HOURS but not breached); `nearest_deadline_utc` is
    the single earliest deadline any clock started on across all runs;
    `ever_breached` is the fleet-level "did we EVER breach"; the `throughput_*`
    fields aggregate the per-run counts. Every value is a pure fold over the sealed
    clock and protocol entries, so it is safe to fold next to the signed root."""
    per_run: list[RunSla]
    total_filings: int
    total_breaches: int
    worst_margin_hours: float | None
    worst_margin_run: str
    worst_margin_clock: str
    median_margin_hours: float | None
    near_breach_count: int
    near_breach_hours: float
    nearest_deadline_utc: str | None
    ever_breached: bool
    throughput_drafted: int
    throughput_filings: int
    throughput_released: int
    throughput_suppressed: int
    throughput_diff_conflicts: int


def portfolio_sla(runs: list[SealedRun]) -> PortfolioSla:
    """Fold the fleet SLA / throughput roll-up over the ATTESTED sealed runs.

    Only runs that passed their per-run signature are folded (a flagged run never
    counts), so the rollup attests the same verified set as the Merkle root. For
    each run the filed-clock margins are read straight from its `clock_started` /
    `clock_stopped` entries (deadline minus filed-at, the same math the packet
    renders), the throughput counts are folded from its protocol events, and the
    nearest started deadline is taken. The fleet aggregates then follow: worst-case
    margin (and which run/clock owns it), median margin, near-breach count, breach
    count, the single nearest deadline across the fleet, and the summed throughput.
    Pure and deterministic: same captures, same rollup, no now(), no LLM."""
    attested = sorted(
        (r for r in runs if r.signature_valid), key=lambda r: r.name)
    per_run = [_run_sla(r) for r in attested]

    all_margins: list[FiledMargin] = []
    for run_sla in per_run:
        all_margins.extend(run_sla.margins)

    worst: FiledMargin | None = None
    for margin in all_margins:
        if worst is None or margin.margin_hours < worst.margin_hours:
            worst = margin

    nearest_candidates = sorted(
        r.nearest_deadline_utc for r in per_run
        if r.nearest_deadline_utc is not None)

    return PortfolioSla(
        per_run=per_run,
        total_filings=len(all_margins),
        total_breaches=sum(1 for m in all_margins if m.breached),
        worst_margin_hours=worst.margin_hours if worst else None,
        worst_margin_run=worst.run if worst else "",
        worst_margin_clock=worst.clock if worst else "",
        median_margin_hours=_median([m.margin_hours for m in all_margins]),
        near_breach_count=sum(
            1 for m in all_margins
            if not m.breached and m.margin_hours < NEAR_BREACH_HOURS),
        near_breach_hours=NEAR_BREACH_HOURS,
        nearest_deadline_utc=nearest_candidates[0] if nearest_candidates else None,
        ever_breached=any(m.breached for m in all_margins),
        throughput_drafted=sum(r.throughput["drafted"] for r in per_run),
        throughput_filings=sum(r.throughput["filings"] for r in per_run),
        throughput_released=sum(r.throughput["released"] for r in per_run),
        throughput_suppressed=sum(r.throughput["suppressed"] for r in per_run),
        throughput_diff_conflicts=sum(
            r.throughput["diff_conflicts"] for r in per_run),
    )


def sla_dict(sla: PortfolioSla) -> dict:
    """The canonical, sorted-key dict the SLA rollup serializes to inside the signed
    manifest. Mirrors the manifest's own canonicalization so a verifier (Python or
    browser) rebuilds identical bytes and the same digest. Every value is a count, a
    margin, or a sorted per-run row; no field carries generated prose."""
    return {
        "near_breach_count": sla.near_breach_count,
        "near_breach_hours": sla.near_breach_hours,
        "ever_breached": sla.ever_breached,
        "median_margin_hours": sla.median_margin_hours,
        "nearest_deadline_utc": sla.nearest_deadline_utc,
        "per_run": [
            {
                "name": r.name,
                "mode": r.mode,
                "filings_landed": r.filings_landed,
                "min_margin_hours": r.min_margin_hours,
                "breaches": r.breaches,
                "nearest_deadline_utc": r.nearest_deadline_utc,
                "throughput": dict(sorted(r.throughput.items())),
                "margins": [
                    {
                        "clock": m.clock,
                        "correlation_id": m.correlation_id,
                        "regime": m.regime,
                        "deadline_utc": m.deadline_utc,
                        "filed_utc": m.filed_utc,
                        "margin_hours": m.margin_hours,
                        "breached": m.breached,
                    }
                    for m in r.margins
                ],
            }
            for r in sla.per_run
        ],
        "total_breaches": sla.total_breaches,
        "total_filings": sla.total_filings,
        "throughput_diff_conflicts": sla.throughput_diff_conflicts,
        "throughput_drafted": sla.throughput_drafted,
        "throughput_filings": sla.throughput_filings,
        "throughput_released": sla.throughput_released,
        "throughput_suppressed": sla.throughput_suppressed,
        "worst_margin_clock": sla.worst_margin_clock,
        "worst_margin_hours": sla.worst_margin_hours,
        "worst_margin_run": sla.worst_margin_run,
    }


def sla_dict_digest(sla_obj: dict) -> str:
    """The sha256 of a canonical SLA DICT (sorted keys, no whitespace). Used by a
    verifier that holds the stored rollup straight from a manifest, so it can
    recompute the exact digest the signature folded in without rebuilding a
    `PortfolioSla`."""
    payload = json.dumps(
        sla_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sla_digest(sla: PortfolioSla) -> str:
    """The sha256 of the canonical SLA bytes: the value the PORTFOLIO signature
    folds in alongside the root, run count, and insights, so editing any rollup
    number moves this digest, which moves the signed payload, which breaks the
    signature."""
    return sla_dict_digest(sla_dict(sla))


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
    sla = portfolio_sla(runs)
    return {
        "portfolio_version": "1",
        "run_count": len(attested),
        "portfolio_root": merkle_root(heads),
        "insights": insights_dict(insights),
        "sla": sla_dict(sla),
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
    sla: PortfolioSla
    sla_sha256: str
    attested: list[SealedRun]
    flagged: list[SealedRun]


def attest_portfolio(runs: list[SealedRun]) -> PortfolioAttestation:
    """Build the portfolio attestation over the verified runs.

    Folds a Merkle root over the SORTED chain heads of every run that passed its
    per-run signature, alongside a canonical sorted manifest. Runs that failed
    verification are recorded in `flagged` and excluded from the root, never
    silently included. The cross-incident insights and the fleet SLA / throughput
    rollup are folded into the manifest, and their digests into the signed payload,
    so editing any finding or any rollup number breaks the portfolio signature.
    Pure and deterministic: the same set of sealed runs yields the same root and
    manifest digest on every build and platform."""
    attested = sorted(
        (r for r in runs if r.signature_valid), key=lambda r: r.name)
    flagged = sorted(
        (r for r in runs if not r.signature_valid), key=lambda r: r.name)
    insights = cross_incident_patterns(runs)
    sla = portfolio_sla(runs)
    manifest = _canonical_manifest(runs)
    return PortfolioAttestation(
        manifest=manifest,
        root=manifest["portfolio_root"],
        run_count=manifest["run_count"],
        manifest_sha256=manifest_digest(manifest),
        insights=insights,
        insights_sha256=insights_digest(insights),
        sla=sla,
        sla_sha256=sla_digest(sla),
        attested=attested,
        flagged=flagged,
    )


# ---------------------------------------------------------------------------
# Deterministic incident intake queue + status board (E6.6). A standing ops
# center is not a single incident: incidents arrive, are triaged, and move
# through states (queued -> active -> released -> closed). The operator watches
# a status board, and each running incident's status is READ from its sealed
# log, never asserted. This is a pure read over the same sealed entries the SLA
# rollup folds (the branch state-machine transitions and the started deadlines),
# plus a declarative set of PENDING intake records (web/data/intake.json) that
# have arrived but not yet run, and therefore sit in `queued`. The board sorts by
# nearest statutory deadline and surfaces the fleet worst-case. Zero LLM, no
# now(): same captures plus the same pending set yield the same board everywhere.
# ---------------------------------------------------------------------------

# The lifecycle a standing ops center moves an incident through, in order. The
# index in this tuple is the deterministic sort key for "stage": a queued
# incident outranks an active one on the board's nearest-deadline-then-stage sort
# only when their deadlines tie. These are the REAL dispositions the sealed log
# supports (a branch terminal state of `released`, `suppressed`, or `failed`), not
# a cosmetic relabel. `queued` is reserved for declarative pending records that
# have not run; the four running states below are read from a run's branches.
QUEUE_STAGES = ("queued", "active", "released", "suppressed", "failed", "closed")

# The settled (non-amendable in normal flow) terminal branch dispositions. A
# `released` branch is settled but reopenable via amendment; `suppressed` and
# `failed` are hard-terminal. A branch still in any other state is in flight.
_SETTLED_BRANCH_STATES = frozenset({"released", "suppressed", "failed"})


def _branch_terminal_states(entries: list[dict]) -> dict[str, str]:
    """The LAST state-machine `to_state` reached on each branch (correlation id),
    read straight from the run's `protocol_event` entries in log order. Each
    admitted protocol event carries the `to_state` the branch moved to, so the
    final one per correlation id is that branch's terminal status in the sealed
    record. Read-only: this asserts nothing the entries do not already say."""
    terminal: dict[str, str] = {}
    for entry in entries:
        if entry.get("type") != "protocol_event":
            continue
        payload = entry.get("payload", {})
        if not isinstance(payload, dict):
            continue
        if payload.get("admitted") is False:
            continue
        corr = str(payload.get("correlation_id", ""))
        to_state = payload.get("to_state")
        if corr and isinstance(to_state, str) and to_state:
            terminal[corr] = to_state
    return terminal


def _run_status(branch_states: dict[str, str]) -> str:
    """Roll a run's branch terminal states up to one honest board status.

    The status only ever reflects what the branches actually reached, never a
    greener label than the data supports:

      * any branch NOT in a settled disposition (still drafting, amending,
        awaiting signoff, ...) -> `active` (the incident is still in flight);
      * every branch settled and at least one `failed` -> `failed`;
      * every branch settled and at least one `suppressed` (none failed) ->
        `suppressed`;
      * every branch settled to `released` -> `released`;
      * no branches at all (no transitions in the log) -> `active` (it ran but
        the board cannot assert a terminal status, so it is never called closed).

    A run is reported `closed` only by the caller, never inferred here, because
    closure is an operator disposition layered over a settled record, not a state
    the Warden writes."""
    if not branch_states:
        return "active"
    states = set(branch_states.values())
    if not states <= _SETTLED_BRANCH_STATES:
        return "active"
    if "failed" in states:
        return "failed"
    if "suppressed" in states:
        return "suppressed"
    return "released"


@dataclass(frozen=True)
class QueueItem:
    """One incident on the status board, queued or running.

    `key` is a stable board identifier (the run-log name for a running incident,
    or the pending record's id for a queued one); `incident_id` is the incident it
    belongs to; `kind` is `run` for a sealed run or `pending` for a declarative
    intake record; `status` is the lifecycle stage (a value in QUEUE_STAGES),
    READ from the sealed log for a run and fixed to `queued` for a pending record;
    `mode` is the run's scenario branch (empty for pending); `regime` is the
    pending record's target regime (empty for a run, which spans regimes);
    `nearest_deadline_utc` is the earliest statutory deadline driving the sort
    (from the sealed clocks for a run, declared on a pending record); `branches`
    is the per-branch terminal state map for a run (empty for pending); `label` is
    a short human title for the board. Every field is a pure read."""
    key: str
    incident_id: str
    kind: str
    status: str
    mode: str
    regime: str
    nearest_deadline_utc: str | None
    branches: dict[str, str]
    label: str


def _pending_item(record: dict) -> QueueItem:
    """Build a `queued` board item from one declarative pending intake record.

    A pending record is an incident that has ARRIVED but not yet run, so its
    status is fixed to `queued`: the board never asserts a run status for an
    incident with no sealed log. The record declares its own nearest statutory
    deadline (it has not run, so no clock entry exists to read), an incident id, an
    optional target regime, and a short label. Missing fields degrade to empty
    strings / None rather than raising, so a sparse record still sorts."""
    incident_id = str(record.get("incident_id", ""))
    deadline = record.get("nearest_deadline_utc")
    if not isinstance(deadline, str) or not deadline:
        deadline = None
    key = str(record.get("id") or incident_id or "pending")
    label = str(record.get("label") or incident_id or key)
    return QueueItem(
        key=key,
        incident_id=incident_id,
        kind="pending",
        status="queued",
        mode="",
        regime=str(record.get("regime", "")),
        nearest_deadline_utc=deadline,
        branches={},
        label=label,
    )


def _run_item(run: SealedRun) -> QueueItem:
    """Build a board item from one sealed run, reading its terminal status.

    The per-branch terminal states are read from the run's protocol events and
    rolled up to one honest run status; the nearest deadline is the earliest the
    run STARTED a clock on (the same value the SLA rollup uses), so a still-active
    incident sorts by its tightest live deadline. Pure read of the sealed log."""
    entries = _entries_of(_canonical_jsonl(run.log_path))
    branch_states = _branch_terminal_states(entries)
    started = _run_started_deadlines(entries)
    incident_ids = sorted(_run_incident_ids(entries))
    incident_id = incident_ids[0] if incident_ids else ""
    return QueueItem(
        key=run.name,
        incident_id=incident_id,
        kind="run",
        status=_run_status(branch_states),
        mode=_mode_of(run.name),
        regime="",
        nearest_deadline_utc=started[0] if started else None,
        branches=dict(sorted(branch_states.items())),
        label=(_mode_of(run.name) or run.name).replace("_", " "),
    )


def _queue_sort_key(item: QueueItem) -> tuple:
    """The deterministic board sort: nearest statutory deadline first, then by
    lifecycle stage, then by a stable identifier. An item with no deadline sorts
    LAST (a high sentinel) so a dated incident never hides behind an undated one;
    ties on the deadline break by stage index (queued before active before
    settled) and finally by key, so the board is total-ordered and identical on
    every platform."""
    deadline = item.nearest_deadline_utc or "9999-12-31T23:59:59+00:00"
    try:
        stage = QUEUE_STAGES.index(item.status)
    except ValueError:
        stage = len(QUEUE_STAGES)
    return (deadline, stage, item.key)


@dataclass(frozen=True)
class QueueBoard:
    """The intake queue + status board over the sealed fleet and the pending set.

    `items` is every incident, running or queued, SORTED by nearest statutory
    deadline then lifecycle stage; `queued` / `active` / `released` / `suppressed`
    / `failed` / `closed` are the counts per stage (a closed count is always 0
    here because closure is an operator disposition the sealed log never asserts);
    `nearest_deadline_utc` is the single earliest deadline anywhere on the board
    (the next thing due), and `nearest_deadline_key` names the item that owns it;
    `worst_case_margin_hours` / `worst_case_run` / `worst_case_clock` surface the
    fleet worst-case statutory margin (folded by the SLA rollup), so the board
    flags the tightest filing the ops center has on record; `ever_breached` is the
    fleet-level breach flag. Every value is a pure, deterministic read."""
    items: list[QueueItem]
    queued: int
    active: int
    released: int
    suppressed: int
    failed: int
    closed: int
    nearest_deadline_utc: str | None
    nearest_deadline_key: str
    worst_case_margin_hours: float | None
    worst_case_run: str
    worst_case_clock: str
    ever_breached: bool


def queue_view(
    runs: list[SealedRun], pending: list[dict] | None = None
) -> QueueBoard:
    """Build the deterministic intake queue + status board over the sealed fleet.

    Each ATTESTED sealed run becomes one board item whose status is READ from its
    last per-branch state-machine transition (released / suppressed / failed /
    active), never asserted; a flagged run is excluded, matching the rest of the
    portfolio path. Declarative `pending` intake records (incidents that arrived
    but have not run) sit in `queued`, since the board never reports a run status
    for an incident with no sealed log. The combined set is sorted by nearest
    statutory deadline then lifecycle stage, and the fleet worst-case margin (from
    the SLA rollup) is surfaced so the tightest filing on record is flagged. Pure
    and deterministic: the same sealed runs plus the same pending set yield the
    same board on every platform, with no now() and no LLM."""
    attested = sorted(
        (r for r in runs if r.signature_valid), key=lambda r: r.name)
    items = [_run_item(r) for r in attested]
    for record in pending or []:
        if isinstance(record, dict):
            items.append(_pending_item(record))
    items.sort(key=_queue_sort_key)

    counts = {stage: 0 for stage in QUEUE_STAGES}
    for item in items:
        if item.status in counts:
            counts[item.status] += 1

    dated = [it for it in items if it.nearest_deadline_utc is not None]
    nearest_item = min(
        dated, key=_queue_sort_key) if dated else None

    sla = portfolio_sla(runs)
    return QueueBoard(
        items=items,
        queued=counts["queued"],
        active=counts["active"],
        released=counts["released"],
        suppressed=counts["suppressed"],
        failed=counts["failed"],
        closed=counts["closed"],
        nearest_deadline_utc=nearest_item.nearest_deadline_utc
        if nearest_item else None,
        nearest_deadline_key=nearest_item.key if nearest_item else "",
        worst_case_margin_hours=sla.worst_margin_hours,
        worst_case_run=sla.worst_margin_run,
        worst_case_clock=sla.worst_margin_clock,
        ever_breached=sla.ever_breached,
    )


def queue_dict(board: QueueBoard) -> dict:
    """The canonical, sorted-key dict the queue board serializes to for the web
    panel and any verifier. Every value is a count, a deadline, or a sorted board
    row; no field carries generated prose, so it mirrors the rest of the read
    layer's canonical shapes."""
    return {
        "counts": {
            "queued": board.queued,
            "active": board.active,
            "released": board.released,
            "suppressed": board.suppressed,
            "failed": board.failed,
            "closed": board.closed,
        },
        "nearest_deadline_utc": board.nearest_deadline_utc,
        "nearest_deadline_key": board.nearest_deadline_key,
        "worst_case_margin_hours": board.worst_case_margin_hours,
        "worst_case_run": board.worst_case_run,
        "worst_case_clock": board.worst_case_clock,
        "ever_breached": board.ever_breached,
        "items": [
            {
                "key": it.key,
                "incident_id": it.incident_id,
                "kind": it.kind,
                "status": it.status,
                "mode": it.mode,
                "regime": it.regime,
                "nearest_deadline_utc": it.nearest_deadline_utc,
                "branches": dict(sorted(it.branches.items())),
                "label": it.label,
            }
            for it in board.items
        ],
    }
