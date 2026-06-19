"""The offline seal worker: run a posted incident through the floor and seal it.

The write path of the governance service accepts a new incident and must produce
a sealed, signed run-log in the corpus WITHOUT a live Band room (the account is at
its room cap, and a deployment must work offline anyway). This worker drives the
SAME in-process FakeBand harness `web/capture_scenarios.py` uses: the full floor
orchestration over a `FakeRoom`, with the drafter stubs returning deterministic
per-regime prose so the run is reproducible with no API keys.

The worker NEVER mutates the Warden path and NEVER overwrites a frozen capture.
The four sealed single-incident captures (run-inc-8842-{normal,inject_contradiction,
chaos,amendment}.jsonl) are byte-frozen; a posted incident is sealed under a
DISTINCT, unique run-log name carrying the posted incident id and a short token, so
discovery folds it into the portfolio alongside the frozen runs without touching a
single frozen byte.

Sealing recipe, identical to the capture scripts:
  1. Run the floor offline -> an Examiner Packet whose replay block carries the
     detached Ed25519 signature over the run-log bytes.
  2. Assert the bundled run log's sha matches the packet's claimed replay sha and
     that replay is byte-identical (the floor already verifies this; we re-assert).
  3. Write the run-log JSONL and its `<name>.sig.json` sidecar into the corpus, so
     `floor.portfolio.load_portfolio` discovers and re-verifies it like any other
     sealed run. The seal is the durable record; the service caches nothing.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from floor.run_floor import DRAFTER_ROLES, run_floor
from floor.shell_adapter import FakeBandClient, FakeRoom
from warden.replay import RunLog
from warden.signing import verify_run_log_jsonl

# The scenario beats a posted incident may run. These are the offline, no-LLM,
# reproducible floor modes the capture harness already exercises; the write path
# defaults to the clean "normal" beat. A posted mode outside this set is rejected
# loud rather than silently coerced, so the service never runs an unintended beat.
ALLOWED_MODES = ("normal", "inject_contradiction", "chaos", "amendment")

# A conservative incident-id shape: lowercase letters, digits, and dashes only, so
# the sealed run-log file name is always a safe, predictable path component and can
# never escape the corpus directory or collide with an unrelated artifact.
_INCIDENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


@dataclass(frozen=True)
class IncidentRequest:
    """A posted incident to run and seal.

    `incident_id` names the incident on the board and in the sealed file name;
    `mode` selects the offline floor beat (a value in ALLOWED_MODES); `label` is an
    optional short human title carried back in the response. Validation is strict:
    a malformed incident id or an unknown mode is rejected before any run, so the
    worker never seals an ambiguous artifact."""
    incident_id: str
    mode: str = "normal"
    label: str = ""

    def validate(self) -> None:
        """Reject a malformed request loudly before running anything."""
        if not _INCIDENT_ID_RE.match(self.incident_id):
            raise ValueError(
                "incident_id must be lowercase alphanumeric with dashes, "
                f"1-63 chars; got {self.incident_id!r}")
        if self.mode not in ALLOWED_MODES:
            raise ValueError(
                f"mode must be one of {ALLOWED_MODES}; got {self.mode!r}")


@dataclass(frozen=True)
class SealedIncident:
    """The result of sealing one posted incident into the corpus.

    `run_log_name` is the sealed run-log file name (the stable board key);
    `sha256` is the run-log integrity digest; `chain_head` is the per-entry chain
    head folded into the portfolio Merkle root; `signature_valid` records that the
    detached per-run signature re-verifies over the sealed bytes; `incident_id` and
    `mode` echo the request. Every field is read straight from the sealed
    artifact, not asserted by the worker."""
    incident_id: str
    mode: str
    run_log_name: str
    sha256: str
    chain_head: str
    signature_valid: bool


def _build_clients() -> tuple[FakeRoom, dict]:
    """The in-process FakeBand clients the offline floor runs over, exactly as the
    capture harness builds them: a Warden, a Triage agent, and one drafter per
    regime, all bound to one `FakeRoom`. No network, no keys."""
    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for role in DRAFTER_ROLES:
        clients[role.branch] = FakeBandClient(
            room, f"{role.branch}-id", f"{role.branch}_drafter",
            f"draft:{role.branch}")
    return room, clients


def _draft_fns(incident_id: str) -> dict:
    """Deterministic per-regime drafter stubs for the offline run.

    Each stub returns a short, reproducible regulatory-style statement naming the
    posted incident and the regime, so the structured [CLAIMS] block the floor
    appends parses off genuine labelled text rather than an empty string. Pure
    string assembly: no LLM, no now(), so the sealed run is byte-reproducible. For
    the amendment beat the two reconciliation characterizations are stubbed to one
    shared sentence, mirroring the capture harness, so the propose/concur exchange
    runs offline."""
    def make(regime: str):
        def fn(_claim_facts) -> str:
            return (
                f"Regulatory notification for incident {incident_id} under the "
                f"{regime.upper()} regime. The regulated entity reports the "
                "incident from the authoritative fact-record; scope, timing, and "
                "containment are stated as recorded.")
        return fn

    fns: dict = {role.branch: make(role.regime) for role in DRAFTER_ROLES}

    def characterize(_counterpart_text: str) -> str:
        return (
            f"The revised forensic analysis for incident {incident_id} reconciled "
            "the affected-record count across filings.")

    fns["sec:characterize"] = characterize
    fns["nis2:characterize"] = characterize
    return fns


def run_incident_offline(
    request: IncidentRequest, data_dir: str | Path
) -> SealedIncident:
    """Run a posted incident through the floor OFFLINE and seal it into the corpus.

    The floor runs over the in-process FakeBand harness (no live room, no keys),
    producing an Examiner Packet whose replay block carries the detached Ed25519
    signature over the run-log bytes. The sealed run log and its signature sidecar
    are then written into `data_dir` under a UNIQUE name derived from the posted
    incident id, the mode, and a short token, so the new run is folded into the
    portfolio without overwriting any frozen capture. The seal is verified before
    it lands: the bundled log sha must match the packet's replay sha, replay must
    be byte-identical, and the detached signature must verify over the sealed bytes.

    The worker mutates nothing in the Warden path and caches nothing: the written
    artifact is the durable record, and the service re-reads it from disk."""
    request.validate()
    target_dir = Path(data_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    # The floor names its run log run-<INCIDENT_ID>-<mode>.jsonl where INCIDENT_ID
    # is a module constant (inc-8842). Run into an ISOLATED scratch directory so the
    # generic name never touches the corpus, then move the sealed bytes into the
    # corpus under a unique, posted-incident name. This keeps the frozen captures
    # untouched even though the floor always emits the same internal id.
    with tempfile.TemporaryDirectory(prefix="deadline-room-seal-") as scratch:
        room, clients = _build_clients()
        packet = run_floor(
            out_dir=scratch, mode=request.mode, clients=clients,
            draft_fns=_draft_fns(request.incident_id))

        produced = sorted(Path(scratch).glob("run-*.jsonl"))
        if len(produced) != 1:
            raise RuntimeError(
                "offline floor run did not produce exactly one run log "
                f"(found {len(produced)})")
        src_log = produced[0]

        log = RunLog.load(src_log)
        replay = packet["replay"]
        if log.sha256() != replay["original_sha256"]:
            raise RuntimeError(
                "sealed log hash does not match the packet replay hash")
        if replay.get("byte_identical") is not True:
            raise RuntimeError("offline replay was not byte-identical")

        signature = replay["signature"]
        jsonl = log.to_jsonl()
        if not verify_run_log_jsonl(jsonl, signature):
            raise RuntimeError(
                "the packet signature does not verify over the run-log bytes")

        token = uuid.uuid4().hex[:12]
        run_log_name = (
            f"run-{request.incident_id}-{request.mode}-{token}.jsonl")
        dst_log = target_dir / run_log_name
        dst_sig = dst_log.with_suffix(dst_log.suffix + ".sig.json")

        shutil.move(str(src_log), str(dst_log))
        dst_sig.write_text(
            json.dumps(signature, indent=2) + "\n", encoding="utf-8")

    # Re-read the sealed bytes from the corpus so the returned summary derives from
    # the durable record, not from in-flight worker state.
    sealed_jsonl = dst_log.read_text(encoding="utf-8")
    sealed_log = RunLog.load(dst_log)
    from warden.chain import head_for_log

    return SealedIncident(
        incident_id=request.incident_id,
        mode=request.mode,
        run_log_name=run_log_name,
        sha256=sealed_log.sha256(),
        chain_head=head_for_log(sealed_log),
        signature_valid=verify_run_log_jsonl(sealed_jsonl, signature),
    )
