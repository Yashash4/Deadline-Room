"""Independent third-party provenance verifier: trust the math, not us.

This is the tool a REGULATOR or any third party runs on THEIR machine, offline,
against a filing set's packet JSON and its sealed sidecars ALONE. It trusts only
the committed Warden public key, nothing else in this repo and nothing on the
network. From those bytes it RE-DERIVES the whole provenance chain and reports
whether it holds, in a plain attestation a non-cryptographer can read.

WHY THIS IS DIFFERENT FROM THE OTHER VERIFIERS. scripts/verify_signature.py,
verify_intoto.py, verify_timestamp.py, and audit_run.py are framed as the
project's own demo steps; they read defaults, lean on the packet's replay block,
and speak the team's language. This one is framed as the OUTSIDE party's receipt:
it takes the sealed files, recomputes every value the seal commits to FROM the
bytes (never trusting a recorded field), and prints one self-contained
attestation paragraph plus the honest demo-key caveat. A supervisor hands its
output, and its exit code, to their own audit team.

THE CANONICAL RECIPE (the one subtlety that matters). The run-log seal, the hash
chain, and the Ed25519 signature are all taken over the run-log's CANONICAL bytes:
UTF-8, Unix LF line endings, exactly what `RunLog.to_jsonl()` emits. A run-log
file checked out on Windows carries CRLF on disk, so a naive `sha256` of the raw
file bytes does NOT match the seal. This verifier reads the run log with
`read_text(encoding="utf-8")`, whose universal-newline translation collapses CRLF
back to the canonical LF the seal was taken over, then re-encodes UTF-8. That is
the recipe the seal uses, and it is what makes the recomputed sha match the sealed
sha byte for byte on every platform. One genuinely flipped byte (not a line-ending
difference) moves the sha, moves the chain head, and fails the signature, which is
the whole point.

WHAT IT CHECKS, all re-derived from the sealed bytes + the committed public key:

  1. RUN-LOG SHA. sha256 of the run-log's canonical bytes. Compared against the
     sha the signature record commits to.
  2. CHAIN HEAD. The per-entry hash chain folded fresh from the run-log entries.
     Compared against the head the signature record commits to. A reorder or an
     omission moves this.
  3. SIGNATURE. The detached Ed25519 signature over the bound payload
     {sha256, chain_head, attestation_sha, fact_record_hash}, rebuilt from the
     recomputed sha and head plus the record's two derived digests, verified
     against the COMMITTED public key (not the key embedded in the record, unless
     they agree). A flipped field, a reorder, a tampered margin, or a swapped
     input all fail here.
  4. IN-TOTO / DSSE (when the .intoto.json sidecar is present). The DSSE envelope
     signature verifies over the PAE, and the in-toto subject digest equals the
     recomputed run-log sha. Names our provenance in the recognized standard.
  5. RFC 3161 TIMESTAMP (when the .tst.json sidecar is present). The demo TSA
     signature verifies over the TSTInfo, and the timestamped messageImprint
     equals the artifact digest rebuilt from the signature record. Anchors WHEN.

  py scripts/verify_thirdparty.py                       (all sealed scenarios)
  py scripts/verify_thirdparty.py <scenario>            (one: normal, chaos, ...)
  py scripts/verify_thirdparty.py <packet.json>         (a packet handed to you)
  py scripts/verify_thirdparty.py <packet.json> <run-log.jsonl>

Exit 0 only when EVERY present check verifies on EVERY target; nonzero naming the
first failure otherwise. The committed public key the verifier trusts is printed,
with its fingerprint, and the honest demo-key caveat prints every time.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from warden.chain import chain_head  # noqa: E402
from warden.intoto import (  # noqa: E402
    sidecar_path_for as intoto_sidecar_for,
    statement_of_envelope,
    verify_dsse_envelope,
)
from warden.signing import (  # noqa: E402
    DEMO_KEY_CAVEAT,
    bound_payload_bytes,
    fingerprint,
    load_public_key_hex,
    verify_bytes,
)
from warden.timestamp import (  # noqa: E402
    DEMO_TSA_CAVEAT,
    sidecar_path_for as tst_sidecar_for,
    verify_timestamp_token,
)

# The four byte-frozen sealed captures a third party verifies against by default.
DATA = REPO_ROOT / "web" / "data"
SEALED_SCENARIOS = ("normal", "inject_contradiction", "chaos", "amendment")


def canonical_run_log_text(run_log_path: Path) -> str:
    """Read a run log as the CANONICAL text the seal was taken over.

    `read_text(encoding="utf-8")` applies universal-newline translation, so a file
    stored with CRLF line endings (Windows checkout) is read back with the LF line
    endings `RunLog.to_jsonl()` emits and the signature, chain, and sha were all
    computed over. Re-encoding this text UTF-8 yields the exact bytes the seal
    commits to, independent of how the file was stored on disk. This is the single
    recipe every recomputed value here depends on."""
    return run_log_path.read_text(encoding="utf-8")


def recompute_sha256(canonical_text: str) -> str:
    """sha256 of the run-log's canonical UTF-8 bytes: the run-log integrity hash,
    recomputed from the bytes the verifier holds, never read from any record."""
    return hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()


def recompute_chain_head(canonical_text: str) -> str:
    """The per-entry hash chain head, folded fresh from the run-log entries parsed
    out of the canonical text. A reorder or an omission moves this; it is derived,
    never trusted from a field."""
    entries = [
        json.loads(line) for line in canonical_text.splitlines() if line.strip()
    ]
    return chain_head(entries)


@dataclass(frozen=True)
class Check:
    """One re-derived check's verdict: a stable name, ok True/False, and a one-line
    detail that names the locus on failure (and summarizes on success)."""

    name: str
    ok: bool
    detail: str


@dataclass
class TargetResult:
    """The full third-party verdict for one filing set: the recomputed sha and
    chain head, the signer fingerprint, the human-readable facts pulled read-only
    from the packet (for the attestation paragraph), and the per-check list."""

    label: str
    packet_path: Path
    run_log_path: Path
    sha256: str = ""
    chain_head: str = ""
    signer_fp: str = ""
    incident_id: str = ""
    filed_authorities: list[str] = field(default_factory=list)
    timeliness: list[tuple[str, str]] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.checks) and all(
            c.ok for c in self.checks)


# --- Locating the sealed files for a target -----------------------------------


def _run_log_for_packet(packet: dict, packet_path: Path) -> Path | None:
    """The run log a packet indexes. The packet's incident block records the mode;
    the committed capture sits beside the packet as run-inc-<id>-<mode>.jsonl. Falls
    back to deriving the mode from the packet's own file name (packet-<mode>.json)
    so a packet handed over on its own still finds its log."""
    incident = packet.get("incident", {}) or {}
    incident_id = incident.get("incident_id", "")
    mode = incident.get("mode", "")
    data_dir = packet_path.parent
    if incident_id and mode:
        candidate = data_dir / f"run-inc-{incident_id.split('-')[-1]}-{mode}.jsonl"
        if candidate.exists():
            return candidate
    name = packet_path.name
    if name.startswith("packet-") and name.endswith(".json"):
        derived_mode = name[len("packet-"):-len(".json")]
        for stem in (incident_id.split("-")[-1] if incident_id else "", "8842"):
            if not stem:
                continue
            candidate = data_dir / f"run-inc-{stem}-{derived_mode}.jsonl"
            if candidate.exists():
                return candidate
    return None


def _signature_record(packet: dict, run_log_path: Path) -> dict | None:
    """The sealed detached signature record: the packet's replay.signature, else a
    sibling <run-log>.sig.json sidecar. A third party who is handed a packet alone
    finds the signature inside it; one handed loose files finds the sidecar."""
    sig = (packet.get("replay") or {}).get("signature")
    if sig:
        return sig
    sidecar = run_log_path.with_suffix(run_log_path.suffix + ".sig.json")
    if sidecar.exists():
        return json.loads(sidecar.read_text(encoding="utf-8"))
    return None


# --- The packet facts the attestation paragraph reads (read-only) -------------


def _filed_authorities(packet: dict) -> list[str]:
    """The regimes (and authority when named) this filing set was filed to, read
    from the packet's filings list in order, each named once. Read-only display
    data for the attestation sentence; not part of any verified digest here."""
    out: list[str] = []
    for filing in packet.get("filings", []) or []:
        if not isinstance(filing, dict):
            continue
        regime = filing.get("regime")
        if not regime:
            continue
        authority = filing.get("authority")
        label = f"{regime} ({authority})" if authority else regime
        if label not in out:
            out.append(label)
    return out


def _timeliness(packet: dict) -> list[tuple[str, str]]:
    """Per-clock on-time / breached pairs for the attestation, read from the
    packet's clocks. Display only: the timeliness verdict itself is bound into the
    signature via the attestation digest, which check (3) verifies cryptographically."""
    out: list[tuple[str, str]] = []
    for clock in packet.get("clocks", []) or []:
        if not isinstance(clock, dict):
            continue
        name = clock.get("name", clock.get("correlation_id", "clock"))
        verdict = "BREACHED" if clock.get("breached") else "on-time"
        out.append((name, verdict))
    return out


# --- The re-derived checks ----------------------------------------------------


def _check_sha(recomputed: str, signature: dict) -> Check:
    sealed = signature.get("sha256", "")
    if not sealed:
        return Check("RUN-LOG SHA", False,
                     "the signature record commits to no sha256 to compare")
    if recomputed == sealed:
        return Check("RUN-LOG SHA", True,
                     f"recomputed sha256 {recomputed[:16]} == the sealed sha")
    return Check("RUN-LOG SHA", False,
                 f"recomputed sha256 {recomputed[:16]} != sealed "
                 f"{sealed[:16]} (the run-log bytes were edited)")


def _check_chain(recomputed: str, signature: dict) -> Check:
    sealed = signature.get("chain_head", "")
    if not sealed:
        return Check("CHAIN HEAD", False,
                     "the signature record commits to no chain_head to compare")
    if recomputed == sealed:
        return Check("CHAIN HEAD", True,
                     f"recomputed chain head {recomputed[:16]} == the sealed head")
    return Check("CHAIN HEAD", False,
                 f"recomputed chain head {recomputed[:16]} != sealed "
                 f"{sealed[:16]} (entries reordered or omitted)")


def _check_signature(sha256: str, chain_head_hex: str, signature: dict,
                     committed_pubkey_hex: str) -> Check:
    """Verify the detached Ed25519 signature over the bound payload, rebuilt from
    the RECOMPUTED sha and head (not the record's stored values) plus the record's
    two derived digests, against the COMMITTED public key. Rebuilding the payload
    from the recomputed values is what ties the signature to the bytes on disk: a
    tampered run log moves the sha or head, the rebuilt payload no longer matches
    what was signed, and the signature fails."""
    payload = bound_payload_bytes(
        sha256,
        chain_head_hex,
        signature.get("attestation_sha", ""),
        signature.get("fact_record_hash", ""),
    )
    record_pubkey = signature.get("public_key", "")
    # A third party trusts the COMMITTED key. If the record names a different key,
    # that is itself a red flag, so verify against the committed key explicitly.
    if record_pubkey and record_pubkey != committed_pubkey_hex:
        return Check("SIGNATURE", False,
                     "the signature record names a public key that is NOT the "
                     "committed Warden key; refusing to trust the record's key")
    ok = verify_bytes(
        payload, signature.get("signature", ""), committed_pubkey_hex)
    if ok:
        return Check("SIGNATURE", True,
                     f"valid Ed25519 over {{sha256,chain_head,attestation_sha,"
                     f"fact_record_hash}} under committed key fp "
                     f"{fingerprint(committed_pubkey_hex)}")
    return Check("SIGNATURE", False,
                 "the detached Ed25519 signature does NOT verify against the "
                 "committed Warden public key")


def _check_intoto(run_log_path: Path, recomputed_sha: str) -> Check | None:
    """When an in-toto/DSSE sidecar is present, verify the envelope signature over
    the PAE and confirm the in-toto subject digest equals the recomputed run-log
    sha. Returns None when no sidecar is present (the check is optional, present
    only on the four fully-sealed captures)."""
    sidecar = intoto_sidecar_for(run_log_path)
    if not sidecar.exists():
        return None
    envelope = json.loads(sidecar.read_text(encoding="utf-8"))
    sig_ok = verify_dsse_envelope(envelope)
    subject_digest = ""
    try:
        statement = statement_of_envelope(envelope)
        subjects = statement.get("subject") or [{}]
        subject_digest = (subjects[0].get("digest") or {}).get("sha256", "")
    except (ValueError, json.JSONDecodeError):
        subject_digest = ""
    digest_matches = bool(subject_digest) and subject_digest == recomputed_sha
    if sig_ok and digest_matches:
        return Check("IN-TOTO / DSSE", True,
                     "DSSE envelope verifies over the PAE; in-toto subject digest "
                     "equals the recomputed run-log sha")
    if not sig_ok:
        return Check("IN-TOTO / DSSE", False,
                     "the DSSE envelope signature does NOT verify over the PAE")
    return Check("IN-TOTO / DSSE", False,
                 "the in-toto subject digest does NOT equal the recomputed "
                 "run-log sha")


def _check_timestamp(run_log_path: Path, signature: dict) -> Check | None:
    """When an RFC 3161 timestamp sidecar is present, verify the TSA signature over
    the TSTInfo and confirm the timestamped messageImprint equals the artifact
    digest rebuilt from the signature record. Returns None when no sidecar is
    present (the check is optional)."""
    sidecar = tst_sidecar_for(run_log_path)
    if not sidecar.exists():
        return None
    token = json.loads(sidecar.read_text(encoding="utf-8"))
    verification = verify_timestamp_token(token, signature)
    if verification.valid:
        gen = (verification.gen_time.isoformat()
               if verification.gen_time else "?")
        return Check("RFC 3161 TIMESTAMP", True,
                     f"TSA signature valid; messageImprint matches the signed "
                     f"artifact; timestamped at {gen}")
    return Check("RFC 3161 TIMESTAMP", False,
                 f"timestamp does NOT verify: {verification.detail}")


# --- Orchestration ------------------------------------------------------------


def verify_target(packet_path: Path, committed_pubkey_hex: str,
                  run_log_override: Path | None = None) -> TargetResult:
    """Re-derive and verify the full provenance chain for one filing set, from the
    sealed files + the committed public key only. Returns the structured result;
    never raises on tampered or absent evidence, so the caller prints a verdict and
    exits cleanly."""
    label = packet_path.stem
    result = TargetResult(label=label, packet_path=packet_path,
                          run_log_path=run_log_override or packet_path)

    if not packet_path.exists():
        result.error = f"packet not found at {packet_path}"
        return result
    packet = json.loads(packet_path.read_text(encoding="utf-8"))

    run_log_path = run_log_override or _run_log_for_packet(packet, packet_path)
    if run_log_path is None or not run_log_path.exists():
        result.error = ("the run log this packet indexes was not found beside it; "
                        "a third-party verify needs the run-log bytes")
        return result
    result.run_log_path = run_log_path

    signature = _signature_record(packet, run_log_path)
    if signature is None:
        result.error = ("no detached signature found (packet replay.signature or "
                        "a <run-log>.sig.json sidecar); nothing to verify against")
        return result

    canonical_text = canonical_run_log_text(run_log_path)
    sha256 = recompute_sha256(canonical_text)
    head = recompute_chain_head(canonical_text)
    result.sha256 = sha256
    result.chain_head = head
    result.signer_fp = (signature.get("pubkey_fingerprint")
                        or fingerprint(committed_pubkey_hex))

    incident = packet.get("incident", {}) or {}
    result.incident_id = incident.get("incident_id", "")
    result.filed_authorities = _filed_authorities(packet)
    result.timeliness = _timeliness(packet)

    checks: list[Check] = [
        _check_sha(sha256, signature),
        _check_chain(head, signature),
        _check_signature(sha256, head, signature, committed_pubkey_hex),
    ]
    intoto = _check_intoto(run_log_path, sha256)
    if intoto is not None:
        checks.append(intoto)
    timestamp = _check_timestamp(run_log_path, signature)
    if timestamp is not None:
        checks.append(timestamp)
    result.checks = checks
    return result


def _resolve_targets(args: list[str]) -> list[tuple[Path, Path | None]]:
    """Resolve the verify targets from the command line: a scenario name, a packet
    path (optionally with an explicit run-log path), or nothing (all four sealed
    captures). Returns (packet_path, run_log_override) pairs."""
    if not args:
        return [(DATA / f"packet-{mode}.json", None) for mode in SEALED_SCENARIOS]
    first = Path(args[0])
    if first.suffix == ".json" and first.exists():
        override = (Path(args[1]).resolve()
                    if len(args) >= 2 and Path(args[1]).exists() else None)
        return [(first.resolve(), override)]
    # Treat the argument as a scenario name.
    return [(DATA / f"packet-{args[0]}.json", None)]


def _print_result(result: TargetResult) -> None:
    print("=" * 78)
    print(f"FILING SET: {result.label}")
    print("=" * 78)
    if result.error:
        print(f"  COULD NOT VERIFY: {result.error}")
        print()
        return
    print(f"  run log        : {result.run_log_path.name}")
    print(f"  run-log sha256 : {result.sha256}")
    print(f"  chain head     : {result.chain_head}")
    print(f"  signer fp      : {result.signer_fp}")
    print()
    name_width = max(len(c.name) for c in result.checks)
    for c in result.checks:
        status = "VERIFIED" if c.ok else "FAILED"
        print(f"  [{status:>8}] {c.name.ljust(name_width)}  {c.detail}")
    print()

    # The plain third-party-readable attestation paragraph.
    print("  ATTESTATION (re-derived offline, from the sealed files + the "
          "committed key):")
    if result.ok:
        authorities = (", ".join(result.filed_authorities)
                       if result.filed_authorities else "the named authorities")
        late = [name for name, verdict in result.timeliness
                if verdict == "BREACHED"]
        timeliness = ("every statutory clock met on time"
                      if not late else
                      f"breached: {', '.join(late)}")
        incident = result.incident_id or "this incident"
        print(f"    This filing set for {incident}, filed to {authorities}, has a")
        print(f"    run log that hashes to {result.sha256[:16]}..., chains to")
        print(f"    {result.chain_head[:16]}..., and is signed by the Warden key")
        print(f"    fp {result.signer_fp}. The bound timeliness attestation records")
        print(f"    {timeliness}. One flipped byte of the run log fails this check:")
        print("    the sha moves, the chain head moves, and the signature no "
              "longer verifies.")
    else:
        first_fail = next(c for c in result.checks if not c.ok)
        print(f"    PROVENANCE DOES NOT HOLD. First failure: {first_fail.name}: "
              f"{first_fail.detail}.")
        print("    Do not accept this filing set as authentic.")
    print()


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]

    committed_pubkey_hex = load_public_key_hex()

    print("=" * 78)
    print("INDEPENDENT THIRD-PARTY PROVENANCE VERIFIER")
    print("=" * 78)
    print("You run this. Offline, on your machine, against the sealed filing set")
    print("and the committed public key alone. No network, no private key, no")
    print("trust in us: every value below is RE-DERIVED from the bytes you hold.")
    print()
    print(f"Committed Warden public key : {committed_pubkey_hex}")
    print(f"  fingerprint               : {fingerprint(committed_pubkey_hex)}")
    print()

    targets = _resolve_targets(args)
    results = [
        verify_target(packet_path, committed_pubkey_hex, override)
        for packet_path, override in targets
    ]
    for result in results:
        _print_result(result)

    all_ok = bool(results) and all(r.ok for r in results)
    passed = sum(1 for r in results if r.ok)
    print("=" * 78)
    print(f"OVERALL: {passed}/{len(results)} filing set(s) re-verify offline from "
          f"the sealed files alone.")
    if all_ok:
        print("Every re-derived run-log sha, chain head, and Ed25519 signature "
              "matches the seal,")
        print("and every present in-toto/DSSE envelope and RFC 3161 timestamp "
              "verifies. Provenance")
        print("holds with zero trust in the producer.")
    else:
        first_bad = next((r for r in results if not r.ok), None)
        if first_bad is not None:
            if first_bad.error:
                locus = first_bad.error
            else:
                fc = next(c for c in first_bad.checks if not c.ok)
                locus = f"{first_bad.label}: {fc.name}: {fc.detail}"
            print(f"PROVENANCE FAILED. First failure: {locus}")
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print(f"Note: {DEMO_TSA_CAVEAT}")
    print("=" * 78)
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
