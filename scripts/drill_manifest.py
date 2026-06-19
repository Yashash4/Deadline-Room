"""Examiner Drill manifest: a sealed run becomes a self-grading answer key (E9.4).

Byte-identical replay means a captured incident is a FIXED, authoritative answer
key. At every gate the Warden either let the filing set out or held it, and that
verdict is cryptographically pinned in the sealed run-log: reorder or edit one
entry and the chain head moves. This module turns that pinned truth into a
DERIVED drill: it walks a sealed run in order, extracts each "release or block?"
decision point, and records the deterministic ground-truth verdict straight from
the bytes. The drill answer key is therefore DERIVED, never hand-authored, so a
human scored against it is scored against the same cryptographically-fixed truth
an examiner would verify.

Two kinds of gate are extracted, both genuine release-or-block decisions:

  * CONTRADICTION-DIFF: the Warden's deterministic cross-filing veto. A `diff`
    event with a non-empty conflict set is a BLOCK (the contradiction veto fires);
    an empty conflict set is a RELEASE (the filings agree and signoff is armed).
  * TWO-KEY RELEASE: the human two-key gate. A `release_signoff` with only the
    first distinct key present is a BLOCK (release withheld, segregation of duties
    not yet satisfied); the signoff that completes the second distinct key is a
    RELEASE (both keys present, release admitted).

Each decision point carries the seq it rests on, the branch, the prompt a human
answers, the ground-truth verdict, and the rule that fixes it, all read from the
sealed bytes.

The CERTIFICATION RECEIPT is a SEPARATE, DETACHED Ed25519 signature under a
DISTINCT label, exactly like the egress attestation (floor/egress_attestation.py)
and the portfolio receipt (warden/portfolio_signing.py). It is NOT folded into
the run-log 4-field bound payload {sha256, chain_head, attestation_sha,
fact_record_hash}; folding it would force re-signing every sealed capture and
break their committed signatures. Instead the receipt rests beside the sealed
run: it never enters the hashed run-log, so the run-log sha, the chain head, the
four sealed .sig.json bound signatures, and byte-identical replay are all
untouched. This module reads the sealed bytes; it never writes them.

The receipt certifies a PERFECT pass of the drill (every gate answered to match
the cryptographically-fixed ground truth) bound to that run: it signs the answer
key digest, the run-log sha256, and the chain head together, under the distinct
"certification" label. A human earns the receipt in the browser only by matching
every fixed verdict; the receipt then verifies against the committed public key,
and a tampered copy (any edited field) fails. Deterministic: zero LLM calls, no
now(), no randomness. The same sealed run always derives the byte-identical
manifest, digest, and signature (Ed25519 is deterministic).

Honest demo-key caveat: the private key shipped with this repo is a DEMONSTRATION
key (warden/signing.py). The signature MECHANISM is fully real (one flipped byte
of the receipt makes it INVALID), but the key's SECRECY is not production-grade
because anyone with the repo holds it.

  py scripts/drill_manifest.py                 (extract + sign all four sealed runs, print)
  py scripts/drill_manifest.py --write         (also write web/data/drill-<mode>.json)
  py scripts/drill_manifest.py <run-log.jsonl> (one run log)
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from warden.chain import chain_head  # noqa: E402
from warden.replay import RunLog  # noqa: E402
from warden.signing import (  # noqa: E402
    DEMO_KEY_CAVEAT,
    fingerprint,
    load_public_key_hex,
    sign_bytes,
    verify_bytes,
)

DATA = REPO_ROOT / "web" / "data"
SCENARIOS = ("normal", "inject_contradiction", "chaos", "amendment")

# The distinct certification label. A per-run receipt carries
# "canonical_json{sha256,chain_head,attestation_sha,fact_record_hash}"; the egress
# attestation carries "canonical_json(egress_attestation)"; the drill certification
# carries THIS, so the receipts can never be confused and a certification signature
# can never be replayed as a per-run signature (the signed bytes differ).
CERTIFICATION_SIGNED_PAYLOAD = "canonical_json(drill_certification)"

# The signer's stated role on the receipt: the same identity the run-log signature
# attributes the seal to.
CERTIFICATION_SIGNER = "Deadline Warden"

# The two distinct human roles that must both sign to release a filing, mirrored
# from warden/release_gate.REQUIRED_ROLES (kept as a literal here, like
# scripts/audit_run.py, so the drill states its own segregation-of-duties contract
# and does not depend on a runtime import of the gate that produced the log).
REQUIRED_RELEASE_ROLES = frozenset({"head_of_ir", "general_counsel"})

# The two answers a human gives at every gate. RELEASE = let the filing set out;
# BLOCK = hold it. The ground truth at each gate is one of these, fixed by the
# sealed bytes.
RELEASE = "release"
BLOCK = "block"

REGULATOR_OF = {"sec": "SEC", "nis2": "NIS2", "dora": "DORA"}


def _regulator(corr: str) -> str:
    """The regulator label for a correlation id like 'inc-8842:sec'."""
    branch = corr.split(":")[-1] if corr else ""
    branch = branch.split("-")[0]  # 'nis2-early' -> 'nis2'
    return REGULATOR_OF.get(branch, branch.upper() or "the filing")


@dataclass(frozen=True)
class DecisionPoint:
    """One gate a human is asked to call, with the deterministic ground truth read
    from the sealed bytes. `seq` is the run-log entry the verdict rests on; `kind`
    is the gate type; `branch` the correlation id (or "all" for a fan-out diff);
    `prompt` is what the human answers; `ground_truth` is RELEASE or BLOCK; `rule`
    names the deterministic reason the verdict is fixed."""
    seq: int
    kind: str
    branch: str
    prompt: str
    ground_truth: str
    rule: str

    def as_dict(self) -> dict:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "branch": self.branch,
            "prompt": self.prompt,
            "ground_truth": self.ground_truth,
            "rule": self.rule,
        }


def extract_decision_points(entries: list[dict]) -> list[DecisionPoint]:
    """Walk a sealed run IN ORDER and derive every release-or-block gate.

    Pure read of the sealed bytes: no LLM, no now(), no randomness. The same run
    always yields the same decision points in the same order. Two gate kinds are
    extracted (contradiction diff, two-key release); the verdict at each is read
    straight from the entry, so the answer key is DERIVED, never asserted."""
    points: list[DecisionPoint] = []
    # Track, per branch, how many distinct release keys have landed so the two-key
    # gate prompt names whether this signoff withholds (first key) or admits
    # (completing key). Read from the sealed `have_roles`/`released` fields.
    for entry in entries:
        etype = entry.get("type")
        payload = entry.get("payload", {})
        seq = entry.get("seq", -1)

        if etype == "diff":
            # A diff is a single fan-out gate across all branches at this point.
            # Non-empty conflicts => the contradiction veto fires => BLOCK; empty
            # conflicts => the filings agree => RELEASE (signoff armed). The
            # amendment phase diff carries `phase:"amendment"`; round-numbered
            # diffs carry `round`. Both are real gates, both extracted.
            conflicts = payload.get("conflicts") or []
            round_no = payload.get("round")
            phase = payload.get("phase")
            if round_no is not None:
                label = f"contradiction diff round {round_no}"
            elif phase:
                label = f"contradiction diff ({phase} phase)"
            else:
                label = "contradiction diff"
            if conflicts:
                prompt = (
                    f"The cross-filing {label} found "
                    f"{len(conflicts)} conflict(s) on a load-bearing fact. "
                    "Release the filing set, or block it?")
                gt, rule = BLOCK, (
                    "SAFE-2: a non-empty contradiction set blocks release until "
                    "every conflicting fact is reconciled and the diff re-runs "
                    "clean.")
            else:
                prompt = (
                    f"The cross-filing {label} found no conflicts: every "
                    "filing agrees on the load-bearing facts. Release, or block?")
                gt, rule = RELEASE, (
                    "A clean contradiction diff arms signoff: the deterministic "
                    "veto has nothing to hold.")
            points.append(DecisionPoint(
                seq=seq, kind="contradiction_diff", branch="all",
                prompt=prompt, ground_truth=gt, rule=rule))
            continue

        if etype == "release_signoff":
            corr = payload.get("correlation_id", "")
            role = payload.get("role", "")
            released = bool(payload.get("released"))
            have = sorted(payload.get("have_roles") or [])
            regulator = _regulator(corr)
            if released:
                prompt = (
                    f"The {regulator} filing now has both distinct release keys "
                    f"({', '.join(have)}). Release it, or block it?")
                gt, rule = RELEASE, (
                    "SAFE-1: two DISTINCT release keys (general_counsel and "
                    "head_of_ir) are present, so release is admitted.")
            else:
                missing = sorted(REQUIRED_RELEASE_ROLES - set(have))
                prompt = (
                    f"The {regulator} filing has one release key "
                    f"({role}) but still needs {', '.join(missing)}. "
                    "Release it now, or block it?")
                gt, rule = BLOCK, (
                    "SAFE-1: only one distinct release key is present; release is "
                    "withheld until the second distinct key signs (segregation of "
                    "duties).")
            points.append(DecisionPoint(
                seq=seq, kind="two_key_release", branch=corr,
                prompt=prompt, ground_truth=gt, rule=rule))
            continue

    return points


def answer_key_digest(points: list[DecisionPoint]) -> str:
    """The sha256 over the canonical answer key: the ordered (seq, kind, branch,
    ground_truth) of every decision point. This is the digest the certification
    receipt binds, so editing any extracted verdict moves it and breaks the
    signature. Uses the SAME canonicalization recipe as the run log and every
    other detached signature (sorted keys, no whitespace, no now(), no RNG)."""
    key = [
        {
            "seq": p.seq,
            "kind": p.kind,
            "branch": p.branch,
            "ground_truth": p.ground_truth,
        }
        for p in points
    ]
    canon = json.dumps(key, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()


def certification_document(incident_id: str, mode: str, run_sha256: str,
                           run_chain_head: str,
                           points: list[DecisionPoint]) -> dict:
    """The canonical CERTIFICATION DOCUMENT: the exact JSON the digest is taken
    over and the receipt signature attests. Stable key order so the digest is
    byte-stable. It certifies a PERFECT pass of this drill (every gate answered to
    match the fixed ground truth) bound to this exact sealed run.

    A valid signature over this document reads as "the holder of this receipt
    matched all N cryptographically-fixed gate verdicts for this exact ordered,
    complete run". The browser awards the receipt only on a perfect score; editing
    the run sha, the chain head, the gate count, or the answer key digest changes
    the document and breaks the signature."""
    return {
        "claim": "examiner_drill_passed",
        "incident_id": incident_id,
        "mode": mode,
        "signer": CERTIFICATION_SIGNER,
        "run_sha256": run_sha256,
        "run_chain_head": run_chain_head,
        "gate_count": len(points),
        "answer_key_sha256": answer_key_digest(points),
        "required_score": len(points),
    }


def canonical_certification_bytes(document: dict) -> bytes:
    """The certification document serialized to canonical JSON bytes, the SAME
    recipe the run log, the bound signing payload, and every other detached
    signature use (sorted keys, no whitespace, no now(), no RNG), so the same
    document always yields the same bytes and the same digest. A verifier rebuilds
    these exact bytes from the re-derived document to check the signature."""
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
        "utf-8")


def certification_digest(document: dict) -> str:
    """The sha256 over the canonical certification bytes: the digest the detached
    Ed25519 signature is taken over, so a single edited field in the receipt moves
    it and breaks the signature."""
    return hashlib.sha256(canonical_certification_bytes(document)).hexdigest()


def sign_certification(document: dict, private_key=None) -> dict:
    """Sign the certification DOCUMENT with a SEPARATE, DETACHED Ed25519 signature
    under the DISTINCT certification label, with the committed demo key by default.

    It is DETACHED and SEPARATE from the run-log bound signature: it attests the
    certification document only, it is never folded into the run-log bound payload,
    and it never enters the hashed run-log. So the run-log sha, the chain head, the
    four sealed run-log signatures, and byte-identical replay are all untouched.

    The record carries the digest, the detached signature, the public key, its
    fingerprint, and the honest demo-key caveat, so a verifier re-derives the
    document, recomputes the digest, rebuilds the signed bytes, and checks the
    signature with no private key."""
    digest = certification_digest(document)
    signed_bytes = canonical_certification_bytes(document)
    signature_hex = sign_bytes(signed_bytes, private_key)
    pub_hex = load_public_key_hex()
    return {
        "algorithm": "ed25519",
        "detached": True,
        "separate_from_run_log_signature": True,
        "signed_payload": CERTIFICATION_SIGNED_PAYLOAD,
        "certification_digest": digest,
        "signature": signature_hex,
        "public_key": pub_hex,
        "pubkey_fingerprint": fingerprint(pub_hex),
        "signer": CERTIFICATION_SIGNER,
        "demo_key": True,
        "caveat": DEMO_KEY_CAVEAT,
    }


def verify_certification(document: dict, signature_record: dict) -> bool:
    """Verify a detached certification signature against a re-derived document.
    True only when the digest the record carries matches the digest of the
    canonical bytes of THIS document AND the Ed25519 signature is valid over those
    bytes under the record's public key.

    The digest is recomputed from the document handed in, not trusted from the
    record, so an edit to any field (the digest moves) breaks the check. Returns
    False on any mismatch or malformed input rather than raising, so a verifier
    prints INVALID and exits nonzero without a stack trace on a tampered receipt."""
    recomputed = certification_digest(document)
    if recomputed != str(signature_record.get("certification_digest", "")):
        return False
    return verify_bytes(
        canonical_certification_bytes(document),
        signature_record.get("signature", ""),
        signature_record.get("public_key"))


def _incident_id_of(entries: list[dict]) -> str:
    """The incident id the run is for, read from a correlation id in the log."""
    for entry in entries:
        corr = entry.get("payload", {}).get("correlation_id")
        if corr and ":" in corr:
            return corr.split(":")[0]
    return "inc"


def _mode_of(entries: list[dict], log_path: Path) -> str:
    """The scenario mode, from the `room` event's mode field, else the filename."""
    for entry in entries:
        if entry.get("type") == "room":
            mode = entry.get("payload", {}).get("mode")
            if mode:
                return mode
    name = log_path.name
    prefix, suffix = "run-inc-8842-", ".jsonl"
    if name.startswith(prefix) and name.endswith(suffix):
        return name[len(prefix):-len(suffix)]
    return log_path.stem


@dataclass(frozen=True)
class DrillManifest:
    log_path: Path
    incident_id: str
    mode: str
    run_sha256: str
    run_chain_head: str
    points: list[DecisionPoint]
    document: dict
    signature: dict

    def as_dict(self) -> dict:
        """The web-ready drill manifest: the decision points (answer key), the
        certification document, and its detached signature. JSON-serializable; the
        browser loads it, pauses at each decision point, scores the human, and on a
        perfect score awards the signed certification receipt."""
        return {
            "incident_id": self.incident_id,
            "mode": self.mode,
            "run_sha256": self.run_sha256,
            "run_chain_head": self.run_chain_head,
            "decision_points": [p.as_dict() for p in self.points],
            "certification": {
                "document": self.document,
                "signature": self.signature,
            },
        }

    @property
    def receipt_verifies(self) -> bool:
        return verify_certification(self.document, self.signature)


def build_drill_manifest(log_path: Path) -> DrillManifest:
    """Derive the full drill manifest for one sealed run: extract the decision
    points, compute the run sha and chain head, build the certification document,
    and sign it with a separate detached signature. Pure read of the sealed bytes.
    """
    log = RunLog.load(log_path)
    entries = log.entries()
    run_sha = log.sha256()
    head = chain_head(entries)
    incident_id = _incident_id_of(entries)
    mode = _mode_of(entries, log_path)
    points = extract_decision_points(entries)
    document = certification_document(
        incident_id, mode, run_sha, head, points)
    signature = sign_certification(document)
    return DrillManifest(
        log_path=log_path, incident_id=incident_id, mode=mode,
        run_sha256=run_sha, run_chain_head=head, points=points,
        document=document, signature=signature)


def _print_manifest(m: DrillManifest) -> None:
    print("=" * 78)
    print(f"EXAMINER DRILL: {m.log_path.name}  (mode {m.mode})")
    print("=" * 78)
    print(f"  run-log sha256 : {m.run_sha256}")
    print(f"  chain head     : {m.run_chain_head}")
    print(f"  decision points: {len(m.points)}")
    print()
    print("  Extracted decision points (answer key, derived from the sealed run):")
    seq_w = max((len(str(p.seq)) for p in m.points), default=3)
    for i, p in enumerate(m.points, 1):
        verdict = p.ground_truth.upper()
        print(f"   {str(i).rjust(2)}. seq {str(p.seq).rjust(seq_w)}  "
              f"[{p.kind}] {p.branch}")
        print(f"       Q: {p.prompt}")
        print(f"       GROUND TRUTH: {verdict}  ({p.rule})")
    print()
    print(f"  answer key sha256 : {m.document['answer_key_sha256']}")
    print()
    print("  Signed certification receipt (separate detached Ed25519, distinct "
          "label):")
    sig = m.signature
    print(f"    signed_payload     : {sig['signed_payload']}")
    print(f"    certification_digest: {sig['certification_digest']}")
    print(f"    signature          : {sig['signature'][:32]}...")
    print(f"    public_key         : {sig['public_key']}")
    print(f"    pubkey_fingerprint : {sig['pubkey_fingerprint']}")
    verifies = m.receipt_verifies
    print(f"    receipt verifies   : {'VALID' if verifies else 'INVALID'}")
    print()


def main(argv: list[str]) -> int:
    write = "--write" in argv
    args = [a for a in argv if not a.startswith("--")]

    if args:
        log_path = Path(args[0]).resolve()
        if not log_path.exists():
            print(f"drill_manifest: run log not found at {log_path}",
                  file=sys.stderr)
            return 2
        targets = [log_path]
    else:
        targets = []
        for mode in SCENARIOS:
            lp = DATA / f"run-inc-8842-{mode}.jsonl"
            if not lp.exists():
                print(f"drill_manifest: default capture missing at {lp}",
                      file=sys.stderr)
                return 2
            targets.append(lp)

    manifests = [build_drill_manifest(lp) for lp in targets]
    all_ok = True
    for m in manifests:
        _print_manifest(m)
        if not m.receipt_verifies:
            all_ok = False
        if write:
            out = DATA / f"drill-{m.mode}.json"
            out.write_text(
                json.dumps(m.as_dict(), indent=1) + "\n", encoding="utf-8")
            print(f"  wrote {out.relative_to(REPO_ROOT)}")
            print()

    print("=" * 78)
    total_gates = sum(len(m.points) for m in manifests)
    print(f"OVERALL: {len(manifests)} drill(s), {total_gates} gate(s) total, "
          f"every certification receipt {'VALID' if all_ok else 'INVALID'}.")
    print(f"Note: {DEMO_KEY_CAVEAT}")
    print("=" * 78)
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
