"""in-toto Statement + DSSE envelope: name our signed provenance in the standard.

`warden/signing.py` already produces the SUBSTANCE of a supply-chain attestation:
a detached Ed25519 signature over a canonical, ordered, hash-chained record (the
bound `{sha256, chain_head}` payload). What it lacks is the ECOSYSTEM'S name and
structure for that fact. This module re-expresses the exact same provenance as a
standards-conformant in-toto Statement wrapped in a DSSE (Dead Simple Signing
Envelope), so the run-log seal verifies not only with our own
`verify_signature.py` but as a recognized in-toto / SLSA attestation that
Sigstore/cosign-class tooling speaks.

STRICTLY ADDITIVE, derived read-only. This module never touches
`warden/signing.py`'s `bound_payload_bytes`, never re-computes or replaces the
existing detached signature, and never writes a byte into the hashed run-log
JSONL. It reads bytes already on disk (the run-log, the sealed signature record)
and emits a NEW sidecar beside them. The run-log sha256, the per-entry chain
head, the existing signature, audit_run, tamper_sweep, and byte-identical replay
are all UNCHANGED by anything here.

The shapes follow the published specs exactly:

  * in-toto Statement, type "https://in-toto.io/Statement/v1": a `subject` list
    whose entries carry a `name` and a `digest` map (we name the run-log and pin
    its `sha256`), a `predicateType` URI, and a `predicate` object. The predicate
    carries the Deadline Room run facts that the packet already holds: the chain
    head, the regulatory frameworks that filed, the SEC statutory deadline, and
    the signer fingerprint.
    https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md

  * DSSE envelope: the Statement is the `payload`, the `payloadType` is the
    in-toto media type, and the signature is taken over the PAE
    (Pre-Authentication Encoding) of `(payloadType, payload)`, not the raw
    payload. PAE is "DSSEv1" SP len(type) SP type SP len(body) SP body, with the
    two lengths as ASCII decimal. The payload travels base64 in the envelope.
    https://github.com/secure-systems-lab/dsse/blob/master/protocol.md

Honest demo-key caveat (the same one signing.py states, and it applies in FULL
here): the DSSE envelope is signed with the SAME committed DEMO Ed25519 key. The
signing MECHANISM is fully real (PAE is exact, one flipped byte makes the
envelope INVALID), but the key ships with the repo, so a valid envelope proves
"signed by whoever holds this demo key", not HSM/KMS-grade secrecy. Production
custody (KMS/HSM, rotation, a published key directory, RFC-3161 timestamping) is
Phase 2, exactly as `signing.py` records.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .chain import chain_head
from .signing import (
    DEMO_KEY_CAVEAT,
    fingerprint,
    load_demo_private_key,
    load_public_key,
    public_key_hex_of,
)

# The in-toto Statement envelope type id, fixed by the spec (v1).
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# The DSSE payloadType for an in-toto Statement: the registered media type. The
# DSSE signature binds this string into the PAE, so a verifier that swaps the
# payload type cannot reuse the signature.
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Our self-hosted predicate type URI. in-toto allows a predicate of any type
# named by a stable URI; this one names a Deadline Room run attestation. It is a
# type IDENTIFIER, not a fetched URL, so emitting the attestation needs no
# network and stays byte-stable.
PREDICATE_TYPE = "https://deadline-room.dev/attestation/run/v1"

# The keyid carried in the DSSE signature object: the public-key fingerprint from
# signing.py, so the envelope names its signer the same way the sig.json sidecar
# and the verify receipts do.


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding of (payload_type, payload).

    Exactly the DSSE v1 wire format:

        "DSSEv1" SP LEN(payload_type) SP payload_type SP LEN(payload) SP payload

    where SP is a single ASCII space (0x20) and each LEN is the byte length
    rendered as ASCII decimal. The type is UTF-8 encoded; the payload is the raw
    payload BYTES (here, the UTF-8 in-toto Statement). The signature is taken
    over THIS, never over the bare payload, which is what stops a payload or a
    type from being swapped under a captured signature.
    """
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (
        len(type_bytes),
        type_bytes,
        len(payload),
        payload,
    )


def canonical_statement_bytes(statement: dict) -> bytes:
    """The in-toto Statement serialized to canonical JSON bytes.

    Uses the SAME canonicalization recipe as the run log and the bound signing
    payload (`json.dumps(..., sort_keys=True, separators=(",",":"))`), so the
    Statement is byte-stable: the same run always yields the same Statement bytes,
    the same PAE, and (Ed25519 being deterministic) the same envelope signature.
    """
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def build_statement(
    run_log_jsonl: str,
    *,
    subject_name: str,
    filed_frameworks: list[str],
    sec_deadline: str | None,
    signer_fingerprint: str,
    chain_head_hex: str | None = None,
    sha256_hex: str | None = None,
) -> dict:
    """Build the in-toto Statement for a Deadline Room run.

    The subject is the run-log named by `subject_name`, pinned by its `sha256`
    digest (recomputed here from the bytes handed in, so the Statement attests
    these exact bytes). The predicate carries the run facts the packet already
    holds: the per-entry chain head (the single value that summarizes the
    ordered, complete run), the regulatory frameworks that filed, the SEC
    statutory deadline, and the signer's public-key fingerprint. Every value is
    derived read-only from the run-log bytes or passed in from the sealed packet,
    so the Statement is a pure render: no `now()`, no LLM, nothing that could
    drift between runs.
    """
    if sha256_hex is None:
        sha256_hex = _sha256_hex(run_log_jsonl.encode("utf-8"))
    if chain_head_hex is None:
        entries = [
            json.loads(line)
            for line in run_log_jsonl.splitlines()
            if line.strip()
        ]
        chain_head_hex = chain_head(entries)
    predicate = {
        "signer": "Deadline Warden",
        "signer_fingerprint": signer_fingerprint,
        "chain_head": chain_head_hex,
        "filed_frameworks": list(filed_frameworks),
        "sec_deadline": sec_deadline,
        "demo_key": True,
        "caveat": DEMO_KEY_CAVEAT,
    }
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": subject_name, "digest": {"sha256": sha256_hex}},
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def build_dsse_envelope(
    statement: dict,
    private_key: Ed25519PrivateKey | None = None,
) -> dict:
    """Wrap an in-toto Statement in a signed DSSE envelope.

    The Statement is canonicalized to bytes, those bytes are PAE-encoded with the
    in-toto payloadType, and the PAE is signed with the committed demo Ed25519
    key (the SAME key signing.py uses). The envelope carries the payload base64
    (the DSSE wire form), the payloadType, and one signature object: the
    signature hex and a keyid (the public-key fingerprint).

    Ed25519 is deterministic, so a given Statement always yields the same
    envelope signature, which keeps the sidecar reproducible byte for byte.
    """
    if private_key is None:
        private_key = load_demo_private_key()
    payload = canonical_statement_bytes(statement)
    to_sign = pae(INTOTO_PAYLOAD_TYPE, payload)
    sig = private_key.sign(to_sign)
    pub_hex = public_key_hex_of(private_key)
    return {
        "payloadType": INTOTO_PAYLOAD_TYPE,
        "payload": base64.standard_b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": fingerprint(pub_hex),
                "sig": base64.standard_b64encode(sig).decode("ascii"),
            }
        ],
        "public_key": pub_hex,
    }


def verify_dsse_envelope(envelope: dict, public_key_hex: str | None = None) -> bool:
    """True iff the DSSE envelope's signature verifies over the PAE of its payload.

    Decodes the base64 payload, re-encodes the PAE with the envelope's
    payloadType, and checks the first signature against the public key (the
    envelope's own committed key by default). Returns False on any invalid
    signature or malformed field rather than raising, so a verifier can print
    INVALID and exit nonzero without a stack trace on tampered evidence. A
    single flipped byte in the payload, the type, or the signature fails here.
    """
    try:
        payload = base64.standard_b64decode(envelope["payload"])
        payload_type = envelope["payloadType"]
        sig_b64 = envelope["signatures"][0]["sig"]
        sig = base64.standard_b64decode(sig_b64)
        key_hex = public_key_hex or envelope.get("public_key")
        public_key = load_public_key(key_hex)
        public_key.verify(sig, pae(payload_type, payload))
        return True
    except (InvalidSignature, ValueError, KeyError, IndexError):
        return False


def statement_of_envelope(envelope: dict) -> dict:
    """Decode the in-toto Statement carried in a DSSE envelope's base64 payload."""
    payload = base64.standard_b64decode(envelope["payload"])
    return json.loads(payload.decode("utf-8"))


def _filed_frameworks_from_packet(packet: dict) -> list[str]:
    """The regulatory frameworks that filed, read from the packet's filings, in
    the order they appear.

    Falls back to an empty list if filings are absent so the render never raises
    on a sparse packet; each framework name appears at most once. This reads the
    PACKET (the run's own output), never the regime catalog config, so the no-LLM
    core stays config-agnostic."""
    seen: list[str] = []
    for filing in packet.get("filings", []) or []:
        if isinstance(filing, dict):
            name = filing.get("regime")
            if name and name not in seen:
                seen.append(name)
    return seen


def _sec_deadline_from_packet(packet: dict) -> str | None:
    """The SEC 8-K statutory deadline, read from the packet's clocks list.

    Matches the clock whose correlation id is the SEC branch (`...:sec`), with a
    name-based fallback, and returns its deadline. None when no SEC clock is
    present, so the predicate field is explicitly null rather than guessed."""
    for clock in packet.get("clocks", []) or []:
        if not isinstance(clock, dict):
            continue
        corr = clock.get("correlation_id", "")
        if corr.endswith(":sec") or "SEC" in clock.get("name", ""):
            return clock.get("deadline")
    return None


def _signer_fingerprint_from_packet(packet: dict) -> str:
    """The signer's public-key fingerprint, taken from the sealed signature in the
    packet's replay block when present, else computed from the committed key.

    Read-only: the fingerprint NAMES the same key signing.py sealed with; it is
    never the thing being signed here."""
    sig = (packet.get("replay") or {}).get("signature") or {}
    fp = sig.get("pubkey_fingerprint")
    if fp:
        return fp
    pub = sig.get("public_key")
    if pub:
        return fingerprint(pub)
    from .signing import load_public_key_hex

    return fingerprint(load_public_key_hex())


def attestation_for_capture(
    run_log_jsonl: str,
    packet: dict,
    *,
    subject_name: str,
    private_key: Ed25519PrivateKey | None = None,
) -> dict:
    """Build the signed DSSE/in-toto attestation for one captured run.

    Pulls the filed regulatory frameworks, the SEC deadline, and the signer
    fingerprint from data the packet already carries, pins the run-log sha256 and
    chain head from the run-log bytes, builds the in-toto Statement, and wraps it
    in a signed DSSE envelope. The result is the additive sidecar emitted beside
    the capture; it is derived entirely from bytes already on disk and is never
    written into the hashed run-log."""
    statement = build_statement(
        run_log_jsonl,
        subject_name=subject_name,
        filed_frameworks=_filed_frameworks_from_packet(packet),
        sec_deadline=_sec_deadline_from_packet(packet),
        signer_fingerprint=_signer_fingerprint_from_packet(packet),
    )
    return build_dsse_envelope(statement, private_key)


def sidecar_path_for(run_log_path: str | Path) -> Path:
    """The in-toto/DSSE sidecar path that sits beside a run log:
    `<run-log>.intoto.json`. Mirrors how the `.sig.json` sidecars are named, and
    is a NEW file, so the run-log/packet/sig.json bytes are never rewritten."""
    p = Path(run_log_path)
    return p.with_suffix(p.suffix + ".intoto.json")
