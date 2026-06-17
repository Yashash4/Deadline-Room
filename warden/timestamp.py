"""RFC 3161 trusted timestamp over the signed artifact: prove WHEN, not just WHO.

The detached Ed25519 signature (`warden/signing.py`) proves the run-log was signed
by the holder of the Warden key. It does NOT prove WHEN it was signed: a holder of
the key could in principle have produced the same signature at any moment, so
"signed after the breach was already public" is not ruled out. An RFC 3161 trusted
timestamp closes that gap. A Time-Stamping Authority (TSA) takes a hash of the
artifact, binds it to a point in time, and signs that binding. A verifier later
checks the TSA signature and that the timestamped hash equals the artifact's hash,
and reads a time a court accepts as "this digest existed no later than then".

WHAT IS TIMESTAMPED (the messageImprint). The TSP messageImprint here is the
sha256 of the BOUND-PAYLOAD bytes: the exact bytes `warden/signing.py`'s
`bound_payload_bytes` produces and the Ed25519 signature is taken over
({sha256, chain_head, attestation_sha, fact_record_hash}). Timestamping the bound
payload (rather than the raw run-log sha) means the timestamp anchors the SAME fact
the signature attests: the ordered, complete run, driven from this fact-record,
that met these deadlines. One value, timestamped and signed, that a tampered margin
or a reordered entry both move.

STRICTLY ADDITIVE, derived read-only. This module never touches
`bound_payload_bytes`, never re-computes the existing detached signature, and never
writes a byte into the hashed run-log JSONL or any sealed packet/sig.json/intoto
sidecar. It reads bytes already on disk and emits a NEW `.tst.json` sidecar beside
them. The run-log sha256, the chain head, the existing signature, audit_run,
tamper_sweep, and byte-identical replay are all UNCHANGED by anything here.

THE RFC 3161 STRUCTURES ARE REAL; THE LIBRARY IS A HAND-ROLLED DER SUBSET. RFC 3161
defines its messages in ASN.1, DER-encoded. Rather than pull a heavy ASN.1 stack
(pyasn1 + rfc3161ng) for the small subset this needs, this module hand-rolls the
exact DER structures RFC 3161 specifies:

  * MessageImprint  ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
                                   hashedMessage  OCTET STRING }   (RFC 3161 2.4.1)
  * TimeStampReq    ::= SEQUENCE { version INTEGER(1), messageImprint MessageImprint,
                                   ... certReq BOOLEAN DEFAULT FALSE, ... }
  * TSTInfo         ::= SEQUENCE { version INTEGER(1), policy OBJECT IDENTIFIER,
                                   messageImprint MessageImprint, serialNumber INTEGER,
                                   genTime GeneralizedTime, ... }   (RFC 3161 2.4.2)
  * TimeStampResp   ::= SEQUENCE { status PKIStatusInfo, timeStampToken ... }

The signed timestamp token here is the DER-encoded TSTInfo signed with Ed25519 by
the demo TSA key. A production deployment swaps the demo TSA for a real RFC 3161
TSA (DigiCert, freeTSA, etc.), whose token is a full CMS SignedData wrapping the
same TSTInfo; the messageImprint, the TSTInfo shape, the genTime, and the
verification logic (TSA signature over the TSTInfo, messageImprint equals the
artifact digest) are identical. The DER encoder/decoder below implements the
minimal TLV set (INTEGER, OCTET STRING, OBJECT IDENTIFIER, SEQUENCE, BOOLEAN,
GeneralizedTime) needed for these structures, faithfully to X.690 DER.

DETERMINISTIC DEMO TSA, configurable for production. A deterministic, offline,
reproducible artifact cannot depend on a live network TSA call: that would add a
network dependency and, worse, a non-deterministic genTime (the real TSA stamps
`now()`), so the sealed sidecar would differ on every capture and byte-identical
reproduction would break. So the DEFAULT authority is a LOCAL DEMO TSA: a
self-issued authority with its own clearly-labeled demo key
(`warden/keys/tsa_seed.demo.ed25519`) that issues a TST over the artifact digest at
a FIXED genTime PASSED IN by the caller (never `now()`), so the sealed sidecar is
byte-stable and reproducible. The TSA is selected through a small `TimestampAuthority`
interface, so a real RFC 3161 TSA endpoint can be plugged in for production (see
`README` in `warden/keys/`), but the build DEFAULTS to the deterministic demo TSA
so it stays reproducible and keyless-runnable.

HONEST DEMO-TSA CAVEAT (stated plainly, the same ethos as the demo-signing-key
caveat). The RFC 3161 MECHANISM is fully real: the messageImprint is a real sha256
of the artifact, the TSTInfo is real DER, the token is a real Ed25519 signature
over it, and one flipped byte of the digest or the token makes verification fail.
What is NOT production-grade is the AUTHORITY. The timestamp is issued by a LOCAL
DEMO TSA whose key ships in this repo, not by a qualified third-party TSA. So a
valid token here proves "this digest was bound to this genTime and signed by the
demo TSA key", not "an independent, trusted, auditable authority witnessed this
digest at this time". Pointing the same interface at a real RFC 3161 TSA (a
deployment configuration, documented in `warden/keys/README.md`) is what makes the
WHEN independently trustworthy. Until then we claim only what the mechanism
delivers.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .signing import bound_payload_bytes

# The demo TSA keypair lives beside the Warden signing keys. It is a SEPARATE key
# from the Warden's: the Warden signs the artifact, the TSA witnesses and signs the
# time, so the two roles (signer and time authority) are held by distinct keys, as
# a real deployment separates them. The seed is named .demo. so it is never
# mistaken for a protected production TSA key.
_KEYS_DIR = Path(__file__).resolve().parent / "keys"
TSA_SEED_PATH = _KEYS_DIR / "tsa_seed.demo.ed25519"
TSA_PUBKEY_PATH = _KEYS_DIR / "tsa_pubkey.ed25519"

# The standard the mechanism implements, named in every receipt.
STANDARD = "RFC 3161 (Time-Stamp Protocol)"

# A fixed, deterministic genTime for the DEMO TSA, used when a caller does not pass
# one. Chosen as the moment just after the inc-8842 captures' final release window
# so the sealed timestamp reads as a plausible "sealed at" instant. A real TSA
# would stamp now(); the demo TSA stamps a PASSED-IN fixed instant so the artifact
# stays byte-identical across runs and machines.
DEMO_GENTIME = datetime(2026, 6, 17, 0, 0, 0, tzinfo=timezone.utc)

# A fixed serial number for the demo TSA tokens. A real TSA issues a fresh,
# unpredictable serial per token; the demo TSA pins one so the sealed sidecar is
# reproducible byte for byte. The serial is part of the signed TSTInfo, so it is
# covered by the token signature like every other field.
DEMO_SERIAL = 1

# The hash algorithm OID (sha256, 2.16.840.1.101.3.4.2.1) and the demo TSA policy
# OID. The policy OID under the 1.3.6.1.4.1 (IANA private enterprise) arc names
# THIS demo TSA's policy; a real TSA carries its own published policy OID.
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_DEMO_TSA_POLICY = "1.3.6.1.4.1.99999.3161.1"

# The one honest line that travels with every timestamp verification output. The
# RFC 3161 mechanism is real; the AUTHORITY is a local demo, not a qualified TSA.
DEMO_TSA_CAVEAT = (
    "Demo TSA: the RFC 3161 mechanism is fully real (the messageImprint is a real "
    "sha256 of the signed artifact, the TSTInfo is real DER, the token is a real "
    "Ed25519 signature over it, and one flipped byte fails verification), but this "
    "timestamp is issued by a LOCAL demo Time-Stamping Authority whose key ships "
    "with the repo, not by a qualified third-party TSA (DigiCert, freeTSA). It "
    "proves 'this digest was bound to this genTime and signed by the demo TSA key', "
    "not that an independent, trusted authority witnessed it. Pointing the same "
    "interface at a real RFC 3161 TSA is a deployment configuration (Phase 2)."
)


# --- A minimal, faithful X.690 DER encoder/decoder ----------------------------
# Only the tags RFC 3161's MessageImprint / TSTInfo / TimeStampReq need: INTEGER,
# BOOLEAN, OCTET STRING, NULL, OBJECT IDENTIFIER, GeneralizedTime, and SEQUENCE.
# Each `der_*` returns the full TLV (tag + length + value); `_read_tlv` parses one.

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_GENERALIZEDTIME = 0x18


def _der_len(length: int) -> bytes:
    """DER definite-length octets for a content length (X.690 8.1.3).

    Lengths under 128 use a single short-form byte; longer lengths use the
    long form: a leading byte 0x80|n followed by n big-endian length bytes."""
    if length < 0:
        raise ValueError("DER length cannot be negative")
    if length < 0x80:
        return bytes([length])
    out = bytearray()
    n = length
    while n > 0:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _tlv(tag: int, value: bytes) -> bytes:
    """Wrap a value in a tag and a DER definite length."""
    return bytes([tag]) + _der_len(len(value)) + value


def der_integer(value: int) -> bytes:
    """DER INTEGER (X.690 8.3): minimal two's-complement big-endian content with a
    leading 0x00 when the high bit would otherwise read as negative."""
    if value < 0:
        raise ValueError("only non-negative integers are needed here")
    if value == 0:
        body = b"\x00"
    else:
        body = bytearray()
        n = value
        while n > 0:
            body.insert(0, n & 0xFF)
            n >>= 8
        if body[0] & 0x80:
            body.insert(0, 0x00)
        body = bytes(body)
    return _tlv(TAG_INTEGER, body)


def der_boolean(value: bool) -> bytes:
    """DER BOOLEAN (X.690 8.2): TRUE is 0xFF, FALSE is 0x00."""
    return _tlv(TAG_BOOLEAN, b"\xff" if value else b"\x00")


def der_octet_string(value: bytes) -> bytes:
    """DER OCTET STRING: the raw bytes as content."""
    return _tlv(TAG_OCTET_STRING, value)


def der_null() -> bytes:
    """DER NULL: an empty-content TLV."""
    return _tlv(TAG_NULL, b"")


def der_oid(oid: str) -> bytes:
    """DER OBJECT IDENTIFIER (X.690 8.19): first two arcs fold into 40*a1+a2, each
    remaining arc is base-128 with the high bit set on all but the last octet."""
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        raise ValueError("an OID needs at least two arcs")
    body = bytearray([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        if arc == 0:
            body.append(0x00)
            continue
        stack = []
        n = arc
        while n > 0:
            stack.insert(0, n & 0x7F)
            n >>= 7
        for k in range(len(stack) - 1):
            stack[k] |= 0x80
        body.extend(stack)
    return _tlv(TAG_OID, bytes(body))


def der_generalizedtime(dt: datetime) -> bytes:
    """DER GeneralizedTime (X.690 11.7) for a UTC instant: 'YYYYMMDDHHMMSSZ', no
    fractional seconds, the 'Z' zulu suffix. The datetime is normalized to UTC
    first so the encoding is zone-independent and byte-stable."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    text = dt.strftime("%Y%m%d%H%M%S") + "Z"
    return _tlv(TAG_GENERALIZEDTIME, text.encode("ascii"))


def der_sequence(*elements: bytes) -> bytes:
    """DER SEQUENCE: the concatenated element TLVs wrapped in the SEQUENCE tag."""
    return _tlv(TAG_SEQUENCE, b"".join(elements))


def _read_len(data: bytes, pos: int) -> tuple[int, int]:
    """Read a DER length starting at pos; return (length, new_pos)."""
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    num = first & 0x7F
    if num == 0:
        raise ValueError("indefinite-length DER is not allowed")
    length = 0
    for _ in range(num):
        length = (length << 8) | data[pos]
        pos += 1
    return length, pos


def _read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """Read one TLV at pos; return (tag, value_bytes, new_pos)."""
    tag = data[pos]
    pos += 1
    length, pos = _read_len(data, pos)
    value = data[pos:pos + length]
    if len(value) != length:
        raise ValueError("truncated DER value")
    return tag, value, pos + length


def _parse_integer(value: bytes) -> int:
    """Parse a DER INTEGER content (non-negative here) to an int."""
    return int.from_bytes(value, "big")


def _parse_oid(value: bytes) -> str:
    """Parse a DER OBJECT IDENTIFIER content back to its dotted string."""
    if not value:
        raise ValueError("empty OID")
    first = value[0]
    arcs = [first // 40, first % 40]
    n = 0
    for byte in value[1:]:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(n)
            n = 0
    return ".".join(str(a) for a in arcs)


# --- RFC 3161 structures ------------------------------------------------------


def message_imprint(hashed_message: bytes,
                    hash_oid: str = OID_SHA256) -> bytes:
    """RFC 3161 2.4.1 MessageImprint ::= SEQUENCE { hashAlgorithm
    AlgorithmIdentifier, hashedMessage OCTET STRING }.

    `hashed_message` is the digest of the data being timestamped (here, the sha256
    of the bound-payload bytes). The AlgorithmIdentifier is the sha256 OID with a
    NULL parameter, the canonical encoding for sha256."""
    alg = der_sequence(der_oid(hash_oid), der_null())
    return der_sequence(alg, der_octet_string(hashed_message))


def build_timestamp_request(artifact_digest: bytes,
                            *, cert_req: bool = True) -> bytes:
    """RFC 3161 2.4.1 TimeStampReq over an artifact digest: SEQUENCE { version
    INTEGER 1, messageImprint MessageImprint, certReq BOOLEAN }.

    This is the request a client sends a TSA. It is DER here so a real TSA endpoint
    could be handed these exact bytes; the demo TSA below consumes them in-process.
    nonce and reqPolicy are omitted (both OPTIONAL in RFC 3161); the deterministic
    demo path needs no nonce, and omitting it keeps the request byte-stable."""
    return der_sequence(
        der_integer(1),
        message_imprint(artifact_digest),
        der_boolean(cert_req),
    )


def build_tst_info(artifact_digest: bytes, gen_time: datetime,
                   *, serial: int = DEMO_SERIAL,
                   policy_oid: str = OID_DEMO_TSA_POLICY) -> bytes:
    """RFC 3161 2.4.2 TSTInfo: SEQUENCE { version INTEGER 1, policy OBJECT
    IDENTIFIER, messageImprint MessageImprint, serialNumber INTEGER, genTime
    GeneralizedTime }.

    This is the structure the TSA SIGNS: it binds the messageImprint (the artifact
    digest) to a genTime under a serial and a policy. The DER bytes of THIS are what
    the demo TSA's Ed25519 signature is taken over, so a verifier re-encodes the
    TSTInfo and checks the signature, then checks the embedded messageImprint
    equals the artifact's digest."""
    return der_sequence(
        der_integer(1),
        der_oid(policy_oid),
        message_imprint(artifact_digest),
        der_integer(serial),
        der_generalizedtime(gen_time),
    )


@dataclass(frozen=True)
class ParsedTstInfo:
    """The fields decoded back out of a TSTInfo's DER, for verification and
    display: the version, the policy OID, the hash OID, the timestamped digest
    (hex), the serial, and the genTime."""

    version: int
    policy_oid: str
    hash_oid: str
    hashed_message_hex: str
    serial: int
    gen_time: datetime


def parse_tst_info(tst_info_der: bytes) -> ParsedTstInfo:
    """Decode a TSTInfo's DER back into its fields (the inverse of build_tst_info).

    Walks the SEQUENCE: version, policy OID, MessageImprint (itself a SEQUENCE of
    AlgorithmIdentifier and the hashed OCTET STRING), serialNumber, genTime. Raises
    ValueError on any structural surprise so a tampered token fails loudly rather
    than silently mis-parsing."""
    tag, body, _ = _read_tlv(tst_info_der, 0)
    if tag != TAG_SEQUENCE:
        raise ValueError("TSTInfo is not a SEQUENCE")
    pos = 0
    tag, val, pos = _read_tlv(body, pos)
    if tag != TAG_INTEGER:
        raise ValueError("TSTInfo version is not an INTEGER")
    version = _parse_integer(val)

    tag, val, pos = _read_tlv(body, pos)
    if tag != TAG_OID:
        raise ValueError("TSTInfo policy is not an OID")
    policy_oid = _parse_oid(val)

    tag, mi_body, pos = _read_tlv(body, pos)
    if tag != TAG_SEQUENCE:
        raise ValueError("TSTInfo messageImprint is not a SEQUENCE")
    # MessageImprint: AlgorithmIdentifier SEQUENCE, then the hashed OCTET STRING.
    atag, alg_body, mpos = _read_tlv(mi_body, 0)
    if atag != TAG_SEQUENCE:
        raise ValueError("messageImprint hashAlgorithm is not a SEQUENCE")
    otag, oid_val, _ = _read_tlv(alg_body, 0)
    if otag != TAG_OID:
        raise ValueError("hashAlgorithm OID missing")
    hash_oid = _parse_oid(oid_val)
    htag, hashed, _ = _read_tlv(mi_body, mpos)
    if htag != TAG_OCTET_STRING:
        raise ValueError("messageImprint hashedMessage is not an OCTET STRING")

    tag, val, pos = _read_tlv(body, pos)
    if tag != TAG_INTEGER:
        raise ValueError("TSTInfo serialNumber is not an INTEGER")
    serial = _parse_integer(val)

    tag, val, pos = _read_tlv(body, pos)
    if tag != TAG_GENERALIZEDTIME:
        raise ValueError("TSTInfo genTime is not a GeneralizedTime")
    gen_time = _parse_generalizedtime(val)

    return ParsedTstInfo(
        version=version,
        policy_oid=policy_oid,
        hash_oid=hash_oid,
        hashed_message_hex=hashed.hex(),
        serial=serial,
        gen_time=gen_time,
    )


def _parse_generalizedtime(value: bytes) -> datetime:
    """Parse a DER GeneralizedTime 'YYYYMMDDHHMMSSZ' back to an aware UTC datetime."""
    text = value.decode("ascii")
    if not text.endswith("Z"):
        raise ValueError("only zulu (Z) GeneralizedTime is produced here")
    dt = datetime.strptime(text[:-1], "%Y%m%d%H%M%S")
    return dt.replace(tzinfo=timezone.utc)


# --- The artifact digest the timestamp anchors --------------------------------


def artifact_digest_from_signature(signature_record: dict) -> bytes:
    """The sha256 of the bound-payload bytes the Ed25519 signature was taken over,
    rebuilt from a sealed signature record.

    The signature record carries the four bound values (sha256, chain_head,
    attestation_sha, fact_record_hash). `bound_payload_bytes` reassembles the exact
    canonical bytes the signature covers; sha256 of those bytes is the messageImprint
    the timestamp binds. Timestamping THIS digest anchors the same fact the signature
    attests, so a verifier can confirm the timestamp is over the very artifact that
    was signed (the signature record's own sha256 is recomputable from the run-log
    bytes, closing the loop back to the log)."""
    payload = bound_payload_bytes(
        signature_record.get("sha256", ""),
        signature_record.get("chain_head", ""),
        signature_record.get("attestation_sha", ""),
        signature_record.get("fact_record_hash", ""),
    )
    return hashlib.sha256(payload).digest()


# --- The Time-Stamping Authority interface ------------------------------------


class TimestampAuthority:
    """The pluggable TSA seam: given a TimeStampReq, return a TimeStampResp.

    The DEFAULT implementation is the deterministic local demo TSA below. A
    production deployment subclasses this with an `HttpRfc3161Authority` that POSTs
    the DER request to a real TSA URL (Content-Type application/timestamp-query) and
    returns the TSA's TimeStampResp, whose timeStampToken is a CMS SignedData over
    the same TSTInfo. The rest of the pipeline (request build, response parse,
    verification, sidecar) is identical regardless of which authority signs."""

    def request_token(self, request_der: bytes) -> dict:
        raise NotImplementedError


def load_demo_tsa_private_key() -> Ed25519PrivateKey:
    """Load the committed DEMO TSA Ed25519 private key from its hex seed. Raises if
    the seed is missing or malformed: a timestamping path must never silently fall
    back to an unsigned token."""
    seed_hex = TSA_SEED_PATH.read_text(encoding="utf-8").strip()
    seed = bytes.fromhex(seed_hex)
    if len(seed) != 32:
        raise ValueError(
            f"demo TSA Ed25519 seed must be 32 bytes (64 hex chars); got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed)


def load_demo_tsa_public_key_hex() -> str:
    """Load the committed demo TSA public key as a 64-char hex string. This is what
    a verifier checks the timestamp token signature against."""
    return TSA_PUBKEY_PATH.read_text(encoding="utf-8").strip()


def _load_tsa_public_key(public_key_hex: str | None = None) -> Ed25519PublicKey:
    if public_key_hex is None:
        public_key_hex = load_demo_tsa_public_key_hex()
    raw = bytes.fromhex(public_key_hex)
    if len(raw) != 32:
        raise ValueError(
            f"TSA Ed25519 public key must be 32 bytes (64 hex chars); got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


class DemoTimestampAuthority(TimestampAuthority):
    """A self-issued LOCAL demo TSA: it parses the request's messageImprint, builds
    a TSTInfo binding it to a FIXED genTime, and signs the TSTInfo's DER with the
    committed demo TSA key.

    Deterministic by construction: the genTime, the serial, and the policy are all
    fixed inputs (never now(), never a random nonce or serial), and Ed25519 is
    deterministic, so the same request always yields the same token byte for byte.
    That is what keeps the sealed `.tst.json` sidecar reproducible. The token is the
    DER-encoded TSTInfo plus its detached Ed25519 signature; a production TSA would
    return a CMS SignedData wrapping the identical TSTInfo, which is the only part
    that changes when the demo authority is swapped for a real one."""

    def __init__(self, gen_time: datetime | None = None,
                 private_key: Ed25519PrivateKey | None = None,
                 *, serial: int = DEMO_SERIAL,
                 policy_oid: str = OID_DEMO_TSA_POLICY,
                 provider: object | None = None) -> None:
        if private_key is not None and provider is not None:
            raise ValueError(
                "pass a custody provider OR a raw private_key, not both")
        self.gen_time = gen_time or DEMO_GENTIME
        self._private_key = private_key
        self._provider = provider
        self.serial = serial
        self.policy_oid = policy_oid

    def _key(self) -> Ed25519PrivateKey:
        if self._private_key is not None:
            return self._private_key
        return load_demo_tsa_private_key()

    def _signing_provider(self) -> object:
        """The custody provider that signs the TSTInfo (the TSA's key). DEFAULT:
        the committed demo TSA key, in process, byte-identical to before. The
        explicit `private_key` override is wrapped to the same interface, and a
        deployment can pass a `KmsProvider`/`Pkcs11Provider` so the TSA private
        key never leaves the KMS/HSM. Imported locally so this module need not
        depend on custody at import time."""
        if self._provider is not None:
            return self._provider
        if self._private_key is not None:
            from .custody import LocalKeyProvider
            return LocalKeyProvider(self._private_key)
        from .custody import tsa_signing_provider
        return tsa_signing_provider()

    def request_token(self, request_der: bytes) -> dict:
        """Issue a TimeStampResp dict for a DER TimeStampReq.

        Parses the messageImprint out of the request, builds the TSTInfo over it at
        the fixed genTime, signs the TSTInfo DER through the TSA custody provider
        (the demo TSA key by default), and returns a response carrying PKIStatus
        granted (0), the TSTInfo DER (hex), the genTime, the serial, the policy, the
        token signature (hex), and the TSA public key."""
        digest = _message_imprint_digest_of_request(request_der)
        tst_info = build_tst_info(
            digest, self.gen_time, serial=self.serial, policy_oid=self.policy_oid)
        signer = self._signing_provider()
        signature = bytes.fromhex(signer.sign(tst_info))
        pub_hex = signer.public_key_hex()
        return {
            "standard": STANDARD,
            "tsa": "Deadline Room demo TSA",
            "demo_tsa": True,
            "pki_status": 0,
            "pki_status_string": "granted",
            "policy_oid": self.policy_oid,
            "serial_number": self.serial,
            "gen_time": self.gen_time.astimezone(timezone.utc).isoformat(),
            "hash_algorithm": "sha256",
            "hash_oid": OID_SHA256,
            "timestamped_digest": digest.hex(),
            "tst_info_der": tst_info.hex(),
            "signature_algorithm": "ed25519",
            "token_signature": signature.hex(),
            "tsa_public_key": pub_hex,
            "tsa_pubkey_fingerprint": hashlib.sha256(
                bytes.fromhex(pub_hex)).hexdigest()[:16],
            "caveat": DEMO_TSA_CAVEAT,
        }


def _message_imprint_digest_of_request(request_der: bytes) -> bytes:
    """Pull the hashedMessage bytes out of a DER TimeStampReq's messageImprint.

    Walks TimeStampReq: version INTEGER, then MessageImprint SEQUENCE (an
    AlgorithmIdentifier SEQUENCE, then the hashed OCTET STRING). Returns the raw
    digest bytes the request asked to be timestamped."""
    tag, body, _ = _read_tlv(request_der, 0)
    if tag != TAG_SEQUENCE:
        raise ValueError("TimeStampReq is not a SEQUENCE")
    pos = 0
    tag, _, pos = _read_tlv(body, pos)  # version
    if tag != TAG_INTEGER:
        raise ValueError("TimeStampReq version is not an INTEGER")
    tag, mi_body, pos = _read_tlv(body, pos)  # messageImprint
    if tag != TAG_SEQUENCE:
        raise ValueError("TimeStampReq messageImprint is not a SEQUENCE")
    atag, _, mpos = _read_tlv(mi_body, 0)  # AlgorithmIdentifier
    if atag != TAG_SEQUENCE:
        raise ValueError("messageImprint hashAlgorithm is not a SEQUENCE")
    htag, hashed, _ = _read_tlv(mi_body, mpos)
    if htag != TAG_OCTET_STRING:
        raise ValueError("messageImprint hashedMessage is not an OCTET STRING")
    return bytes(hashed)


# --- Issuing and verifying a timestamp over a signed artifact -----------------


def timestamp_signature_record(signature_record: dict,
                               authority: TimestampAuthority | None = None) -> dict:
    """Issue an RFC 3161 timestamp token over a sealed signature record.

    Computes the artifact digest (sha256 of the bound-payload bytes the Ed25519
    signature covers), builds the DER TimeStampReq, asks the authority (the
    deterministic demo TSA by default) to issue the response, and returns the
    response token dict that lands in the `.tst.json` sidecar. Derived read-only
    from the signature record; it never touches the run log or any sealed sidecar."""
    if authority is None:
        authority = DemoTimestampAuthority()
    digest = artifact_digest_from_signature(signature_record)
    request_der = build_timestamp_request(digest)
    token = authority.request_token(request_der)
    # Record the bound values the digest was built from, so a verifier can confirm
    # the timestamp anchors the SAME artifact the signature attests (and recompute
    # the digest itself from the signature record without trusting the token).
    token["bound"] = {
        "sha256": signature_record.get("sha256", ""),
        "chain_head": signature_record.get("chain_head", ""),
        "attestation_sha": signature_record.get("attestation_sha", ""),
        "fact_record_hash": signature_record.get("fact_record_hash", ""),
    }
    token["artifact_digest"] = digest.hex()
    return token


@dataclass(frozen=True)
class TimestampVerification:
    """The structured verdict of verifying a timestamp token: overall validity, the
    two component checks (the TSA signature over the TSTInfo, and the messageImprint
    equalling the artifact digest), the parsed genTime, and the serial/policy."""

    valid: bool
    signature_valid: bool
    imprint_matches: bool
    gen_time: datetime | None
    serial: int | None
    policy_oid: str | None
    detail: str


def verify_timestamp_token(token: dict, signature_record: dict) -> TimestampVerification:
    """Verify an RFC 3161 timestamp token against a sealed signature record.

    Two independent checks, both must hold for VALID:

      1. SIGNATURE: the demo TSA's Ed25519 signature verifies over the TSTInfo DER
         carried in the token (re-decoded, never trusted blind). One flipped byte of
         the TSTInfo or the signature fails this.
      2. IMPRINT: the messageImprint inside the TSTInfo equals the artifact digest
         recomputed from the signature record (sha256 of the bound-payload bytes).
         This is what ties the timestamp to the very artifact that was signed; a
         timestamp over a different digest fails here even with a valid signature.

    Returns a structured verdict (never raises on tampered input) so a verifier can
    print VALID/INVALID and exit 0/nonzero with the genTime and the locus."""
    tst_info_hex = token.get("tst_info_der", "")
    token_sig_hex = token.get("token_signature", "")
    tsa_pub_hex = token.get("tsa_public_key")

    signature_valid = False
    imprint_matches = False
    parsed: ParsedTstInfo | None = None
    try:
        tst_info_der = bytes.fromhex(tst_info_hex)
        public_key = _load_tsa_public_key(tsa_pub_hex)
        public_key.verify(bytes.fromhex(token_sig_hex), tst_info_der)
        signature_valid = True
    except (InvalidSignature, ValueError):
        signature_valid = False

    try:
        if signature_valid:
            parsed = parse_tst_info(bytes.fromhex(tst_info_hex))
            expected = artifact_digest_from_signature(signature_record).hex()
            imprint_matches = parsed.hashed_message_hex == expected
    except (ValueError, KeyError):
        imprint_matches = False

    valid = signature_valid and imprint_matches
    if valid:
        detail = (
            f"TSA signature valid over TSTInfo; messageImprint equals the artifact "
            f"digest; timestamped at {parsed.gen_time.isoformat()}")
    elif not signature_valid:
        detail = "the demo TSA signature does NOT verify over the TSTInfo"
    else:
        detail = ("the TSTInfo messageImprint does NOT equal the signed artifact's "
                  "digest")
    return TimestampVerification(
        valid=valid,
        signature_valid=signature_valid,
        imprint_matches=imprint_matches,
        gen_time=parsed.gen_time if parsed else None,
        serial=parsed.serial if parsed else None,
        policy_oid=parsed.policy_oid if parsed else None,
        detail=detail,
    )


def sidecar_path_for(run_log_path: str | Path) -> Path:
    """The RFC 3161 timestamp sidecar path beside a run log: `<run-log>.tst.json`.
    Mirrors how the `.sig.json` and `.intoto.json` sidecars are named, and is a NEW
    file, so the run-log/packet/sig.json/intoto bytes are never rewritten."""
    p = Path(run_log_path)
    return p.with_suffix(p.suffix + ".tst.json")
