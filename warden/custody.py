"""Key-custody seam: WHERE the signing key lives is a swappable provider, so a
production deployment can sign through a KMS/HSM where the private key never
leaves the device, while the build DEFAULTS to the committed local demo key and
keeps every sealed artifact byte-identical.

The honest demo-key caveat in `warden/signing.py` admits the private seed ships
in this repo. That caveat is about SECRECY, not about the mechanism: the Ed25519
signature is fully real and one flipped byte makes it INVALID. The production fix
for the secrecy gap is a code seam, not prose, so this module turns "load the
seed, sign in process" into "ask a SigningProvider to sign these bytes". The
default provider (`LocalKeyProvider`) still loads the committed demo seed and
signs in process, so today's behavior and every committed signature are
unchanged. A production provider (`KmsProvider`, `Pkcs11Provider`) delegates the
sign call to an external KMS/HSM, so the raw private key never enters the
process; the rest of the pipeline (bound payload, signature record, verifier)
does not change.

WHY A PROVIDER, NOT JUST AN OPTIONAL KEY ARGUMENT. The signing functions already
accept an optional `Ed25519PrivateKey`. That is enough for a TEST to pass a key,
but it is the wrong shape for production custody: a KMS/HSM never hands back a
private-key object, it exposes only a `sign(bytes) -> signature` operation behind
an access policy. Modeling custody as a provider with `sign()` plus
`public_key_hex()`/`fingerprint()` (and deliberately NO raw-key accessor on the
remote path) is the shape a real KMS/HSM has, so the seam is faithful: the
in-process demo key and a remote KMS key are interchangeable through it.

WHAT IS BYTE-PRESERVING. Ed25519 is deterministic: the same payload and the same
key always yield the same 64-byte signature. The `LocalKeyProvider` loads the
SAME committed demo seed `warden/signing.py` loads today and calls the SAME
`Ed25519PrivateKey.sign`, so a signature produced through the provider is
byte-identical to one produced by the pre-custody path. The four sealed captures
and their TSA tokens are therefore unchanged; nothing is re-signed.

TWO KEYS, ONE SEAM. The Warden signs the run-log artifact; the demo TSA witnesses
and signs the time. They are distinct roles held by distinct keys, and BOTH route
through this one interface (`warden_signing_provider()` and `tsa_signing_provider()`),
so a deployment points each at its own KMS/HSM key independently.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .signing import (
    load_demo_private_key,
    public_key_hex_of,
)


def _fingerprint_of(public_key_hex: str) -> str:
    """The short, stable display fingerprint of a public key: the first 16 hex
    chars of sha256(pubkey bytes). Mirrors `warden.signing.fingerprint`, kept
    local so a provider can name its signer without an import cycle back into the
    signing functions that will call providers."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


class SigningProvider:
    """The custody seam: an object that can SIGN bytes and NAME its public key,
    without ever exposing the private key material to the caller.

    Three operations, the exact surface a KMS/HSM offers:

      * `sign(payload) -> signature_hex` : produce a detached Ed25519 signature
        over `payload`, returned as 128-char hex (the 64-byte signature). On a
        remote provider this is a network/HSM call; the private key never leaves
        the device.
      * `public_key_hex() -> str`        : the 64-char hex public key a verifier
        checks the signature against. Public material only.
      * `fingerprint() -> str`           : the short display fingerprint of the
        public key, for receipts and the packet.

    There is deliberately NO method that returns the raw private key. A local
    provider holds one in process (it has to, to sign), but the INTERFACE never
    surfaces it, so signing call sites are written against custody, not against a
    key object, and swapping in a KMS/HSM changes only which provider is
    constructed."""

    def sign(self, payload: bytes) -> str:
        raise NotImplementedError

    def public_key_hex(self) -> str:
        raise NotImplementedError

    def fingerprint(self) -> str:
        return _fingerprint_of(self.public_key_hex())

    def public_key(self) -> Ed25519PublicKey:
        """The Ed25519 public-key object, built from the public hex. Public
        material only, so this is safe on every provider including the remote
        ones; it is the verifier-side counterpart to `sign`."""
        raw = bytes.fromhex(self.public_key_hex())
        if len(raw) != 32:
            raise ValueError(
                f"Ed25519 public key must be 32 bytes (64 hex chars); got {len(raw)}")
        return Ed25519PublicKey.from_public_bytes(raw)


class LocalKeyProvider(SigningProvider):
    """The DEFAULT provider: an in-process Ed25519 key, signed locally. This is
    the pre-custody behavior, now behind the seam.

    Constructed with an `Ed25519PrivateKey` already in hand, or via
    `from_demo_seed()` / `from_demo_tsa_seed()` to load a committed demo seed.
    Because it loads the SAME seed and calls the SAME `Ed25519PrivateKey.sign`
    the pre-custody path used, signatures it produces are BYTE-IDENTICAL to the
    committed ones; nothing is re-signed by routing through it.

    The private key lives in process here (a local key has to, to sign), but the
    SigningProvider interface still never exposes it: callers see only `sign`,
    `public_key_hex`, and `fingerprint`, the same three operations a KMS/HSM
    offers. That is what makes a deployment able to swap this for a remote
    provider without touching a signing call site."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key_hex = public_key_hex_of(private_key)

    @classmethod
    def from_demo_seed(cls) -> "LocalKeyProvider":
        """Load the committed Warden DEMO signing seed (`warden/keys/
        warden_seed.demo.ed25519`). This is exactly the key the pre-custody
        signing path loaded, so the produced signatures are byte-identical."""
        return cls(load_demo_private_key())

    @classmethod
    def from_demo_tsa_seed(cls) -> "LocalKeyProvider":
        """Load the committed DEMO TSA seed (`warden/keys/tsa_seed.demo.ed25519`).
        The TSA's key is distinct from the Warden's (signer and time authority are
        separate roles), but both route through this one interface."""
        # Local import to avoid an import cycle: timestamp.py imports from signing,
        # and signing has no need to know about the TSA key loader.
        from .timestamp import load_demo_tsa_private_key
        return cls(load_demo_tsa_private_key())

    def sign(self, payload: bytes) -> str:
        """Detached Ed25519 signature over `payload`, as 128-char hex. Ed25519 is
        deterministic, so this equals the pre-custody `sign_bytes` output for the
        same payload and key, which is what keeps the captures byte-identical."""
        return self._private_key.sign(payload).hex()

    def public_key_hex(self) -> str:
        return self._public_key_hex


class MockKmsProvider(SigningProvider):
    """An in-memory provider shaped like a KMS, for tests and to PROVE the seam.

    It signs with the SAME Ed25519 primitive a real provider would, but reaches
    the key only through a KMS-shaped operation (`_kms_sign`) rather than holding
    an `Ed25519PrivateKey` the caller can read. A real `KmsProvider` makes the
    identical call over the network to AWS KMS / Azure Key Vault / GCP KMS; this
    mock makes it against an in-memory key, so a test exercises the exact seam a
    deployment uses without a cloud dependency.

    Critically, the interface exposes NO raw private key: `_key_handle` is a label
    (as a KMS key ARN/URI is a label, not the key), and there is no method that
    returns private bytes. A signature it produces verifies under an UNCHANGED
    verifier, because the wire form (a detached Ed25519 signature over the same
    payload) is identical regardless of where the key sits. That is the whole
    point of the seam: signing through KMS yields a signature the existing
    `verify_run_log_jsonl` / `verify_bytes` accept with no change."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None,
                 *, key_handle: str = "mock-kms://deadline-room/warden") -> None:
        # The "remote" key. A real KMS holds this inside the service and never
        # returns it; the mock keeps it in a private attribute reachable only
        # through `_kms_sign`, never through any public method, to model that
        # boundary. A caller cannot retrieve it through the SigningProvider API.
        self.__private_key = private_key or Ed25519PrivateKey.generate()
        self._key_handle = key_handle
        self._public_key_hex = public_key_hex_of(self.__private_key)

    def _kms_sign(self, payload: bytes) -> bytes:
        """The KMS-shaped sign primitive: hand the payload to the key service,
        get back raw signature bytes. A real provider POSTs to the KMS sign API
        with the key handle and the payload digest; this mock signs in memory.
        The key bytes never cross this boundary in either direction."""
        return self.__private_key.sign(payload)

    def sign(self, payload: bytes) -> str:
        """Detached Ed25519 signature over `payload` as 128-char hex, produced via
        the KMS-shaped `_kms_sign`. The output is an ordinary Ed25519 signature,
        so an unchanged verifier accepts it."""
        return self._kms_sign(payload).hex()

    def public_key_hex(self) -> str:
        return self._public_key_hex


class KmsProvider(SigningProvider):
    """Production custody via a cloud KMS asymmetric-sign API. SHIPPED AS A CLEAN
    INTERFACE, not a live call: the network call is left to a deployer to wire to
    its chosen KMS, because a reproducible offline build must not depend on a
    cloud round-trip. This is the seam, documented, that a deployment fills in.

    Wiring (AWS KMS, Azure Key Vault, GCP KMS all follow this shape):

      * Create an asymmetric Ed25519 signing key in the KMS. The PRIVATE key never
        leaves the KMS; it is non-exportable by policy.
      * `public_key_hex()` returns the key's PUBLIC half, fetched once from the
        KMS (AWS `GetPublicKey`, Azure `getKey`, GCP `getPublicKey`) and cached.
        Public material only, safe to hold and to publish in a key directory.
      * `sign(payload)` calls the KMS sign operation with the key id and the
        payload:
          - AWS KMS:        `kms.sign(KeyId=..., Message=payload,
                            MessageType='RAW', SigningAlgorithm='EDDSA')`.
          - Azure Key Vault: the Cryptography client `sign` with the Ed25519 alg
                            over the payload.
          - GCP KMS:        `asymmetricSign` on the key version with the payload.
        The KMS returns the 64-byte Ed25519 signature; this provider returns it as
        128-char hex, the identical wire form the verifier already accepts.

    Because the signature wire form is identical, the bound payload, the signature
    record, and `verify_run_log_jsonl` do not change: only WHERE the private key
    lives changes. In this mode no private key is in the repo. Construction takes
    the KMS key id/ARN and a region/endpoint; `sign` and `public_key_hex` are the
    two methods a deployer implements against its KMS SDK. They raise here so a
    misconfigured deployment fails loudly rather than silently signing with a
    wrong key."""

    def __init__(self, key_id: str, *, region: str | None = None,
                 endpoint: str | None = None) -> None:
        self.key_id = key_id
        self.region = region
        self.endpoint = endpoint

    def sign(self, payload: bytes) -> str:
        raise NotImplementedError(
            "KmsProvider.sign is the production seam: implement the KMS "
            "asymmetric-sign call (AWS kms.sign EDDSA / Azure Key Vault sign / "
            "GCP asymmetricSign) for key_id "
            f"{self.key_id!r} and return the 64-byte Ed25519 signature as hex. "
            "The private key never leaves the KMS.")

    def public_key_hex(self) -> str:
        raise NotImplementedError(
            "KmsProvider.public_key_hex is the production seam: fetch the public "
            f"half of KMS key {self.key_id!r} (AWS GetPublicKey / Azure getKey / "
            "GCP getPublicKey), return its 32 raw bytes as 64-char hex, and cache "
            "it. Public material only.")


class Pkcs11Provider(SigningProvider):
    """Production custody via a PKCS#11 hardware security module (HSM). SHIPPED AS
    A CLEAN INTERFACE, not a live call, for the same reason as `KmsProvider`: a
    reproducible offline build cannot depend on an attached HSM.

    Wiring (any PKCS#11-conformant HSM: a YubiHSM, a Luna HSM, a SoftHSM in test):

      * Provision an Ed25519 key pair on the token with a label/CKA_ID. The
        private key is generated ON the device and marked non-extractable, so it
        physically cannot leave the HSM.
      * Open a session against the PKCS#11 module (`pkcs11` / `python-pkcs11`),
        log in with the user PIN, and locate the private key object by label.
      * `sign(payload)` calls `C_Sign` (the library's `key.sign(payload,
        mechanism=Mechanism.EDDSA)`) and returns the 64-byte signature as hex.
        The HSM performs the signature internally; the host process never sees the
        private key.
      * `public_key_hex()` reads the matching public-key object's EC point and
        returns its 32 raw Ed25519 bytes as hex. Public material only.

    The signature wire form is identical to the local path, so nothing downstream
    changes; only the key custody does. In this mode no private key is in the
    repo. Construction takes the PKCS#11 module path, the token label, and the key
    label; `sign` and `public_key_hex` are the two methods a deployer implements
    against the HSM session. They raise here so a misconfigured HSM fails loudly."""

    def __init__(self, module_path: str, *, token_label: str,
                 key_label: str) -> None:
        self.module_path = module_path
        self.token_label = token_label
        self.key_label = key_label

    def sign(self, payload: bytes) -> str:
        raise NotImplementedError(
            "Pkcs11Provider.sign is the production seam: open a PKCS#11 session "
            f"on module {self.module_path!r}, find the private key labelled "
            f"{self.key_label!r}, call C_Sign with the EDDSA mechanism over the "
            "payload, and return the 64-byte signature as hex. The HSM signs "
            "internally; the key never leaves the device.")

    def public_key_hex(self) -> str:
        raise NotImplementedError(
            "Pkcs11Provider.public_key_hex is the production seam: read the public "
            f"key object labelled {self.key_label!r} from the HSM, return its 32 "
            "raw Ed25519 bytes as 64-char hex. Public material only.")


# --- The default providers the pipeline uses ----------------------------------
# Each signing call site asks for a provider rather than loading a seed, so the
# custody is configurable in one place. The DEFAULTS are the committed demo keys,
# which keeps the build keyless-runnable, offline, and byte-identical. A
# deployment swaps these for a KmsProvider/Pkcs11Provider pointed at its own key.


def warden_signing_provider() -> SigningProvider:
    """The provider that signs the run-log artifact (the Warden's key). DEFAULT:
    the committed demo signing key, in process, byte-identical to today. A
    deployment returns a `KmsProvider`/`Pkcs11Provider` here instead, and no
    private key is in the repo."""
    return LocalKeyProvider.from_demo_seed()


def tsa_signing_provider() -> SigningProvider:
    """The provider that signs the RFC 3161 timestamp token (the demo TSA's key).
    DEFAULT: the committed demo TSA key, in process, byte-identical to today.
    Distinct from the Warden's signing key, since signer and time authority are
    distinct roles; routed through the SAME custody interface so a deployment
    points it at its own KMS/HSM key independently."""
    return LocalKeyProvider.from_demo_tsa_seed()


def verify_with_provider_pubkey(payload: bytes, signature_hex: str,
                                provider: SigningProvider) -> bool:
    """True iff `signature_hex` verifies over `payload` under `provider`'s public
    key. The verify side needs only public material, so this works for every
    provider (local, mock KMS, real KMS, HSM) identically: a signature made
    through any provider is verified the same way, which is the proof the seam is
    real. Returns False on any invalid signature rather than raising."""
    try:
        provider.public_key().verify(bytes.fromhex(signature_hex), payload)
        return True
    except (InvalidSignature, ValueError):
        return False
