"""Key-custody seam (warden/custody.py): WHERE the signing key lives is a
swappable provider, and the swap is behavior-preserving.

These tests pin the two guarantees that make E2.5 real and not prose:

  * THE DEFAULT IS BYTE-IDENTICAL. `LocalKeyProvider` (the committed demo key, in
    process) produces signatures byte-for-byte equal to the committed captures'
    sealed `.sig.json`, in-toto `.intoto.json`, and RFC 3161 `.tst.json`. The
    refactor re-signs nothing; the sealed evidence is untouched and still VALID.
  * THE KMS SEAM WORKS END TO END. Signing through `MockKmsProvider` (the same
    Ed25519 reached only through a KMS-shaped operation) yields a signature an
    UNCHANGED verifier accepts. The interface exposes no raw private key on the
    KMS path, and a provider's fingerprint matches its public key. That proves the
    seam without a cloud dependency: a real KMS/HSM is interchangeable through it.

Both the Warden signing key and the demo TSA key route through the one interface,
so both are exercised here.
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden.custody import (
    KmsProvider,
    LocalKeyProvider,
    MockKmsProvider,
    Pkcs11Provider,
    SigningProvider,
    tsa_signing_provider,
    verify_with_provider_pubkey,
    warden_signing_provider,
)
from warden.intoto import attestation_for_capture, build_dsse_envelope, verify_dsse_envelope
from warden.replay import RunLog
from warden.signing import (
    bound_payload_bytes,
    fingerprint,
    load_demo_private_key,
    load_public_key_hex,
    sign_run_log_jsonl,
    verify_run_log_jsonl,
)
from warden.timestamp import (
    DemoTimestampAuthority,
    load_demo_tsa_private_key,
    load_demo_tsa_public_key_hex,
    timestamp_signature_record,
    verify_timestamp_token,
)

DATA = Path(__file__).resolve().parents[1] / "web" / "data"
SCENARIOS = ("normal", "inject_contradiction", "chaos", "amendment")


# --- the default LocalKeyProvider is byte-identical to the committed captures --

@pytest.mark.parametrize("mode", SCENARIOS)
def test_local_provider_signature_byte_identical_to_committed_capture(mode):
    """The DEFAULT custody path (LocalKeyProvider over the committed demo key)
    reproduces each sealed capture's signature byte-for-byte. The refactor is
    behavior-preserving: no capture is re-signed, the bytes on disk are unchanged,
    and the signature the provider produces equals the one already sealed."""
    packet = json.loads((DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))
    log = RunLog.load(DATA / f"run-inc-8842-{mode}.jsonl")
    jsonl = log.to_jsonl()

    committed = packet["replay"]["signature"]
    # Re-sign through the default provider path with the SAME two derived digests
    # the capture was sealed with (read from the committed record so the bound
    # payload is identical), and the produced signature must match byte for byte.
    fresh = sign_run_log_jsonl(
        jsonl, committed["attestation_sha"], committed["fact_record_hash"])

    assert fresh["signature"] == committed["signature"]
    assert fresh["public_key"] == committed["public_key"]
    assert fresh["pubkey_fingerprint"] == committed["pubkey_fingerprint"]
    # And the sealed signature still verifies against the unchanged bytes.
    assert verify_run_log_jsonl(jsonl, committed) is True


@pytest.mark.parametrize("mode", SCENARIOS)
def test_local_provider_intoto_and_tsa_byte_identical_to_committed(mode):
    """The same byte-identity holds for the two sidecars that sign with the same
    custody seam: the in-toto DSSE envelope (Warden key) and the RFC 3161 TSA
    token (demo TSA key). Re-producing them through the default provider path
    matches the committed sidecars byte for byte."""
    packet = json.loads((DATA / f"packet-{mode}.json").read_text(encoding="utf-8"))
    log = RunLog.load(DATA / f"run-inc-8842-{mode}.jsonl")
    jsonl = log.to_jsonl()

    committed_env = json.loads(
        (DATA / f"run-inc-8842-{mode}.jsonl.intoto.json").read_text(encoding="utf-8"))
    fresh_env = attestation_for_capture(
        jsonl, packet, subject_name=f"run-inc-8842-{mode}.jsonl")
    assert fresh_env["signatures"][0]["sig"] == committed_env["signatures"][0]["sig"]
    assert fresh_env["public_key"] == committed_env["public_key"]

    committed_tok = json.loads(
        (DATA / f"run-inc-8842-{mode}.jsonl.tst.json").read_text(encoding="utf-8"))
    fresh_tok = timestamp_signature_record(packet["replay"]["signature"])
    assert fresh_tok["token_signature"] == committed_tok["token_signature"]
    assert fresh_tok["tsa_public_key"] == committed_tok["tsa_public_key"]


def test_local_provider_matches_the_raw_demo_key_path():
    """`LocalKeyProvider.from_demo_seed()` loads the exact key the pre-custody path
    loaded, so its public key, fingerprint, and a signature over any payload equal
    the raw `load_demo_private_key().sign` output. This is why routing through the
    provider is byte-identical."""
    provider = warden_signing_provider()
    assert isinstance(provider, LocalKeyProvider)
    assert provider.public_key_hex() == load_public_key_hex()
    assert provider.fingerprint() == fingerprint(load_public_key_hex())

    raw_key = load_demo_private_key()
    payload = bound_payload_bytes("a" * 64, "b" * 64, "c" * 64, "d" * 64)
    assert provider.sign(payload) == raw_key.sign(payload).hex()


def test_tsa_provider_matches_the_raw_demo_tsa_key_path():
    """The TSA key routes through the same interface. The default TSA provider's
    public key, fingerprint, and signature equal the raw demo TSA key's, so the
    TSA token is byte-identical too."""
    provider = tsa_signing_provider()
    assert isinstance(provider, LocalKeyProvider)
    assert provider.public_key_hex() == load_demo_tsa_public_key_hex()

    raw_key = load_demo_tsa_private_key()
    payload = b"some tst_info DER stand-in"
    assert provider.sign(payload) == raw_key.sign(payload).hex()


# --- the MockKms seam: sign through KMS, an unchanged verifier accepts ----------

def test_mock_kms_signature_verifies_under_the_unchanged_verifier():
    """Signing a run log THROUGH the KMS-shaped MockKmsProvider yields a record the
    REAL verifier accepts with no change. The wire form (a detached Ed25519
    signature over the bound payload) is identical regardless of where the key
    sits, which is the whole point of the seam."""
    log = RunLog.load(DATA / "run-inc-8842-normal.jsonl")
    jsonl = log.to_jsonl()
    kms = MockKmsProvider()

    record = sign_run_log_jsonl(jsonl, "a" * 64, "b" * 64, provider=kms)

    # The unchanged verifier accepts it: the signature is over the same bound
    # payload, and the record carries the KMS key's public half.
    assert verify_run_log_jsonl(jsonl, record) is True
    assert record["public_key"] == kms.public_key_hex()
    assert record["pubkey_fingerprint"] == kms.fingerprint()


def test_mock_kms_low_level_signature_verifies_with_provider_pubkey():
    """The provider seam verifies symmetrically: a signature from MockKmsProvider
    over arbitrary bytes verifies under that provider's public key via the
    public-only verify helper, and a wrong payload fails. This exercises the seam
    at the raw `sign`/`public_key` level."""
    kms = MockKmsProvider()
    payload = b"the bound payload bytes the warden signs"
    sig = kms.sign(payload)
    assert verify_with_provider_pubkey(payload, sig, kms) is True
    assert verify_with_provider_pubkey(payload + b"x", sig, kms) is False
    # A malformed signature returns False rather than raising.
    assert verify_with_provider_pubkey(payload, "not-hex", kms) is False


def test_mock_kms_tsa_path_token_verifies():
    """The TSA seam also works through a KMS-shaped provider: a DemoTimestampAuthority
    whose key sits behind MockKmsProvider issues a token the unchanged timestamp
    verifier accepts (the TSA public key travels in the token)."""
    log = RunLog.load(DATA / "run-inc-8842-normal.jsonl")
    sig = sign_run_log_jsonl(log.to_jsonl(), "a" * 64, "b" * 64)

    tsa_kms = MockKmsProvider(key_handle="mock-kms://deadline-room/tsa")
    authority = DemoTimestampAuthority(provider=tsa_kms)
    token = timestamp_signature_record(sig, authority=authority)

    verdict = verify_timestamp_token(token, sig)
    assert verdict.valid is True
    assert token["tsa_public_key"] == tsa_kms.public_key_hex()


def test_mock_kms_intoto_envelope_verifies():
    """The in-toto DSSE seam works through the KMS provider too: an envelope signed
    via MockKmsProvider verifies under its own carried public key."""
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}],
        "predicateType": "https://deadline-room/Attestation/v1",
        "predicate": {"k": "v"},
    }
    kms = MockKmsProvider()
    envelope = build_dsse_envelope(statement, provider=kms)
    assert verify_dsse_envelope(envelope) is True
    assert envelope["public_key"] == kms.public_key_hex()


# --- the interface exposes no raw private key on the KMS path ------------------

def test_kms_provider_interface_exposes_no_raw_private_key():
    """The custody contract: a KMS-shaped provider never surfaces the private key.
    MockKmsProvider keeps its key in a name-mangled private attribute reachable
    only through the internal `_kms_sign`, and the SigningProvider surface offers
    only sign / public_key_hex / fingerprint / public_key (public material). No
    public attribute or method returns private bytes."""
    kms = MockKmsProvider()

    # No public method or attribute hands back a private key object or its bytes.
    public_names = [n for n in dir(kms) if not n.startswith("_")]
    for name in public_names:
        attr = getattr(kms, name)
        assert not isinstance(attr, Ed25519PrivateKey), (
            f"{name} exposes a private key on the KMS provider")
    # The mangled private store is not reachable as an ordinary attribute name.
    assert not hasattr(kms, "private_key")
    # public_key() returns public material only (the verify side), which is fine.
    assert kms.public_key().__class__.__name__ == "Ed25519PublicKey"


def test_provider_fingerprint_matches_its_public_key():
    """A provider's fingerprint is exactly the display fingerprint of its public
    key, for every provider kind. The receipt names the signer from public
    material alone."""
    for provider in (warden_signing_provider(), tsa_signing_provider(),
                     MockKmsProvider()):
        assert provider.fingerprint() == fingerprint(provider.public_key_hex())


# --- the production providers are a documented seam that fails loudly ----------

def test_kms_and_pkcs11_providers_are_unimplemented_seams_not_silent_stubs():
    """The cloud-KMS and PKCS#11 HSM providers ship as a clean interface, not a
    live call (a reproducible offline build must not depend on a cloud round-trip).
    They raise NotImplementedError with wiring guidance rather than silently
    signing with a wrong or empty key, so a misconfigured deployment fails loudly.
    Construction records the deployer's configuration."""
    kms = KmsProvider("arn:aws:kms:us-east-1:111122223333:key/abcd", region="us-east-1")
    assert kms.key_id.startswith("arn:aws:kms:")
    with pytest.raises(NotImplementedError):
        kms.sign(b"payload")
    with pytest.raises(NotImplementedError):
        kms.public_key_hex()

    hsm = Pkcs11Provider("/usr/lib/softhsm/libsofthsm2.so",
                         token_label="deadline-room", key_label="warden")
    assert hsm.key_label == "warden"
    with pytest.raises(NotImplementedError):
        hsm.sign(b"payload")
    with pytest.raises(NotImplementedError):
        hsm.public_key_hex()


def test_providers_are_signing_providers():
    """Every provider, local and remote, is a SigningProvider, so the signing call
    sites that take `provider` accept any of them interchangeably."""
    for provider in (
        warden_signing_provider(),
        tsa_signing_provider(),
        MockKmsProvider(),
        KmsProvider("k"),
        Pkcs11Provider("m", token_label="t", key_label="k"),
    ):
        assert isinstance(provider, SigningProvider)


def test_passing_both_provider_and_private_key_is_rejected():
    """A caller must pick one custody source. Passing both a provider and a raw
    private_key is a configuration error, rejected so no path can silently sign
    with the wrong key."""
    log = RunLog.load(DATA / "run-inc-8842-normal.jsonl")
    with pytest.raises(ValueError):
        sign_run_log_jsonl(
            log.to_jsonl(), "a" * 64, "b" * 64,
            private_key=Ed25519PrivateKey.generate(), provider=MockKmsProvider())
    with pytest.raises(ValueError):
        DemoTimestampAuthority(
            private_key=Ed25519PrivateKey.generate(), provider=MockKmsProvider())


def test_explicit_private_key_override_still_works_through_the_seam():
    """The low-level `private_key=` override is wrapped to the provider interface,
    so it still signs verifiably (used by tests and tooling). A freshly generated
    key signs a record that verifies under its own public key."""
    log = RunLog.load(DATA / "run-inc-8842-normal.jsonl")
    jsonl = log.to_jsonl()
    key = Ed25519PrivateKey.generate()
    record = sign_run_log_jsonl(jsonl, "a" * 64, "b" * 64, private_key=key)
    assert verify_run_log_jsonl(jsonl, record) is True
    # And it is NOT the demo key (the override took effect).
    assert record["public_key"] != load_public_key_hex()
