# Warden signing keys (DEMONSTRATION keypair)

This directory holds the Ed25519 keypair the Deadline Warden uses to sign the
canonical run-log bytes of every captured run. The signature is detached: it is
stored beside the log (in the Examiner Packet sidecar / replay_info), never
inside the hashed JSONL, so the run-log sha and the byte-identical replay are
completely unaffected.

- `warden_pubkey.ed25519`: the 32-byte public key, hex. Anyone verifies a
  signature against this. Committed on purpose so a judge can verify offline.
- `warden_seed.demo.ed25519`: the 32-byte private seed, hex. This is a
  DEMONSTRATION private key.

## What is real, stated plainly (no security theater)

The signature MECHANISM is fully real. It cryptographically binds the run-log
bytes to the public key above. Anyone holding the public key can verify, in
Python (`py scripts/verify_signature.py`) or in a browser, that these exact
bytes were signed by the holder of the matching private key, and one flipped
byte makes the signature INVALID. The integrity, append-only (hash chain), and
authenticity-relative-to-this-keypair claims are real and independently
checkable today.

## What is a hackathon simplification, stated openly

The private key SECRECY is not production-grade. The demo private seed ships in
this repo, so anyone with the repo could produce a valid signature. The
signature therefore proves "signed by whoever holds this demo key", not "signed
by a key only a trusted Warden could ever hold".

In production the private key lives in an HSM or KMS, never in the repo, with key
rotation, a published key directory, and RFC-3161 timestamping so "signed after
the fact" is also ruled out. The custody seam for that is built today (see "Key
custody: pointing the Warden and the TSA at a KMS/HSM" below); the only thing
that is Phase 2 is wiring it to a specific cloud KMS or HSM. We claim nothing more
than the mechanism delivers.

## Key custody: pointing the Warden and the TSA at a KMS/HSM

WHERE the signing key lives is a swappable provider, not a hard-coded seed load.
The seam is `warden/custody.py`: a `SigningProvider` interface with `sign(payload)
-> signature_hex`, `public_key_hex()`, and `fingerprint()`, and deliberately NO
method that returns raw private-key bytes (a real KMS/HSM never hands the key
back, it exposes only a sign operation behind an access policy). Both the Warden
signing key and the demo TSA key route through this one interface.

The DEFAULT providers (`warden_signing_provider()`, `tsa_signing_provider()`)
return a `LocalKeyProvider` over the committed demo seeds in this directory. That
is the pre-custody behavior, now behind the seam: the key is loaded and signs in
process, so every sealed capture's signature, in-toto envelope, and RFC 3161
token is byte-identical to before. The build stays keyless-runnable and offline.

For PRODUCTION, return a remote provider instead, and no private key is in the
repo:

- `KmsProvider(key_id, region=..., endpoint=...)` signs through a cloud KMS
  asymmetric-sign API. Create a non-exportable Ed25519 signing key in the KMS;
  `public_key_hex()` fetches the public half once (AWS `GetPublicKey`, Azure
  `getKey`, GCP `getPublicKey`) and `sign(payload)` calls the KMS sign operation
  (AWS `kms.sign(KeyId=..., Message=payload, MessageType='RAW',
  SigningAlgorithm='EDDSA')`, the Azure Key Vault Cryptography client `sign`, or
  GCP `asymmetricSign`). The KMS returns the 64-byte Ed25519 signature; the
  provider returns it as hex, the identical wire form the verifier already
  accepts. The private key never leaves the KMS.
- `Pkcs11Provider(module_path, token_label=..., key_label=...)` signs through a
  PKCS#11 HSM (a Luna or YubiHSM in production, SoftHSM in test). Generate the
  Ed25519 key ON the device as non-extractable, open a session, and `sign(payload)`
  calls `C_Sign` with the EDDSA mechanism. The HSM signs internally; the host
  process never sees the private key.

Both ship as a CLEAN INTERFACE with documented wiring, not a live cloud call: a
reproducible offline build must not depend on a cloud round-trip, so the
`sign`/`public_key_hex` methods raise `NotImplementedError` with the exact SDK
call to make, and a deployer fills them in against its KMS/HSM SDK. The
`MockKmsProvider` in `warden/custody.py` proves the seam end to end in tests: it
signs with the same Ed25519 primitive reached only through a KMS-shaped operation,
and an UNCHANGED verifier accepts the result, so a real KMS/HSM is interchangeable
through the interface without a cloud dependency in CI.

Wiring is a single substitution: have `warden_signing_provider()` and
`tsa_signing_provider()` return the production provider (or pass one explicitly,
`sign_run_log_jsonl(..., provider=...)` and `DemoTimestampAuthority(provider=...)`).
The bound payload, the signature record, and every verifier are unchanged, because
only the custody of the private key changes, never the signature wire form. In
that mode no private key is in the repo: the committed `.demo.` seeds are the
demonstration default, not a production secret.

## RFC 3161 trusted timestamp (demo TSA)

The signature proves WHO signed a run; it does not prove WHEN. An RFC 3161
trusted timestamp closes that gap: a Time-Stamping Authority (TSA) binds the
signed artifact's digest to a point in time and signs that binding, so a verifier
can read a time a court accepts. The implementation is in `warden/timestamp.py`
and the receipt is `py scripts/verify_timestamp.py`.

- `tsa_seed.demo.ed25519`: the 32-byte private seed of the demo TSA, hex. A
  DEMONSTRATION key, separate from the Warden's signing key (signer and time
  authority are distinct roles, held by distinct keys).
- `tsa_pubkey.ed25519`: the 32-byte demo TSA public key, hex. A verifier checks
  the timestamp token signature against this.

What the timestamp binds: the messageImprint is the sha256 of the bound-payload
bytes the Warden's Ed25519 signature was taken over
({sha256, chain_head, attestation_sha, fact_record_hash}), so the timestamp
anchors the same fact the signature attests. The token is the DER-encoded RFC 3161
TSTInfo signed by the demo TSA key, emitted as an additive `<run-log>.tst.json`
sidecar that never touches the sealed run-log, packet, sig.json, or intoto bytes.

### What is real, and the honest demo-TSA caveat

The RFC 3161 MECHANISM is fully real: the messageImprint is a real sha256 of the
signed artifact, the TSTInfo is real X.690 DER (cross-checked decodable by a
standard ASN.1 decoder), the token is a real Ed25519 signature over it, and one
flipped byte of the digest or the token makes verification fail. What is NOT
production-grade is the AUTHORITY: the timestamp is issued by a LOCAL demo TSA
whose key ships in this repo, not by a qualified third-party TSA. A valid token
here proves "this digest was bound to this genTime and signed by the demo TSA
key", not "an independent, trusted, auditable authority witnessed this digest at
this time".

The demo TSA is also DETERMINISTIC by design: it stamps a FIXED genTime passed in
by the caller (never `now()`), so the sealed `.tst.json` sidecar is reproducible
byte for byte. A reproducible, offline artifact cannot make a live network TSA
call: that would add a network dependency and a non-deterministic genTime, which
would break byte-identical reproduction.

### Plugging in a real RFC 3161 TSA for production

The TSA is selected through the `TimestampAuthority` interface in
`warden/timestamp.py`. The default is `DemoTimestampAuthority`. For production,
implement an `HttpRfc3161Authority(TimestampAuthority)` whose `request_token`
POSTs the DER `TimeStampReq` (already built by `build_timestamp_request`) to a
real TSA endpoint with `Content-Type: application/timestamp-query` (DigiCert,
freeTSA, or any qualified TSA), and returns the TSA's `TimeStampResp`, whose
`timeStampToken` is a CMS SignedData wrapping the same TSTInfo. The messageImprint,
the TSTInfo shape, the genTime, and the verification logic (TSA signature over the
TSTInfo, messageImprint equals the artifact digest) are identical; only the
authority that signs changes. Pass the production authority into
`timestamp_signature_record(signature_record, authority=...)`. The genTime then
becomes the real TSA's wall-clock time, so a production run's token is not
byte-reproducible (as expected): the demo default keeps the committed captures
reproducible and keyless-runnable.
