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
the fact" is also ruled out. Those are Phase 2. We claim nothing more than the
mechanism delivers.

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
