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
