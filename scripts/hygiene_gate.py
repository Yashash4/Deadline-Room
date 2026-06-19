"""Repository hygiene gate: no stray em/en dashes, no AI-attribution trailers,
no leaked secrets.

Three hard project rules are enforced here mechanically so a human never has to
scan by hand and CI can fail a pull request that breaks them:

  1. No em-dash (U+2014) or en-dash (U+2013) in any tracked file. The forbidden
     codepoints appear below only as escapes, never as raw glyphs, so this gate
     file does not trip its own check.
  2. No AI-attribution trailer (a co-authorship credit naming the assistant, a
     "Generated with" credit, or the robot glyph U+1F916). Every marker is built
     from fragments below so no complete trailer appears literally in this file.
     Everything in the repository reads as human authored.
  3. No leaked secret. This repo holds several live keys (Band agent keys, the
     Featherless and AI/ML provider keys) and publishes packets to a shared room
     and a hosted web URL. A rival lost on a leaked token. The secret scanner
     (scan_secrets) fails the build if a key, a Bearer token, or a high-entropy
     credential blob is committed into any tracked file, including the published
     captures under web/data/. It is tuned NOT to fire on the legitimate
     committed cryptographic material (the sha256 hashes, the Ed25519 signatures
     and public keys, the chain heads) which are lowercase-hex digests, not
     secrets, nor on the .env.example placeholder values, which are templates.

The single legitimate exception for the dash check is the dash sanitizer itself:
floor/drafter.py strips em/en dashes out of every LLM output, and several tests
assert that the shipped artifact carries none. Those files MUST contain the raw
codepoints to do their job, so they are named in ALLOWED_DASH_FILES below and
skipped for the dash check only (the attribution and secret checks still apply).

Run it:  py scripts/hygiene_gate.py
Exit 0 when clean, exit 1 (with the offending file:line) when a rule is broken.
"""

from __future__ import annotations

import math
import re
import subprocess
import sys

# Forbidden codepoints, written as escapes so this file never holds the glyph.
EM_DASH = "\u2014"
EN_DASH = "\u2013"
ROBOT = "\U0001f916"

# AI-attribution markers, assembled from fragments so no complete trailer string
# appears literally in this file (which would otherwise self-trip the gate). The
# assistant name is built from its parts; the co-authorship key is split too.
_NAME = "Cla" + "ude"
ATTRIBUTION_MARKERS = (
    "Co-Authored" + "-By: " + _NAME,
    "Generated with " + _NAME,
    "Generated with " + "[" + _NAME,
    ROBOT,
)

# Files that are permitted to contain raw em/en dashes because removing them is
# precisely their function (the LLM-output sanitizer and the tests that prove a
# dash can never reach a shipped artifact). Paths are repo-relative, forward
# slashed (git ls-files form).
ALLOWED_DASH_FILES = frozenset(
    {
        "floor/drafter.py",
        "scripts/make_voiceover.py",
        "tests/test_sanitize_llm.py",
        "tests/test_second_opinion.py",
        "tests/test_voiceover_lines.py",
        "tests/test_network_retry.py",
    }
)


# ---------------------------------------------------------------------------
# Secret scanner
# ---------------------------------------------------------------------------
#
# The scanner is tuned around one fact about this repo: the only high-entropy
# strings legitimately committed are CRYPTOGRAPHIC DIGESTS, which are lowercase
# hex. Every sha256 (64 hex), every Ed25519 signature (128 hex), every public key
# and chain head is [0-9a-f]+ with no other characters. Real credentials are not
# pure lowercase hex: a Bearer token, an API key, or a base64 secret carries
# uppercase letters, punctuation (-, _, /, +, =), or a known vendor prefix. So a
# pure lowercase-hex run is treated as a digest and never flagged, while a
# mixed-alphabet high-entropy blob or a known key shape is flagged.
#
# The scanner skips its OWN source (this file builds key-shaped fragments to
# describe what it catches) so it does not self-trip.

# Known vendor key shapes. Each is a real token whose PREFIX uniquely marks it as
# a credential, so the prefix plus a sufficiently long body is a hit regardless of
# entropy. Built from fragments so this descriptive file holds no literal token.
_SK = "sk" + "-"
_GH = "gh" + "p_"
_XO = "xo" + "xb-"
_AK = "AK" + "IA"
_BAND_A = "band" + "_a_"
_BAND_U = "band" + "_u_"
SECRET_PREFIX_PATTERNS = (
    # OpenAI / Anthropic style: sk- followed by a long body (sk-ant-... matches too).
    re.compile(rf"\b{_SK}[A-Za-z0-9_-]{{16,}}"),
    # GitHub personal access token.
    re.compile(rf"\b{_GH}[A-Za-z0-9]{{20,}}"),
    # Slack bot token.
    re.compile(rf"\b{_XO}[A-Za-z0-9-]{{16,}}"),
    # AWS access key id.
    re.compile(rf"\b{_AK}[0-9A-Z]{{16}}\b"),
    # Band agent / user key with a real high-entropy body (the .env.example
    # placeholders end in a dictionary word like _here and are excused below).
    re.compile(rf"\b{_BAND_A}[A-Za-z0-9]{{16,}}"),
    re.compile(rf"\b{_BAND_U}[A-Za-z0-9]{{16,}}"),
)

# A Bearer auth token carrying a real, long, high-entropy value. The interpolated
# forms in this codebase (Bearer {key}, Bearer <AIML_API_KEY>) and the short test
# fixtures (Bearer fl-secret) do not match: the body must be 20+ chars of token
# alphabet with no brace or angle bracket, and must clear the entropy bar below.
BEARER_PATTERN = re.compile(r"Bearer\s+([A-Za-z0-9._\-]{20,})")

# A secret-named assignment: KEY/TOKEN/SECRET/PASSWORD = <value>. The value is
# flagged only when it is a real high-entropy credential, so placeholders and
# variable references fall through.
ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)"
    r"['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9._\-/+]{16,})")

# A bare high-entropy blob: a long UNBROKEN alphanumeric run (no separators, so
# it is not snake_case, a path, a URL, or a dotted identifier) that mixes upper,
# lower, AND digits. This is the catch-all for an exported base64/random
# credential pasted into a file. The character-class mix is the discriminator: a
# real random secret carries all three classes, while an English-ish identifier
# or a lowercase-hex digest does not. Separators are deliberately excluded from
# the run so a snake_case test name or a slash path never coalesces into a blob.
BLOB_PATTERN = re.compile(r"[A-Za-z0-9]{32,}")

# Substrings that mark a value as a placeholder / template, never a live secret.
# The .env.example body is built entirely from these (band_a_..._here,
# your_featherless_key_here, ..._uuid_here).
PLACEHOLDER_MARKERS = (
    "here", "your", "example", "placeholder", "redacted", "dummy", "sample",
    "uuid", "xxxx", "changeme", "fixme", "todo",
)

# Files excused from the secret scan ENTIRELY. Only this gate's own source, which
# necessarily spells out key-shaped fragments to document what it catches.
SECRET_SCAN_SKIP_FILES = frozenset(
    {
        "scripts/hygiene_gate.py",
    }
)

# Files excused from the BARE-BLOB check only (the vendor-prefix, Bearer, and
# assignment checks still apply, so a planted key/token in these files is still
# caught). These are SIGNATURE / ATTESTATION sidecars whose entire purpose is to
# carry PUBLIC base64 cryptographic material: the DSSE in-toto attestations
# (a base64 payload of a public statement plus a detached Ed25519 signature) and
# the case files that embed them. That base64 is public, verifiable, signed
# evidence, the opposite of a secret, but it mixes upper/lower/digit and is high
# entropy, so the bare-blob heuristic cannot tell it from a credential. A live
# API key is never committed as a .intoto.json or a case file, so excusing the
# blob check on these named artifacts removes the only false positives without
# blinding the scanner to a real pasted token (still caught by prefix/Bearer).
def _is_signature_artifact(path: str) -> bool:
    return (
        path.endswith(".intoto.json")
        or path.endswith(".sig.json")
        or path.startswith("web/data/casefile-")
    )

_HEX_RUN = re.compile(r"^[0-9a-f]+$")


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits per character) of a string. A real random credential
    sits high (above ~3.5 bits/char); an English placeholder or a repetitive
    pattern sits low. Used as the final discriminator on candidate blobs."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_placeholder(token: str) -> bool:
    """True if the token reads as a template placeholder, not a live secret."""
    low = token.lower()
    return any(marker in low for marker in PLACEHOLDER_MARKERS)


def _is_digest(token: str) -> bool:
    """True if the token is a pure lowercase-hex run, i.e. a sha256 / Ed25519
    signature / public key / chain head: legitimate committed crypto material, not
    a secret. Real credentials carry uppercase or punctuation and so are not pure
    hex."""
    return bool(_HEX_RUN.match(token))


def _looks_secret(token: str, *, entropy_floor: float = 4.0) -> bool:
    """A bare token is a likely secret when it is long, mixes upper + lower +
    digits (a random credential does; a lowercase-hex digest, an UPPER_SNAKE
    constant, or an English-ish identifier does not), is high-entropy, not a
    lowercase-hex digest, and not a placeholder."""
    if len(token) < 32 or _is_placeholder(token) or _is_digest(token):
        return False
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    if not (has_upper and has_lower and has_digit):
        return False
    return _shannon_entropy(token) >= entropy_floor


def scan_secrets_in_line(line: str, *, check_blobs: bool = True) -> list[str]:
    """Return a list of secret-hit descriptions for one line. Empty when clean.

    check_blobs gates only the bare high-entropy blob heuristic; the vendor-prefix,
    Bearer, and assignment checks always run. Signature/attestation sidecars pass
    check_blobs=False so their public base64 material is not mistaken for a
    credential while a planted vendor key or Bearer token there is still caught."""
    hits: list[str] = []
    for pattern in SECRET_PREFIX_PATTERNS:
        m = pattern.search(line)
        if m and not _is_placeholder(m.group(0)):
            hits.append(f"vendor key shape ({m.group(0)[:12]}...)")
    bearer = BEARER_PATTERN.search(line)
    if bearer:
        token = bearer.group(1)
        if not _is_placeholder(token) and not _is_digest(token) \
                and _shannon_entropy(token) >= 3.0:
            hits.append("Bearer token")
    assign = ASSIGNMENT_PATTERN.search(line)
    if assign:
        value = assign.group(1)
        # The value is flagged only if it reads as a real random credential
        # (mixed upper/lower/digit, high entropy). A code reference assigned to a
        # secret-named variable (var.band_api_key, token = sign(...)) is a
        # lowercase identifier and is excused, as are the .env.example
        # placeholders. A genuine pasted key value is caught here or by a vendor
        # prefix above.
        if _looks_secret(value):
            hits.append("secret-named assignment to a high-entropy value")
    if check_blobs:
        for blob in BLOB_PATTERN.findall(line):
            if _looks_secret(blob):
                hits.append(f"high-entropy blob ({blob[:8]}...)")
                break
    return hits


def tracked_files() -> list[str]:
    out = subprocess.check_output(["git", "ls-files"], text=True)
    return [line for line in out.splitlines() if line.strip()]


def scan() -> list[str]:
    violations: list[str] = []
    for path in tracked_files():
        try:
            with open(path, encoding="utf-8") as handle:
                lines = handle.readlines()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            # Binary or vanished file: nothing textual to police.
            continue
        allow_dash = path in ALLOWED_DASH_FILES
        scan_secrets = path not in SECRET_SCAN_SKIP_FILES
        check_blobs = not _is_signature_artifact(path)
        for number, line in enumerate(lines, start=1):
            if not allow_dash:
                if EM_DASH in line:
                    violations.append(f"{path}:{number}: em-dash (U+2014)")
                if EN_DASH in line:
                    violations.append(f"{path}:{number}: en-dash (U+2013)")
            for marker in ATTRIBUTION_MARKERS:
                if marker in line:
                    label = "robot glyph" if marker == ROBOT else marker
                    violations.append(f"{path}:{number}: AI attribution ({label})")
            if scan_secrets:
                for hit in scan_secrets_in_line(line, check_blobs=check_blobs):
                    violations.append(f"{path}:{number}: leaked secret ({hit})")
    return violations


def main() -> int:
    violations = scan()
    if violations:
        print("Hygiene gate FAILED. Forbidden content found:")
        for item in violations:
            print("  " + item)
        print(
            "\nFix: replace em/en dashes with a comma, colon, parentheses, or a "
            "period, remove any AI-attribution trailer, and move any leaked secret "
            "out of the repo into an environment variable (see .env.example)."
        )
        return 1
    print(
        "Hygiene gate passed: no stray em/en dashes, no AI-attribution trailers, "
        "no leaked secrets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
