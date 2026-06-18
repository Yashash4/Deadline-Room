"""Independent third-party provenance verifier (scripts/verify_thirdparty.py).

These tests pin the regulator-grade guarantee: a neutral party, handed only a
filing set's packet JSON, its run log, and the sealed sidecars, plus the committed
public key, can re-derive the whole provenance chain offline and get a clean
VERIFIED, and any tamper of the run log or the signature turns it into a named
FAILURE with a nonzero exit. The four sealed web/data captures are the fixtures;
the tamper cases run over TEMP COPIES so the byte-frozen captures are never
touched.

What is asserted:

  * the verifier passes (exit 0, every check VERIFIED) on each sealed scenario,
    using only the packet + run-log + sidecars + the committed public key;
  * a one-byte tamper of the run log fails it (the sha moves, the chain head
    moves, the signature no longer verifies), exit nonzero;
  * a tamper of the detached signature fails it, exit nonzero;
  * the run-log sha and chain head it recomputes match the values the seal
    committed to, recomputed via the canonical UTF-8 LF recipe (so a CRLF
    checkout still verifies);
  * the verdict is deterministic: the same inputs yield the same result twice.
"""

import json
import shutil
from pathlib import Path

import pytest

from scripts.verify_thirdparty import (
    SEALED_SCENARIOS,
    canonical_run_log_text,
    main,
    recompute_chain_head,
    recompute_sha256,
    verify_target,
)
from warden.signing import load_public_key_hex

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "web" / "data"

# Every sidecar suffix the verifier reads beside a run log, so a temp copy of a
# sealed bundle carries the exact same evidence the captures do.
SIDECAR_SUFFIXES = (".sig.json", ".intoto.json", ".tst.json")


def _committed_pubkey() -> str:
    return load_public_key_hex()


def _sealed_packet(scenario: str) -> Path:
    return DATA / f"packet-{scenario}.json"


def _sealed_run_log(scenario: str) -> Path:
    return DATA / f"run-inc-8842-{scenario}.jsonl"


def _copy_bundle(scenario: str, dest_dir: Path) -> tuple[Path, Path]:
    """Copy a sealed scenario's packet, run log, and every present sidecar into a
    temp directory, preserving file names so the verifier's own file-location logic
    finds them. Returns (packet_copy, run_log_copy). The run-log copy is written
    through the canonical text so its on-disk form round-trips to the same canonical
    bytes regardless of the host's line-ending convention."""
    packet_src = _sealed_packet(scenario)
    run_log_src = _sealed_run_log(scenario)

    packet_dst = dest_dir / packet_src.name
    shutil.copyfile(packet_src, packet_dst)

    run_log_dst = dest_dir / run_log_src.name
    # Write the canonical text with newline="" so the LF bytes are preserved as-is;
    # read_text on the verifier side normalizes either way.
    run_log_dst.write_text(
        canonical_run_log_text(run_log_src), encoding="utf-8", newline="")

    for suffix in SIDECAR_SUFFIXES:
        sidecar_src = run_log_src.with_suffix(run_log_src.suffix + suffix)
        if sidecar_src.exists():
            shutil.copyfile(
                sidecar_src,
                run_log_dst.with_suffix(run_log_dst.suffix + suffix),
            )
    return packet_dst, run_log_dst


# --- the verifier passes on the sealed captures -------------------------------


@pytest.mark.parametrize("scenario", SEALED_SCENARIOS)
def test_sealed_capture_reverifies(scenario):
    """Each sealed scenario re-verifies from its own files + the committed key."""
    result = verify_target(_sealed_packet(scenario), _committed_pubkey())
    assert result.ok, (
        f"{scenario} did not verify: "
        + "; ".join(f"{c.name}: {c.detail}" for c in result.checks if not c.ok)
    )
    # The four fully-sealed captures carry all five checks (sha, chain, signature,
    # in-toto, timestamp); none is silently skipped.
    names = {c.name for c in result.checks}
    assert names == {
        "RUN-LOG SHA",
        "CHAIN HEAD",
        "SIGNATURE",
        "IN-TOTO / DSSE",
        "RFC 3161 TIMESTAMP",
    }
    assert all(c.ok for c in result.checks)


def test_cli_main_exit_zero_on_all_sealed():
    """The CLI over all four sealed captures exits 0."""
    assert main([]) == 0


@pytest.mark.parametrize("scenario", SEALED_SCENARIOS)
def test_recomputed_values_match_the_seal(scenario):
    """The sha and chain head the verifier recomputes from the canonical run-log
    bytes equal the values the sealed signature record commits to. This is the
    canonical UTF-8 LF recipe: it must match even though the file on disk may carry
    CRLF."""
    packet = json.loads(_sealed_packet(scenario).read_text(encoding="utf-8"))
    signature = (packet.get("replay") or {}).get("signature") or {}
    text = canonical_run_log_text(_sealed_run_log(scenario))
    assert recompute_sha256(text) == signature["sha256"]
    assert recompute_chain_head(text) == signature["chain_head"]


# --- a tampered run log fails it ----------------------------------------------


def test_tampered_run_log_fails(tmp_path):
    """One flipped byte of the run log fails the verify: the sha and chain head move
    and the signature no longer matches the bound payload. Run over a temp copy so
    the sealed capture is untouched."""
    packet_copy, run_log_copy = _copy_bundle("normal", tmp_path)

    original = run_log_copy.read_text(encoding="utf-8")
    tampered = original.replace('"admitted":true', '"admitted":false', 1)
    assert tampered != original, "fixture must contain a flippable byte"
    run_log_copy.write_text(tampered, encoding="utf-8", newline="")

    result = verify_target(packet_copy, _committed_pubkey(), run_log_copy)
    assert not result.ok
    failed = {c.name for c in result.checks if not c.ok}
    # The byte edit moves the sha and the chain head, and breaks the signature.
    assert "RUN-LOG SHA" in failed
    assert "CHAIN HEAD" in failed
    assert "SIGNATURE" in failed

    # The CLI over the tampered bundle exits nonzero.
    assert main([str(packet_copy), str(run_log_copy)]) != 0


def test_untampered_temp_copy_still_verifies(tmp_path):
    """A faithful temp copy of the sealed bundle (no edit) verifies, proving the
    tamper test's failure is caused by the edit, not by the copy itself."""
    packet_copy, run_log_copy = _copy_bundle("normal", tmp_path)
    result = verify_target(packet_copy, _committed_pubkey(), run_log_copy)
    assert result.ok
    assert main([str(packet_copy), str(run_log_copy)]) == 0


# --- a tampered signature fails it --------------------------------------------


def test_tampered_signature_fails(tmp_path):
    """Editing the detached signature in the packet's replay block fails the verify:
    the signature no longer matches the bound payload under the committed key. Run
    over a temp copy."""
    packet_copy, run_log_copy = _copy_bundle("normal", tmp_path)

    packet = json.loads(packet_copy.read_text(encoding="utf-8"))
    sig_hex = packet["replay"]["signature"]["signature"]
    # Flip the first hex nibble of the signature so it is still valid hex but a
    # different 64-byte signature.
    flipped = ("0" if sig_hex[0] != "0" else "1") + sig_hex[1:]
    assert flipped != sig_hex
    packet["replay"]["signature"]["signature"] = flipped
    packet_copy.write_text(
        json.dumps(packet, indent=2), encoding="utf-8", newline="")

    result = verify_target(packet_copy, _committed_pubkey(), run_log_copy)
    assert not result.ok
    failed = {c.name for c in result.checks if not c.ok}
    assert "SIGNATURE" in failed
    # The sha and chain head still match (only the signature was edited), so the
    # failure is isolated to the signature check.
    ok_checks = {c.name for c in result.checks if c.ok}
    assert "RUN-LOG SHA" in ok_checks
    assert "CHAIN HEAD" in ok_checks

    assert main([str(packet_copy), str(run_log_copy)]) != 0


def test_signature_record_naming_other_key_is_rejected(tmp_path):
    """If the signature record names a public key that is NOT the committed Warden
    key, the verifier refuses to trust the record's key and fails the signature
    check (a third party trusts only the committed key)."""
    packet_copy, run_log_copy = _copy_bundle("normal", tmp_path)

    packet = json.loads(packet_copy.read_text(encoding="utf-8"))
    # A different but well-formed 32-byte hex public key.
    packet["replay"]["signature"]["public_key"] = "cd" * 32
    packet_copy.write_text(
        json.dumps(packet, indent=2), encoding="utf-8", newline="")

    result = verify_target(packet_copy, _committed_pubkey(), run_log_copy)
    assert not result.ok
    sig_check = next(c for c in result.checks if c.name == "SIGNATURE")
    assert not sig_check.ok
    assert "committed" in sig_check.detail.lower()


# --- determinism --------------------------------------------------------------


def test_verdict_is_deterministic():
    """The same sealed inputs yield the same checks and verdict on repeated runs."""
    first = verify_target(_sealed_packet("normal"), _committed_pubkey())
    second = verify_target(_sealed_packet("normal"), _committed_pubkey())
    assert first.ok and second.ok
    assert first.sha256 == second.sha256
    assert first.chain_head == second.chain_head
    assert [(c.name, c.ok) for c in first.checks] == [
        (c.name, c.ok) for c in second.checks
    ]


def test_missing_packet_is_reported_not_crashed(tmp_path):
    """A packet path that does not exist is reported as a clean non-verification,
    not a crash, and the CLI exits nonzero."""
    missing = tmp_path / "packet-does-not-exist.json"
    result = verify_target(missing, _committed_pubkey())
    assert not result.ok
    assert result.error
    assert main([str(missing)]) != 0
