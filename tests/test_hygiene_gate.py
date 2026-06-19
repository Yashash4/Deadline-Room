"""test_hygiene_gate.py -- the repository hygiene gate (E9.5 secret scanner).

The gate enforces three rules over every tracked file: no em/en dashes, no
AI-attribution trailers, and no leaked secret. These tests focus on the secret
scanner: a PLANTED token of each shape must be caught, the legitimate committed
cryptographic material and the .env.example placeholders must NOT be flagged, and
the gate must pass clean on the current repository.
"""

import subprocess
import sys
from pathlib import Path

from scripts.hygiene_gate import (
    main,
    scan,
    scan_secrets_in_line,
)

_CODE = Path(__file__).resolve().parent.parent


# ---- 1. The scanner catches each planted secret shape -----------------------

def test_planted_bearer_token_is_caught():
    line = "Authorization: Bearer aB3xK9mZ7qLp2WvR8nT4yU6sE1dF0gH5jC"
    assert scan_secrets_in_line(line)


def test_planted_vendor_keys_are_caught():
    # OpenAI/Anthropic-style key, GitHub PAT, Slack bot token, AWS access key id,
    # and a Band agent key with a real high-entropy body.
    planted = [
        "OPENAI = sk-aB3xK9mZ7qLp2WvR8nT4yU6sE1dFabcd1234",
        "token=ghp_aB3xK9mZ7qLp2WvR8nT4yU6sE1dFabcd",
        "SLACK=xoxb-aB3xK9mZ7qLp2WvR8nT4yU6sE1dF",
        "aws_access_key_id = AKIAJL3MN4PQ5RST6UVW",
        "BAND_API_KEY=band_a_aB3xK9mZ7qLp2WvR8nT4yU6sE1dF",
    ]
    for line in planted:
        assert scan_secrets_in_line(line), line


def test_planted_base64_credential_blob_is_caught():
    line = 'cfg = "aB3xK9mZ7qLp2WvR8nT4yU6sE1dF0gH5jCkN"'
    assert scan_secrets_in_line(line)


# ---- 2. The legitimate committed material is NOT flagged --------------------

def test_sha256_and_signature_digests_are_not_secrets():
    # A lowercase-hex sha256, an Ed25519 public key, and a chain head: all
    # legitimate committed crypto material, never a secret.
    benign = [
        "be0037b82ce62d1ecb5e5855b9b2e42a5cede73325b91145deaa6b233025a6a8",
        '"chain_head": "833560371e5c2d4107952fa13c1d810720ec62d371a1923d21bfac0ba168e429"',
        '"sha256": "0ca07fb0a1f975a84de67966d2724137210c4b7ede1b5ddde96a53650d0c8bbc"',
    ]
    for line in benign:
        assert not scan_secrets_in_line(line), line


def test_env_placeholders_are_not_secrets():
    placeholders = [
        "BAND_API_KEY=band_a_warden_key_here",
        "FEATHERLESS_API_KEY=your_featherless_key_here",
        "BAND_AGENT_ID=warden_agent_uuid_here",
    ]
    for line in placeholders:
        assert not scan_secrets_in_line(line), line


def test_code_references_to_secret_named_vars_are_not_secrets():
    # An interpolated Bearer header, a short test fixture, a function-call
    # assignment, and a Terraform variable reference: all code, not credentials.
    code = [
        'headers={"Authorization": f"Bearer {key}"}',
        'assert call["headers"]["Authorization"] == "Bearer fl-secret"',
        "token = timestamp_signature_record(sig)",
        "BAND_API_KEY = var.band_api_key",
    ]
    for line in code:
        assert not scan_secrets_in_line(line), line


def test_signature_artifact_base64_is_excused_for_blob_check_only():
    # A DSSE base64 payload (public, signed evidence) is excused from the bare
    # blob heuristic, but a real vendor key planted in the same file is still
    # caught.
    dsse_payload = "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQ"
    assert not scan_secrets_in_line(dsse_payload, check_blobs=False)
    planted = "Bearer aB3xK9mZ7qLp2WvR8nT4yU6sE1dF0gH5jC"
    assert scan_secrets_in_line(planted, check_blobs=False)


# ---- 3. The gate passes clean on the current repository ---------------------

def test_clean_repo_passes_the_gate():
    # scan() walks the real tracked tree; on the committed repo it must be empty.
    assert scan() == []
    assert main() == 0


# ---- 4. A planted secret file fails the gate end to end ---------------------

def test_planted_secret_file_fails_the_gate(tmp_path):
    # Stage a file carrying a planted token in a throwaway git repo, run the gate
    # there, and assert it exits non-zero naming the leak. This exercises the full
    # tracked-file walk, not just the per-line check.
    repo = tmp_path / "planted"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    leak = repo / "config.py"
    leak.write_text(
        'API_KEY = "sk-aB3xK9mZ7qLp2WvR8nT4yU6sE1dFabcd1234"\n',
        encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    gate = _CODE / "scripts" / "hygiene_gate.py"
    proc = subprocess.run(
        [sys.executable, str(gate)], cwd=repo,
        capture_output=True, text=True)
    assert proc.returncode == 1
    assert "leaked secret" in proc.stdout
    assert "config.py" in proc.stdout
