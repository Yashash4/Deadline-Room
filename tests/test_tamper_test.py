"""The tamper receipt is itself covered by the suite.

scripts/tamper_test.py is a judge-facing receipt, so its two outcomes are
pinned here: the honest baseline reproduces the sealed hash, and a single
flipped field both breaks the seal binding and fails self-certification
under replay. We assert against the same mechanics the script uses, plus
run the script end to end and check its exit code and output.
"""

import copy
import subprocess
import sys
from pathlib import Path

from warden.replay import RunLog, replay

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "tamper_test.py"
LOG_PATH = REPO_ROOT / "web" / "data" / "run-inc-8842-chaos.jsonl"


def _flip_first_admitted(entries: list[dict]) -> None:
    for entry in entries:
        if entry["type"] == "protocol_event" and entry["payload"].get("admitted") is True:
            entry["payload"]["admitted"] = False
            entry["payload"]["to_state"] = None
            return
    raise AssertionError("fixture has no admitted protocol_event")


def test_clean_baseline_reproduces_the_sealed_hash():
    sealed = RunLog.load(LOG_PATH)
    assert replay(sealed).sha256() == sealed.sha256()


def test_flipped_field_breaks_seal_binding_and_self_certification():
    sealed = RunLog.load(LOG_PATH)
    sealed_hash = sealed.sha256()

    tampered = RunLog()
    tampered._entries = copy.deepcopy(sealed.entries())  # noqa: SLF001
    tampered._seq = tampered._entries[-1]["seq"] + 1  # noqa: SLF001
    _flip_first_admitted(tampered.entries())

    tampered_hash = tampered.sha256()
    # seal binding: the tampered log no longer matches the sealed hash.
    assert tampered_hash != sealed_hash

    # self-certification: replay re-derives the honest value, so replay of the
    # tampered log differs from the tampered log itself.
    replay_of_tampered = replay(tampered).sha256()
    assert replay_of_tampered != tampered_hash
    # and replay recovers exactly the honest sealed hash, proving replay
    # re-executes the state machine rather than echoing the (forged) log.
    assert replay_of_tampered == sealed_hash


def test_script_runs_clean_and_exits_zero_with_pass_verdict():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "VERDICT: PASS" in out
    assert "Tamper detected" in out
    assert "seal binding broken : True" in out
    assert "self-certifies      : False" in out


def test_script_shows_a_reorder_breaks_the_signature():
    # The new binding: with the chain head signed, a reorder makes the signature
    # INVALID too. The script's signature beat now verifies the reordered log and
    # reports it as not valid; the verdict line names it.
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "sealed bytes VALID    : True" in out
    assert "REORDERED VALID       : False" in out
    assert "the signature now breaks on a reorder too" in out
