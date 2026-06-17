"""The self-certifying tamper sweep is itself covered by the suite.

scripts/tamper_sweep.py enumerates thousands of single-point forgeries over the
four sealed captures and proves every one is caught by the frozen verification
stack (replay-sha, chain-head, signature, logcheck). This test pins the three
properties that make that headline trustworthy:

  1. SOUND: over the real sealed captures, 0 of N mutations evade every detector,
     and the script exits 0 with the headline receipt.
  2. NON-VACUOUS: the sweep actually distinguishes caught from evaded. A blinded
     detector panel (one that catches nothing) lets the mutations through, and a
     panel deliberately blind to ONE family (truncation) lets exactly that family
     survive. If the sweep were an always-pass, neither weakening would change the
     verdict; both do, by construction.
  3. DETERMINISTIC: the same seed yields the identical sweep on every run.

The captures on disk are never touched: the sweep mutates deep copies only.
"""

import random
import subprocess
import sys
from pathlib import Path

import scripts.tamper_sweep as ts

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "tamper_sweep.py"
DATA = REPO_ROOT / "web" / "data"
NORMAL_LOG = DATA / "run-inc-8842-normal.jsonl"


def _default_paths() -> list[Path]:
    return [DATA / f"run-inc-8842-{mode}.jsonl" for mode in ts.SCENARIOS]


def test_zero_mutations_survive_over_every_sealed_capture():
    aggregate, per_run = ts.run_sweep(_default_paths(), ts.MASTER_SEED)
    # The whole point: not one forgery evades every detector.
    assert aggregate.evaded == [], aggregate.evaded[:5]
    # And the sweep is substantial, not a token handful of mutations.
    assert aggregate.total >= 2000, aggregate.total
    assert aggregate.caught == aggregate.total
    # Every audited run contributes catches.
    for mode, stats in per_run:
        assert stats.total > 0, mode
        assert stats.evaded == [], (mode, stats.evaded[:3])


def test_no_op_count_is_honest():
    # No-ops (byte-identical to the seal) are reported, never counted as evaded or
    # as caught. Whatever the count is, it must be consistent: total + no_ops
    # accounts for every generated mutation, and no-ops are non-negative.
    aggregate, _ = ts.run_sweep(_default_paths(), ts.MASTER_SEED)
    assert aggregate.no_ops >= 0
    # caught + evaded == total (no-ops are excluded from total by construction).
    assert aggregate.caught + len(aggregate.evaded) == aggregate.total


def test_sweep_is_non_vacuous_blind_panel_lets_mutations_through():
    # If the detector panel catches NOTHING, the log-byte mutations must survive.
    # A sweep that still reported 0 survivors here would be an always-pass fraud.
    sealed = ts._load_sealed(NORMAL_LOG)

    class BlindPanel(ts.Detectors):
        def first_catch(self, entries, jsonl):
            return None

    stats = ts.sweep_run(sealed, BlindPanel(sealed), random.Random(ts.MASTER_SEED))
    # The vast majority (every log-byte mutation) now evades; only the
    # packet-tamper family, whose detection is computed directly rather than
    # through first_catch, still registers as caught.
    assert len(stats.evaded) > 0
    assert len(stats.evaded) >= stats.total - 16, (stats.total, len(stats.evaded))


def test_sweep_is_non_vacuous_blinding_one_family_lets_that_family_survive():
    # Blind the panel to truncation specifically: a panel that pretends a
    # short log is fine must let every truncation through, proving the sweep
    # distinguishes the truncation class rather than blanket-passing.
    sealed = ts._load_sealed(NORMAL_LOG)
    full_len = len(sealed.sealed_entries)

    class BlindToTruncation(ts.Detectors):
        def first_catch(self, entries, jsonl):
            if len(entries) < full_len:
                return None  # the weakened detector ignores a shortened log
            return super().first_catch(entries, jsonl)

    weak = ts.sweep_run(sealed, BlindToTruncation(sealed), random.Random(ts.MASTER_SEED))
    truncation_survivors = [s for s in weak.evaded if "truncate" in s]
    assert truncation_survivors, "blinding truncation should let truncations survive"

    # The REAL panel catches every one of those same truncations.
    strong = ts.sweep_run(sealed, ts.Detectors(sealed), random.Random(ts.MASTER_SEED))
    assert [s for s in strong.evaded if "truncate" in s] == []


def test_sweep_is_deterministic_across_runs():
    a, _ = ts.run_sweep(_default_paths(), ts.MASTER_SEED)
    b, _ = ts.run_sweep(_default_paths(), ts.MASTER_SEED)
    assert a.total == b.total
    assert a.caught == b.caught
    assert a.no_ops == b.no_ops
    assert a.evaded == b.evaded
    assert a.by_detector == b.by_detector


def test_captures_on_disk_are_untouched_by_the_sweep():
    before = {p.name: p.read_bytes() for p in _default_paths()}
    ts.run_sweep(_default_paths(), ts.MASTER_SEED)
    after = {p.name: p.read_bytes() for p in _default_paths()}
    assert before == after


def test_script_runs_clean_and_exits_zero_with_headline():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "0 survived" in out
    assert "deterministic, seed" in out
    assert "every mutation caught by replay-sha / chain-head / signature / logcheck" in out


def test_seed_override_is_honored_and_still_catches_all():
    # A different seed draws different forged values; the sweep must still catch
    # every mutation (the forged values change, the integrity guarantee does not).
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--seed", "1234"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 survived" in result.stdout
    assert "seed 1234" in result.stdout
