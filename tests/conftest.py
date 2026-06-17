"""Pytest collection-time setup: a deterministic Hypothesis profile.

Hypothesis defaults to a random seed and persists a local example database, so a
re-run can explore a different sample. That violates the receipts-not-vibes
discipline this repo holds: a judge who re-runs the suite must get the identical
verdict the maintainers got, byte for byte. So we register a profile that:

  * derandomizes (a fixed internal seed): the SAME inputs are generated on every
    run and on every machine, so a green run is reproducible and a failing run
    shrinks to the SAME minimal counterexample for everyone.
  * disables the example database: no hidden local state steers the next run.
  * bounds max_examples so the property suite stays a few seconds, not minutes,
    keeping the whole suite fast and CI-friendly.
  * sets a sane per-example deadline so a slow machine does not flake a test that
    is really passing (the run_incident pipeline is pure Python and quick, but a
    cold first call under coverage can exceed a tight default).

The profile is registered AND loaded here, at import time, so it is active for
every property test without each test having to opt in. This is the project's
single source of Hypothesis configuration; there is no pytest.ini to carry it.
"""

from __future__ import annotations

from hypothesis import HealthCheck, settings

DETERMINISTIC_PROFILE = "deadline_room"

settings.register_profile(
    DETERMINISTIC_PROFILE,
    max_examples=200,
    derandomize=True,
    database=None,
    deadline=2000,  # milliseconds per example; generous for the pure pipeline
    print_blob=True,  # print the reproducing blob on any failure
    suppress_health_check=[HealthCheck.too_slow],
)

settings.load_profile(DETERMINISTIC_PROFILE)
