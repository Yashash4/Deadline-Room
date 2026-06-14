# Deadline Room: one-command bring-up.
#
# Targets:
#   make test     run the property suite (188 tests, no keys, no network)
#   make lint     run ruff over the repository
#   make demo     run a live incident (needs BAND_API_KEY + FEATHERLESS_API_KEY)
#   make verify   run the tamper receipt (break the evidence, watch the seal fail)
#   make check    test + lint + the dash/attribution hygiene gate (the CI gate)
#
# PY is the Python launcher. It defaults to "python" (Linux, macOS, CI, Docker).
# On Windows the launcher is usually "py", so run e.g.  make test PY=py
# or use the documented bare commands in the README Quickstart.
PY ?= python

.PHONY: test lint demo verify gate check

test:
	$(PY) -m pytest tests/ -q

lint:
	$(PY) -m ruff check .

demo:
	$(PY) floor/run_floor.py

verify:
	$(PY) scripts/tamper_test.py

gate:
	$(PY) scripts/hygiene_gate.py

check: test lint gate
	@echo "check passed: suite green, lint clean, hygiene gate clean."
