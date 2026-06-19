"""The package must stand alone: prove the lifted modules import NOTHING from the
Deadline Room app (no floor/, no warden/, no shell/). If any of these modules
dragged in an application import, it would not be installable as a library.

The test imports each band-once module in a way that executes its top-level
imports, then inspects sys.modules for any forbidden module name. It also reads
the source of each module and asserts no `from floor` / `import floor` /
`from warden` / `warden.clocks` import statement exists.
"""

import importlib
import sys
from pathlib import Path

import band_once
import band_once.fake_band
import band_once.ledger
import band_once.proof
import band_once.retry
import band_once.shell
import band_once.verify

_FORBIDDEN_PREFIXES = ("floor", "warden", "shell.")
_PKG_DIR = Path(band_once.__file__).resolve().parent


def test_no_application_module_is_imported():
    # No module under floor/ or warden/ (the Deadline Room app) may be loaded by
    # importing band-once. shell.band_agent_shell is the original; the lift must
    # not pull it in either.
    leaked = [
        name for name in sys.modules
        if name == "floor" or name.startswith("floor.")
        or name == "warden" or name.startswith("warden.")
        or name == "shell.band_agent_shell"
    ]
    assert leaked == [], f"band-once leaked application imports: {leaked}"


def test_no_module_source_imports_floor_or_warden_clocks():
    for py in _PKG_DIR.glob("*.py"):
        text = py.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                for bad in _FORBIDDEN_PREFIXES:
                    assert not stripped.startswith(f"from {bad}"), (
                        f"{py.name}: forbidden import '{stripped}'")
                    assert not stripped.startswith(f"import {bad}"), (
                        f"{py.name}: forbidden import '{stripped}'")
                assert "warden.clocks" not in stripped, (
                    f"{py.name}: forbidden import '{stripped}'")


def test_every_public_module_imports_clean():
    for mod in ("band_once.shell", "band_once.ledger", "band_once.retry",
                "band_once.fake_band", "band_once.proof", "band_once.verify"):
        assert importlib.import_module(mod) is not None
