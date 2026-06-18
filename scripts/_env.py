"""Minimal no-dependency .env loader for the scripts directory.

Finds code/.env (one level up from this file), reads KEY=VALUE lines, and sets
any key that is not already in the environment. The scoring paths never need this
(they read the committed caches); only the --record paths, which make live model
calls, read the API keys. Import and call at the top of a recording path:

    from _env import load_env
    load_env()

Mirrors spikes/_env.py so the scripts and the spikes load the same .env the same
way. Pure stdlib, no third-party dependency.
"""

from __future__ import annotations

import os


def load_env() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    # code/scripts/_env.py -> code/.env
    candidate = os.path.join(os.path.dirname(here), ".env")
    if not os.path.exists(candidate):
        return
    with open(candidate, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and value and key not in os.environ:
                os.environ[key] = value
