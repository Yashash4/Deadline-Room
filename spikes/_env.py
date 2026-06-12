"""Minimal no-dependency .env loader.

Finds code/.env (walking up from this file), reads KEY=VALUE lines, and sets any
that are not already in the environment. Import and call at the top of a spike:

    from _env import load_env
    load_env()
"""

import os


def load_env():
    here = os.path.dirname(os.path.abspath(__file__))
    # code/spikes/_env.py -> code/.env
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
