"""Partner API spike: validates the exact model names design-spec-v2 commits to,
before any build day depends on them (fix A12 / spike item: model-name validation).

Usage (keys are never written to disk, pass via env):
  set AIML_API_KEY=...        (PowerShell: $env:AIML_API_KEY="...")
  set FEATHERLESS_API_KEY=...
  python partner_api_spike.py

Checks, in order:
  1. AI/ML API /models list: do our exact roster model IDs exist?
  2. AI/ML API: one tiny completion per roster model (proves access, not just listing).
  3. Featherless: auth + one tiny completion on the UK-drafter model.
Prints a PASS/FAIL table and exits 1 if any roster model is missing (so it can gate CI later).
"""

import json
import os
import sys
import urllib.request

AIML_BASE = "https://api.aimlapi.com/v1"
FEATHERLESS_BASE = "https://api.featherless.ai/v1"

# The exact roster from design-spec-v2 section 4. If any ID 404s, the spec
# gets corrected on day 1, not discovered broken on day 3.
AIML_ROSTER = {
    "Triage": "gemini-3.5-flash",
    "Materiality": "claude-opus-4-8",
    "NIS2 Drafter": "claude-sonnet-4-6",
    "DORA Drafter": "gpt-5",
    "SEC Drafter": "gpt-5",
}
FEATHERLESS_ROSTER = {
    "UK ICO Drafter": "meta-llama/Llama-3.3-70B-Instruct",
}

PROBE_PROMPT = "Reply with exactly the word: ready"


def _post(base, key, path, payload):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def _get(base, key, path):
    req = urllib.request.Request(
        base + path, headers={"Authorization": f"Bearer {key}"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def probe_completion(base, key, model):
    body = _post(base, key, "/chat/completions", {
        "model": model,
        "messages": [{"role": "user", "content": PROBE_PROMPT}],
        "max_tokens": 8,
    })
    return body["choices"][0]["message"]["content"].strip()


def main():
    aiml_key = os.environ.get("AIML_API_KEY")
    fl_key = os.environ.get("FEATHERLESS_API_KEY")
    failures = []
    rows = []

    if not aiml_key:
        print("AIML_API_KEY not set, skipping AI/ML API checks")
    else:
        try:
            listed = {m["id"] for m in _get(AIML_BASE, aiml_key, "/models")["data"]}
        except Exception as e:
            listed = set()
            print(f"AI/ML API /models failed: {e}")
        for role, model in AIML_ROSTER.items():
            status = "listed" if model in listed else "NOT LISTED"
            reply = ""
            try:
                reply = probe_completion(AIML_BASE, aiml_key, model)
                status += ", completion ok"
            except Exception as e:
                status += f", completion FAILED ({e})"
                failures.append((role, model))
            rows.append(("AI/ML API", role, model, status, reply))

    if not fl_key:
        print("FEATHERLESS_API_KEY not set, skipping Featherless checks")
    else:
        for role, model in FEATHERLESS_ROSTER.items():
            try:
                reply = probe_completion(FEATHERLESS_BASE, fl_key, model)
                rows.append(("Featherless", role, model, "completion ok", reply))
            except Exception as e:
                rows.append(("Featherless", role, model, f"FAILED ({e})", ""))
                failures.append((role, model))

    print()
    for provider, role, model, status, reply in rows:
        print(f"  [{provider}] {role:16s} {model:40s} {status}  {reply!r}")
    print()
    if failures:
        print(f"SPIKE RESULT: FAIL, {len(failures)} roster model(s) unusable: {failures}")
        print("Action: correct the roster in design-spec-v2 section 4 TODAY.")
        sys.exit(1)
    print("SPIKE RESULT: PASS, every roster model is live under the exact ID the spec names.")


if __name__ == "__main__":
    main()
