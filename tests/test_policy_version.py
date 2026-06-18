"""test_policy_version.py -- the render-time policy / config version stamp (E4.10).

The policy version stamp is a composite sha over the governing catalogs
(regimes.yaml, controls.yaml) and the Warden rule set (the transition-authority
table), so a reader knows which policy version governed a run. It is RENDER-TIME
ONLY: it is derived at packet assembly and is NEVER folded into the hashed run-log
(that would move the sealed sha), so the four sealed captures' run-log shas and
byte-identical replay are untouched.

Layers:

  Unit layer over floor/policy_version.py: the stamp covers the real catalogs and
  the rule set; it is deterministic; an edit to any component moves the composite.

  Render-only invariant: the stamp is flagged render-time-only and out of the
  hashed log; it never appears in a sealed run-log JSONL.

  Render layer over the packet HTML: the policy-version stamp renders.

  Guard layer: the four DEFAULT sealed captures' run-log shas are byte-for-byte
  unchanged.
"""

import hashlib
import inspect
import json
from pathlib import Path

import floor.policy_version as pv_mod
from floor.policy_version import policy_version, policy_version_record

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "web" / "data"
DEFAULT_MODES = ("normal", "inject_contradiction", "chaos", "amendment")


# ---- unit layer: the stamp is sound and complete ----------------------------

def test_stamp_covers_the_real_catalogs_and_the_rule_set():
    pv = policy_version()
    names = {c["name"] for c in pv["components"]}
    assert {"regimes.yaml", "controls.yaml", "rule_set"} <= names
    # Each component carries a real 64-hex sha.
    for c in pv["components"]:
        assert len(c["sha256"]) == 64, f"{c['name']} has no real sha"
    assert len(pv["policy_version"]) == 64


def test_each_component_sha_matches_the_file_on_disk():
    pv = policy_version()
    by_name = {c["name"]: c["sha256"] for c in pv["components"]}
    for fname in ("regimes.yaml", "controls.yaml"):
        disk = hashlib.sha256((REPO / "floor" / fname).read_bytes()).hexdigest()
        assert by_name[fname] == disk, f"{fname} sha does not match the file bytes"


def test_stamp_is_deterministic():
    a = policy_version()
    b = policy_version()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_composite_moves_when_a_component_sha_changes(monkeypatch):
    # An edit to any policy component must move the composite policy_version sha, so
    # a reader can tell two runs ran under different policy. Simulate a changed
    # rule-set serialization and confirm the composite changes.
    base = policy_version()["policy_version"]
    monkeypatch.setattr(pv_mod, "_ruleset_canonical",
                        lambda: '{"changed":"ruleset"}')
    changed = policy_version()["policy_version"]
    assert changed != base, "the composite must move when a component changes"


# ---- render-only invariant: never in the hashed run-log ----------------------

def test_stamp_is_flagged_render_time_only():
    pv = policy_version_record({})
    assert pv["render_time_only"] is True
    assert pv["in_hashed_run_log"] is False


def test_policy_version_token_never_appears_in_a_sealed_run_log():
    # The stamp must never have entered the hashed JSONL. No sealed run-log capture
    # may carry a policy_version event.
    for mode in DEFAULT_MODES:
        jsonl = (DATA / f"run-inc-8842-{mode}.jsonl").read_text(encoding="utf-8")
        assert "policy_version" not in jsonl, (
            f"{mode}: policy_version leaked into the hashed run-log")


def test_record_is_independent_of_the_run():
    # The stamp is a function of the policy files and the rule set, not the run, so
    # the same policy yields the same stamp for any packet handed in.
    a = policy_version_record({"incident": {"incident_id": "x"}})
    b = policy_version_record({"incident": {"incident_id": "y"}})
    assert a["policy_version"] == b["policy_version"]


# ---- derived: no LLM surface, no run-log mutation ----------------------------

def test_module_exposes_no_llm_or_run_log_writer_surface():
    src = inspect.getsource(pv_mod)
    for token in ("llm_complete", "draft_filing", "openai", "httpx", "api_key",
                  "datetime.now", "time.time", "random.", "uuid", "requests",
                  "log.append", "RunLog", ".save("):
        assert token not in src, f"policy_version module must not reference {token!r}"


# ---- render layer -----------------------------------------------------------

def test_packet_html_renders_the_policy_version():
    from floor.packet import _render_html
    packet = json.loads((DATA / "packet-normal.json").read_text(encoding="utf-8"))
    packet["policy_version"] = policy_version_record(packet)
    html = _render_html(packet)
    assert "Governing policy version" in html
    assert packet["policy_version"]["policy_version"] in html
    assert "regimes.yaml" in html


# ---- guard layer: the sealed captures are byte-for-byte unchanged ------------

_SEALED_SHAS = {
    "normal": (
        "4721e56cced08b2cfc663b0bca2e392bddae18ceec919f8a386a544f2d17b625",
        "89dae1455e3719996036ff4fc671755894003ef44b3938f3b9dc597aa54226f3"),
    "inject_contradiction": (
        "4de0c9d86e6afab0923801d2aa258d50a59db88c83ddfd6c88fd3c90e26487a6",
        "f1f2223aa57b4bace83bf3fcfc5886e2a657d86f15b5d9ed0762646142e34e98"),
    "chaos": (
        "81ecd17595336435f6e3bb73dbc32f7f79cb729e462d7d5fdd0bd9de6cdfa463",
        "303c437140df55fc6694780d6b54715921e9eed017eb8b9c4a348907b268b520"),
    "amendment": (
        "a10940ab4df880cd2e3aa6f9ec1a4095ac18c5e1e338bf7510e11429317eeaf4",
        "0ca07fb0a1f975a84de67966d2724137210c4b7ede1b5ddde96a53650d0c8bbc"),
}


def test_sealed_run_log_shas_unchanged_by_this_derive_only_feature():
    for mode in DEFAULT_MODES:
        jsonl = DATA / f"run-inc-8842-{mode}.jsonl"
        sig = json.loads((DATA / f"run-inc-8842-{mode}.jsonl.sig.json")
                         .read_text(encoding="utf-8"))
        file_sha = hashlib.sha256(jsonl.read_bytes()).hexdigest()
        expected_file_sha, expected_signed_sha = _SEALED_SHAS[mode]
        assert file_sha == expected_file_sha, (
            f"{mode}: on-disk run-log bytes changed; the policy-version stamp must "
            f"be render-only and never touch the sealed log")
        assert sig["sha256"] == expected_signed_sha, (
            f"{mode}: signed run-log sha changed; policy_version must never enter "
            f"the hashed run-log")
