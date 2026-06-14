"""test_model_rationale.py -- the on-camera "why THIS model for THIS role"
rationale. The named-model-per-role mapping was already real; this pins that the
WHY now renders too, in the provider print and in the Examiner Packet, and that
adding the rationale did NOT change the hashed run-log bytes (the replay sha is
byte-identical, because the rationale is static config rendered at print/packet
time and never written into the hashed JSONL).
"""

import tempfile

from floor import drafter, roster
from floor.packet import write_packet


# Pinned run-log sha for the offline prod normal floor. It must equal the
# pre-rationale baseline: the rationale lives in roster.py config and is rendered
# only into the packet/print, never into the hashed run log, so this sha is
# unchanged by it. If a future edit writes rationale into the log, this fails.
EXPECTED_PROD_NORMAL_SHA = (
    "24b8542157b7d3063ffc172540383bc54365cffb124101da9d75e65d33f9c134")


class _FakeResp:
    status_code = 200
    text = "error-body"

    def json(self):
        return {"choices": [{"message": {"content":
                "A deterministic drafted filing body."}}]}


def _fake_post(url, headers=None, json=None, timeout=None):
    return _FakeResp()


def _prod_floor(monkeypatch, tmp_path):
    from floor.run_floor import DRAFTER_ROLES, run_floor
    from floor.shell_adapter import FakeBandClient, FakeRoom

    monkeypatch.setenv("FEATHERLESS_API_KEY", "fl-secret")
    monkeypatch.setenv("AIML_API_KEY", "aiml-secret")
    monkeypatch.setattr(drafter.requests, "post", _fake_post)

    room = FakeRoom()
    clients = {
        "warden": FakeBandClient(room, "warden-id", "warden", "warden"),
        "triage": FakeBandClient(room, "triage-id", "triage", "triage"),
    }
    for r in DRAFTER_ROLES:
        clients[r.branch] = FakeBandClient(
            room, f"{r.branch}-id", f"{r.branch}_drafter", f"draft:{r.branch}")
    return run_floor(out_dir=str(tmp_path), mode="normal", clients=clients,
                     provider_set=roster.PROVIDER_PROD)


# ---- every role names a model AND a reason --------------------------------

def test_every_role_has_a_non_empty_rationale():
    roles = (roster.WARDEN, roster.TRIAGE, roster.NIS2_DRAFTER,
             roster.SEC_DRAFTER, roster.DORA_DRAFTER, roster.UK_DRAFTER,
             roster.NYDFS_DRAFTER, roster.MATERIALITY)
    # The Warden makes no LLM call, so it carries no model and needs no rationale.
    for role in roles:
        if not role.model:
            continue
        assert role.rationale.strip(), f"{role.name} has no dev rationale"


def test_every_prod_override_has_a_rationale():
    for role in (roster.TRIAGE, roster.NIS2_DRAFTER, roster.SEC_DRAFTER,
                 roster.DORA_DRAFTER):
        why = roster.prod_role_rationale(role)
        assert why.strip(), f"{role.name} has no prod rationale"


def test_every_featherless_hero_has_a_rationale():
    heroes = roster.prod_featherless_hero_models()
    rationales = roster.prod_featherless_hero_rationales()
    for label in heroes:
        assert rationales.get(label, "").strip(), f"{label} hero has no rationale"


def test_prod_rationale_names_the_actual_routed_model():
    # The rationale must match the model the role is actually routed to in prod,
    # so the WHY can never drift from the WHAT (the SEC/UK drift Valerii flagged).
    expect_token = {
        roster.TRIAGE: "gemini-3.5-flash",
        roster.NIS2_DRAFTER: "claude-sonnet-4",
        roster.DORA_DRAFTER: "gpt-5-chat-latest",
        roster.SEC_DRAFTER: "claude-opus-4-1",
    }
    for role, token in expect_token.items():
        _provider, model = roster.resolve(role, roster.PROVIDER_PROD)
        assert token in model, f"{role.name} model id drifted from {token}"
        assert token in roster.prod_role_rationale(role), \
            f"{role.name} rationale does not name its routed model {token}"


# ---- the provider print speaks the rationale ------------------------------

def test_provider_print_includes_the_rationale(monkeypatch, tmp_path):
    packet = _prod_floor(monkeypatch, tmp_path)
    trace = "\n".join(packet["trace"])
    assert "[0] Provider set: PROD" in trace
    # Every prod drafter's reason appears in the run output, not just its name.
    for role in (roster.TRIAGE, roster.NIS2_DRAFTER, roster.SEC_DRAFTER,
                 roster.DORA_DRAFTER):
        assert roster.prod_role_rationale(role) in trace, \
            f"{role.name} rationale missing from the provider print"


# ---- the packet renders model + reason per filing -------------------------

def test_packet_filings_carry_the_rationale(monkeypatch, tmp_path):
    packet = _prod_floor(monkeypatch, tmp_path)
    assert packet["filings"], "no filings produced"
    for f in packet["filings"]:
        assert f.get("rationale", "").strip(), \
            f"{f.get('regime')} filing has no rationale"


def test_packet_html_shows_model_and_reason(monkeypatch, tmp_path):
    packet = _prod_floor(monkeypatch, tmp_path)
    with tempfile.TemporaryDirectory() as d:
        _json_path, html_path = write_packet(packet, d)
        html = open(html_path, encoding="utf-8").read()
    # The "why this model holds this role" line renders next to "via <model>".
    assert "holds this role" in html
    sec_rationale = roster.prod_role_rationale(roster.SEC_DRAFTER)
    # html escaping turns no characters of this sentence, so a substring check
    # of a distinctive clause is safe.
    assert "highest-reasoning model drafts the highest-stakes filing" in html
    assert sec_rationale[:30] in html


# ---- the byte-identical guard: rationale did NOT change the run-log sha ----

def test_adding_rationale_did_not_change_the_replay_sha(monkeypatch, tmp_path):
    packet = _prod_floor(monkeypatch, tmp_path)
    replay = packet["replay"]
    assert replay["byte_identical"] is True
    assert replay["original_sha256"] == EXPECTED_PROD_NORMAL_SHA, (
        "the run-log sha changed: rationale must be render-time config only, "
        "never written into the hashed JSONL")
