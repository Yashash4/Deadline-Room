"""Agent roster: the seam where more Band agents drop in, and the seam where each
role's LLM provider + model is chosen.

Two concerns live here:

1. Band identity. Only the Band agents whose key + UUID resolve from the
   environment are live. A role is live iff its agent_key and agent_id resolve.

2. LLM provider per role. Every drafting role names a provider ("featherless" or
   "aimlapi") and a model id. There are TWO provider SETS:

     dev  (default): every role on Featherless. Flat-rate, zero AI/ML credit
          burned. This is the day-to-day build and test configuration.
     prod: the prize-winning split. Two real authority roles stay on big
          Featherless open models (the open-model story for the two Featherless
          judges); the parallel racing drafters move to AI/ML API named models
          (the multi-model gateway story for the AI/ML judge).

   The active set is chosen at run time by `--provider dev|prod`; dev is the
   default so no AI/ML credit is ever spent unless prod is explicitly requested.

A role's `provider`/`model` fields hold its DEV defaults. The PROD overrides live
in PROD_OVERRIDES and are applied by `resolve(role, provider_set)`, so swapping a
model is a one-line change and dev stays all-Featherless by construction.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Provider identifiers used across the floor.
FEATHERLESS = "featherless"
AIMLAPI = "aimlapi"

# The two provider SETS selectable at run time.
PROVIDER_DEV = "dev"
PROVIDER_PROD = "prod"


@dataclass(frozen=True)
class Role:
    role: str                 # warden | triage | drafter | materiality ...
    name: str                 # human label
    branch: str               # "" for non-branch roles (warden, triage)
    regime: str               # "" or e.g. "NIS2", "SEC"
    key_env: str              # env var holding the Band agent key
    id_env: str               # env var holding the Band agent UUID
    model: str                # DEV LLM model id ("" for the no-LLM Warden)
    provider: str = FEATHERLESS  # DEV provider; dev set is all-Featherless

    @property
    def agent_key(self) -> str:
        return os.environ.get(self.key_env, "")

    @property
    def agent_id(self) -> str:
        return os.environ.get(self.id_env, "")

    @property
    def live(self) -> bool:
        return bool(self.agent_key and self.agent_id)


# The full intended roster. DEV provider/model on every role (all Featherless).
WARDEN = Role(
    role="warden", name="Deadline Warden", branch="", regime="",
    key_env="BAND_API_KEY", id_env="BAND_AGENT_ID", model="",
)

NIS2_DRAFTER = Role(
    role="drafter", name="NIS2 Drafter", branch="nis2", regime="NIS2",
    key_env="BAND_API_KEY_2", id_env="BAND_AGENT_ID_2",
    model="deepseek-ai/DeepSeek-V3.2",
)

SEC_DRAFTER = Role(
    role="drafter", name="SEC Drafter", branch="sec", regime="SEC",
    key_env="BAND_API_KEY_SEC", id_env="BAND_AGENT_ID_SEC",
    model="deepseek-ai/DeepSeek-V3-0324",
)

DORA_DRAFTER = Role(
    role="drafter", name="DORA Drafter", branch="dora", regime="DORA",
    key_env="BAND_API_KEY_DORA", id_env="BAND_AGENT_ID_DORA",
    model="Qwen/Qwen2.5-72B-Instruct",
)

TRIAGE = Role(
    role="triage", name="Triage", branch="", regime="",
    key_env="BAND_API_KEY_TRIAGE", id_env="BAND_AGENT_ID_TRIAGE",
    model="deepseek-ai/DeepSeek-V3.2",
)

# The UK ICO Drafter is recruited at RUNTIME (floor/recruit.py), only when a UK
# subsidiary is in the incident blast radius. It is a real Band agent (keys in
# .env as BAND_*_UK) but it is not added to the room at startup; the Warden
# discovers and recruits it live when the content demands it. Its model is the
# latest MiniMax on Featherless, the open-model data-sovereignty story.
UK_DRAFTER = Role(
    role="drafter", name="UK ICO Drafter", branch="uk", regime="UK ICO",
    key_env="BAND_API_KEY_UK", id_env="BAND_AGENT_ID_UK",
    model="MiniMaxAI/MiniMax-M2",
)

# Materiality is an LLM judgment role (floor/materiality.py) that decides whether
# the SEC clock is triggered at all. On dev it runs on Featherless. It is not a
# separate Band agent on the floor; it is invoked in-process by the Warden's
# orchestration and its verdict crosses into the deterministic gate as data.
MATERIALITY = Role(
    role="materiality", name="Materiality Assessor", branch="sec", regime="SEC",
    key_env="", id_env="", model="deepseek-ai/DeepSeek-V3.2",
)

ALL_ROLES = [WARDEN, NIS2_DRAFTER, SEC_DRAFTER, DORA_DRAFTER, TRIAGE]


# ---------------------------------------------------------------------------
# PROD provider split (verified model ids, see research/spikes/MODEL-ROSTER.md).
#
# Keyed by role role+branch identity (the same identity run_floor walks). Each
# entry is (provider, model). dev never reads this table, so dev burns zero
# AI/ML credit by construction.
#
#   Featherless HERO roles (open-model story, the two Featherless judges):
#     - Materiality is an LLM judgment role; it is not yet a separate Band agent
#       on the live floor, so its hero assignment is recorded here for the packet
#       and is applied if/when a materiality role is wired. (The Warden itself is
#       deterministic and makes NO LLM call; that separation is unchanged.)
#     - UK ICO Drafter on MiniMax-M2.7 (latest MiniMax, the data-sovereignty
#       story, replaces the gated Llama).
#
#   AI/ML API parallel drafters (multi-model gateway story, the AI/ML judge):
#     - Triage gemini-3.5-flash, NIS2 claude-sonnet-4, DORA gpt-5-chat-latest,
#       SEC claude-opus-4-1. Different named models per role, on-camera rationale.
# ---------------------------------------------------------------------------
def _role_id(role: "Role") -> str:
    return f"{role.role}:{role.branch}" if role.branch else role.role


PROD_OVERRIDES: dict[str, tuple[str, str]] = {
    # AI/ML API parallel racing drafters (multi-model gateway story). Different
    # named models per role; AI/ML concurrency is independent of Featherless.
    _role_id(TRIAGE): (AIMLAPI, "gemini-3.5-flash"),
    _role_id(NIS2_DRAFTER): (AIMLAPI, "claude-sonnet-4-20250514"),
    _role_id(DORA_DRAFTER): (AIMLAPI, "gpt-5-chat-latest"),
    _role_id(SEC_DRAFTER): (AIMLAPI, "claude-opus-4-1-20250805"),
}

# Featherless HERO roles (open-model story, the two Featherless judges). These are
# real authority roles, not narrators. They are not live racing-drafter Band
# agents on the floor today, so their assignment is recorded here for the packet
# and the startup availability check; they apply directly when their Band agent
# is wired (UK ICO key + id already exist in .env as BAND_*_UK).
MATERIALITY_HERO = (FEATHERLESS, "deepseek-ai/DeepSeek-V3.2")
UK_HERO = (FEATHERLESS, "MiniMaxAI/MiniMax-M2.7")


def resolve(role: "Role", provider_set: str) -> tuple[str, str]:
    """Return the active (provider, model) for a role under a provider set.

    dev  -> always the role's own (Featherless) provider + model. No AI/ML.
    prod -> the PROD_OVERRIDES entry if one exists, else the role's dev default.
    """
    if provider_set == PROVIDER_PROD:
        return PROD_OVERRIDES.get(_role_id(role), (role.provider, role.model))
    if provider_set == PROVIDER_DEV:
        return (role.provider, role.model)
    raise ValueError(f"unknown provider set: {provider_set!r}")


_ROLE_LABEL = {
    _role_id(TRIAGE): "Triage",
    _role_id(NIS2_DRAFTER): "NIS2 Drafter",
    _role_id(SEC_DRAFTER): "SEC Drafter",
    _role_id(DORA_DRAFTER): "DORA Drafter",
}


def prod_aiml_validation_models() -> dict[str, str]:
    """The AI/ML model ids prod will actually call, keyed by a human role label,
    for the cheap startup availability check. Only AI/ML models (the ones that
    cost credit) are validated; Featherless is flat-rate."""
    out: dict[str, str] = {}
    for role in (TRIAGE, NIS2_DRAFTER, SEC_DRAFTER, DORA_DRAFTER):
        provider, model = resolve(role, PROVIDER_PROD)
        if provider == AIMLAPI:
            out[_ROLE_LABEL[_role_id(role)]] = model
    return out


def prod_featherless_hero_models() -> dict[str, str]:
    """The Featherless hero (open-model) roles for the prod split, keyed by a
    human role label. Featherless is flat-rate, so these are shown for the run
    summary but do not need a credit-spending validation call."""
    return {
        "Materiality": MATERIALITY_HERO[1],
        "UK ICO Drafter": UK_HERO[1],
    }


def live_drafters() -> list[Role]:
    return [r for r in (NIS2_DRAFTER, SEC_DRAFTER, DORA_DRAFTER) if r.live]
