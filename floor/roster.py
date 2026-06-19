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
    rationale: str = ""       # one line: why this model holds this role (dev)

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
    rationale="DeepSeek-V3.2 holds NIS2 in dev because it is a strong open "
              "reasoning model that handles structured statutory prose at "
              "flat rate, so the day-to-day build burns no metered credit.",
)

SEC_DRAFTER = Role(
    role="drafter", name="SEC Drafter", branch="sec", regime="SEC",
    key_env="BAND_API_KEY_SEC", id_env="BAND_AGENT_ID_SEC",
    model="deepseek-ai/DeepSeek-V3-0324",
    rationale="DeepSeek-V3-0324 holds SEC in dev as a separate open checkpoint "
              "from the NIS2 drafter, so two branches draft from genuinely "
              "different model state even before the prod split.",
)

DORA_DRAFTER = Role(
    role="drafter", name="DORA Drafter", branch="dora", regime="DORA",
    key_env="BAND_API_KEY_DORA", id_env="BAND_AGENT_ID_DORA",
    model="Qwen/Qwen2.5-72B-Instruct",
    rationale="Qwen2.5-72B-Instruct holds DORA in dev because its long "
              "instruction-following is a good fit for DORA's incident-report "
              "field skeleton, and it is a third open family on flat rate.",
)

TRIAGE = Role(
    role="triage", name="Triage", branch="", regime="",
    key_env="BAND_API_KEY_TRIAGE", id_env="BAND_AGENT_ID_TRIAGE",
    model="deepseek-ai/DeepSeek-V3.2",
    rationale="DeepSeek-V3.2 holds Triage in dev because first-pass fact "
              "extraction wants a capable open model at flat rate, with no "
              "metered call on the hot path that opens every incident.",
)

# The UK ICO Drafter is recruited at RUNTIME (floor/recruit.py), only when a UK
# subsidiary is in the incident blast radius. It is a real Band agent (keys in
# .env as BAND_*_UK) but it is not added to the room at startup; the Warden
# discovers and recruits it live when the content demands it. Its model is the
# latest MiniMax on Featherless, the open-model data-sovereignty story.
UK_DRAFTER = Role(
    role="drafter", name="UK ICO Drafter", branch="uk", regime="UK ICO",
    key_env="BAND_API_KEY_UK", id_env="BAND_AGENT_ID_UK",
    model="MiniMaxAI/MiniMax-M2.7",
    rationale="MiniMax-M2.7 holds UK ICO because the UK 72-hour GDPR filing is "
              "the data-sovereignty story: a bank can self-host the open model "
              "that drafts its regulator notice instead of sending facts to a "
              "third-party API.",
)

# The NYDFS Drafter is recruited at RUNTIME (floor/recruit.py), only when a New
# York licensed entity is in the incident blast radius. It is a real Band agent
# (keys in .env as BAND_*_NYDFS) but it is not added to the room at startup; the
# Warden discovers and recruits it live when the content demands it. It runs on a
# SECOND open-model family (Qwen on Featherless): a US bank self-hosting an open
# model for its New York regulator filing, the data-sovereignty story.
NYDFS_DRAFTER = Role(
    role="drafter", name="NYDFS Drafter", branch="nydfs", regime="NYDFS 23 NYCRR 500",
    key_env="BAND_API_KEY_NYDFS", id_env="BAND_AGENT_ID_NYDFS",
    model="Qwen/Qwen2.5-72B-Instruct",
    rationale="Qwen2.5-72B-Instruct holds NYDFS as a SECOND open family beside "
              "the UK MiniMax drafter, so a US bank self-hosts an open model for "
              "its New York regulator filing without a single-vendor dependency.",
)

# The Challenger is the adversarial pre-submission reviewer (floor/challenger.py):
# an independent LLM agent that critiques each drafted filing BEFORE the Warden
# gates it, posting a structured [CHALLENGE] into the room @mentioning the
# drafter. It is a real, distinct Band agent (keys in .env as BAND_*_CHALLENGER)
# so its critique appears in the room under its own identity. It runs on a SECOND
# open family (Qwen on Featherless) so the reviewer is a genuinely different model
# from the DeepSeek drafters it challenges, not one model arguing with itself. It
# NEVER gates: its objections are content, adjudicated by the deterministic
# grounding scorer. Under the free-tier 10-agent cap.
CHALLENGER = Role(
    role="challenger", name="Challenger", branch="", regime="",
    key_env="BAND_API_KEY_CHALLENGER", id_env="BAND_AGENT_ID_CHALLENGER",
    model="Qwen/Qwen2.5-72B-Instruct",
    rationale="Qwen2.5-72B-Instruct holds the adversarial Challenger because the "
              "red-team reviewer must be a DIFFERENT open family from the "
              "DeepSeek drafters it critiques, so the challenge is one model "
              "interrogating another, not a model marking its own homework.",
)

# Materiality is an LLM judgment role (floor/materiality.py) that decides whether
# the SEC clock is triggered at all. On dev it runs on Featherless. It is not a
# separate Band agent on the floor; it is invoked in-process by the Warden's
# orchestration and its verdict crosses into the deterministic gate as data.
MATERIALITY = Role(
    role="materiality", name="Materiality Assessor", branch="sec", regime="SEC",
    key_env="", id_env="", model="deepseek-ai/DeepSeek-V3.2",
    rationale="DeepSeek-V3.2 holds Materiality because the SEC Item 1.05 "
              "materiality call is the highest-stakes judgment in the room, and "
              "a bank can self-host the open model that makes it rather than "
              "trust that decision to a closed API.",
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

# Why THIS model holds THIS role in the prod split: the on-camera rationale,
# keyed by the same role identity as PROD_OVERRIDES. Static config, rendered at
# print and packet time only; never written into the hashed run-log JSONL, so the
# replay sha is byte-identical with or without it. Accurate to the model ids
# above: change a model and you change its line here.
PROD_RATIONALE: dict[str, str] = {
    _role_id(TRIAGE): "gemini-3.5-flash holds Triage because the first-pass "
                      "incident classifier is the fastest call in the room and "
                      "flash is the quickest named model on the gateway.",
    _role_id(NIS2_DRAFTER): "claude-sonnet-4 holds NIS2 because structured "
                            "statutory prose (the Article 23 notification) is "
                            "exactly its strength: precise, well-formatted "
                            "legal drafting without top-tier reasoning cost.",
    _role_id(DORA_DRAFTER): "gpt-5-chat-latest holds DORA to put a DIFFERENT "
                            "named vendor on the third racing branch, proving "
                            "the gateway routes real multi-vendor traffic, not "
                            "one model behind a proxy.",
    _role_id(SEC_DRAFTER): "claude-opus-4-1 holds SEC because Item 1.05 "
                           "materiality is the highest-reasoning call in the "
                           "room, so the highest-reasoning model drafts the "
                           "highest-stakes filing.",
}


def prod_role_rationale(role: "Role") -> str:
    """The on-camera rationale for a role under the prod split: the PROD_RATIONALE
    entry if the role is a prod override, else the role's own dev rationale. Pure
    config lookup, called only at print/packet render time."""
    return PROD_RATIONALE.get(_role_id(role), role.rationale)

# Featherless HERO roles (open-model story, the two Featherless judges). These are
# real authority roles, not narrators. They are not live racing-drafter Band
# agents on the floor today, so their assignment is recorded here for the packet
# and the startup availability check; they apply directly when their Band agent
# is wired (UK ICO key + id already exist in .env as BAND_*_UK).
MATERIALITY_HERO = (FEATHERLESS, "deepseek-ai/DeepSeek-V3.2")
# The second independent open model that cross-checks the same SEC materiality
# judgment when --second-opinion is set. A DIFFERENT family from the primary
# (MiniMax vs DeepSeek), so their agreement is real corroboration and not one
# model agreeing with itself. Sequential with the primary, so only one big model
# runs at a time; the pinned two-model set stays under the switch cap.
MATERIALITY_SECOND_HERO = (FEATHERLESS, "MiniMaxAI/MiniMax-M2.7")
UK_HERO = (FEATHERLESS, "MiniMaxAI/MiniMax-M2.7")

# Why each Featherless hero (open-model) role runs on its model. Static config,
# rendered at print/packet time only, never hashed into the run log. Keyed by the
# same human labels prod_featherless_hero_models() emits.
HERO_RATIONALE: dict[str, str] = {
    "Materiality": "DeepSeek-V3.2 makes the SEC materiality call on an open "
                   "model a bank can self-host: the highest-stakes judgment "
                   "stays inside the bank's own infrastructure.",
    "Materiality (second opinion)": "MiniMax-M2.7 is a DIFFERENT open family "
                                    "from the primary, so a second-opinion "
                                    "AGREE is real corroboration, not one model "
                                    "agreeing with itself.",
    "UK ICO Drafter": "MiniMax-M2.7 drafts the UK 72-hour GDPR notice on a "
                      "self-hostable open model: the data-sovereignty story for "
                      "the highest-privacy filing.",
}


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


# ---------------------------------------------------------------------------
# E5.7 part 1: ordered model preference (FAILOVER) chains.
#
# A production multi-model deployment never bets the filing on one model being
# up. Each drafting role declares an ORDERED preference chain of (provider, model)
# pairs: the primary first, then cross-family fallbacks. When the primary returns
# a TERMINAL error (a model 404, a forbidden key, a hard refusal), the drafter
# tries the next entry in the chain, and records which model SERVED the filing and
# which it FELL BACK FROM. That served_by / fell_back_from record is OUT-OF-LOG
# (it rides the trace like recovered_retries), NEVER in the hashed [CLAIMS], so a
# clean single-model run is byte-identical.
#
# The chains here are CROSS-FAMILY by construction (DeepSeek -> MiniMax -> Qwen on
# Featherless), so a whole-family outage on the gateway still produces a filing
# from a genuinely different open model. All entries are Featherless (flat-rate),
# so exercising a fallback in dev burns zero metered credit.
#
# DEFAULT OFF: nothing here is read unless a caller asks for failover explicitly
# (drafter.draft_filing_with_failover / run_floor --failover). The plain
# draft_filing path is unchanged, so the offline suite and replay stay
# byte-identical.
# ---------------------------------------------------------------------------

# The cross-family open-model order the failover walks: DeepSeek first (the hero
# open model), then MiniMax (a different family, the data-sovereignty model), then
# Qwen (a third family). Used to build each role's chain so every role fails over
# across genuinely different model families on flat-rate Featherless.
CROSS_FAMILY_CHAIN: tuple[tuple[str, str], ...] = (
    (FEATHERLESS, "deepseek-ai/DeepSeek-V3.2"),
    (FEATHERLESS, "MiniMaxAI/MiniMax-M2.7"),
    (FEATHERLESS, "Qwen/Qwen2.5-72B-Instruct"),
)


def fallback_chain(role: "Role", provider_set: str) -> list[tuple[str, str]]:
    """The ordered (provider, model) preference chain for a role under a provider
    set: the role's active primary first, then the cross-family open-model
    fallbacks that are not already the primary, de-duplicated in order.

    The primary is whatever resolve() picks for the active provider set, so a dev
    chain leads with the role's Featherless model and a prod chain leads with its
    AI/ML model, then both fall back across the open-model families. Pure config;
    nothing here calls a model or reads the network. The CALLER decides whether to
    walk the chain (failover ON) or only ever use entry 0 (the default)."""
    primary = resolve(role, provider_set)
    chain: list[tuple[str, str]] = [primary]
    for entry in CROSS_FAMILY_CHAIN:
        if entry not in chain:
            chain.append(entry)
    return chain


# ---------------------------------------------------------------------------
# E5.7 part 2: complexity TIERS (cheap / mid / premium).
#
# A production gateway routes by COST and COMPLEXITY: a low-complexity filing goes
# to a cheap fast model, a high-complexity one to a premium model. The tier table
# names one (provider, model) per tier, plus a RELATIVE cost weight (a unitless
# multiplier, NEVER a dollar figure, so the packet shows a relative-cost estimate,
# never a fabricated invoice). All Featherless, flat-rate, so routing in dev burns
# zero metered credit.
#
# DEFAULT OFF: the router is only consulted when a caller asks for it
# (run_floor --route). The default drafting path ignores tiers entirely, so the
# offline suite and replay stay byte-identical.
# ---------------------------------------------------------------------------

TIER_CHEAP = "cheap"
TIER_MID = "mid"
TIER_PREMIUM = "premium"
TIERS = (TIER_CHEAP, TIER_MID, TIER_PREMIUM)


@dataclass(frozen=True)
class TierSpec:
    """One complexity tier: the model that serves it and a RELATIVE cost weight.

    cost_weight is a unitless multiplier (cheap = 1.0 baseline), used only to
    render a RELATIVE-cost estimate in the packet. It is never a currency amount
    and never multiplied by a real price, so the ledger states relative cost, not a
    fabricated invoice."""
    tier: str
    provider: str
    model: str
    cost_weight: float
    rationale: str


# The deterministic tier table. cheap = the fast small-context model, mid = the
# hero open model, premium = the largest-context reasoning model. Cost weights are
# relative only (cheap is the 1.0 baseline).
TIER_TABLE: dict[str, TierSpec] = {
    TIER_CHEAP: TierSpec(
        tier=TIER_CHEAP, provider=FEATHERLESS,
        model="MiniMaxAI/MiniMax-M2.7", cost_weight=1.0,
        rationale="MiniMax-M2.7 serves the cheap tier: a fast self-hostable open "
                  "model for a low-complexity filing that needs no deep reasoning.",
    ),
    TIER_MID: TierSpec(
        tier=TIER_MID, provider=FEATHERLESS,
        model="deepseek-ai/DeepSeek-V3.2", cost_weight=2.0,
        rationale="DeepSeek-V3.2 serves the mid tier: the hero open reasoning "
                  "model for a standard statutory filing.",
    ),
    TIER_PREMIUM: TierSpec(
        tier=TIER_PREMIUM, provider=FEATHERLESS,
        model="Qwen/Qwen2.5-72B-Instruct", cost_weight=3.0,
        rationale="Qwen2.5-72B-Instruct serves the premium tier: the largest "
                  "open model for a high-complexity filing with many factors.",
    ),
}


def tier_spec(tier: str) -> TierSpec:
    """The TierSpec for a tier name, raising on an unknown tier. Pure config."""
    try:
        return TIER_TABLE[tier]
    except KeyError as e:
        raise ValueError(f"unknown tier: {tier!r}") from e


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
        "Materiality (second opinion)": MATERIALITY_SECOND_HERO[1],
        "UK ICO Drafter": UK_HERO[1],
    }


def prod_featherless_hero_rationales() -> dict[str, str]:
    """The on-camera rationale per Featherless hero role, keyed by the same human
    labels prod_featherless_hero_models() uses. Static config, render time only."""
    return dict(HERO_RATIONALE)


def live_drafters() -> list[Role]:
    return [r for r in (NIS2_DRAFTER, SEC_DRAFTER, DORA_DRAFTER) if r.live]
