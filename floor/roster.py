"""Agent roster: the seam where more Band agents drop in.

Only TWO real Band agents exist today (the Warden and the NIS2 Drafter), so
the live floor run wires those two. Every other role is declared here with a
placeholder so that the moment its agent key + UUID exist in .env, it slots in
with no orchestration change: add the env var names, flip `live=True`.

A role is live iff its agent_key and agent_id resolve from the environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Role:
    role: str                 # warden | triage | drafter | materiality ...
    name: str                 # human label
    branch: str               # "" for non-branch roles (warden, triage)
    regime: str               # "" or e.g. "NIS2", "SEC"
    key_env: str              # env var holding the Band agent key
    id_env: str               # env var holding the Band agent UUID
    model: str                # LLM model id ("" for the no-LLM Warden)

    @property
    def agent_key(self) -> str:
        return os.environ.get(self.key_env, "")

    @property
    def agent_id(self) -> str:
        return os.environ.get(self.id_env, "")

    @property
    def live(self) -> bool:
        return bool(self.agent_key and self.agent_id)


# The full intended roster. Today only WARDEN and NIS2 are live; the rest are
# declared so the second drafter (needed for the contradiction-diff beat) and
# the others drop in by populating their env vars.
WARDEN = Role(
    role="warden", name="Deadline Warden", branch="", regime="",
    key_env="BAND_API_KEY", id_env="BAND_AGENT_ID", model="",
)

NIS2_DRAFTER = Role(
    role="drafter", name="NIS2 Drafter", branch="nis2", regime="NIS2",
    key_env="BAND_API_KEY_2", id_env="BAND_AGENT_ID_2",
    model="deepseek-ai/DeepSeek-V3.2",
)

# Pending agent keys (the seam). When these env vars are populated the role goes
# live with zero code change. The contradiction-diff beat needs SEC_DRAFTER.
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

ALL_ROLES = [WARDEN, NIS2_DRAFTER, SEC_DRAFTER, DORA_DRAFTER, TRIAGE]


def live_drafters() -> list[Role]:
    return [r for r in (NIS2_DRAFTER, SEC_DRAFTER, DORA_DRAFTER) if r.live]
