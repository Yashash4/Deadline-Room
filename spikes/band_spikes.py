"""Band Agent API spike harness for Deadline Room (floor scope).

Reverse-engineered against the LIVE API on 2026-06-13. Every schema below is
confirmed working. Run from code/:  py spikes/band_spikes.py

Needs (in code/.env): BAND_API_KEY (agent 1), BAND_API_KEY_2 (agent 2),
BAND_AGENT_ID, BAND_AGENT_ID_2. Writes spike_results.json + prints a PASS/FAIL table.

Verified API map (authoritative; supersedes spec guesses):
  Auth:   header  X-API-Key: <agent key>   (NOT Authorization: Bearer)
  Base:   https://app.band.ai/api/v1
  GET  /agent/me
  POST /agent/chats                          body {"chat":{"title": str}}            -> 201 {data:{id}}
  POST /agent/chats/{id}/participants        body {"participant":{"participant_id": agent_uuid}} -> 201
  POST /agent/chats/{id}/messages            body {"message":{"content": str, "mentions":[{"id": agent_uuid}]}}
                                              (mentioned agent MUST be a room participant)
  GET  /agent/chats/{id}/messages/next       -> 200 backlog | 204 empty   (PER-CHAT drain, not global)
  GET  /agent/chats/{id}/context             -> 200
  GET  /agent/peers?not_in_chat={id}         -> 200
"""

from __future__ import annotations

import json
import os
import sys

import requests

from _env import load_env

load_env()

BASE = os.environ.get("BAND_BASE_URL", "https://app.band.ai/api/v1")
KEY1 = os.environ.get("BAND_API_KEY", "")
KEY2 = os.environ.get("BAND_API_KEY_2", "")
ID1 = os.environ.get("BAND_AGENT_ID", "")
ID2 = os.environ.get("BAND_AGENT_ID_2", "")

RESULTS: list[dict] = []


def rec(spike: str, status: str, note: str, raw=None) -> None:
    RESULTS.append({"spike": spike, "status": status, "note": note,
                    "raw": (str(raw)[:500] if raw is not None else None)})
    print(f"[{status:5}] {spike}: {note}")


def call(key, method, path, body=None, params=None):
    try:
        r = requests.request(method, BASE + path, params=params, json=body, timeout=30,
                             headers={"X-API-Key": key, "Content-Type": "application/json"})
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, r.text
    except requests.RequestException as e:
        return -1, str(e)


def main() -> int:
    if not (KEY1 and KEY2 and ID1 and ID2):
        print("Need BAND_API_KEY, BAND_API_KEY_2, BAND_AGENT_ID, BAND_AGENT_ID_2 in .env")
        return 1
    print(f"Base URL: {BASE}\n")

    # 1. auth
    c, d = call(KEY1, "GET", "/agent/me")
    rec("1 auth agent1", "PASS" if c == 200 else "FAIL", f"HTTP {c}", d if c != 200 else None)
    c, d = call(KEY2, "GET", "/agent/me")
    rec("1b auth agent2", "PASS" if c == 200 else "FAIL", f"HTTP {c}", d if c != 200 else None)

    # 2. create room (agent1 = Warden)
    c, d = call(KEY1, "POST", "/agent/chats", {"chat": {"title": "deadline-room-spike"}})
    if c != 201:
        rec("2 create room", "FAIL", f"HTTP {c}", d)
        _save()
        return 1
    cid = d["data"]["id"]
    rec("2 create room", "PASS", f"chat_id={cid}")

    # 3. add agent2 (NIS2 Drafter) as participant
    c, d = call(KEY1, "POST", f"/agent/chats/{cid}/participants",
                {"participant": {"participant_id": ID2}})
    rec("3 add_participant", "PASS" if c == 201 else "FAIL", f"HTTP {c}", d if c != 201 else None)

    # 4. agent1 sends a MENTIONED message to agent2
    c, d = call(KEY1, "POST", f"/agent/chats/{cid}/messages",
                {"message": {"content": "Fact record ready. @nis2 draft the 72h notification.",
                             "mentions": [{"id": ID2}]}})
    rec("4 send mentioned msg", "PASS" if c in (200, 201) else "FAIL", f"HTTP {c}", d if c not in (200, 201) else None)

    # 5. agent2 drains its per-chat inbox: should SEE the mentioned message
    c, d = call(KEY2, "GET", f"/agent/chats/{cid}/messages/next")
    saw_mentioned = c == 200 and bool(d)
    rec("5 agent2 drain /next (mentioned)", "PASS" if saw_mentioned else "WARN",
        f"HTTP {c}, saw_message={saw_mentioned}", d if not saw_mentioned else None)

    # 6. SPIKE-12: isolation. agent1 posts a message mentioning ONLY agent1 (self).
    #    Does agent2 (un-mentioned) see it via /next and via /context?
    c, d = call(KEY1, "POST", f"/agent/chats/{cid}/messages",
                {"message": {"content": "Internal warden note, not for NIS2.",
                             "mentions": [{"id": ID1}]}})
    rec("6a post self-mentioned msg", "PASS" if c in (200, 201) else "FAIL", f"HTTP {c}", d if c not in (200, 201) else None)
    c_next, d_next = call(KEY2, "GET", f"/agent/chats/{cid}/messages/next")
    agent2_next_sees = c_next == 200 and "Internal warden note" in json.dumps(d_next)
    c_ctx, d_ctx = call(KEY2, "GET", f"/agent/chats/{cid}/context")
    agent2_ctx_sees = c_ctx == 200 and "Internal warden note" in json.dumps(d_ctx)
    if not agent2_next_sees and not agent2_ctx_sees:
        rec("6 SPIKE-12 isolation", "PASS",
            "un-mentioned agent2 sees the message in NEITHER /next NOR /context: mention-filtering is ENFORCED isolation")
    elif not agent2_next_sees and agent2_ctx_sees:
        rec("6 SPIKE-12 isolation", "WARN",
            "un-mentioned agent2 does NOT get it via /next but DOES via /context: isolation is push-only, /context leaks full room history (Sealed Bid/Two-Key separators would be app-layer only)")
    else:
        rec("6 SPIKE-12 isolation", "WARN",
            f"un-mentioned agent2 sees it (next={agent2_next_sees}, ctx={agent2_ctx_sees}): no transport isolation")

    # 6b. message lifecycle (PER-CHAT under the message, verified 2026-06-13):
    #     processing -> processed advances /next; failed takes {"error": str}.
    c, d = call(KEY1, "POST", f"/agent/chats/{cid}/messages",
                {"message": {"content": "Lifecycle probe for the drafter.",
                             "mentions": [{"id": ID2}]}})
    c, d = call(KEY2, "GET", f"/agent/chats/{cid}/messages/next")
    if c == 200 and isinstance(d, dict) and d.get("data"):
        mid = d["data"]["id"]
        c_pr, _ = call(KEY2, "POST", f"/agent/chats/{cid}/messages/{mid}/processing")
        c_pd, _ = call(KEY2, "POST", f"/agent/chats/{cid}/messages/{mid}/processed", {})
        ok = c_pr == 200 and c_pd == 200
        rec("6b lifecycle processing->processed", "PASS" if ok else "FAIL",
            f"processing HTTP {c_pr}, processed HTTP {c_pd}")
    else:
        rec("6b lifecycle processing->processed", "WARN", f"no message to drain (HTTP {c})")

    # 7. context rehydrate (agent1, the poster, should always see full room)
    c, d = call(KEY1, "GET", f"/agent/chats/{cid}/context")
    rec("7 /context rehydrate (agent1)", "PASS" if c == 200 else "FAIL", f"HTTP {c}", d if c != 200 else None)

    # 8. peers discovery
    c, d = call(KEY1, "GET", "/agent/peers", params={"not_in_chat": cid})
    rec("8 peers?not_in_chat", "PASS" if c == 200 else "WARN", f"HTTP {c}")

    _save()
    fails = [r for r in RESULTS if r["status"] == "FAIL"]
    print(f"\nFloor-scope verdict: {'ALL CLEAR' if not fails else str(len(fails)) + ' FAIL(s)'}")
    return 1 if fails else 0


def _save():
    with open(os.path.join(os.path.dirname(__file__), "spike_results.json"), "w", encoding="utf-8") as fh:
        json.dump(RESULTS, fh, indent=2)
    print("\nSaved spike_results.json")


if __name__ == "__main__":
    sys.exit(main())
