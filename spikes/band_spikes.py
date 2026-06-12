"""Band API spike harness for Deadline Room (floor scope).

Run:  set BAND_API_KEY=...   (Windows)  then:  python spikes.py
Optional: BAND_API_KEY_2 (a second agent's key, enables the mention-isolation
and two-agent spikes), BAND_BASE_URL (default below).

Every endpoint path lives in EP below. If a path differs from your
B-band-platform.md, fix it THERE, in one place, and re-run.

Output: a PASS/FAIL table on stdout + spike_results.json next to this file.
No pytest, no framework, no excuses. ~10 minutes with a key.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid

import requests

BASE = os.environ.get("BAND_BASE_URL", "https://api.band.ai/v1")
KEY1 = os.environ.get("BAND_API_KEY", "")
KEY2 = os.environ.get("BAND_API_KEY_2", "")  # optional second agent

# ---- endpoint map: fix paths HERE against B-band-platform.md if needed ----
EP = {
    "me":            "/agent/me",
    "chats":         "/agent/chats",
    "participants":  "/agent/chats/{chat_id}/participants",
    "context":       "/agent/chats/{chat_id}/context",
    "messages":      "/agent/chats/{chat_id}/messages",
    "next":          "/agent/messages/next",
    "processing":    "/agent/messages/{msg_id}/processing",
    "processed":     "/agent/messages/{msg_id}/processed",
    "failed":        "/agent/messages/{msg_id}/failed",
    "peers":         "/agent/peers",
}

RESULTS: list[dict] = []


def record(spike: str, status: str, note: str, raw=None) -> None:
    RESULTS.append({"spike": spike, "status": status, "note": note,
                    "raw": (str(raw)[:400] if raw is not None else None)})
    pad = {"PASS": "PASS ", "FAIL": "FAIL ", "WARN": "WARN ", "SKIP": "SKIP ", "INFO": "INFO "}
    print(f"[{pad.get(status, status)}] {spike}: {note}")


def call(key: str, method: str, path: str, body: dict | None = None, params=None):
    url = BASE + path
    try:
        r = requests.request(method, url, params=params, json=body, timeout=30,
                             headers={"Authorization": f"Bearer {key}",
                                      "Content-Type": "application/json"})
        try:
            data = r.json()
        except ValueError:
            data = r.text
        return r.status_code, data
    except requests.RequestException as e:
        return -1, str(e)


def gid(data, *keys):
    """Dig an id out of unknown response shapes."""
    if isinstance(data, dict):
        for k in (*keys, "id", "uuid", "chat_id", "message_id"):
            if k in data:
                return data[k]
        for v in data.values():
            found = gid(v, *keys)
            if found:
                return found
    if isinstance(data, list) and data:
        return gid(data[0], *keys)
    return None


def main() -> int:
    if not KEY1:
        print("Set BAND_API_KEY first."); return 1
    print(f"Base URL: {BASE}\n")
    chat_id = None
    me2 = None

    # SPIKE 1: auth ---------------------------------------------------------
    code, data = call(KEY1, "GET", EP["me"])
    if code == 200:
        record("1 auth/identity", "PASS", f"authenticated, agent={gid(data, 'agent_id')}", data)
    else:
        record("1 auth/identity", "FAIL", f"HTTP {code} — fix EP['me'] or the key", data)
        # auth failure gates everything; still try chats in case /me just doesn't exist
    if KEY2:
        c2, d2 = call(KEY2, "GET", EP["me"])
        me2 = gid(d2, "agent_id") if c2 == 200 else None
        record("1b second agent", "PASS" if c2 == 200 else "WARN", f"HTTP {c2}", d2)

    # SPIKE 2: create room --------------------------------------------------
    code, data = call(KEY1, "POST", EP["chats"], {"name": f"spike-{uuid.uuid4().hex[:8]}"})
    chat_id = gid(data, "chat_id")
    if code in (200, 201) and chat_id:
        record("2 create room", "PASS", f"chat_id={chat_id}", None)
    else:
        record("2 create room", "FAIL", f"HTTP {code} — floor scope blocked until this works", data)
        save(); return 1

    # SPIKE 3: send message (self-addressed so we can drain it) -------------
    code, data = call(KEY1, "POST", EP["messages"].format(chat_id=chat_id),
                      {"content": "spike ping", "mentions": []})
    msg_ok = code in (200, 201)
    record("3 send message", "PASS" if msg_ok else "FAIL", f"HTTP {code}", data)

    # SPIKE 4: drain /messages/next + 204-when-empty -------------------------
    code, data = call(KEY1, "GET", EP["next"])
    record("4 drain /next", "INFO", f"HTTP {code} (200=backlog, 204=empty)", data)
    drained_id = gid(data, "message_id") if code == 200 else None

    # SPIKE 5: lifecycle + attempt counter (CRITICAL for the Warden) ---------
    if drained_id:
        c1, d1 = call(KEY1, "POST", EP["processing"].format(msg_id=drained_id))
        a1 = gid(d1, "attempt", "attempt_number")
        record("5a mark processing", "PASS" if c1 in (200, 201) else "FAIL",
               f"HTTP {c1}, attempt={a1}", d1)
        # crash position A simulation: do NOT mark processed; re-drain
        time.sleep(2)
        c2_, d2_ = call(KEY1, "GET", EP["next"])
        re_id = gid(d2_, "message_id") if c2_ == 200 else None
        if re_id == drained_id:
            c3, d3 = call(KEY1, "POST", EP["processing"].format(msg_id=drained_id))
            a2 = gid(d3, "attempt", "attempt_number")
            inc = (a1 is not None and a2 is not None and a2 > a1)
            record("5b stuck-processing re-delivery", "PASS",
                   f"resurfaced; attempt {a1} -> {a2} ({'increments' if inc else 'NO increment — check'})", d3)
        else:
            record("5b stuck-processing re-delivery", "WARN",
                   "did not resurface within 2s — re-run with longer sleep; "
                   "Warden's own clock is the primary stall signal anyway", d2_)
        c4, d4 = call(KEY1, "POST", EP["processed"].format(msg_id=drained_id))
        record("5c mark processed", "PASS" if c4 in (200, 201) else "FAIL", f"HTTP {c4}", d4)
    else:
        record("5 lifecycle", "WARN", "nothing to drain — check mention semantics on spike 3")

    # SPIKE 6: context rehydration -------------------------------------------
    code, data = call(KEY1, "GET", EP["context"].format(chat_id=chat_id))
    record("6 /context rehydrate", "PASS" if code == 200 else "FAIL",
           f"HTTP {code} — read-then-act dedup guard depends on this", data)

    # SPIKE 7: peers + not_in_chat (stretch: recruit beat) --------------------
    code, data = call(KEY1, "GET", EP["peers"], params={"not_in_chat": chat_id})
    record("7 peers?not_in_chat", "PASS" if code == 200 else "WARN",
           f"HTTP {code} (stretch-only; floor doesn't need it)", data)

    # SPIKE 8: add_participant + S-A isolation (needs second key) -------------
    if KEY2 and me2:
        code, data = call(KEY1, "POST", EP["participants"].format(chat_id=chat_id),
                          {"agent_id": me2})
        record("8 add_participant", "PASS" if code in (200, 201) else "WARN", f"HTTP {code}", data)
        # send a message mentioning NOBODY, then see if agent 2 can read it via context
        call(KEY1, "POST", EP["messages"].format(chat_id=chat_id),
             {"content": "SECRET-LANE-A", "mentions": []})
        c2_, d2_ = call(KEY2, "GET", EP["context"].format(chat_id=chat_id))
        leaked = "SECRET-LANE-A" in json.dumps(d2_) if c2_ == 200 else False
        record("8b S-A mention isolation over REST",
               "INFO", ("un-mentioned participant CAN read full context — "
                        "mention-filtering is push-path ergonomics, NOT a security wall"
                        if leaked else
                        "un-mentioned participant did NOT see it — isolation may be real"),
               f"HTTP {c2_}")
    else:
        record("8 add_participant / S-A isolation", "SKIP", "set BAND_API_KEY_2 to run")

    save()
    fails = sum(1 for r in RESULTS if r["status"] == "FAIL")
    print(f"\n{'='*60}\nFloor-scope verdict: "
          + ("GO — start the shell binding now." if fails == 0
             else f"{fails} FAIL(s) — fix EP paths / key and re-run before building."))
    return 0


def save() -> None:
    with open("spike_results.json", "w") as f:
        json.dump(RESULTS, f, indent=2)
    print("\nSaved spike_results.json")


if __name__ == "__main__":
    sys.exit(main())
