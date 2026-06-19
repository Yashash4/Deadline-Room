"""A minimal Band agent built on the band-once lifecycle shell.

It joins a room and echoes every message it is mentioned in straight back,
carrying a dedup_key so a re-delivery after a crash never double-posts the echo.
This is the smallest complete demonstration of the shell: the author writes ONLY
the handle() function; every Band plumbing concern (drain, processing, post,
processed, the read-then-act dedup guard, bounded retry) lives in the shell.

Run against a real room:

    export BAND_API_KEY=band_a_...      # an AGENT key from the Band web UI
    python examples/echo_agent.py <chat_id> <warden_or_peer_uuid>

The second argument is a peer UUID to @mention (Band requires every message to
mention a participant; you cannot mention yourself).
"""

from __future__ import annotations

import os
import sys

from band_once.shell import BandAgentShell, strip_mention_markers


def make_handle(reply_to: str):
    """Build a handle() that echoes the inbound message back to `reply_to`,
    keyed for exactly-once on the inbound message id so a crash-retry of this
    same message never posts the echo twice."""

    def handle(message: dict, context: list[dict]) -> dict | None:
        body = strip_mention_markers(message.get("content", ""))
        if not body:
            return None
        return {
            "content": f"echo: {body}",
            "mentions": [reply_to],
            "dedup_key": f"echo:{message.get('id')}",
        }

    return handle


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python examples/echo_agent.py <chat_id> <peer_uuid_to_mention>")
        return 2
    chat_id, reply_to = argv
    key = os.environ.get("BAND_API_KEY")
    if not key:
        print("set BAND_API_KEY to an agent key (band_a_...) from the Band web UI")
        return 2

    shell = BandAgentShell(api_key=key, agent_name="echo_agent",
                           dedup_namespace="echo", max_attempts=3)
    shell.whoami()
    shell.join(chat_id)
    handled = shell.run(make_handle(reply_to), idle_breaks=5, max_loops=200)
    print(f"echo_agent handled {handled} message(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
