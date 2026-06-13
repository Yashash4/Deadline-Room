"""Render the Deadline Room narration clips with the AI/ML API text-to-speech endpoint.

This is a standalone, offline, run-once asset generator, the audio analogue of
scripts/make_cover.py. It POSTs each load-bearing video line to the AI/ML API TTS
endpoint, downloads the returned mp3, and writes it under samples/voiceover/ as a
committed static asset that the 5-minute video lays into its audio track.

Verified live on our key (June 13, 2026):

    POST https://api.aimlapi.com/v1/tts
    Authorization: Bearer <AIML_API_KEY>
    body: {"model": "openai/tts-1-hd", "text": ..., "voice": ..., "response_format": "mp3"}
    -> 200 {"audio": {"url": "https://cdn.aimlapi.com/generations/...mp3"}, "meta": {...}}

The script reads body["audio"]["url"], then GETs the mp3 to disk. Same base URL,
same Authorization: Bearer auth, and same AIML_API_KEY env var that floor/drafter.py
already uses for the LLM roles, so no new credential or transport.

NOTHING in the deterministic Warden, the live floor, the dev path, or the test suite
imports or calls this. The audio is a build artifact, like samples/cover.png. The
clips are generated once during video prep; the recording has zero runtime network
dependency on TTS.

Usage:

    py scripts/make_voiceover.py            # render any clips that are missing
    py scripts/make_voiceover.py --force    # re-render every clip

Requires AIML_API_KEY in the environment or in code/.env. Fails loudly if the key
is missing or if TTS is not enabled on the key (no swallowed errors).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import requests

AIMLAPI_BASE = "https://api.aimlapi.com/v1"
TTS_ENDPOINT = AIMLAPI_BASE + "/tts"
MODEL = "openai/tts-1-hd"  # verified higher-fidelity OpenAI TTS on our key
TIMEOUT = 120

# A serious enterprise register for the war-room narration (onyx) with a clear
# measured voice (sage) for the spoken guarantees. Both are on the verified
# AI/ML TTS voice list (alloy, ash, ballad, coral, echo, fable, nova, onyx,
# sage, shimmer, verse).
#
# (clip_id, voice, text). The text is the exact locked video copy pulled from
# research/specs/design-spec-v2.md section 1 and slides/DECK.md, pre-scanned for
# em/en dashes and smart quotes so the spoken narration says exactly what the
# slides and README say. Do not edit a line here without editing it in the spec.
LINES: list[tuple[str, str, str]] = [
    (
        "cold-open-dinner",
        "onyx",
        "The second a bank gets hacked, four government clocks start counting "
        "down. Deadline Room runs four parallel filing teams to hit every clock, "
        "physically blocks submission if any two reports disagree, and keeps "
        "running even when you kill an agent mid-race. The books always come out "
        "exactly right.",
    ),
    (
        "separator",
        "onyx",
        "Deadline Room is the only system where four government clocks race at "
        "once, a no-AI referee blocks submission the instant any two reports "
        "disagree, the AI teams correct each other when the facts change, and "
        "even when you kill an agent live the books still come out exactly right.",
    ),
    (
        "verdict-contradiction",
        "onyx",
        "Submission blocked. Two filings disagree on a load-bearing fact. The "
        "referee refuses signoff until they reconcile.",
    ),
    (
        "guarantee-exactly-once",
        "sage",
        "Exactly-once verified. Even when an agent is killed mid-filing, the "
        "report lands exactly once.",
    ),
    (
        "guarantee-replay",
        "sage",
        "Replay byte-identical. The whole run reproduces from its log, hash for "
        "hash.",
    ),
    (
        "packet-outro",
        "sage",
        "Four of four clocks met. Zero contradictions. Exactly-once verified. "
        "One amendment reconciled.",
    ),
]

# Punctuation that must never reach spoken narration. The source lines are
# already clean; this is a fail-loud guard, not a silent normalizer, so a dash
# sneaking into the copy stops the run instead of being read aloud.
_FORBIDDEN = {
    "—": "em dash",
    "–": "en dash",
    "‒": "figure dash",
    "―": "horizontal bar",
    "‘": "left single quote",
    "’": "right single quote",
    "“": "left double quote",
    "”": "right double quote",
    "…": "ellipsis",
}


class VoiceoverError(RuntimeError):
    pass


def out_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "samples" / "voiceover"


def require_key() -> str:
    """Return the AIML_API_KEY, loading code/.env if present, raising if absent."""
    key = os.environ.get("AIML_API_KEY", "")
    if not key:
        # Best-effort load from code/.env so the tool works the same way the
        # spikes do, without making python-dotenv a dependency.
        env_path = Path(__file__).resolve().parent.parent / ".env"
        if env_path.exists():
            with env_path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    name, _, value = line.partition("=")
                    name = name.strip()
                    value = value.strip().strip('"').strip("'")
                    if name == "AIML_API_KEY" and value:
                        key = value
                        break
    if not key:
        raise VoiceoverError(
            "AIML_API_KEY is not set. Export it or put it in code/.env. "
            "This is the same key floor/drafter.py uses for the LLM roles."
        )
    return key


def check_lines() -> None:
    """Fail loudly if any narration line carries a forbidden glyph or is too long."""
    for clip_id, _voice, text in LINES:
        for glyph, name in _FORBIDDEN.items():
            if glyph in text:
                raise VoiceoverError(
                    f"clip {clip_id!r} contains a {name} ({glyph!r}); "
                    f"spoken narration must be plain ASCII punctuation"
                )
        if not (1 <= len(text) <= 4096):
            raise VoiceoverError(
                f"clip {clip_id!r} text length {len(text)} is outside the "
                f"AI/ML TTS 1..4096 character range"
            )


def synth(text: str, voice: str, key: str, *, model: str = MODEL) -> bytes:
    """POST one line to the AI/ML TTS endpoint, follow audio.url, return mp3 bytes.

    Raises VoiceoverError on a transport error, a non-200 (including the case where
    TTS is not enabled on the key), a malformed body, or an audio download failure.
    Errors surface structurally and are never swallowed."""
    payload = {
        "model": model,
        "text": text,
        "voice": voice,
        "response_format": "mp3",
    }
    try:
        r = requests.post(
            TTS_ENDPOINT,
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json"},
            json=payload, timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        raise VoiceoverError(f"TTS transport error: {e}") from e
    if r.status_code != 200:
        raise VoiceoverError(
            f"TTS HTTP {r.status_code}: {r.text[:300]}. If this is 401/403/404, "
            f"the TTS endpoint is likely not enabled on this AIML_API_KEY; the "
            f"LLM models can be live while the TTS product surface is not."
        )
    try:
        url = r.json()["audio"]["url"]
    except (ValueError, KeyError, TypeError) as e:
        raise VoiceoverError(f"TTS malformed response: {r.text[:300]}") from e
    try:
        a = requests.get(url, timeout=TIMEOUT)
    except requests.RequestException as e:
        raise VoiceoverError(f"audio download transport error: {e}") from e
    if a.status_code != 200:
        raise VoiceoverError(f"audio download HTTP {a.status_code} for {url}")
    data = a.content
    if not _is_mp3(data):
        raise VoiceoverError(
            f"downloaded audio for {url} is not a valid mp3 (head {data[:4]!r})"
        )
    return data


def _is_mp3(data: bytes) -> bool:
    """An mp3 begins with an ID3 tag or an MPEG audio frame sync (0xFFEx/Fx)."""
    if len(data) < 4:
        return False
    if data[:3] == b"ID3":
        return True
    return data[0] == 0xFF and (data[1] & 0xE0) == 0xE0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="re-render every clip even if it already exists")
    args = parser.parse_args(argv)

    check_lines()
    key = require_key()

    dest = out_dir()
    dest.mkdir(parents=True, exist_ok=True)

    manifest: list[dict] = []
    generated = 0
    skipped = 0
    for clip_id, voice, text in LINES:
        path = dest / f"{clip_id}.mp3"
        if path.exists() and not args.force:
            data = path.read_bytes()
            print(f"skip   {path.name}  ({len(data)} bytes, already present)")
            skipped += 1
        else:
            data = synth(text, voice, key)
            path.write_bytes(data)
            print(f"wrote  {path.name}  ({len(data)} bytes, voice {voice})")
            generated += 1
        manifest.append({
            "clip_id": clip_id,
            "file": path.name,
            "voice": voice,
            "model": MODEL,
            "text": text,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })

    manifest_path = dest / "manifest.json"
    manifest_path.write_text(
        json.dumps({"endpoint": TTS_ENDPOINT, "model": MODEL, "clips": manifest},
                   indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"manifest {manifest_path.name}  ({len(manifest)} clips)")
    print(f"done: {generated} generated, {skipped} skipped, {len(LINES)} total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
