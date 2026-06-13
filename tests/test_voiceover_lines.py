"""Offline guard for the narration script (scripts/make_voiceover.py).

This is the one thing about the voiceover tool worth a pytest case: that no
em/en dash, smart quote, or over-length string can reach spoken narration. The
network call (synth) is monkeypatched out, so the test is fully offline and keeps
the suite's offline determinism intact. It never hits the AI/ML API.

scripts/ is not a package, so the module is loaded by file path with importlib.
"""

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "make_voiceover.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("make_voiceover", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mv = _load_module()


def test_no_forbidden_glyphs_and_in_range():
    """check_lines passes for the committed copy: no dashes, no smart quotes,
    every line within the AI/ML TTS 1..4096 character window."""
    mv.check_lines()  # raises VoiceoverError on any violation


@pytest.mark.parametrize("glyph", ["—", "–", "‘", "“", "…"])
def test_check_lines_rejects_forbidden_glyph(monkeypatch, glyph):
    """A dash or smart quote sneaking into a line fails the run loudly."""
    poisoned = [("bad", "onyx", f"a line with a {glyph} in it")]
    monkeypatch.setattr(mv, "LINES", poisoned)
    with pytest.raises(mv.VoiceoverError):
        mv.check_lines()


def test_check_lines_rejects_overlong_line(monkeypatch):
    """A line past 4096 characters fails before any network call."""
    monkeypatch.setattr(mv, "LINES", [("long", "onyx", "x" * 4097)])
    with pytest.raises(mv.VoiceoverError):
        mv.check_lines()


def test_main_is_offline_with_monkeypatched_synth(monkeypatch, tmp_path):
    """main() writes one mp3 per line and a manifest without touching the network.

    synth, require_key, and the output directory are all stubbed, so this exercises
    the write/manifest path with zero AI/ML API calls. A minimal valid mp3 frame
    header keeps the _is_mp3 guard (used by the real synth) honest by example."""
    fake_mp3 = b"\xff\xfb\x90\x00" + b"\x00" * 64
    monkeypatch.setattr(mv, "require_key", lambda: "test-key")
    monkeypatch.setattr(mv, "synth", lambda text, voice, key, model=mv.MODEL: fake_mp3)
    monkeypatch.setattr(mv, "out_dir", lambda: tmp_path)

    assert mv.main([]) == 0

    written = sorted(p.name for p in tmp_path.glob("*.mp3"))
    assert written == sorted(f"{clip_id}.mp3" for clip_id, _v, _t in mv.LINES)
    manifest = (tmp_path / "manifest.json").read_text(encoding="utf-8")
    assert mv.MODEL in manifest
    assert "sha256" in manifest


def test_is_mp3_recognizes_frame_sync_and_id3():
    assert mv._is_mp3(b"\xff\xfb\x00\x00")  # MPEG frame sync
    assert mv._is_mp3(b"ID3\x04abcd")        # ID3 tag
    assert not mv._is_mp3(b"<htm")           # an HTML error page is not mp3
    assert not mv._is_mp3(b"")
