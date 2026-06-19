"""The proof prints the exactly-once headline and exits 0, and the
BandAgentShell read-then-act dedup guard drops a re-post offline.
"""

import tempfile

from band_once.fake_band import FakeBand
from band_once.proof import main as proof_main
from band_once.shell import BandAgentShell


def test_proof_prints_headline_and_exits_zero(capsys):
    # A small sweep keeps the test fast; the headline shape is identical.
    rc = proof_main(["--schedules", "300"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "exactly-once held across 300 schedules" in out
    assert "0 double-posts, 0 lost messages" in out


def test_shell_dedup_guard_drops_a_second_post_for_the_same_key():
    band = FakeBand()
    shell = BandAgentShell(api_key="x", agent_name="a",
                           dedup_namespace="work", log_dir=tempfile.mkdtemp())
    # Bind context() and post()'s network call to the FakeBand room, so the
    # shell's own already_posted() guard runs offline against real logic.
    shell.context = lambda chat_id=None: list(band.room_log)

    posts = []

    def post(content, mentions=None, dedup_key=None):
        if dedup_key and shell.already_posted(dedup_key):
            return None
        band.post_to_room("a", {"content": content, "dedup_key": dedup_key})
        posts.append(dedup_key)
        return {"posted": True}

    shell.post = post
    key = "work:job-1:round-1"
    assert shell.post("first", dedup_key=key) is not None
    # A crash-retry re-posts the same key: the guard must drop it.
    assert shell.post("retry", dedup_key=key) is None
    assert posts == [key]
    assert sum(1 for e in band.room_log if e.get("dedup_key") == key) == 1


def test_strip_mention_markers():
    from band_once.shell import strip_mention_markers
    raw = "@[[12345678-1234-1234-1234-123456789abc]] hello there"
    assert strip_mention_markers(raw) == "hello there"
