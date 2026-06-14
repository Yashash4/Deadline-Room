"""The verifier-only malformed-log validator (warden/logcheck.py): a truncated,
missing-field, or corrupted run log is flagged with a line + reason, never a raw
stack trace. And the load-bearing guarantee: a VALID log still replays
byte-identical through the untouched replay path.
"""

import pytest

from warden.logcheck import ValidationResult, validate_file, validate_jsonl
from warden.replay import RunLog, replay
from warden.simulate import KillSchedule, run_incident


def _good_jsonl() -> str:
    return run_incident(
        kill_schedule=KillSchedule({("nis2", 1): "B"}),
        contradiction_in="sec",
    ).log.to_jsonl()


# --- valid logs pass, and still replay byte-identical -------------------

def test_a_real_run_log_validates_clean():
    res = validate_jsonl(_good_jsonl())
    assert res.ok is True
    assert bool(res) is True


def test_valid_log_still_replays_byte_identical_after_validation(tmp_path):
    r = run_incident(contradiction_in="nis2")
    jsonl = r.log.to_jsonl()
    assert validate_jsonl(jsonl).ok is True
    # the validator is read-only and off the hot path: the real loader + replay
    # reproduce the exact bytes, unchanged. Prove it across the on-disk roundtrip
    # the validator does not participate in.
    p = tmp_path / "run.jsonl"
    original_sha = r.log.save(p)
    loaded = RunLog.load(p)
    assert replay(loaded).to_jsonl() == jsonl
    assert replay(loaded).sha256() == original_sha


def test_blank_lines_are_tolerated_like_runlog_load():
    jsonl = _good_jsonl()
    padded = "\n" + jsonl.replace("\n", "\n\n")  # extra blank lines everywhere
    assert validate_jsonl(padded).ok is True


# --- malformed logs are flagged cleanly, not crashed --------------------

@pytest.mark.parametrize("bad,needle", [
    ('{"seq":0,"type":"protocol_event","payload":{"event":"draft_posted"',
     "not valid JSON"),                                              # truncated
    ('{"seq":0,"type":"protocol_event"}',
     "missing required field 'payload'"),                            # missing field
    ('{"seq":0,"type":"protocol_event","payload":{"correlation_id":"x","ts":"t"}}',
     "missing required field 'event'"),                              # missing inner field
    ('{"seq":0,"type":"protocol_event",'
     '"payload":{"correlation_id":"x","event":"NOPE","ts":"t"}}',
     "unknown event"),                                               # unknown event
    ('not json at all',
     "not valid JSON"),                                              # corrupted line
    ('[1,2,3]',
     "expected an object"),                                          # JSON, wrong shape
    ('',
     "log is empty"),                                                # nothing to validate
])
def test_validate_reports_a_reason_instead_of_raising(bad, needle):
    res = validate_jsonl(bad)
    assert isinstance(res, ValidationResult)
    assert res.ok is False
    assert isinstance(res.reason, str) and needle in res.reason


def test_truncated_tail_of_a_real_log_is_flagged():
    # Realistic crash artifact: the process died mid-write, so the LAST line is a
    # half-written JSON object. The validator names the truncated line.
    jsonl = _good_jsonl()
    lines = jsonl.splitlines()
    lines[-1] = lines[-1][: len(lines[-1]) // 2]  # chop the last line in half
    res = validate_jsonl("\n".join(lines))
    assert res.ok is False
    assert res.line == len(lines)
    assert "not valid JSON" in res.reason


def test_noncontiguous_seq_is_flagged_as_reorder_or_drop():
    # Drop a middle line so the seq column jumps: the validator catches the gap.
    lines = _good_jsonl().splitlines()
    del lines[2]
    res = validate_jsonl("\n".join(lines))
    assert res.ok is False
    assert "out of order" in res.reason


def test_missing_file_is_a_structured_result_not_an_exception(tmp_path):
    res = validate_file(tmp_path / "does-not-exist.jsonl")
    assert res.ok is False
    assert "not found" in res.reason


def test_validate_file_accepts_a_saved_run_log(tmp_path):
    r = run_incident()
    p = tmp_path / "run.jsonl"
    r.log.save(p)
    assert validate_file(p).ok is True
