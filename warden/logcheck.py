"""Malformed run-log validator: a VERIFIER-ONLY structural check.

The premise of this product is "the agent crashed mid-run", so the realistic
artifact a verifier is handed is a HALF-WRITTEN log: a truncated last line, a
line missing a field, a corrupted line, a non-contiguous seq. RunLog.load and
replay() are deliberately lean (they assume a well-formed log so the sealed-log
replay stays byte-identical), which means a malformed log fed to them raises a
raw json/KeyError stack trace rather than a clean diagnosis.

This module closes that gap WITHOUT touching the hot path. It re-parses a JSONL
run log defensively and reports the FIRST structural problem as a typed result
(line number + reason) instead of crashing. It does NOT re-execute the state
machine and it does NOT replace RunLog.load: a verifier or receipt script calls
validate_jsonl first to fail cleanly on garbage, then hands a clean log to the
real loader. Because nothing here is on the replay path, the byte-identical
guarantee and the 282 core tests are untouched.

A VALID log per this checker still replays byte-identical through replay(); a
test pins that.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .state_machine import Event

# The structural contract every run-log entry must satisfy.
_REQUIRED_ENTRY_FIELDS = ("seq", "type", "payload")
# Fields a protocol_event payload must carry for replay to re-execute it.
_REQUIRED_PROTOCOL_FIELDS = ("correlation_id", "event", "ts")
_VALID_EVENTS = frozenset(e.value for e in Event)


@dataclass(frozen=True)
class ValidationResult:
    """A structured verdict. ok=True means the log is structurally sound; on a
    problem ok=False, line is the 1-based line number (0 for whole-file issues),
    and reason names the defect in one human-readable clause."""
    ok: bool
    line: int = 0
    reason: str = ""

    def __bool__(self) -> bool:  # so `if validate_jsonl(...):` reads naturally
        return self.ok


def validate_jsonl(text: str) -> ValidationResult:
    """Validate a run log given as JSONL text. Returns a ValidationResult; never
    raises on malformed input. Blank lines are skipped (RunLog.load skips them
    too). The checks, in order: each non-blank line parses as a JSON object;
    carries seq/type/payload of the right types; seqs run contiguously from 0;
    a protocol_event payload carries correlation_id/event/ts and a known event
    string."""
    expected_seq = 0
    saw_any = False
    for idx, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError as exc:
            return ValidationResult(False, idx, f"line is not valid JSON: {exc.msg}")
        if not isinstance(entry, dict):
            return ValidationResult(
                False, idx, f"entry is a {type(entry).__name__}, expected an object")

        for fld in _REQUIRED_ENTRY_FIELDS:
            if fld not in entry:
                return ValidationResult(False, idx, f"missing required field '{fld}'")
        if not isinstance(entry["seq"], int) or isinstance(entry["seq"], bool):
            return ValidationResult(False, idx, "field 'seq' is not an integer")
        if not isinstance(entry["type"], str):
            return ValidationResult(False, idx, "field 'type' is not a string")
        if not isinstance(entry["payload"], dict):
            return ValidationResult(False, idx, "field 'payload' is not an object")

        if entry["seq"] != expected_seq:
            return ValidationResult(
                False, idx,
                f"seq {entry['seq']} out of order (expected {expected_seq}); "
                f"an entry was reordered, dropped, or duplicated")
        expected_seq += 1
        saw_any = True

        if entry["type"] == "protocol_event":
            payload = entry["payload"]
            for fld in _REQUIRED_PROTOCOL_FIELDS:
                if fld not in payload:
                    return ValidationResult(
                        False, idx,
                        f"protocol_event payload missing required field '{fld}'")
            if payload["event"] not in _VALID_EVENTS:
                return ValidationResult(
                    False, idx,
                    f"protocol_event has unknown event '{payload['event']}'")

    if not saw_any:
        return ValidationResult(False, 0, "log is empty: no entries to validate")
    return ValidationResult(True)


def validate_file(path: str | Path) -> ValidationResult:
    """Validate a run log on disk. A missing or unreadable file is reported as a
    structured result, never an uncaught exception."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ValidationResult(False, 0, f"run log not found at {p}")
    except (OSError, UnicodeDecodeError) as exc:
        return ValidationResult(False, 0, f"run log is unreadable: {exc}")
    return validate_jsonl(text)
