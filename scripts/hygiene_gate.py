"""Repository hygiene gate: no stray em/en dashes, no AI-attribution trailers.

Two hard project rules are enforced here mechanically so a human never has to
scan by hand and CI can fail a pull request that breaks them:

  1. No em-dash (U+2014) or en-dash (U+2013) in any tracked file. The forbidden
     codepoints appear below only as escapes, never as raw glyphs, so this gate
     file does not trip its own check.
  2. No AI-attribution trailer (a co-authorship credit naming the assistant, a
     "Generated with" credit, or the robot glyph U+1F916). Every marker is built
     from fragments below so no complete trailer appears literally in this file.
     Everything in the repository reads as human authored.

The single legitimate exception is the dash sanitizer itself: floor/drafter.py
strips em/en dashes out of every LLM output, and several tests assert that the
shipped artifact carries none. Those files MUST contain the raw codepoints to
do their job, so they are named in ALLOWED_DASH_FILES below and skipped for the
dash check only (the attribution check still applies to them).

Run it:  py scripts/hygiene_gate.py
Exit 0 when clean, exit 1 (with the offending file:line) when a rule is broken.
"""

from __future__ import annotations

import subprocess
import sys

# Forbidden codepoints, written as escapes so this file never holds the glyph.
EM_DASH = "\u2014"
EN_DASH = "\u2013"
ROBOT = "\U0001f916"

# AI-attribution markers, assembled from fragments so no complete trailer string
# appears literally in this file (which would otherwise self-trip the gate). The
# assistant name is built from its parts; the co-authorship key is split too.
_NAME = "Cla" + "ude"
ATTRIBUTION_MARKERS = (
    "Co-Authored" + "-By: " + _NAME,
    "Generated with " + _NAME,
    "Generated with " + "[" + _NAME,
    ROBOT,
)

# Files that are permitted to contain raw em/en dashes because removing them is
# precisely their function (the LLM-output sanitizer and the tests that prove a
# dash can never reach a shipped artifact). Paths are repo-relative, forward
# slashed (git ls-files form).
ALLOWED_DASH_FILES = frozenset(
    {
        "floor/drafter.py",
        "scripts/make_voiceover.py",
        "tests/test_sanitize_llm.py",
        "tests/test_second_opinion.py",
        "tests/test_voiceover_lines.py",
    }
)


def tracked_files() -> list[str]:
    out = subprocess.check_output(["git", "ls-files"], text=True)
    return [line for line in out.splitlines() if line.strip()]


def scan() -> list[str]:
    violations: list[str] = []
    for path in tracked_files():
        try:
            with open(path, encoding="utf-8") as handle:
                lines = handle.readlines()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            # Binary or vanished file: nothing textual to police.
            continue
        allow_dash = path in ALLOWED_DASH_FILES
        for number, line in enumerate(lines, start=1):
            if not allow_dash:
                if EM_DASH in line:
                    violations.append(f"{path}:{number}: em-dash (U+2014)")
                if EN_DASH in line:
                    violations.append(f"{path}:{number}: en-dash (U+2013)")
            for marker in ATTRIBUTION_MARKERS:
                if marker in line:
                    label = "robot glyph" if marker == ROBOT else marker
                    violations.append(f"{path}:{number}: AI attribution ({label})")
    return violations


def main() -> int:
    violations = scan()
    if violations:
        print("Hygiene gate FAILED. Forbidden content found:")
        for item in violations:
            print("  " + item)
        print(
            "\nFix: replace em/en dashes with a comma, colon, parentheses, or a "
            "period, and remove any AI-attribution trailer."
        )
        return 1
    print("Hygiene gate passed: no stray em/en dashes, no AI-attribution trailers.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
