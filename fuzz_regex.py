#!/usr/bin/env python3
"""Atheris fuzz harness for the `regex` package (mrabarnett/mrab-regex).

Design goals, learned from an earlier broken iteration:
  1. A catastrophic-backtracking input must NOT kill the whole fuzzing
     process. Earlier versions relied on libFuzzer's global `-timeout`,
     which aborts the entire run on the first slow input -- useless for a
     multi-hour campaign, since regex backtracking explosions are common
     and expected, not each one a "finding" worth stopping for.
     This version installs its own short SIGALRM-based watchdog around
     every single input. A slow input is caught, logged to redos_log.jsonl
     for later triage, and the campaign continues immediately.
  2. Real bugs (memory corruption, type-safety violations, engine
     disagreements, corrupted global state) still raise AssertionError,
     which IS a libFuzzer crash -- that's what we want stopped and saved.
  3. One shell script does setup end-to-end. No more manual multi-step
     back-and-forth.

Modes (env var REGEX_MODE, default "match"):
    match        - compile a pattern, run it against a subject
    roundtrip    - differential: `regex` module vs stdlib `re`
    fuzzy        - exercise regex's fuzzy-matching extension ({e<=N} etc.)
    scan         - finditer invariants (ordering, non-overlap, termination)
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import time

import atheris

with atheris.instrument_imports():
    import regex


MODE = os.environ.get("REGEX_MODE", "match").lower()
VALID_MODES = {"match", "roundtrip", "fuzzy", "scan"}
if MODE not in VALID_MODES:
    raise SystemExit(f"REGEX_MODE must be one of: {', '.join(sorted(VALID_MODES))}")

MAX_PATTERN_LEN = 200
MAX_SUBJECT_LEN = 4096

# Per-input wall-clock budget. Must be comfortably shorter than libFuzzer's
# own -timeout (set in run.sh) so our handler always fires first.
PER_INPUT_BUDGET_SECONDS = 2

REDOS_LOG_PATH = os.environ.get("REDOS_LOG", "redos_log.jsonl")

EXPECTED_COMPILE_ERRORS = (re.error, regex.error)
EXPECTED_RUNTIME_ERRORS = (
    IndexError,     # out-of-range explicit group reference
    OverflowError,  # absurd repeat counts rejected by the engine
    MemoryError,    # pattern legitimately too large/expensive
)


# ---------------------------------------------------------------------------
# Per-input watchdog
# ---------------------------------------------------------------------------

class RegexTimeout(Exception):
    """Raised when a single input exceeds PER_INPUT_BUDGET_SECONDS.

    Not treated as a crash: backtracking engines are expected to have
    pathological inputs. It's logged for later ReDoS triage instead of
    aborting the whole fuzzing process.
    """


def _alarm_handler(signum, frame):  # noqa: ARG001
    raise RegexTimeout()


signal.signal(signal.SIGALRM, _alarm_handler)


def _log_redos(pattern: str, subject: str, elapsed_hint: str) -> None:
    try:
        with open(REDOS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "pattern": pattern,
                        "subject_len": len(subject),
                        "subject_preview": subject[:80],
                        "note": elapsed_hint,
                    }
                )
                + "\n"
            )
    except OSError:
        pass  # logging must never crash the fuzzer


# ---------------------------------------------------------------------------
# Canary: must pass every single run regardless of what the fuzzed input did
# ---------------------------------------------------------------------------

CANARY_PATTERN = r"(?P<x>\w+)\s+(?P<y>\d+)"
CANARY_SUBJECT = "hello 123"


def assert_canary() -> None:
    m = regex.match(CANARY_PATTERN, CANARY_SUBJECT)
    if m is None or m.group("x") != "hello" or m.group("y") != "123":
        raise AssertionError(
            "canary pattern failed after a prior input -- "
            "engine state looks corrupted"
        )


# ---------------------------------------------------------------------------
# Structured pattern generation -- bias toward syntactically valid,
# semantically varied regex instead of raw noise, which mostly just hits
# re.error / regex.error before reaching interesting matcher code.
# ---------------------------------------------------------------------------

ATOMS = [
    r"a", r".", r"\d", r"\D", r"\w", r"\W", r"\s", r"\S",
    r"[a-z]", r"[^a-z]", r"[a-z0-9_-]", r"\p{L}", r"\p{N}",
    r"(?:ab)", r"(ab)", r"(?P<g1>ab)", r"(?P<g1>a)(?P=g1)",
    r"\b", r"\B", r"^", r"$", r"\A", r"\Z",
]
QUANTIFIERS = [
    r"", r"*", r"+", r"?", r"*?", r"+?", r"??",
    r"{2}", r"{2,4}", r"{2,}", r"{0,3}", r"{2,4}+",
]
COMBINATORS = [r"", r"|"]
LOOKAROUNDS = [r"(?=ab)", r"(?!ab)", r"(?<=ab)", r"(?<!ab)"]
FUZZY_WRAPPERS = [
    r"(?:{inner}){{e<=1}}",
    r"(?:{inner}){{e<=2,s<=1,i<=1,d<=1}}",
    r"(?:{inner}){{1<=e<=3}}",
    r"fuzzy({inner}){{e<=2}}",
]
FLAGS = [r"", r"(?i)", r"(?m)", r"(?s)", r"(?x)", r"(?a)", r"(?V1)", r"(?V0)"]


def _pick(fdp: "atheris.FuzzedDataProvider", options: list[str]) -> str:
    return options[fdp.ConsumeIntInRange(0, len(options) - 1)]


def build_pattern(fdp: "atheris.FuzzedDataProvider", fuzzy: bool = False) -> str:
    n_parts = fdp.ConsumeIntInRange(1, 5)
    parts: list[str] = []
    for _ in range(n_parts):
        choice = fdp.ConsumeIntInRange(0, 3)
        if choice == 0:
            atom = _pick(fdp, ATOMS)
        elif choice == 1:
            atom = _pick(fdp, LOOKAROUNDS)
        elif choice == 2:
            inner = _pick(fdp, ATOMS)
            atom = f"({inner}{_pick(fdp, QUANTIFIERS)})"
        else:
            atom = _pick(fdp, ATOMS)

        if fuzzy and fdp.ConsumeBool():
            atom = _pick(fdp, FUZZY_WRAPPERS).format(inner=atom)
        else:
            atom += _pick(fdp, QUANTIFIERS)

        parts.append(atom)
        if fdp.ConsumeBool():
            parts.append(_pick(fdp, COMBINATORS))

    pattern = _pick(fdp, FLAGS) + "".join(parts)
    return pattern[:MAX_PATTERN_LEN]


def build_subject(fdp: "atheris.FuzzedDataProvider") -> str:
    n = fdp.ConsumeIntInRange(0, MAX_SUBJECT_LEN)
    return fdp.ConsumeBytes(n).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Oracle helpers
# ---------------------------------------------------------------------------

def match_summary(m) -> tuple:
    if m is None:
        return (None,)
    try:
        return (m.span(), m.groups(), m.groupdict())
    except Exception:  # noqa: BLE001 - summarising a result, not running it
        return ("unsummarisable",)


# ---------------------------------------------------------------------------
# Per-mode bodies
# ---------------------------------------------------------------------------

def run_match(pattern: str, subject: str) -> None:
    compiled = regex.compile(pattern)
    compiled.match(subject)
    compiled.search(subject)
    compiled.fullmatch(subject)
    list(compiled.finditer(subject))
    compiled.findall(subject)


def run_roundtrip(pattern: str, subject: str) -> None:
    """Where `regex` claims re-compatibility, it should agree with `re`."""
    try:
        std = re.compile(pattern)
    except re.error:
        return  # pattern uses regex's superset syntax -- not comparable

    try:
        rx = regex.compile(pattern)
    except regex.error as e:
        raise AssertionError(
            f"stdlib re accepted pattern but regex rejected it: {pattern!r} ({e})"
        ) from e

    for name in ("match", "search"):
        a = match_summary(getattr(std, name)(subject))
        b = match_summary(getattr(rx, name)(subject))
        if a != b:
            raise AssertionError(
                f"re/regex .{name}() disagree: pattern={pattern!r} "
                f"subject={subject!r} re={a!r} regex={b!r}"
            )


def run_fuzzy(pattern: str, subject: str) -> None:
    compiled = regex.compile(pattern)
    m = compiled.search(subject)
    if m is not None:
        counts = getattr(m, "fuzzy_counts", None)
        if counts is not None and any(c < 0 for c in counts):
            raise AssertionError(f"negative fuzzy_counts: {counts} for {pattern!r}")


def run_scan(pattern: str, subject: str) -> None:
    compiled = regex.compile(pattern)
    prev_end = None
    n = 0
    for m in compiled.finditer(subject):
        start, end = m.span()
        if prev_end is not None and start < prev_end:
            raise AssertionError(
                f"finditer produced overlapping/out-of-order matches "
                f"(prev_end={prev_end}, next_start={start}) for pattern={pattern!r}"
            )
        prev_end = end
        n += 1
        if n > 100_000:
            raise AssertionError("finditer did not terminate in a reasonable match count")


DISPATCH = {
    "match": run_match,
    "roundtrip": run_roundtrip,
    "fuzzy": run_fuzzy,
    "scan": run_scan,
}


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    pattern = build_pattern(fdp, fuzzy=(MODE == "fuzzy"))
    subject = build_subject(fdp)

    signal.alarm(PER_INPUT_BUDGET_SECONDS)
    t0 = time.monotonic()
    try:
        DISPATCH[MODE](pattern, subject)
    except RegexTimeout:
        elapsed = time.monotonic() - t0
        _log_redos(pattern, subject, f"~{elapsed:.1f}s (budget={PER_INPUT_BUDGET_SECONDS}s)")
    except EXPECTED_COMPILE_ERRORS:
        pass
    except EXPECTED_RUNTIME_ERRORS:
        pass
    finally:
        signal.alarm(0)  # always cancel -- never leave a stray alarm pending

    # Every run, regardless of outcome above, the engine must still handle a
    # known-good pattern correctly. Catches state corrupted by a prior input.
    assert_canary()


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()