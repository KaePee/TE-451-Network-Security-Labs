"""
How to write a lab
==================

A lab is a LabDef holding an ordered list of tasks. Each task:

* generate(rng) -> dict   picks this student's parameters. Use only `rng`,
                          never `random` or `secrets` directly, so the same
                          student always sees the same numbers.
* prompt(p) -> str        HTML shown to the student. Interpolate with
                          format_html() so parameters are escaped;
                          use mark_safe() for static text.
* check(p, answer) -> bool | float
                          auto-graded tasks only. Return a float in [0, 1]
                          for partial credit (e.g. 3 of 5 classified right).
* files(p) -> {name: bytes}  optional downloads (captures, ciphertexts...),
                          generated on demand, never stored. If building them
                          is slow, also override file_names(p) so the lab page
                          can list them without building them.

Parameters are cached per process (params_for), so a slow generate() (big
primes, ~0.3 s) is paid once per student per worker, not on every page view.
Treat the returned dict as read-only.

Optional knobs:
* seed_key      tasks with the same seed_key get the same rng, so several
                tasks can ask about one shared artefact (e.g. one pcap).
* max_attempts  per-task cap, combined with the lab's setting (the lower wins).
                Set it on anything guessable (multiple choice, classification).

Manual (TA-graded) tasks set `kind = "manual"` and a `rubric`, which TAs see
in the grading queue.

Register the lab in content/__init__.py, then run `manage.py sync_labs`.
"""

import functools
import hashlib
import random
from dataclasses import dataclass, field

from django.utils.html import format_html
from django.utils.safestring import mark_safe


def task_rng(seed: int, task_key: str) -> random.Random:
    digest = hashlib.sha256(f"{seed}:{task_key}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def parse_int(answer: str) -> int | None:
    """Accept '1234', '1 234', '1,234' or '0x4d2'. Anything else -> None."""
    text = answer.strip().replace(",", "").replace(" ", "").replace("_", "")
    try:
        if text.lower().startswith(("0x", "-0x")):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def normalise(answer: str) -> str:
    return " ".join(answer.strip().lower().split())


def letters(answer: str, alphabet: str) -> str:
    """'c, I / a' -> 'CIA' for classification answers."""
    return "".join(c for c in answer.upper() if c in alphabet)


def fraction_matching(given: str, expected: str) -> float:
    """Partial credit for a sequence of single-letter answers. A wrong-length
    answer scores 0 so students can't pad their way to marks."""
    if len(given) != len(expected):
        return 0.0
    return sum(g == e for g, e in zip(given, expected)) / len(expected)


class TaskDef:
    key: str = ""
    title: str = ""
    points: int = 10
    kind: str = "auto"
    # "text" renders a single line input, "textarea" a multi-line box.
    input: str = "text"
    placeholder: str = ""
    rubric: str = ""
    seed_key: str | None = None
    max_attempts: int | None = None

    def generate(self, rng: random.Random) -> dict:
        return {}

    def files(self, p: dict) -> dict[str, bytes]:
        return {}

    def file_names(self, p: dict) -> list[str]:
        return sorted(self.files(p))

    def prompt(self, p: dict) -> str:
        raise NotImplementedError

    def check(self, p: dict, answer: str) -> bool | float:
        raise NotImplementedError

    def params_for(self, seed: int) -> dict:
        return _cached_params(self, seed)


# ~150 students x ~60 tasks fits comfortably; entries are small dicts.
@functools.lru_cache(maxsize=16384)
def _cached_params(taskdef: TaskDef, seed: int) -> dict:
    return taskdef.generate(task_rng(seed, taskdef.seed_key or taskdef.key))


class ManualTask(TaskDef):
    kind = "manual"
    input = "textarea"
    points = 10

    def check(self, p, answer):  # pragma: no cover - never called
        raise RuntimeError("manual tasks are graded by a TA")


@dataclass
class LabDef:
    slug: str
    lecture: int
    title: str
    summary: str
    intro: str
    tasks: list[TaskDef] = field(default_factory=list)
    default_mode: str = "deadline"
    default_duration: int = 120

    def task(self, key: str) -> TaskDef | None:
        return next((t for t in self.tasks if t.key == key), None)


__all__ = ["LabDef", "ManualTask", "TaskDef", "format_html", "fraction_matching",
           "letters", "mark_safe", "normalise", "parse_int"]
