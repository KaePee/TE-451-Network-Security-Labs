"""Mark aggregation. One query fetches every scored submission; totals are
summed in Python, which is plenty fast for a class of a few hundred."""

from collections import defaultdict
from decimal import Decimal

from django.db.models import Max

from .models import Lab, Submission, Task

SCORED = (Submission.Status.CORRECT, Submission.Status.PARTIAL, Submission.Status.GRADED)


def task_scores(students=None, labs=None) -> dict[tuple[int, int], Decimal]:
    """{(student_id, task_id): best score}."""
    qs = Submission.objects.filter(status__in=SCORED, task__active=True)
    if students is not None:
        qs = qs.filter(session__student__in=students)
    if labs is not None:
        qs = qs.filter(task__lab__in=labs)
    rows = qs.values("session__student_id", "task_id").annotate(best=Max("score"))
    return {(r["session__student_id"], r["task_id"]): r["best"] for r in rows}


def lab_max_points(labs) -> dict[int, Decimal]:
    out: dict[int, Decimal] = defaultdict(lambda: Decimal("0"))
    for t in Task.objects.filter(lab__in=labs, active=True).only("lab_id", "points"):
        out[t.lab_id] += t.points
    return out


def lab_scores(students, labs) -> dict[tuple[int, int], Decimal]:
    """{(student_id, lab_id): points}."""
    task_lab = dict(Task.objects.filter(lab__in=labs).values_list("id", "lab_id"))
    out: dict[tuple[int, int], Decimal] = defaultdict(lambda: Decimal("0"))
    for (sid, tid), best in task_scores(students, labs).items():
        out[(sid, task_lab[tid])] += best
    return out


def weighted_percent(scores: dict[int, Decimal], labs: list[Lab],
                     maxima: dict[int, Decimal]) -> Decimal:
    """Course total as a percentage: sum(w * score/max) / sum(w)."""
    num = den = Decimal("0")
    for lab in labs:
        if maxima.get(lab.id):
            num += lab.weight * scores.get(lab.id, Decimal("0")) / maxima[lab.id]
            den += lab.weight
    return (num / den * 100).quantize(Decimal("0.01")) if den else Decimal("0.00")
