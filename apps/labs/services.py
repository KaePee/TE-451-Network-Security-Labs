"""State-changing operations on labs. Views stay thin; tests target these."""

import logging
import secrets
from decimal import Decimal

from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.audit.models import record

from . import content
from .models import Lab, LabSession, Submission, Task
from .timing import lab_state

logger = logging.getLogger(__name__)


class LabError(Exception):
    """A user-facing refusal (time up, attempts exhausted, ...)."""


def start_session(lab: Lab, student) -> LabSession:
    state = lab_state(lab, student)
    if state.session is not None:
        return state.session
    if not state.can_start:
        raise LabError("This lab cannot be started right now.")
    try:
        with transaction.atomic():
            # 63 bits so it fits a signed BigIntegerField.
            return LabSession.objects.create(lab=lab, student=student,
                                             seed=secrets.randbits(63))
    except IntegrityError:
        # Double-click on Start: the other request won the race.
        return LabSession.objects.get(lab=lab, student=student)


def finish_session(session: LabSession) -> None:
    if session.finished_at is None:
        session.finished_at = timezone.now()
        session.save(update_fields=["finished_at"])


def task_params(session: LabSession, task: Task) -> dict:
    labdef = content.get(session.lab.slug)
    taskdef = labdef.task(task.key) if labdef else None
    return taskdef.params_for(session.seed) if taskdef else {}


def submit_answer(session: LabSession, task: Task, answer: str) -> Submission:
    answer = answer.strip()
    if not answer:
        raise LabError("Empty answer.")
    if len(answer) > 10_000:
        raise LabError("Answer too long (10,000 characters max).")

    with transaction.atomic():
        # Lock the session row so parallel submits can't dodge the attempt limit.
        session = LabSession.objects.select_for_update().get(pk=session.pk)
        if not lab_state(session.lab, session.student, session).can_submit:
            raise LabError("This lab session is closed. Answers can no longer be submitted.")

        labdef = content.get(session.lab.slug)
        taskdef = labdef.task(task.key) if labdef else None
        if taskdef is None or not task.active:
            raise LabError("This task is no longer available.")

        previous = session.submissions.filter(task=task)

        if task.kind == Task.Kind.MANUAL:
            if previous.filter(status=Submission.Status.GRADED).exists():
                raise LabError("This answer has already been graded.")
            previous.filter(status=Submission.Status.PENDING).update(
                status=Submission.Status.SUPERSEDED)
            return Submission.objects.create(session=session, task=task, answer=answer,
                                             status=Submission.Status.PENDING)

        lab = session.lab
        limit = attempt_limit(lab, taskdef)
        if limit is not None and previous.count() >= limit:
            raise LabError("No attempts left for this task.")
        if lab.show_feedback:
            if previous.filter(status=Submission.Status.CORRECT).exists():
                raise LabError("You have already solved this task.")
        else:
            # Blind mode: the latest answer is the one that counts.
            previous.exclude(status=Submission.Status.SUPERSEDED).update(
                status=Submission.Status.SUPERSEDED)

        try:
            fraction = _as_fraction(taskdef.check(taskdef.params_for(session.seed), answer))
        except Exception:  # a grader bug must never 500 a student mid-lab
            logger.exception("grader crashed: %s/%s", lab.slug, task.key)
            fraction = Decimal("0")
        if fraction == 1:
            status = Submission.Status.CORRECT
        elif fraction > 0:
            status = Submission.Status.PARTIAL
        else:
            status = Submission.Status.INCORRECT
        return Submission.objects.create(
            session=session, task=task, answer=answer, status=status,
            score=(task.points * fraction).quantize(Decimal("0.01")),
        )


def _as_fraction(result) -> Decimal:
    if result is True:
        return Decimal("1")
    if not result:
        return Decimal("0")
    return min(Decimal("1"), max(Decimal("0"), Decimal(str(round(float(result), 4)))))


def attempt_limit(lab: Lab, taskdef) -> int | None:
    limits = [n for n in (lab.max_attempts, getattr(taskdef, "max_attempts", None)) if n]
    return min(limits) if limits else None


def grade_submission(submission: Submission, score: Decimal, feedback: str, grader) -> None:
    task = submission.task
    if not (Decimal("0") <= score <= task.points):
        raise LabError(f"Score must be between 0 and {task.points}.")
    submission.status = Submission.Status.GRADED
    submission.score = score
    submission.feedback = feedback
    submission.graded_by = grader
    submission.graded_at = timezone.now()
    submission.save()
    record(grader, "grade", submission.session.student,
           f"{task}: {score}/{task.points}")


def reset_session(session: LabSession, actor, reason: str) -> None:
    """Delete a student's attempt so they can start fresh (new numbers too)."""
    record(actor, "reset_lab", session.student, f"{session.lab.slug}: {reason}")
    session.delete()
