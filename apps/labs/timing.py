"""
When can a student work on a lab? All the time rules live here so the views,
the staff dashboard and the tests agree.

Rules
-----
* Effective close = the student's deadline override, else lab.closes_at,
  then pushed back by the student's extra minutes.
* DEADLINE mode: work until the effective close.
* TIMED mode: a session ends at start + duration + extra minutes, but never
  later than the effective close (starting five minutes before close gives
  you five minutes).
* Extra time granted mid-session applies immediately: deadlines are
  computed on every request, never stored.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from django.db.models import Q, Sum
from django.utils import timezone

from .models import Accommodation, Lab, LabSession


class Status(str, Enum):
    UNPUBLISHED = "unpublished"
    NOT_OPEN = "not_open"
    OPEN = "open"                # may start
    IN_PROGRESS = "in_progress"
    FINISHED = "finished"        # student pressed Finish
    TIME_UP = "time_up"          # session ran out
    MISSED = "missed"            # closed without ever starting


@dataclass(frozen=True)
class Window:
    opens_at: datetime | None
    closes_at: datetime | None
    extra_minutes: int


def window_for(lab: Lab, student) -> Window:
    accs = Accommodation.objects.filter(student=student).filter(Q(lab=lab) | Q(lab__isnull=True))
    extra = accs.aggregate(total=Sum("extra_minutes"))["total"] or 0
    overrides = [a.closes_at_override for a in accs if a.closes_at_override]
    closes = max(overrides) if overrides else lab.closes_at
    if closes is not None:
        closes = closes + timedelta(minutes=extra)
    return Window(opens_at=lab.opens_at, closes_at=closes, extra_minutes=extra)


def session_deadline(session: LabSession, window: Window | None = None) -> datetime | None:
    window = window or window_for(session.lab, session.student)
    lab = session.lab
    if lab.mode == Lab.Mode.TIMED:
        end = session.started_at + timedelta(minutes=lab.duration_minutes + window.extra_minutes)
        if window.closes_at is not None:
            end = min(end, window.closes_at)
        return end
    return window.closes_at


@dataclass(frozen=True)
class LabState:
    status: Status
    window: Window
    session: LabSession | None
    deadline: datetime | None

    @property
    def can_start(self) -> bool:
        return self.status == Status.OPEN

    @property
    def can_submit(self) -> bool:
        return self.status == Status.IN_PROGRESS

    @property
    def seconds_left(self) -> int | None:
        if self.deadline is None or self.status != Status.IN_PROGRESS:
            return None
        return max(0, int((self.deadline - timezone.now()).total_seconds()))


def lab_state(lab: Lab, student, session: LabSession | None = None,
              now: datetime | None = None) -> LabState:
    now = now or timezone.now()
    if session is None:
        session = LabSession.objects.filter(lab=lab, student=student).first()
    window = window_for(lab, student)

    if session is not None:
        deadline = session_deadline(session, window)
        if session.finished_at is not None:
            status = Status.FINISHED
        elif deadline is not None and now >= deadline:
            status = Status.TIME_UP
        else:
            status = Status.IN_PROGRESS
        return LabState(status, window, session, deadline)

    if not lab.published and not getattr(student, "is_course_staff", False):
        status = Status.UNPUBLISHED
    elif window.opens_at is not None and now < window.opens_at:
        status = Status.NOT_OPEN
    elif window.closes_at is not None and now >= window.closes_at:
        status = Status.MISSED
    else:
        status = Status.OPEN
    return LabState(status, window, None, window.closes_at)
