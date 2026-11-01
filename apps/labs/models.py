from decimal import Decimal

from django.conf import settings
from django.db import models
from django.utils import timezone


class Lab(models.Model):
    """One weekly lab. Content (tasks, prompts, graders) lives in code under
    apps/labs/content/ and is synced in by `manage.py sync_labs`; the fields
    here are the knobs staff control from the dashboard."""

    class Mode(models.TextChoices):
        TIMED = "timed", "Timed session"
        DEADLINE = "deadline", "Open until deadline"

    slug = models.SlugField(unique=True)
    lecture = models.PositiveSmallIntegerField()
    title = models.CharField(max_length=200)
    summary = models.TextField(blank=True)
    order = models.PositiveSmallIntegerField(default=0)

    mode = models.CharField(max_length=16, choices=Mode.choices, default=Mode.DEADLINE)
    opens_at = models.DateTimeField(null=True, blank=True,
                                    help_text="Blank = open as soon as published.")
    closes_at = models.DateTimeField(null=True, blank=True,
                                     help_text="Blank = never closes.")
    duration_minutes = models.PositiveIntegerField(
        default=120, help_text="Timed mode only: length of a session from Start.")
    published = models.BooleanField(default=False)
    max_attempts = models.PositiveIntegerField(
        null=True, blank=True, help_text="Per auto-graded task. Blank = unlimited.")
    weight = models.DecimalField(max_digits=6, decimal_places=2, default=Decimal("1"),
                                 help_text="Relative weight in the course total.")
    show_feedback = models.BooleanField(
        default=True, help_text="Tell students immediately whether an answer is correct.")

    class Meta:
        ordering = ["order", "lecture", "slug"]

    def __str__(self) -> str:
        return f"L{self.lecture}: {self.title}"

    @property
    def max_points(self) -> Decimal:
        return sum((t.points for t in self.tasks.filter(active=True)), Decimal("0"))


class Task(models.Model):
    class Kind(models.TextChoices):
        AUTO = "auto", "Auto-graded"
        MANUAL = "manual", "TA-graded"

    lab = models.ForeignKey(Lab, on_delete=models.CASCADE, related_name="tasks")
    key = models.SlugField()
    order = models.PositiveSmallIntegerField(default=0)
    title = models.CharField(max_length=200)
    points = models.DecimalField(max_digits=6, decimal_places=2, default=Decimal("10"))
    kind = models.CharField(max_length=8, choices=Kind.choices, default=Kind.AUTO)
    # Tasks removed from code are deactivated, never deleted, so old marks survive.
    active = models.BooleanField(default=True)

    class Meta:
        ordering = ["lab", "order"]
        constraints = [models.UniqueConstraint(fields=["lab", "key"], name="uniq_task_key")]

    def __str__(self) -> str:
        return f"{self.lab.slug}/{self.key}"


class Accommodation(models.Model):
    """Extra time and/or a later deadline for one student. lab=None applies to
    every lab (e.g. a standing disability accommodation)."""

    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                related_name="accommodations")
    lab = models.ForeignKey(Lab, null=True, blank=True, on_delete=models.CASCADE,
                            related_name="accommodations")
    extra_minutes = models.PositiveIntegerField(default=0)
    closes_at_override = models.DateTimeField(null=True, blank=True)
    reason = models.CharField(max_length=255)
    granted_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True,
                                   on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        scope = self.lab.slug if self.lab else "all labs"
        return f"{self.student} +{self.extra_minutes}min ({scope})"


class LabSession(models.Model):
    """A student's single run at a lab. The seed drives every per-student
    parameter, so two students never share an answer."""

    student = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                related_name="lab_sessions")
    lab = models.ForeignKey(Lab, on_delete=models.CASCADE, related_name="sessions")
    seed = models.BigIntegerField()
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-started_at"]
        constraints = [
            models.UniqueConstraint(fields=["student", "lab"], name="one_session_per_lab"),
        ]

    def __str__(self) -> str:
        return f"{self.student} · {self.lab.slug}"


class Submission(models.Model):
    class Status(models.TextChoices):
        CORRECT = "correct", "Correct"
        PARTIAL = "partial", "Partly correct"
        INCORRECT = "incorrect", "Incorrect"
        PENDING = "pending", "Awaiting TA"
        GRADED = "graded", "Graded"
        SUPERSEDED = "superseded", "Superseded"

    session = models.ForeignKey(LabSession, on_delete=models.CASCADE, related_name="submissions")
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name="submissions")
    answer = models.TextField()
    status = models.CharField(max_length=16, choices=Status.choices)
    score = models.DecimalField(max_digits=6, decimal_places=2, default=Decimal("0"))
    created_at = models.DateTimeField(default=timezone.now)
    feedback = models.TextField(blank=True)
    graded_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                  on_delete=models.SET_NULL, related_name="+")
    graded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["session", "task"]), models.Index(fields=["status"])]

    def __str__(self) -> str:
        return f"{self.session} · {self.task.key} · {self.status}"
