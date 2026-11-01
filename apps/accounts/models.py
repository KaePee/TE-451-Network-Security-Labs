from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    """Students log in with their index number as the username."""

    class Role(models.TextChoices):
        STUDENT = "student", "Student"
        TA = "ta", "TA / GA"
        LECTURER = "lecturer", "Lecturer"

    role = models.CharField(max_length=16, choices=Role.choices, default=Role.STUDENT)
    index_number = models.CharField(max_length=32, unique=True, null=True, blank=True)
    must_change_password = models.BooleanField(default=True)

    suspended = models.BooleanField(default=False)
    suspended_reason = models.CharField(max_length=255, blank=True)
    suspended_at = models.DateTimeField(null=True, blank=True)

    last_seen = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["index_number", "username"]

    @property
    def is_course_staff(self) -> bool:
        return self.role in (self.Role.TA, self.Role.LECTURER) or self.is_superuser

    @property
    def is_lecturer(self) -> bool:
        return self.role == self.Role.LECTURER or self.is_superuser

    def suspend(self, reason: str) -> None:
        self.suspended = True
        self.suspended_reason = reason
        self.suspended_at = timezone.now()
        self.save(update_fields=["suspended", "suspended_reason", "suspended_at"])

    def unsuspend(self) -> None:
        self.suspended = False
        self.suspended_reason = ""
        self.suspended_at = None
        self.save(update_fields=["suspended", "suspended_reason", "suspended_at"])

    def __str__(self) -> str:
        name = self.get_full_name()
        ident = self.index_number or self.username
        return f"{ident} ({name})" if name else ident


class LoginEvent(models.Model):
    class Kind(models.TextChoices):
        LOGIN = "login", "Login"
        LOGOUT = "logout", "Logout"
        FAILED = "failed", "Failed login"
        BLOCKED = "blocked", "Blocked (suspended)"

    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE,
                             related_name="login_events")
    # Kept for failed attempts against usernames that may not exist.
    username = models.CharField(max_length=150)
    kind = models.CharField(max_length=16, choices=Kind.choices)
    at = models.DateTimeField(default=timezone.now, db_index=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)

    class Meta:
        ordering = ["-at"]
        indexes = [models.Index(fields=["user", "-at"])]

    def __str__(self) -> str:
        return f"{self.username} {self.kind} @ {self.at:%Y-%m-%d %H:%M}"
