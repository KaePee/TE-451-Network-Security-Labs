from django.conf import settings
from django.db import models
from django.utils import timezone


class AuditLog(models.Model):
    """Append-only record of every staff action that changes a student's
    standing: suspensions, extra time, grades, resets, imports."""

    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL,
                              related_name="audit_actions")
    target = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                               on_delete=models.SET_NULL, related_name="audit_targets")
    action = models.CharField(max_length=64, db_index=True)
    detail = models.TextField(blank=True)
    at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-at"]

    def __str__(self) -> str:
        return f"{self.at:%Y-%m-%d %H:%M} {self.actor} {self.action}"


def record(actor, action: str, target=None, detail: str = "") -> AuditLog:
    return AuditLog.objects.create(actor=actor, target=target, action=action, detail=detail)
