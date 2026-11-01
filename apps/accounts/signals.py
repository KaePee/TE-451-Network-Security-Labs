from django.conf import settings
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from .models import LoginEvent, User


def client_ip(request) -> str | None:
    if request is None:
        return None
    # Behind our nginx, X-Forwarded-For is *overwritten* with the real peer
    # address, so it is trustworthy. Without the proxy, a client could forge
    # it, so only REMOTE_ADDR counts.
    if settings.BEHIND_PROXY:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.META.get("REMOTE_ADDR")


def _record(request, kind, user=None, username=""):
    LoginEvent.objects.create(
        user=user,
        username=username or (user.get_username() if user else ""),
        kind=kind,
        ip=client_ip(request),
        user_agent=(request.META.get("HTTP_USER_AGENT", "")[:300] if request else ""),
    )


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    _record(request, LoginEvent.Kind.LOGIN, user=user)


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    if user is not None:
        _record(request, LoginEvent.Kind.LOGOUT, user=user)


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request=None, **kwargs):
    username = credentials.get("username", "")[:150]
    user = User.objects.filter(username=username).first()
    _record(request, LoginEvent.Kind.FAILED, user=user, username=username)
