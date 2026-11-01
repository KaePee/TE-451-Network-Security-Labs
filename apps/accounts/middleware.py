from datetime import timedelta

from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone

from .models import LoginEvent, User
from .signals import client_ip

# Paths a user may reach while forced to change their password.
_PASSWORD_CHANGE_EXEMPT = ("accounts:password_change", "accounts:logout")
LAST_SEEN_RESOLUTION = timedelta(minutes=1)


class AccountStateMiddleware:
    """Enforces account state on every request, not just at login:

    * a suspended user is logged out immediately (suspension takes effect
      mid-session, e.g. during a timed lab);
    * a user flagged must_change_password can only reach the change form;
    * last_seen is refreshed (at most once a minute) for the dashboard.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if user.is_authenticated:
            if user.suspended:
                LoginEvent.objects.create(
                    user=user, username=user.get_username(), kind=LoginEvent.Kind.BLOCKED,
                    ip=client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", "")[:300],
                )
                logout(request)
                return redirect(f"{reverse('accounts:login')}?suspended=1")

            exempt = [reverse(name) for name in _PASSWORD_CHANGE_EXEMPT]
            if (user.must_change_password and request.path not in exempt
                    and not request.path.startswith("/static/")):
                return redirect("accounts:password_change")

            now = timezone.now()
            if user.last_seen is None or now - user.last_seen > LAST_SEEN_RESOLUTION:
                User.objects.filter(pk=user.pk).update(last_seen=now)
                user.last_seen = now

        return self.get_response(request)
