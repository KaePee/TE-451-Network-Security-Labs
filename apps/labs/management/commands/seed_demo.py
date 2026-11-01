from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import User
from apps.labs.models import Lab

DEMO_PASSWORD = "demo-pass-2026"
DEMO_USERS = [
    ("lecturer", User.Role.LECTURER, "Demo", "Lecturer"),
    ("ta", User.Role.TA, "Demo", "TA"),
    ("2045001", User.Role.STUDENT, "Ama", "Mensah"),
    ("2045002", User.Role.STUDENT, "Kofi", "Boateng"),
    ("2045003", User.Role.STUDENT, "Akosua", "Owusu"),
]


class Command(BaseCommand):
    help = "LOCAL DEVELOPMENT ONLY: demo accounts (shared password) and all labs published."

    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise CommandError("seed_demo only runs with DJANGO_DEBUG=1. Never on the server.")
        call_command("sync_labs", stdout=self.stdout)
        for username, role, first, last in DEMO_USERS:
            user, _ = User.objects.get_or_create(username=username)
            user.role, user.first_name, user.last_name = role, first, last
            user.index_number = username if role == User.Role.STUDENT else None
            user.must_change_password = False
            user.is_staff = user.is_superuser = role == User.Role.LECTURER
            user.set_password(DEMO_PASSWORD)
            user.save()
        Lab.objects.update(published=True)
        self.stdout.write(self.style.SUCCESS(
            f"Users: {', '.join(u[0] for u in DEMO_USERS)}  password: {DEMO_PASSWORD}"))
