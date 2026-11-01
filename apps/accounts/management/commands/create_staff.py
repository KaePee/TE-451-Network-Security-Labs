from getpass import getpass

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import User


class Command(BaseCommand):
    help = "Create a lecturer or TA account (prompts for the password)."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("--role", choices=["lecturer", "ta"], default="ta")
        parser.add_argument("--name", default="", help='e.g. "Justice Agyemang"')
        parser.add_argument("--email", default="")
        parser.add_argument("--superuser", action="store_true",
                            help="Also grant Django admin access (lecturer/sysadmin only).")

    def handle(self, username, role, name, email, superuser, **options):
        if User.objects.filter(username=username).exists():
            raise CommandError(f"{username} already exists")
        first, _, last = name.partition(" ")
        user = User(username=username, role=role, first_name=first, last_name=last,
                    email=email, must_change_password=False,
                    is_staff=superuser, is_superuser=superuser)
        password = getpass("Password: ")
        if password != getpass("Again: "):
            raise CommandError("Passwords don't match")
        try:
            validate_password(password, user)
        except ValidationError as e:
            raise CommandError(" ".join(e.messages))
        user.set_password(password)
        user.save()
        self.stdout.write(self.style.SUCCESS(f"Created {role} {username}"))
