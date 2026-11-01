from datetime import timedelta

from django.core.management import call_command
from django.utils import timezone

from apps.accounts.models import User
from apps.labs.models import Lab


def make_student(index="2045001", **kw) -> User:
    u = User(username=index, index_number=index, first_name="Ama", last_name="Mensah",
             must_change_password=False, **kw)
    u.set_password("correct-horse-battery")
    u.save()
    return u


def make_staff(username="ta1", role=User.Role.TA) -> User:
    u = User(username=username, role=role, must_change_password=False)
    u.set_password("correct-horse-battery")
    u.save()
    return u


def synced_lab(slug="l02-number-theory", **settings) -> Lab:
    call_command("sync_labs", stdout=open("/dev/null", "w"))
    lab = Lab.objects.get(slug=slug)
    defaults = {"published": True}
    defaults.update(settings)
    for k, v in defaults.items():
        setattr(lab, k, v)
    lab.save()
    return lab


def ago(**kw):
    return timezone.now() - timedelta(**kw)


def ahead(**kw):
    return timezone.now() + timedelta(**kw)
