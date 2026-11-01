from django.core.management.base import BaseCommand
from django.db import transaction

from apps.labs import content
from apps.labs.models import Lab, Task


class Command(BaseCommand):
    help = ("Create/update Lab and Task rows from apps/labs/content. Staff settings "
            "(mode, dates, published, weight) are only set when a lab is first created.")

    @transaction.atomic
    def handle(self, *args, **options):
        for order, labdef in enumerate(content.LABS):
            lab, created = Lab.objects.get_or_create(
                slug=labdef.slug,
                defaults={"lecture": labdef.lecture, "title": labdef.title,
                          "mode": labdef.default_mode,
                          "duration_minutes": labdef.default_duration},
            )
            lab.lecture, lab.title, lab.summary, lab.order = (
                labdef.lecture, labdef.title, labdef.summary, order)
            lab.save()

            keys = []
            for t_order, taskdef in enumerate(labdef.tasks):
                keys.append(taskdef.key)
                Task.objects.update_or_create(
                    lab=lab, key=taskdef.key,
                    defaults={"order": t_order, "title": taskdef.title,
                              "points": taskdef.points, "kind": taskdef.kind,
                              "active": True},
                )
            retired = lab.tasks.exclude(key__in=keys).filter(active=True).update(active=False)
            verb = "created" if created else "updated"
            msg = f"{verb} {lab.slug}: {len(keys)} tasks"
            if retired:
                msg += f", {retired} retired"
            self.stdout.write(self.style.SUCCESS(msg))

        known = {l.slug for l in content.LABS}
        for orphan in Lab.objects.exclude(slug__in=known):
            self.stdout.write(self.style.WARNING(
                f"{orphan.slug} is in the database but not in code (left untouched)"))
