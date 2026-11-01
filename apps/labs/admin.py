from django.contrib import admin

from .models import Accommodation, Lab, LabSession, Submission, Task


class TaskInline(admin.TabularInline):
    model = Task
    extra = 0
    fields = ("order", "key", "title", "points", "kind", "active")
    readonly_fields = ("key", "kind")


@admin.register(Lab)
class LabAdmin(admin.ModelAdmin):
    list_display = ("slug", "lecture", "title", "mode", "published", "opens_at", "closes_at")
    list_filter = ("mode", "published")
    inlines = [TaskInline]


@admin.register(LabSession)
class LabSessionAdmin(admin.ModelAdmin):
    list_display = ("student", "lab", "started_at", "finished_at")
    list_filter = ("lab",)
    search_fields = ("student__username", "student__index_number")
    exclude = ("seed",)


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = ("session", "task", "status", "score", "created_at")
    list_filter = ("status", "task__lab")
    search_fields = ("session__student__username",)


@admin.register(Accommodation)
class AccommodationAdmin(admin.ModelAdmin):
    list_display = ("student", "lab", "extra_minutes", "closes_at_override", "reason")
