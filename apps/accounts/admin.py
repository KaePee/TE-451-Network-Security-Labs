from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import LoginEvent, User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ("username", "index_number", "first_name", "last_name", "role",
                    "suspended", "last_seen")
    list_filter = ("role", "suspended", "is_active")
    search_fields = ("username", "index_number", "first_name", "last_name", "email")
    fieldsets = BaseUserAdmin.fieldsets + (
        ("Course", {"fields": ("role", "index_number", "must_change_password",
                               "suspended", "suspended_reason", "suspended_at", "last_seen")}),
    )


@admin.register(LoginEvent)
class LoginEventAdmin(admin.ModelAdmin):
    list_display = ("at", "username", "kind", "ip")
    list_filter = ("kind",)
    search_fields = ("username", "ip")
    readonly_fields = [f.name for f in LoginEvent._meta.fields]
