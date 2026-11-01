from django.contrib import admin
from django.urls import include, path

from apps.labs import views as lab_views

admin.site.site_header = "TE 451 Labs: administration"

urlpatterns = [
    path("", lab_views.home, name="home"),
    path("help/", lab_views.help_page, name="help"),
    path("accounts/", include("apps.accounts.urls")),
    path("labs/", include("apps.labs.urls")),
    path("staff/", include("apps.staffpanel.urls")),
    path("django-admin/", admin.site.urls),
]
