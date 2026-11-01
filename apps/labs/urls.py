from django.urls import path

from . import views

app_name = "labs"

urlpatterns = [
    path("<slug:slug>/", views.lab_detail, name="detail"),
    path("<slug:slug>/start/", views.start, name="start"),
    path("<slug:slug>/finish/", views.finish, name="finish"),
    path("<slug:slug>/task/<slug:task_key>/", views.submit, name="submit"),
    path("<slug:slug>/task/<slug:task_key>/files/<str:filename>", views.download,
         name="download"),
]
