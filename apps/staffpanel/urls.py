from django.urls import path

from . import views

app_name = "staff"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("students/", views.student_list, name="students"),
    path("students/add/", views.student_add, name="student_add"),
    path("students/import/", views.student_import, name="student_import"),
    path("students/import/credentials.csv", views.student_import_credentials,
         name="student_import_credentials"),
    path("students/<int:pk>/", views.student_detail, name="student"),
    path("students/<int:pk>/suspend/", views.student_suspend, name="student_suspend"),
    path("students/<int:pk>/unsuspend/", views.student_unsuspend, name="student_unsuspend"),
    path("students/<int:pk>/reset-password/", views.student_reset_password,
         name="student_reset_password"),
    path("students/<int:pk>/time/", views.accommodation_add, name="accommodation_add"),
    path("students/<int:pk>/time/<int:acc_id>/delete/", views.accommodation_delete,
         name="accommodation_delete"),
    path("students/<int:pk>/labs/<slug:slug>/reset/", views.session_reset,
         name="session_reset"),
    path("logins/", views.login_log, name="logins"),
    path("labs/", views.lab_list, name="lab_list"),
    path("labs/<slug:slug>/", views.lab_progress, name="lab_progress"),
    path("labs/<slug:slug>/settings/", views.lab_edit, name="lab_edit"),
    path("grading/", views.grading_queue, name="grading"),
    path("grading/<int:sub_id>/", views.grade, name="grade"),
    path("export/marks.csv", views.export_marks, name="export_marks"),
    path("audit/", views.audit_log, name="audit"),
]
