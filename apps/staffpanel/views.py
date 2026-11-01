import csv
from datetime import timedelta
from decimal import Decimal
from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.accounts.models import LoginEvent, User
from apps.audit.models import AuditLog, record
from apps.labs import content, scoring, services
from apps.labs.models import Accommodation, Lab, LabSession, Submission
from apps.labs.timing import Status, lab_state

from . import roster
from .forms import (AccommodationForm, GradeForm, ImportForm, LabSettingsForm,
                    StudentForm, SuspendForm)

IMPORT_SESSION_KEY = "staff_import_credentials"


def staff_required(view):
    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_course_staff:
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapper


def students():
    return User.objects.filter(role=User.Role.STUDENT)


# --------------------------------------------------------------------- dashboard
@staff_required
def dashboard(request):
    now = timezone.now()
    today = timezone.localtime(now).replace(hour=0, minute=0, second=0, microsecond=0)
    online_since = now - timedelta(minutes=settings.ONLINE_WINDOW_MINUTES)
    studs = students()

    stats = {
        "students": studs.count(),
        "suspended": studs.filter(suspended=True).count(),
        "online": studs.filter(last_seen__gte=online_since).count(),
        "logged_in_today": LoginEvent.objects.filter(
            kind=LoginEvent.Kind.LOGIN, at__gte=today, user__role=User.Role.STUDENT
        ).values("user").distinct().count(),
        "failed_24h": LoginEvent.objects.filter(
            kind=LoginEvent.Kind.FAILED, at__gte=now - timedelta(hours=24)).count(),
        "pending": Submission.objects.filter(status=Submission.Status.PENDING,
                                             session__student__role=User.Role.STUDENT).count(),
        "never_logged_in": studs.filter(last_login__isnull=True).count(),
    }

    labs = list(Lab.objects.annotate(
        started=Count("sessions", filter=Q(sessions__student__role=User.Role.STUDENT),
                      distinct=True),
        finished=Count("sessions", filter=Q(sessions__student__role=User.Role.STUDENT,
                                            sessions__finished_at__isnull=False),
                       distinct=True),
        pending=Count("tasks__submissions",
                      filter=Q(tasks__submissions__status=Submission.Status.PENDING),
                      distinct=True),
    ))
    maxima = scoring.lab_max_points(labs)
    scores = scoring.lab_scores(studs, labs)
    for lab in labs:
        vals = [v for (sid, lid), v in scores.items() if lid == lab.id]
        lab.avg_pct = (sum(vals) / len(vals) / maxima[lab.id] * 100
                       if vals and maxima.get(lab.id) else None)
        lab.max = maxima.get(lab.id)

    recent = LoginEvent.objects.select_related("user")[:12]
    return render(request, "staffpanel/dashboard.html",
                  {"stats": stats, "labs": labs, "recent": recent})


# ---------------------------------------------------------------------- students
@staff_required
def student_list(request):
    qs = students()
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(index_number__icontains=q) | Q(first_name__icontains=q)
                       | Q(last_name__icontains=q) | Q(email__icontains=q))
    if request.GET.get("filter") == "suspended":
        qs = qs.filter(suspended=True)
    elif request.GET.get("filter") == "never":
        qs = qs.filter(last_login__isnull=True)

    page = Paginator(qs, 50).get_page(request.GET.get("page"))
    labs = list(Lab.objects.all())
    maxima = scoring.lab_max_points(labs)
    scores = scoring.lab_scores(page.object_list, labs)
    for s in page.object_list:
        per_lab = {lab.id: scores.get((s.id, lab.id), Decimal("0")) for lab in labs}
        s.total_pct = scoring.weighted_percent(per_lab, labs, maxima)
    return render(request, "staffpanel/student_list.html",
                  {"page": page, "q": q, "filter": request.GET.get("filter", "")})


@staff_required
def student_add(request):
    form = StudentForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        d = form.cleaned_data
        user, password = roster.create_student(d["index_number"], d["first_name"],
                                               d["last_name"], d["email"])
        record(request.user, "create_student", user)
        messages.success(request, f"Created {user}. Temporary password: {password} "
                                  "(shown once; the student must change it at first login).")
        return redirect("staff:student", pk=user.pk)
    return render(request, "staffpanel/student_add.html", {"form": form})


@staff_required
def student_import(request):
    form = ImportForm(request.POST or None, request.FILES or None)
    result = None
    if request.method == "POST" and form.is_valid():
        result = roster.parse_and_create(form.cleaned_data["file"].read())
        if not result.errors:
            record(request.user, "import_students",
                   detail=f"created {len(result.created)}, skipped {len(result.skipped)}")
            request.session[IMPORT_SESSION_KEY] = result.created
    return render(request, "staffpanel/student_import.html", {"form": form, "result": result})


@staff_required
def student_import_credentials(request):
    """One-time download of the passwords generated by the last import."""
    rows = request.session.pop(IMPORT_SESSION_KEY, None)
    if not rows:
        messages.error(request, "No credentials waiting. They can only be downloaded once.")
        return redirect("staff:student_import")
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="te451-credentials.csv"'
    w = csv.writer(response)
    w.writerow(["index_number", "first_name", "last_name", "temporary_password"])
    for r in rows:
        w.writerow([safe_cell(r["index_number"]), safe_cell(r["first_name"]),
                    safe_cell(r["last_name"]), r["password"]])
    return response


@staff_required
def student_detail(request, pk):
    student = get_object_or_404(User, pk=pk)
    labs = list(Lab.objects.all())
    maxima = scoring.lab_max_points(labs)
    scores = scoring.lab_scores([student], labs)
    sessions = {s.lab_id: s for s in LabSession.objects.filter(student=student)}
    rows = [{"lab": lab, "state": lab_state(lab, student, sessions.get(lab.id)),
             "score": scores.get((student.id, lab.id)), "max": maxima.get(lab.id)}
            for lab in labs]
    per_lab = {lab.id: scores.get((student.id, lab.id), Decimal("0")) for lab in labs}
    return render(request, "staffpanel/student_detail.html", {
        "student": student,
        "rows": rows,
        "total_pct": scoring.weighted_percent(per_lab, labs, maxima),
        "logins": student.login_events.all()[:30],
        "accommodations": student.accommodations.select_related("lab", "granted_by"),
        "acc_form": AccommodationForm(),
        "suspend_form": SuspendForm(),
        "audit": AuditLog.objects.filter(target=student).select_related("actor")[:20],
    })


@staff_required
@require_POST
def student_suspend(request, pk):
    student = get_object_or_404(students(), pk=pk)
    form = SuspendForm(request.POST)
    if form.is_valid():
        student.suspend(form.cleaned_data["reason"])
        record(request.user, "suspend", student, form.cleaned_data["reason"])
        messages.success(request, f"{student} suspended. They are logged out immediately.")
    else:
        messages.error(request, "A reason is required to suspend.")
    return redirect("staff:student", pk=pk)


@staff_required
@require_POST
def student_unsuspend(request, pk):
    student = get_object_or_404(students(), pk=pk)
    student.unsuspend()
    record(request.user, "unsuspend", student)
    messages.success(request, f"{student} reinstated.")
    return redirect("staff:student", pk=pk)


@staff_required
@require_POST
def student_reset_password(request, pk):
    student = get_object_or_404(students(), pk=pk)
    password = roster.reset_password(student)
    record(request.user, "reset_password", student)
    messages.success(request, f"New temporary password for {student}: {password} "
                              "(shown once).")
    return redirect("staff:student", pk=pk)


@staff_required
@require_POST
def accommodation_add(request, pk):
    student = get_object_or_404(students(), pk=pk)
    form = AccommodationForm(request.POST)
    if form.is_valid():
        acc = form.save(commit=False)
        acc.student, acc.granted_by = student, request.user
        acc.save()
        record(request.user, "grant_time", student,
               f"{acc.lab.slug if acc.lab else 'all labs'}: +{acc.extra_minutes} min, "
               f"deadline={acc.closes_at_override or '-'}; {acc.reason}")
        messages.success(request, "Extra time granted. It applies immediately, "
                                  "including to a session in progress.")
    else:
        messages.error(request, "; ".join(e for errs in form.errors.values() for e in errs))
    return redirect("staff:student", pk=pk)


@staff_required
@require_POST
def accommodation_delete(request, pk, acc_id):
    acc = get_object_or_404(Accommodation, pk=acc_id, student_id=pk)
    record(request.user, "revoke_time", acc.student, str(acc))
    acc.delete()
    messages.success(request, "Accommodation removed.")
    return redirect("staff:student", pk=pk)


@staff_required
@require_POST
def session_reset(request, pk, slug):
    session = get_object_or_404(LabSession, student_id=pk, lab__slug=slug)
    services.reset_session(session, request.user, request.POST.get("reason", ""))
    messages.success(request, f"{slug} reset. The student can start again with new numbers.")
    return redirect("staff:student", pk=pk)


@staff_required
def login_log(request):
    qs = LoginEvent.objects.select_related("user")
    kind = request.GET.get("kind")
    if kind in LoginEvent.Kind.values:
        qs = qs.filter(kind=kind)
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(ip__startswith=q))
    page = Paginator(qs, 100).get_page(request.GET.get("page"))
    return render(request, "staffpanel/login_log.html",
                  {"page": page, "kind": kind or "", "q": q, "kinds": LoginEvent.Kind.choices})


# -------------------------------------------------------------------------- labs
@staff_required
def lab_list(request):
    return render(request, "staffpanel/lab_list.html", {"labs": Lab.objects.all()})


@staff_required
def lab_edit(request, slug):
    lab = get_object_or_404(Lab, slug=slug)
    form = LabSettingsForm(request.POST or None, instance=lab)
    if request.method == "POST" and form.is_valid():
        form.save()
        record(request.user, "lab_settings", detail=f"{slug}: {', '.join(form.changed_data)}")
        messages.success(request, "Lab settings saved.")
        return redirect("staff:lab_list")
    return render(request, "staffpanel/lab_edit.html", {"lab": lab, "form": form})


@staff_required
def lab_progress(request, slug):
    lab = get_object_or_404(Lab, slug=slug)
    tasks = list(lab.tasks.filter(active=True))
    studs = list(students())
    sessions = {s.student_id: s for s in lab.sessions.all()}
    subs = (Submission.objects.filter(session__lab=lab)
            .exclude(status=Submission.Status.SUPERSEDED)
            .values("session__student_id", "task_id", "status", "score"))
    cells: dict[tuple[int, int], dict] = {}
    for s in subs:
        c = cells.setdefault((s["session__student_id"], s["task_id"]),
                             {"tries": 0, "status": None, "score": None})
        c["tries"] += 1
        # A TA grade of 0 is still a grade; an auto 0 is just a wrong try.
        if s["status"] == Submission.Status.GRADED or (
                s["status"] in scoring.SCORED and s["score"] > 0):
            if c["score"] is None or s["score"] > c["score"]:
                c["status"], c["score"] = s["status"], s["score"]
        elif c["score"] is None and (c["status"] is None
                                     or s["status"] == Submission.Status.PENDING):
            c["status"] = s["status"]

    rows = []
    for st in studs:
        state = lab_state(lab, st, sessions.get(st.id))
        rows.append({"student": st, "state": state,
                     "cells": [cells.get((st.id, t.id)) for t in tasks]})
    order = {Status.IN_PROGRESS: 0, Status.TIME_UP: 1, Status.FINISHED: 2}
    rows.sort(key=lambda r: (order.get(r["state"].status, 3), r["student"].index_number or ""))
    return render(request, "staffpanel/lab_progress.html",
                  {"lab": lab, "tasks": tasks, "rows": rows, "Status": Status})


# ----------------------------------------------------------------------- grading
@staff_required
def grading_queue(request):
    pending = (Submission.objects.filter(status=Submission.Status.PENDING)
               .select_related("task__lab", "session__student").order_by("created_at"))
    lab = request.GET.get("lab")
    if lab:
        pending = pending.filter(task__lab__slug=lab)
    return render(request, "staffpanel/grading_queue.html",
                  {"pending": pending[:200], "labs": Lab.objects.all(), "lab": lab or ""})


@staff_required
def grade(request, sub_id):
    sub = get_object_or_404(Submission.objects.select_related("task__lab", "session__student"),
                            pk=sub_id)
    labdef = content.get(sub.task.lab.slug)
    taskdef = labdef.task(sub.task.key) if labdef else None
    form = GradeForm(request.POST or None, max_points=sub.task.points,
                     initial={"score": sub.score if sub.status == sub.Status.GRADED else None,
                              "feedback": sub.feedback})
    if request.method == "POST" and form.is_valid():
        if sub.status == Submission.Status.SUPERSEDED:
            messages.error(request, "The student has replaced this answer. Grade the newer one.")
            return redirect("staff:grading")
        services.grade_submission(sub, form.cleaned_data["score"],
                                  form.cleaned_data["feedback"], request.user)
        messages.success(request, f"Graded {sub.session.student}.")
        nxt = (Submission.objects.filter(status=Submission.Status.PENDING, task=sub.task)
               .order_by("created_at").first())
        return redirect("staff:grade", sub_id=nxt.pk) if nxt else redirect("staff:grading")
    prompt = taskdef.prompt(taskdef.params_for(sub.session.seed)) if taskdef else ""
    return render(request, "staffpanel/grade.html",
                  {"sub": sub, "form": form, "prompt": prompt,
                   "rubric": getattr(taskdef, "rubric", "")})


# ------------------------------------------------------------------------ export
def safe_cell(value) -> str:
    """Stop CSV formula injection: a student named '=HYPERLINK(...)' must not
    execute when the lecturer opens the export in Excel."""
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@staff_required
def export_marks(request):
    labs = list(Lab.objects.all())
    studs = list(students())
    maxima = scoring.lab_max_points(labs)
    scores = scoring.lab_scores(studs, labs)

    response = HttpResponse(content_type="text/csv")
    stamp = timezone.localtime().strftime("%Y%m%d-%H%M")
    response["Content-Disposition"] = f'attachment; filename="te451-marks-{stamp}.csv"'
    w = csv.writer(response)
    w.writerow(["index_number", "last_name", "first_name", "email",
                *[f"L{lab.lecture} {lab.title} (/{maxima.get(lab.id, 0)})" for lab in labs],
                "total_points", "weighted_percent", "suspended"])
    for s in studs:
        per_lab = {lab.id: scores.get((s.id, lab.id), Decimal("0")) for lab in labs}
        w.writerow([safe_cell(s.index_number), safe_cell(s.last_name),
                    safe_cell(s.first_name), safe_cell(s.email),
                    *[per_lab[lab.id] for lab in labs],
                    sum(per_lab.values(), Decimal("0")),
                    scoring.weighted_percent(per_lab, labs, maxima),
                    "yes" if s.suspended else ""])
    record(request.user, "export_marks", detail=f"{len(studs)} students")
    return response


@staff_required
def audit_log(request):
    if not request.user.is_lecturer:
        raise PermissionDenied
    qs = AuditLog.objects.select_related("actor", "target")
    page = Paginator(qs, 100).get_page(request.GET.get("page"))
    return render(request, "staffpanel/audit_log.html", {"page": page})
