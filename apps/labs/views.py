import mimetypes

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from . import content, scoring, services
from .models import Lab, Submission
from .timing import Status, lab_state

# Slim Docker images have no /etc/mime.types; register what labs hand out.
mimetypes.add_type("application/vnd.tcpdump.pcap", ".pcap")
mimetypes.add_type("application/x-pem-file", ".pem")


def _visible_labs(user):
    qs = Lab.objects.all()
    return qs if user.is_course_staff else qs.filter(published=True)


@login_required
def home(request):
    labs = list(_visible_labs(request.user))
    maxima = scoring.lab_max_points(labs)
    scores = scoring.lab_scores([request.user], labs)
    rows = [{"lab": lab, "state": lab_state(lab, request.user),
             "score": scores.get((request.user.id, lab.id)), "max": maxima.get(lab.id)}
            for lab in labs]
    return render(request, "labs/home.html", {"rows": rows})


@login_required
def lab_detail(request, slug):
    lab = get_object_or_404(_visible_labs(request.user), slug=slug)
    labdef = content.get(slug)
    if labdef is None:
        raise Http404("Lab content missing")
    state = lab_state(lab, request.user)

    tasks = []
    if state.session is not None:
        subs = list(state.session.submissions.select_related("task"))
        for task in lab.tasks.filter(active=True):
            taskdef = labdef.task(task.key)
            if taskdef is None:
                continue
            mine = [s for s in subs if s.task_id == task.id]
            latest = next((s for s in mine if s.status != Submission.Status.SUPERSEDED), None)
            # With feedback hidden, students must not learn they solved it.
            solved = lab.show_feedback and any(
                s.status == Submission.Status.CORRECT for s in mine)
            limit = services.attempt_limit(lab, taskdef) if task.kind == "auto" else None
            out_of_attempts = limit is not None and len(mine) >= limit
            params = taskdef.params_for(state.session.seed)
            tasks.append({
                "task": task,
                "def": taskdef,
                "prompt": taskdef.prompt(params),
                "files": taskdef.file_names(params),
                "latest": latest,
                "solved": solved,
                "attempts": len(mine),
                "limit": limit,
                "locked": solved or out_of_attempts or (
                    latest is not None and latest.status == Submission.Status.GRADED),
            })

    return render(request, "labs/lab_detail.html", {
        "lab": lab, "labdef": labdef, "state": state, "tasks": tasks,
        "Status": Status,
    })


@login_required
@require_POST
def start(request, slug):
    lab = get_object_or_404(_visible_labs(request.user), slug=slug)
    try:
        services.start_session(lab, request.user)
    except services.LabError as e:
        messages.error(request, str(e))
    return redirect("labs:detail", slug=slug)


@login_required
@require_POST
def submit(request, slug, task_key):
    lab = get_object_or_404(_visible_labs(request.user), slug=slug)
    task = get_object_or_404(lab.tasks, key=task_key, active=True)
    state = lab_state(lab, request.user)
    if state.session is None:
        messages.error(request, "Start the lab first.")
        return redirect("labs:detail", slug=slug)
    try:
        sub = services.submit_answer(state.session, task, request.POST.get("answer", ""))
    except services.LabError as e:
        messages.error(request, f"{task.title}: {e}")
    else:
        if sub.status == Submission.Status.PENDING:
            messages.info(request, f"{task.title}: saved. A TA will grade it.")
        elif not lab.show_feedback:
            messages.info(request, f"{task.title}: answer recorded.")
        elif sub.status == Submission.Status.CORRECT:
            messages.success(request, f"{task.title}: correct!")
        elif sub.status == Submission.Status.PARTIAL:
            messages.warning(request, f"{task.title}: partly correct "
                                      f"({sub.score:g} / {task.points:g}).")
        else:
            messages.error(request, f"{task.title}: not correct, try again.")
    return redirect(reverse("labs:detail", kwargs={"slug": slug}) + f"#task-{task_key}")


@login_required
@require_POST
def finish(request, slug):
    lab = get_object_or_404(_visible_labs(request.user), slug=slug)
    state = lab_state(lab, request.user)
    if state.session is not None and state.can_submit:
        services.finish_session(state.session)
        messages.success(request, "Lab submitted. Well done.")
    return redirect("labs:detail", slug=slug)


# Public: students need the CA instructions before they can log in cleanly.
def help_page(request):
    return render(request, "labs/help.html")


@login_required
def download(request, slug, task_key, filename):
    """Per-student files, regenerated from the session seed on every request."""
    lab = get_object_or_404(_visible_labs(request.user), slug=slug)
    task = get_object_or_404(lab.tasks, key=task_key, active=True)
    state = lab_state(lab, request.user)
    labdef = content.get(slug)
    taskdef = labdef.task(task.key) if labdef else None
    if state.session is None or taskdef is None:
        raise Http404
    data = taskdef.files(taskdef.params_for(state.session.seed)).get(filename)
    if data is None:
        raise Http404
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    response = HttpResponse(data, content_type=ctype)
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    response["Cache-Control"] = "private, no-store"
    return response
