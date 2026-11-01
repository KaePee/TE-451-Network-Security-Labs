from django import template

from apps.labs.timing import Status

register = template.Library()

LABELS = {
    Status.UNPUBLISHED: ("Hidden", "muted"),
    Status.NOT_OPEN: ("Not open yet", "muted"),
    Status.OPEN: ("Open", "info"),
    Status.IN_PROGRESS: ("In progress", "warn"),
    Status.FINISHED: ("Submitted", "ok"),
    Status.TIME_UP: ("Time up", "ok"),
    Status.MISSED: ("Missed", "bad"),
}


@register.inclusion_tag("labs/_status_badge.html")
def status_badge(state):
    label, tone = LABELS[state.status]
    return {"label": label, "tone": tone}


@register.filter
def pct(score, maximum):
    if score is None or not maximum:
        return ""
    return f"{score / maximum * 100:.0f}%"
