import hashlib

from django.conf import settings

from .base import LabDef, TaskDef, format_html, mark_safe, normalise

PLEDGE = "I will only test systems I own or am authorised to test"


class Pledge(TaskDef):
    key = "ethics-pledge"
    title = "Ethics pledge"
    points = 5
    placeholder = "Type the sentence exactly"

    def prompt(self, p):
        return format_html(
            "<p>Every technique in TE 451 is taught for defence. Running an attack "
            "against a system you do not own, or have no written permission to test, "
            "is a crime and an academic-integrity violation (Lecture 0, Lecture 12).</p>"
            "<p>Type the following sentence to confirm you understand:</p>"
            "<blockquote>{}</blockquote>", PLEDGE)

    def check(self, p, answer):
        return normalise(answer).rstrip(".") == normalise(PLEDGE)


class RootCA(TaskDef):
    key = "root-ca"
    title = "Trust the lab's root CA"
    points = 5
    placeholder = "AB:CD:EF:..."

    def prompt(self, p):
        return mark_safe(
            "<p>This site's HTTPS certificate is issued by the course's own certificate "
            "authority, not a public one. Download it from "
            "<a href=\"http://netsec.internal/ca.crt\">http://netsec.internal/ca.crt</a> "
            "and install it as a trusted root on your laptop (instructions are on the "
            "help page).</p>"
            "<p>Open the certificate and find its <strong>SHA-256 fingerprint</strong>. "
            "Paste it below. Colons and spaces are optional.</p>"
            "<p class=\"muted\">You will build a CA like this yourself in Lab 6. Ask "
            "yourself now: what exactly did you just agree to trust?</p>")

    def check(self, p, answer):
        expected = settings.ROOT_CA_FINGERPRINT
        if not expected:
            return False
        clean = lambda s: "".join(c for c in s.lower() if c in "0123456789abcdef")
        return clean(answer) == clean(expected)


class HashWarmup(TaskDef):
    key = "python-sha256"
    title = "Python warm-up: hashing"
    points = 10
    placeholder = "16 hex characters"

    def generate(self, rng):
        return {"text": f"TE451-{rng.randrange(16**8):08x}"}

    def prompt(self, p):
        return format_html(
            "<p>Using Python's <code>hashlib</code>, compute the SHA-256 digest of the "
            "UTF-8 string <code>{}</code>.</p>"
            "<p>Submit the <strong>first 16 hex characters</strong> of the digest.</p>",
            p["text"])

    def check(self, p, answer):
        expected = hashlib.sha256(p["text"].encode()).hexdigest()[:16]
        return normalise(answer) == expected


LAB = LabDef(
    slug="l00-orientation",
    lecture=0,
    title="Orientation: platform, tools & ethics",
    summary="Get set up: trust the lab CA, sign the ethics pledge, and check your Python.",
    intro=(
        "<p>This first session gets your laptop ready for the semester. Before the "
        "end of the lab you should have <strong>Python 3</strong>, "
        "<strong>Wireshark</strong> and <strong>Nmap</strong> installed.</p>"
    ),
    tasks=[Pledge(), RootCA(), HashWarmup()],
)
