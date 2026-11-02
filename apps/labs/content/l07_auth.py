"""Lab 7: user authentication and access control. Compute a TOTP code (a
'something you have' factor), evaluate an RBAC policy, and spot a file whose
permissions break least privilege.

Covers Lecture 7: authentication factors / MFA, challenge-response, and the
DAC/MAC/RBAC/ABAC models under least privilege.
"""

import base64
import hashlib
import hmac
import struct

from .base import (LabDef, ManualTask, TaskDef, fraction_matching, format_html,
                   mark_safe, normalise)


def totp(secret_b32: str, unix_time: int, step: int = 30, digits: int = 6) -> str:
    """RFC 6238 TOTP over HMAC-SHA1 (what Google Authenticator computes)."""
    key = base64.b32decode(secret_b32)
    counter = struct.pack("!Q", unix_time // step)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack("!I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % (10 ** digits):0{digits}d}"


class TotpCode(TaskDef):
    key = "totp"
    title = "A one-time code: 'something you have'"
    points = 15
    placeholder = "a 6-digit code"

    def generate(self, rng):
        secret = base64.b32encode(bytes(rng.randrange(256) for _ in range(20))).decode()
        # A fixed instant so the expected code never changes (real TOTP uses 'now').
        t = rng.randrange(1_700_000_000, 1_800_000_000)
        return {"secret": secret, "t": t}

    def prompt(self, p):
        return format_html(
            "<p>An account is protected by a time-based one-time password (TOTP), the "
            "six digits an authenticator app shows. The device and the server share this "
            "secret:</p><pre>secret (base32) = {}</pre>"
            "<p>Using the standard TOTP settings — <strong>HMAC-SHA1, 30-second step, 6 "
            "digits</strong> (RFC 6238) — what code is valid at Unix time "
            "<code>{}</code>? Submit the six digits.</p>"
            "<p class=\"muted\">Compute it with Python's <code>hmac</code>, or add the "
            "secret to an authenticator and set your clock to that instant. Why is this a "
            "stronger second factor than a password, and why must the code expire?</p>",
            p["secret"], p["t"])

    def check(self, p, answer):
        return normalise(answer).replace(" ", "") == totp(p["secret"], p["t"])


ROLES = {
    "student": [("read", "grades"), ("read", "materials"), ("submit", "assignment")],
    "ta": [("read", "grades"), ("read", "materials"), ("grade", "assignment"),
           ("read", "submissions")],
    "lecturer": [("read", "grades"), ("write", "grades"), ("read", "materials"),
                 ("write", "materials"), ("grade", "assignment"), ("read", "submissions")],
    "registrar": [("read", "grades"), ("publish", "transcript")],
}
ACTIONS = [("read", "grades"), ("write", "grades"), ("grade", "assignment"),
           ("publish", "transcript"), ("read", "submissions"), ("write", "materials"),
           ("submit", "assignment")]


class RbacPolicy(TaskDef):
    key = "rbac"
    title = "Role-based access control"
    points = 20
    placeholder = "e.g. A, D, A, D, D, A"

    def generate(self, rng):
        names = ["ama", "kofi", "yaa", "kwame", "efua", "kojo"]
        people = []
        for name in rng.sample(names, 6):
            role = rng.choice(list(ROLES))
            action, resource = rng.choice(ACTIONS)
            people.append({"name": name, "role": role,
                           "action": action, "resource": resource})
        return {"people": people}

    def _answer(self, p):
        return ["A" if (q["action"], q["resource"]) in ROLES[q["role"]] else "D"
                for q in p["people"]]

    def files(self, p):
        import json
        policy = {role: [f"{a}:{r}" for a, r in perms] for role, perms in ROLES.items()}
        return {"policy.json": (json.dumps(policy, indent=2) + "\n").encode()}

    def prompt(self, p):
        rows = "\n".join(
            f"{i + 1}. {q['name']} (role: {q['role']}) wants to {q['action']} {q['resource']}"
            for i, q in enumerate(p["people"]))
        table = "\n".join(f"  {role}: " + ", ".join(f"{a} {r}" for a, r in perms)
                          for role, perms in ROLES.items())
        return format_html(
            "<p>A campus system uses role-based access control. Each role grants a fixed "
            "set of <code>action resource</code> permissions (also in "
            "<code>policy.json</code> below):</p><pre>{}</pre>"
            "<p>Under <strong>least privilege</strong> — a request is allowed only if the "
            "user's role explicitly grants it — decide each request. Submit "
            "<code>A</code> (allow) or <code>D</code> (deny) for each, in order, "
            "comma-separated.</p><pre>{}</pre>", table, rows)

    def check(self, p, answer):
        given = "".join(c for c in answer.upper() if c in "AD")
        return fraction_matching(given, "".join(self._answer(p)))


class LeastPrivilege(TaskDef):
    key = "least-privilege"
    title = "Spot the permissions mistake"
    points = 10
    max_attempts = 2
    placeholder = "a letter, A–E"
    LABELS = "ABCDE"

    # (path, owner, correct mode, description). The bad entry gets an over-broad mode.
    FILES = [
        ("/etc/ssh/ssh_host_ed25519_key", "root", "600", "SSH host private key"),
        ("/home/deploy/.ssh/id_rsa", "deploy", "600", "user's SSH private key"),
        ("/etc/shadow", "root", "640", "password hashes"),
        ("/var/www/app/.env", "www-data", "640", "app secrets (DB password, API keys)"),
        ("/etc/ssl/private/server.key", "root", "600", "TLS server private key"),
        ("/srv/backups/dump.sql", "root", "600", "database backup"),
    ]

    def generate(self, rng):
        chosen = rng.sample(self.FILES, 5)
        bad_index = rng.randrange(5)
        # The mistake: a secret file made world-readable or world-writable.
        bad_mode = rng.choice(["644", "666", "604", "646"])
        return {"files": chosen, "bad": bad_index, "bad_mode": bad_mode}

    def _rows(self, p):
        rows = []
        for i, (path, owner, mode, desc) in enumerate(p["files"]):
            shown = p["bad_mode"] if i == p["bad"] else mode
            rows.append((self.LABELS[i], shown, owner, path, desc))
        return rows

    def prompt(self, p):
        listing = "\n".join(f"{lab}. {mode}  {owner:<8} {path}   # {desc}"
                            for lab, mode, owner, path, desc in self._rows(p))
        return format_html(
            "<p>Here are the permissions (octal mode) on six sensitive files of a server. "
            "Exactly one grants access far beyond what its role needs, breaking least "
            "privilege — a secret any local user could read or change.</p><pre>{}</pre>"
            "<p>Which one is the mistake? Submit its letter.</p>"
            "<p class=\"muted\">Recall that octal mode is owner/group/other; the last "
            "digit is everyone else. What should 'other' be allowed on a private key or a "
            "secrets file? 2 attempts.</p>", listing)

    def check(self, p, answer):
        picked = next((c for c in answer.upper() if c in self.LABELS), None)
        return picked == self.LABELS[p["bad"]]


class AuthShortAnswer(ManualTask):
    key = "auth-models"
    title = "Short answer: factors, protocols and access models"
    rubric = (
        "10 marks. [3] Factors/MFA: something you know / have / are; MFA combines two "
        "different kinds, so a stolen password alone is not enough; passkeys (FIDO2/"
        "WebAuthn) are phishing-resistant. [3] Challenge-response: the verifier sends a "
        "nonce and the client returns a keyed hash/signature of it, proving it holds the "
        "secret without sending it, which defeats replay and eavesdropping; Kerberos uses "
        "a KDC to issue time-limited tickets (SSO, no password per service); OAuth/OIDC "
        "federate the same idea with short-lived tokens. [4] Access control: "
        "authentication (who) vs authorisation (what); DAC (owner grants), MAC (system "
        "labels/clearances), RBAC (rights via roles), ABAC (attributes/context, "
        "zero-trust); apply least privilege and complete mediation. Credit for 802.1X/NAC "
        "authenticating devices at the port (supplicant → authenticator → RADIUS)."
    )

    def prompt(self, p):
        return mark_safe(
            "<p>In 7–10 sentences: (a) name the three kinds of authentication evidence and "
            "say what MFA actually requires; (b) in the TOTP task, which factor did the "
            "code represent, and how does challenge-response let you prove a secret without "
            "sending it? (c) contrast DAC, MAC, RBAC and ABAC in one line each; (d) the "
            "RBAC task denied some requests — which two design principles from Lecture 1 "
            "does that enforce? (e) what does 802.1X authenticate that a login form does "
            "not?</p>")


LAB = LabDef(
    slug="l07-auth",
    lecture=7,
    title="Authentication & access control",
    summary="Compute a TOTP second factor, evaluate a role-based access policy under "
            "least privilege, and find the file whose permissions leak a secret.",
    intro=(
        "<p>Lecture 7, hands on: how systems decide <em>who you are</em> (authentication) "
        "and <em>what you may do</em> (authorisation). You'll compute a real one-time code, "
        "apply an access-control policy, and audit file permissions the way an "
        "administrator does.</p>"
        "<p class=\"small muted\">Python's <code>hmac</code>, <code>hashlib</code>, "
        "<code>base64</code> and <code>struct</code> are all you need for the code; the "
        "rest is reasoning.</p>"
    ),
    tasks=[TotpCode(), RbacPolicy(), LeastPrivilege(), AuthShortAnswer()],
)
