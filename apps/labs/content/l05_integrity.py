"""Lab 5: cryptographic data integrity. Recover weak password hashes with your
own tools (CrackStation, John, hashcat), see why salting defeats precomputed
tables, then verify and forge a MAC.

Builds on the course repo's crack_the_hash/crack.py and data_integrity/hmac_demo.py.
The crackable values are ordinary passwords from public wordlists: the lesson is
that a fast, unsalted hash of a weak password offers no protection at all.
"""

import hashlib
import hmac

from .base import LabDef, ManualTask, TaskDef, format_html, mark_safe, normalise
from .corpus import LEAKED_PASSWORDS

# (label shown to students, hashlib name, hex digest length) for identification.
HASH_KINDS = [("MD5", "md5", 32), ("SHA-1", "sha1", 40),
              ("SHA-256", "sha256", 64), ("SHA-512", "sha512", 128)]


def _hex(algo: str, *parts: bytes) -> str:
    h = hashlib.new(algo)
    for part in parts:
        h.update(part)
    return h.hexdigest()


class IdentifyHashes(TaskDef):
    key = "identify-hash"
    title = "Identify the hash"
    points = 10
    max_attempts = 2
    placeholder = "e.g. MD5, SHA-256, SHA-1"

    def generate(self, rng):
        kinds = rng.sample(HASH_KINDS, 3)
        items = []
        for label, algo, _ in kinds:
            word = f"sample-{rng.randrange(10**6):06d}"
            items.append({"label": label, "digest": _hex(algo, word.encode())})
        return {"items": items}

    def prompt(self, p):
        rows = "\n".join(f"{i + 1}. {it['digest']}" for i, it in enumerate(p["items"]))
        return format_html(
            "<p>Below are three hex digests, each produced by a different algorithm. "
            "Name the algorithm used for each, in order, comma-separated "
            "(e.g. <code>SHA-256, MD5, SHA-1</code>).</p><pre>{}</pre>"
            "<p class=\"muted\">You can reason from the length alone, or use a tool like "
            "<code>hashid</code> / <code>hash-identifier</code>. Which fact about a hash "
            "does the length give away, and which does it not?</p>", rows)

    def check(self, p, answer):
        given = [normalise(x).replace("-", "").replace(" ", "")
                 for x in answer.split(",")]
        want = [it["label"].lower().replace("-", "") for it in p["items"]]
        if len(given) != len(want):
            return 0.0
        return sum(g == w for g, w in zip(given, want)) / len(want)


class CrackUnsalted(TaskDef):
    key = "crack-unsalted"
    title = "Crack an unsalted hash"
    points = 15
    placeholder = "the recovered password"

    def generate(self, rng):
        pw = rng.choice(LEAKED_PASSWORDS)
        algo = rng.choice(["md5", "sha1", "sha256"])
        return {"algo": algo, "digest": _hex(algo, pw.encode())}

    def prompt(self, p):
        label = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[p["algo"]]
        return format_html(
            "<p>A website stored this user's password as a bare <strong>{}</strong> hash, "
            "with no salt:</p><pre>{}</pre>"
            "<p>The password is an ordinary word. Recover it and submit the plaintext.</p>"
            "<p class=\"muted\">Paste the digest into an online lookup such as "
            "<a href=\"https://crackstation.net\" rel=\"noreferrer\">CrackStation</a>, or run "
            "<code>hashcat</code> / <code>john</code> against a wordlist like rockyou. "
            "How long did it take? That is the whole point.</p>", label, p["digest"])

    def check(self, p, answer):
        return _hex(p["algo"], answer.strip().encode()) == p["digest"]


class CrackSalted(TaskDef):
    key = "crack-salted"
    title = "Salt defeats the lookup table"
    points = 15
    placeholder = "both passwords, comma-separated"

    def generate(self, rng):
        salts = [f"{rng.randrange(16**8):08x}", f"{rng.randrange(16**8):08x}"]
        same = rng.choice(LEAKED_PASSWORDS)
        # Two users with the SAME password but different salts -> different digests.
        users = [
            {"name": "kofi", "salt": salts[0],
             "digest": _hex("sha256", salts[0].encode(), same.encode())},
            {"name": "ama", "salt": salts[1],
             "digest": _hex("sha256", salts[1].encode(), same.encode())},
        ]
        return {"users": users, "answers": [same, same]}

    def files(self, p):
        lines = ["# scheme: digest = SHA-256( ASCII(salt) + ASCII(password) )",
                 "# hashcat: -m 1420  (sha256(salt.pass));  john: dynamic",
                 "# username:salt:sha256"]
        lines += [f"{u['name']}:{u['salt']}:{u['digest']}" for u in p["users"]]
        return {"shadow.txt": ("\n".join(lines) + "\n").encode()}

    def prompt(self, p):
        return format_html(
            "<p>Here are two users from a breached <code>shadow</code> file. This time the "
            "store is <strong>salted</strong>: each digest is "
            "<code>SHA-256(salt + password)</code>, with the salt stored alongside.</p>"
            "<pre>{}</pre>"
            "<p>Recover both passwords and submit them comma-separated, in the order "
            "<code>kofi, ama</code>.</p>"
            "<p class=\"muted\">A plain CrackStation lookup will miss these: the salt is not "
            "in its precomputed tables. Feed the salt to <code>hashcat -m 1420</code> or "
            "<code>john</code>, or write a short Python loop over a wordlist. Notice that "
            "the two digests differ even when the passwords are related: that is exactly "
            "what the salt buys. The file is below.</p>",
            "\n".join(f"{u['name']}  salt={u['salt']}  {u['digest']}" for u in p["users"]))

    def check(self, p, answer):
        parts = [x.strip() for x in answer.replace(";", ",").split(",")]
        if len(parts) != 2:
            return 0.0
        hit = 0.0
        for given, u in zip(parts, p["users"]):
            if _hex("sha256", u["salt"].encode(), given.encode()) == u["digest"]:
                hit += 0.5
        return hit


class HmacForge(TaskDef):
    key = "hmac-verify"
    title = "A bare hash is forgeable; a MAC is not"
    points = 15
    placeholder = "message || HMAC, see below"

    def generate(self, rng):
        key = f"{rng.randrange(16**32):032x}"
        acct = f"{rng.randrange(10**9, 10**10)}"
        amount = rng.randrange(2, 90) * 100
        message = f"transfer GHS {amount} to {acct}"
        target_acct = f"{rng.randrange(10**9, 10**10)}"
        forged = f"transfer GHS {amount} to {target_acct}"
        tag = hmac.new(bytes.fromhex(key), message.encode(), "sha256").hexdigest()
        return {"key": key, "message": message, "tag": tag, "acct": acct,
                "target_acct": target_acct, "forged": forged}

    def prompt(self, p):
        return format_html(
            "<p>A payment API authenticates each request with "
            "<code>HMAC-SHA-256</code> under a shared key. You captured one request and, "
            "this time, you also know the key (a key leak):</p>"
            "<pre>key     = {}\nmessage = {}\nHMAC    = {}</pre>"
            "<p>First check that the tag is valid. Then act as an attacker who has the "
            "key: change the destination account to <code>{}</code>, keeping the amount, "
            "and produce a request the API will accept. Submit "
            "<code>message || \":\" || HMAC</code> — the forged message, a colon, then "
            "your new tag in hex.</p>"
            "<p class=\"muted\">Use Python's <code>hmac</code> (see "
            "<code>data_integrity/hmac_demo.py</code>). Then ask yourself: if the key had "
            "<em>not</em> leaked, could you have done this? That is the difference between "
            "a MAC and a bare hash. Why does <code>hmac.compare_digest</code> matter?</p>",
            p["key"], p["message"], p["tag"], p["target_acct"])

    def check(self, p, answer):
        if ":" not in answer:
            return False
        message, _, tag = answer.rpartition(":")
        message, tag = message.strip(), tag.strip().lower()
        if message != p["forged"]:
            return False
        expected = hmac.new(bytes.fromhex(p["key"]), message.encode(), "sha256").hexdigest()
        return hmac.compare_digest(expected, tag)


class WhySlowHashes(ManualTask):
    key = "why-slow-hashes"
    title = "Short answer: storing passwords properly"
    rubric = (
        "10 marks. [3] Salt: a unique random salt per password means identical passwords "
        "get different digests, which defeats precomputed rainbow / lookup tables (e.g. "
        "CrackStation) and stops an attacker cracking many accounts at once; the salt is "
        "not secret and is stored alongside. [4] Slow hash: SHA-256/MD5 are fast, so a GPU "
        "tries billions of guesses/second (the tasks they just did); a deliberately slow, "
        "memory-hard KDF — Argon2 (preferred), scrypt or bcrypt — with a tuned work factor "
        "makes each guess expensive, cutting attacker throughput by orders of magnitude. "
        "[3] Also acceptable/awarded: pepper, rate-limiting and lockout (the platform's own "
        "django-axes), never storing plaintext, and that the attacker still cracks a weak "
        "password — so length/entropy and breach checks matter too. Mentioning that this "
        "site stores passwords with Argon2 earns credit."
    )

    def prompt(self, p):
        return mark_safe(
            "<p>In 6–9 sentences, using what you saw in this lab: (a) what does a salt do, "
            "and which attack from this lab does it stop? (b) why did the unsalted hashes "
            "fall in seconds, and what kind of hash should a password store use instead? "
            "(c) name one real algorithm you would choose and why. (d) even with salt and a "
            "slow hash, one of these passwords is still a bad choice — why?</p>")


LAB = LabDef(
    slug="l05-integrity",
    lecture=5,
    title="Hashes, cracking and MACs",
    summary="Identify and crack weak password hashes with real tools, see why salt "
            "matters, and forge a MAC when the key leaks — then say how to store "
            "passwords properly.",
    intro=(
        "<p>Lecture 5 made concrete. You will use real attacker tools against hashes this "
        "lab generated for you: an online lookup, and optionally <code>hashcat</code> or "
        "<code>john</code>. Everything here is a weak or misused construction on purpose — "
        "the goal is to feel how fast weak password storage collapses, and what fixes it.</p>"
        "<p class=\"small muted\">Lawful use only: crack only the hashes this lab issued to "
        "you. Python's <code>hashlib</code> and <code>hmac</code> cover the rest; see the "
        "course repo's <code>crack_the_hash/</code> and <code>data_integrity/</code>.</p>"
    ),
    tasks=[IdentifyHashes(), CrackUnsalted(), CrackSalted(), HmacForge(), WhySlowHashes()],
)
