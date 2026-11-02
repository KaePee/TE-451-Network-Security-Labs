"""Lab 10: electronic mail security and IP security. Evaluate SPF to catch a
spoofed sender, verify S/MIME-style RSA signatures on email (detecting a
tampered and a forged message), and classify IPsec deployments as transport or
tunnel mode.

Covers Lecture 10: email threats and defences (PGP/S-MIME signing and
encryption, SPF/DKIM/DMARC) and IP-level security (AH vs ESP, transport vs
tunnel mode, IKE, VPNs).
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .base import (LabDef, ManualTask, TaskDef, fraction_matching, format_html,
                   mark_safe, task_rng)
from .x509gen import deterministic_rsa_key


class SpfCheck(TaskDef):
    key = "spf-check"
    title = "Email authentication: evaluate SPF"
    points = 15
    placeholder = "e.g. Y, N, Y, N, Y, N"

    def generate(self, rng):
        a, b = rng.randrange(1, 254), rng.randrange(1, 254)
        blocks = [(41, 204, a), (197, 255, b)]
        roles = ["pass", "pass", "pass", "fail", "fail", "fail"]
        rng.shuffle(roles)
        msgs = []
        for role in roles:
            if role == "pass":
                o1, o2, o3 = rng.choice(blocks)
                ip = f"{o1}.{o2}.{o3}.{rng.randrange(1, 254)}"
            else:
                # First octet avoids 41 and 197 so it is certainly outside both blocks.
                o1 = rng.choice([c for c in range(23, 223) if c not in (41, 197)])
                ip = f"{o1}.{rng.randrange(0, 255)}.{rng.randrange(0, 255)}.{rng.randrange(1, 254)}"
            msgs.append({"ip": ip, "role": role})
        return {"blocks": blocks, "msgs": msgs}

    def prompt(self, p):
        cidrs = "\n".join(f"  {o1}.{o2}.{o3}.0/24" for o1, o2, o3 in p["blocks"])
        rows = "\n".join(f"{i + 1}. from {m['ip']:<16} "
                         f"claiming  From: <notice@knust.edu.gh>"
                         for i, m in enumerate(p["msgs"]))
        return format_html(
            "<p>SPF lets a domain publish the IP addresses allowed to send its mail; the "
            "receiving server checks the connecting IP against that list. "
            "<code>knust.edu.gh</code> publishes:</p>"
            "<pre>v=spf1 ip4:{} ip4:{} -all</pre>"
            "<p>In full, the two authorised sending ranges are:</p><pre>{}</pre>"
            "<p>Six messages arrive, each claiming to be <code>From: &lt;notice@knust.edu.gh&gt;</code>:"
            "</p><pre>{}</pre>"
            "<p>For each, does it <strong>pass</strong> SPF? Submit <code>Y</code> (pass) or "
            "<code>N</code> (fail), in order. A fail means the sender is almost certainly "
            "spoofing the domain.</p>"
            "<p class=\"muted\">Python's <code>ipaddress</code> makes the check exact: "
            "<code>ip_address(ip) in ip_network(cidr)</code>. For the short answer: SPF "
            "checks the IP — what do DKIM and DMARC add that SPF alone cannot?</p>",
            f"{p['blocks'][0][0]}.{p['blocks'][0][1]}.{p['blocks'][0][2]}.0/24",
            f"{p['blocks'][1][0]}.{p['blocks'][1][1]}.{p['blocks'][1][2]}.0/24",
            cidrs, rows)

    def check(self, p, answer):
        given = "".join(c for c in answer.upper() if c in "YN")
        want = "".join("Y" if m["role"] == "pass" else "N" for m in p["msgs"])
        return fraction_matching(given, want)


# (text, substring, replacement) — the tampered copy swaps the amount/account,
# so a student sees exactly what the signature was protecting.
EMAILS = [
    ("From: bursar@knust.edu.gh\nSubject: Outstanding fees\n\n"
     "Your outstanding balance is GHS 1,250. Please pay via the student portal.",
     "1,250", "9,250"),
    ("From: hod.coe@knust.edu.gh\nSubject: Venue change\n\n"
     "The TE 451 exam moves to room PB 012 at 09:00 on Monday.",
     "PB 012", "PB 210"),
    ("From: it-support@knust.edu.gh\nSubject: Account\n\n"
     "Reset code 744198 was issued for your account. It expires in 10 minutes.",
     "744198", "100200"),
    ("From: payroll@knust.edu.gh\nSubject: Salary\n\n"
     "Net pay this month is credited to account 0241556677 as usual.",
     "0241556677", "0249999999"),
    ("From: library@knust.edu.gh\nSubject: Recall\n\n"
     "Please return 'Network Security Essentials' by 14 March to avoid a fine.",
     "14 March", "02 March"),
    ("From: dean@knust.edu.gh\nSubject: Meeting\n\n"
     "The faculty board meets Thursday 15:00 in the Great Hall annex.",
     "15:00", "17:30"),
]


class VerifySignature(TaskDef):
    key = "verify-signature"
    title = "Verify a signed email (S/MIME)"
    points = 15
    placeholder = "e.g. A, C"
    LABELS = "ABCD"

    def generate(self, rng):
        bodies = rng.sample(EMAILS, 4)
        roles = ["authentic", "authentic", "tampered", "forged"]
        rng.shuffle(roles)
        return {"bodies": bodies, "roles": roles, "seed": rng.getrandbits(48)}

    def _material(self, p):
        """(sender_key, {label: (message_bytes, signature_bytes, role)})."""
        rng = task_rng(p["seed"], "l10-sig-keys")
        sender = deterministic_rsa_key(rng, 1024)
        attacker = deterministic_rsa_key(rng, 1024)
        items = {}
        for lab, (text, old, new), role in zip(self.LABELS, p["bodies"], p["roles"]):
            clean = text.encode()
            if role == "authentic":
                msg, sig = clean, sender.sign(clean, padding.PKCS1v15(), hashes.SHA256())
            elif role == "tampered":
                # Signed over the real text, but the delivered copy was altered.
                sig = sender.sign(clean, padding.PKCS1v15(), hashes.SHA256())
                msg = text.replace(old, new).encode()
            else:  # forged: the attacker signed it with their own key
                msg = clean
                sig = attacker.sign(clean, padding.PKCS1v15(), hashes.SHA256())
            items[lab] = (msg, sig, role)
        return sender, items

    def files(self, p):
        sender, items = self._material(p)
        out = {"sender-public.pem": sender.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)}
        for lab, (msg, sig, _) in items.items():
            out[f"email-{lab}.txt"] = msg
            out[f"email-{lab}.sig"] = sig
        return out

    def file_names(self, p):
        names = ["sender-public.pem"]
        for lab in self.LABELS:
            names += [f"email-{lab}.txt", f"email-{lab}.sig"]
        return sorted(names)

    def prompt(self, p):
        return format_html(
            "<p>Four emails (A–D) arrive, each claiming to be from the bursary and each "
            "with a detached RSA signature. You hold the bursary's genuine public key, "
            "<code>sender-public.pem</code>. An S/MIME signature proves two things at once: "
            "that the message really came from the holder of that key, and that not one "
            "byte has changed since.</p>"
            "<p>Verify each message against its signature:</p>"
            "<pre>openssl dgst -sha256 -verify sender-public.pem \\\n"
            "    -signature email-A.sig email-A.txt</pre>"
            "<p>Two of the four are <strong>authentic</strong>. Of the rest, one was "
            "<strong>tampered with</strong> after signing and one is a <strong>forgery</strong> "
            "signed with the wrong key. Submit the letters of the authentic ones "
            "(e.g. <code>A, C</code>).</p>"
            "<p class=\"muted\">Both bad emails fail <code>Verification Failure</code>, even "
            "though they look fine — that is the point. For the short answer: how does "
            "signing an email actually combine a hash (Lecture 5) and a private key "
            "(Lecture 4)?</p>")

    def check(self, p, answer):
        _, items = self._material(p)
        good = {lab for lab, (_, _, role) in items.items() if role == "authentic"}
        picked = {c for c in answer.upper() if c in self.LABELS}
        correct = sum((lab in picked) == (lab in good) for lab in self.LABELS)
        return correct / len(self.LABELS)


class IpsecMode(TaskDef):
    key = "ipsec-mode"
    title = "IPsec: transport or tunnel mode?"
    points = 15
    placeholder = "e.g. U, T, U, T, U"

    SCENARIOS = [
        ("A branch-office gateway and the HQ gateway build a site-to-site VPN across the "
         "public Internet; the hosts behind each are unaware IPsec is involved.", "U"),
        ("Two application servers in the same datacentre authenticate and encrypt traffic "
         "directly between themselves.", "T"),
        ("A lecturer working from home runs the campus VPN client to reach internal "
         "systems through the VPN concentrator.", "U"),
        ("A management station and a router secure their own SNMP session end to end.", "T"),
        ("All traffic between two campus subnets is protected by routing it through a pair "
         "of security gateways.", "U"),
        ("A workstation and a file server on the LAN protect their session end to end, "
         "keeping the original IP headers.", "T"),
    ]

    def generate(self, rng):
        return {"items": rng.sample(self.SCENARIOS, 5)}

    def prompt(self, p):
        rows = "\n".join(f"{i + 1}. {text}" for i, (text, _) in enumerate(p["items"]))
        return format_html(
            "<p>IPsec runs in two modes. In <strong>transport mode</strong> the two end "
            "hosts protect the payload themselves and keep the original IP header — "
            "host-to-host. In <strong>tunnel mode</strong> the entire original packet is "
            "encrypted and wrapped in a new IP header between two gateways — the basis of "
            "VPNs.</p><pre>{}</pre>"
            "<p>For each deployment, submit <code>T</code> (transport) or <code>U</code> "
            "(tunnel), in order.</p>"
            "<p class=\"muted\">Ask one question: are the two IPsec endpoints the end hosts "
            "that actually talk, or a pair of gateways standing in for whole networks? For "
            "the short answer, be ready to say whether each would use AH or ESP.</p>", rows)

    def check(self, p, answer):
        given = "".join(c for c in answer.upper() if c in "TU")
        want = "".join(mode for _, mode in p["items"])
        return fraction_matching(given, want)


class EmailIpShortAnswer(ManualTask):
    key = "email-ip-models"
    title = "Short answer: email trust, and IP-layer security"
    rubric = (
        "10 marks. [3] Email confidentiality+authenticity: a message is signed by hashing "
        "it (Lecture 5) and encrypting the hash with the sender's private key (Lecture 4) — "
        "the verify task — and kept secret by encrypting a fresh symmetric session key with "
        "the recipient's public key (hybrid, Lecture 4) and the body with that session key. "
        "[2] PGP vs S/MIME: same crypto, different trust — PGP uses a decentralised web of "
        "trust (OpenPGP), S/MIME uses X.509 certificates from CAs (Lecture 6). [3] "
        "SPF/DKIM/DMARC: SPF authorises sending IPs (the SPF task catches a spoof), DKIM "
        "puts a domain signature on the headers+body so content/relay tampering shows, "
        "DMARC ties SPF/DKIM results to the visible From domain (alignment) and sets "
        "policy + reporting; together they fight spoofing and phishing. [2] IPsec: AH gives "
        "integrity/authentication only, ESP adds confidentiality (usually the one you want); "
        "transport vs tunnel (the IPsec task); IKE negotiates the security associations and "
        "keys. Credit for noting a site-to-site VPN needs tunnel mode + ESP because whole "
        "packets cross an untrusted network between gateways."
    )

    def prompt(self, p):
        return mark_safe(
            "<p>In 7–10 sentences, drawing the pieces together: (a) to send an email that is "
            "both secret and provably from you, which key encrypts the body and which key "
            "makes the signature — and how does the signature use a hash from Lecture 5? "
            "(b) PGP and S/MIME use the same crypto but trust keys differently — how? "
            "(c) SPF checks the sending IP (you did this) — what do DKIM and DMARC add, and "
            "what attack do all three fight? (d) contrast IPsec's AH and ESP in one line; "
            "(e) why must the site-to-site VPN in the IPsec task use tunnel mode rather than "
            "transport mode?</p>")


LAB = LabDef(
    slug="l10-email-ip",
    lecture=10,
    title="Email security & IPsec",
    summary="Catch a spoofed sender with SPF, verify S/MIME signatures to find a tampered "
            "and a forged email, and tell IPsec transport mode from tunnel mode.",
    intro=(
        "<p>Lecture 10 covers two layers at once. Email was built with no security at all, "
        "so confidentiality, authenticity and anti-spoofing were bolted on — PGP and S/MIME "
        "for the message, SPF/DKIM/DMARC for the sender. IPsec protects at the IP layer "
        "instead, and is what most VPNs are made of. You'll exercise one defence from "
        "each.</p>"
        "<p class=\"small muted\">Use <code>openssl dgst</code> for the signatures and "
        "Python's <code>ipaddress</code> for SPF; the rest is reasoning. The signatures "
        "reuse the same RSA + SHA-256 you met in Labs 4–6.</p>"
    ),
    tasks=[SpfCheck(), VerifySignature(), IpsecMode(), EmailIpShortAnswer()],
)
