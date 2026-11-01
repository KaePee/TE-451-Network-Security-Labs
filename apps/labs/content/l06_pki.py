"""Lab 6: key management and PKI. Read a real X.509 certificate, follow a chain
of trust, and decide which certificate a browser would reject and why.

Every student gets their own three-tier PKI (root -> intermediate -> leaf),
generated deterministically in x509gen.py. Students use `openssl x509` or
Python's `cryptography` to read them.
"""

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .base import LabDef, ManualTask, TaskDef, format_html, mark_safe, normalise
from .base import task_rng
from . import x509gen

HOSTS = ["portal", "library", "results", "vle", "mail", "payments", "eduroam"]


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _build_pki(seed, host):
    """A fresh root/intermediate/leaf chain for one student + host."""
    rng = task_rng(seed, "l06-pki")
    root, root_key = x509gen.make_cert(
        rng, "TE451 Lab Root CA", "TE451 Lab Root CA", None,
        is_ca=True, days_from=-365, days_to=3650, self_signed=True)
    inter, inter_key = x509gen.make_cert(
        rng, "TE451 Lab Issuing CA", "TE451 Lab Root CA",
        root_key, is_ca=True, days_from=-200, days_to=1825)
    leaf, _ = x509gen.make_cert(
        rng, f"{host}.knust.edu.gh", "TE451 Lab Issuing CA", inter_key,
        san=[f"{host}.knust.edu.gh"], days_from=-30, days_to=365)
    return root, inter, leaf


class ReadCertificate(TaskDef):
    key = "read-cert"
    title = "Read an X.509 certificate"
    points = 10
    seed_key = "l06-shared-pki"
    placeholder = "the SHA-256 fingerprint"

    def _pki(self, p):
        return _build_pki(p["seed"], p["host"])

    def generate(self, rng):
        # The seed is carried so the shared PKI is identical across these tasks.
        return {"host": rng.choice(HOSTS), "seed": rng.getrandbits(48)}

    def files(self, p):
        _, _, leaf = self._pki(p)
        return {"server.pem": x509gen.pem(leaf)}

    def file_names(self, p):
        return ["server.pem"]

    def prompt(self, p):
        return format_html(
            "<p>Download the server certificate below and open it:</p>"
            "<pre>openssl x509 -in server.pem -noout -text\n"
            "openssl x509 -in server.pem -noout -fingerprint -sha256</pre>"
            "<p>Read it and answer: what is its <strong>SHA-256 fingerprint</strong>? "
            "Submit it in hex (colons and case don't matter).</p>"
            "<p class=\"muted\">While you're in there: who is the Subject? the Issuer? What "
            "dates is it valid between? Which hostnames does the Subject Alternative Name "
            "list — and why does the browser trust the SAN, not the Common Name?</p>")

    def check(self, p, answer):
        _, _, leaf = self._pki(p)
        clean = lambda s: "".join(c for c in s.lower() if c in "0123456789abcdef")
        return clean(answer) == _fingerprint(leaf)


class ChainOfTrust(TaskDef):
    key = "chain-of-trust"
    title = "Follow the chain of trust"
    points = 15
    seed_key = "l06-shared-pki"
    placeholder = "e.g. B signed C, C signed A"

    LABELS = "ABC"

    def _pki(self, p):
        return _build_pki(p["seed"], p["host"])

    def generate(self, rng):
        return {"host": rng.choice(HOSTS), "seed": rng.getrandbits(48)}

    def _ordered(self, p):
        """(label -> cert) in a seed-shuffled order, plus the right answer."""
        root, inter, leaf = self._pki(p)
        certs = [("root", root), ("intermediate", inter), ("leaf", leaf)]
        rng = task_rng(p["seed"], "l06-chain-order")
        rng.shuffle(certs)
        labelled = dict(zip(self.LABELS, certs))
        where = {role: lab for lab, (role, _) in labelled.items()}
        return labelled, where

    def files(self, p):
        labelled, _ = self._ordered(p)
        return {f"cert-{lab}.pem": x509gen.pem(cert) for lab, (_, cert) in labelled.items()}

    def file_names(self, p):
        return [f"cert-{lab}.pem" for lab in self.LABELS]

    def prompt(self, p):
        _, where = self._ordered(p)
        files = ", ".join(f"cert-{lab}.pem" for lab in self.LABELS)
        return format_html(
            "<p>The three files below — {} — are a root CA, an issuing (intermediate) CA "
            "and a server certificate, but shuffled and labelled A, B and C. Using only "
            "the Subject, Issuer and signatures, work out the chain of trust.</p>"
            "<p>Submit two statements, comma-separated, naming which certificate signed "
            "which, like <code>A signed B, B signed C</code> (root → intermediate → "
            "leaf).</p>"
            "<p class=\"muted\">A certificate's Issuer field names its signer, but don't "
            "take it on faith — verify the signature with the signer's public key "
            "(<code>openssl verify</code>, or <code>public_key().verify(...)</code>). The "
            "root is the one that signed itself.</p>", files)

    def check(self, p, answer):
        _, where = self._ordered(p)
        root, inter, leaf = where["root"], where["intermediate"], where["leaf"]
        wanted = {(root, inter), (inter, leaf)}
        got = set()
        for clause in answer.replace(";", ",").split(","):
            up = clause.upper()
            labels = [c for c in up if c in self.LABELS]
            if "SIGN" in up and len(labels) == 2:
                got.add((labels[0], labels[1]))
        return len(wanted & got) / 2


class SpotTheBadCert(TaskDef):
    key = "spot-bad-cert"
    title = "Which certificate would the browser reject?"
    points = 10
    max_attempts = 2
    seed_key = "l06-badcert"
    placeholder = "a letter, A–D, and the reason"
    LABELS = "ABCD"

    REASONS = {
        "expired": "expired (not-after is in the past)",
        "not_yet": "not yet valid (not-before is in the future)",
        "wrong_host": "wrong hostname (SAN does not match the site)",
    }

    def generate(self, rng):
        host = rng.choice(HOSTS)
        other = rng.choice([h for h in HOSTS if h != host])
        faults = ["expired", "not_yet", "wrong_host"]
        bad = rng.choice(faults)
        return {"host": host, "other": other, "bad": bad, "seed": rng.getrandbits(48)}

    def _certs(self, p):
        """Four leaf certs for the same site; exactly one is valid today."""
        rng = task_rng(p["seed"], "l06-badcert-build")
        root, root_key = x509gen.make_cert(
            rng, "TE451 Lab Root CA", "TE451 Lab Root CA", None,
            is_ca=True, days_from=-365, days_to=3650, self_signed=True)
        host = f"{p['host']}.knust.edu.gh"
        specs = {
            "good": dict(days_from=-30, days_to=365, san=[host]),
            "expired": dict(days_from=-400, days_to=-10, san=[host]),
            "not_yet": dict(days_from=30, days_to=400, san=[host]),
            "wrong_host": dict(days_from=-30, days_to=365,
                               san=[f"{p['other']}.knust.edu.gh"]),
        }
        roles = ["good", p["bad"]]
        fillers = [r for r in specs if r not in roles]
        roles += fillers[:2]                       # four certs total
        rng.shuffle(roles)
        certs = {}
        for label, role in zip(self.LABELS, roles):
            cert, _ = x509gen.make_cert(rng, host, "TE451 Lab Root CA", root_key,
                                        **specs[role])
            certs[label] = (role, cert)
        good = next(lab for lab, (role, _) in certs.items() if role == "good")
        return certs, good

    def files(self, p):
        certs, _ = self._certs(p)
        return {f"cert-{lab}.pem": x509gen.pem(cert) for lab, (_, cert) in certs.items()}

    def file_names(self, p):
        return [f"cert-{lab}.pem" for lab in self.LABELS]

    def prompt(self, p):
        return format_html(
            "<p>The four certificates below (A–D) all claim to be for "
            "<code>{}.knust.edu.gh</code> and were issued by the same CA. A browser "
            "visiting <code>https://{}.knust.edu.gh</code> <strong>today</strong> accepts "
            "exactly one. Which letter is the valid one?</p>"
            "<p>Submit the letter and, in a few words, what is wrong with <em>one</em> of "
            "the rejected certificates, e.g. <code>B — cert A is expired</code>.</p>"
            "<p class=\"muted\">Check each certificate's validity dates and its Subject "
            "Alternative Name against the hostname and today's date. 2 attempts. (Today, "
            "for this lab, is a date after the valid cert's start.)</p>",
            p["host"], p["host"])

    def check(self, p, answer):
        _, good = self._certs(p)
        up = answer.upper()
        picked = next((c for c in up if c in self.LABELS), None)
        return picked == good


class KdcAndRevocation(ManualTask):
    key = "kdc-revocation"
    title = "Short answer: session keys, trust and revocation"
    rubric = (
        "10 marks. [3] KDC / session keys: a Key Distribution Centre shares a long-term "
        "key with each party and issues short-lived session keys on demand (Kerberos); "
        "fresh session keys limit exposure of the long-term key and enable forward "
        "secrecy. [3] Authenticity problem + certificates: a public key alone doesn't "
        "prove whose it is (Eve can substitute hers); a CA vouches for the identity↔key "
        "binding by signing a certificate, and trust chains up to a root in the trust "
        "store (what they verified in the chain task). [4] Revocation: a key can be "
        "stolen before its certificate expires, so it must be disownable — CRLs (lists of "
        "revoked serials) and OCSP (online status check); revocation is the hard part "
        "because clients must fetch fresh status (soft-fail, latency, privacy). Credit for "
        "hierarchical vs web-of-trust trust models, and for noting the lab's own internal "
        "CA is a private hierarchical PKI."
    )

    def prompt(self, p):
        return mark_safe(
            "<p>In 6–10 sentences: (a) what problem does a certificate solve that "
            "encryption alone does not? (b) you trusted the leaf certificate by following "
            "it up to a root — where does that trust ultimately stop, and why? (c) a "
            "server's private key is stolen the day after its certificate is issued, valid "
            "for another year — what mechanism is supposed to protect users, and why is "
            "that mechanism considered the hardest part of PKI? (d) briefly, how does a "
            "KDC issuing session keys reduce risk compared with reusing one long-term "
            "key?</p>")


LAB = LabDef(
    slug="l06-pki",
    lecture=6,
    title="Certificates, chains and PKI",
    summary="Read a real X.509 certificate, verify a chain of trust from your own "
            "root → intermediate → leaf, and spot the certificate a browser rejects.",
    intro=(
        "<p>Lecture 6 in practice. You each get your own little public-key infrastructure: "
        "a root CA, an issuing CA and a server certificate. You'll read them with the same "
        "tools administrators use, and see exactly what your browser checks before it shows "
        "the padlock — and what makes it show a warning instead.</p>"
        "<p class=\"small muted\">Use <code>openssl x509</code> / <code>openssl verify</code>, "
        "or Python's <code>cryptography</code>. This is the same kind of internal CA that "
        "issues this site's own certificate (Lab 0).</p>"
    ),
    tasks=[ReadCertificate(), ChainOfTrust(), SpotTheBadCert(), KdcAndRevocation()],
)
