"""Lab 8: transport-level security. Reason about cipher suites and forward
secrecy, read a real TLS handshake in Wireshark (the SNI and cipher suite leak
in clear), and fingerprint an SSH host key.

Covers Lecture 8: TLS placement and guarantees, the handshake as hybrid crypto,
TLS 1.3 / forward secrecy, HTTPS and SSH, and the metadata TLS does not hide.
"""

import base64
import hashlib

from cryptography.hazmat.primitives import serialization

from .base import (LabDef, ManualTask, TaskDef, fraction_matching, format_html,
                   mark_safe, task_rng)
from . import pcap, tls
from .x509gen import deterministic_rsa_key

HOSTS = ["vle.knust.edu.gh", "portal.knust.edu.gh", "mail.knust.edu.gh",
         "results.knust.edu.gh", "library.knust.edu.gh", "pay.knust.edu.gh"]


class ForwardSecrecy(TaskDef):
    key = "forward-secrecy"
    title = "Cipher suites and forward secrecy"
    points = 15
    placeholder = "e.g. Y, N, Y, N, Y"

    def generate(self, rng):
        codes = rng.sample(list(tls.CIPHER_SUITES), 5)
        return {"codes": codes}

    def prompt(self, p):
        rows = "\n".join(f"{chr(65 + i)}. {tls.CIPHER_SUITES[c][0]}"
                         for i, c in enumerate(p["codes"]))
        return format_html(
            "<p>A cipher suite names the whole toolkit a TLS connection will use: key "
            "exchange, authentication, bulk cipher and hash. Here are five a server might "
            "offer:</p><pre>{}</pre>"
            "<p>For each, does it provide <strong>forward secrecy</strong> — so that "
            "stealing the server's long-term private key later cannot decrypt traffic "
            "captured today? Submit <code>Y</code> or <code>N</code> for each, in order.</p>"
            "<p class=\"muted\">Look at the key-exchange part of the name. Which mechanism "
            "uses a fresh ephemeral key per session, and which lets the server's "
            "long-term key unlock everything? TLS 1.3 suites don't name the key exchange "
            "because it's always ephemeral.</p>", rows)

    def check(self, p, answer):
        given = "".join(c for c in answer.upper() if c in "YN")
        want = "".join("Y" if tls.CIPHER_SUITES[c][1] else "N" for c in p["codes"])
        return fraction_matching(given, want)


class TlsCapture(TaskDef):
    key = "tls-wireshark"
    title = "Read a TLS handshake on the wire"
    points = 20
    seed_key = "l08-tls-capture"
    placeholder = "hostname, 0xXXXX"

    def generate(self, rng):
        sni = rng.choice(HOSTS)
        offered = rng.sample([c for c in tls.CIPHER_SUITES if tls.CIPHER_SUITES[c][1]], 3)
        offered += rng.sample([c for c in tls.CIPHER_SUITES if not tls.CIPHER_SUITES[c][1]], 1)
        rng.shuffle(offered)
        chosen = rng.choice([c for c in offered if tls.CIPHER_SUITES[c][1]])
        subnet = rng.randrange(1, 254)
        return {"sni": sni, "offered": offered, "chosen": chosen, "subnet": subnet,
                "client_ip": f"192.168.{subnet}.{rng.randrange(20, 200)}"}

    def _capture(self, p):
        rng = task_rng(p["subnet"], "l08-tls-build")
        client = pcap.Host(p["client_ip"], pcap.random_mac(rng))
        server = pcap.Host(f"41.204.{p['subnet']}.{rng.randrange(1, 254)}",
                           pcap.random_mac(rng))
        return tls.build_handshake(rng, client, server, p["sni"], p["offered"], p["chosen"])

    def files(self, p):
        return {f"tls-{p['subnet']}.pcap": self._capture(p).to_pcap()}

    def file_names(self, p):
        return [f"tls-{p['subnet']}.pcap"]

    def prompt(self, p):
        return format_html(
            "<p>Download the capture of one HTTPS connection and open it in Wireshark. The "
            "handshake is in clear; only the application data is encrypted.</p>"
            "<p>Find two things the handshake reveals even though the connection is "
            "\"secure\":</p><ul>"
            "<li>the <strong>server name (SNI)</strong> the client asked for, in the "
            "ClientHello;</li>"
            "<li>the <strong>cipher suite the server chose</strong>, in the ServerHello "
            "(its hex code, e.g. <code>0xc02f</code>).</li></ul>"
            "<p>Submit them as <code>hostname, 0xXXXX</code>.</p>"
            "<p class=\"muted\">Filter on <code>tls.handshake.type == 1</code> and "
            "<code>== 2</code>. This is the metadata leak from Lecture 1: TLS hides the "
            "contents, not who you talked to — which is why encrypted DNS and ECH exist.</p>")

    def check(self, p, answer):
        parts = [x.strip().lower() for x in answer.replace(";", ",").split(",")]
        if len(parts) != 2:
            return 0.0
        host_ok = parts[0] == p["sni"].lower()
        want_suite = {f"0x{p['chosen']:04x}", f"{p['chosen']:04x}", str(p["chosen"]),
                      tls.CIPHER_SUITES[p["chosen"]][0].lower()}
        suite_ok = parts[1].replace(" ", "") in want_suite
        return 0.5 * host_ok + 0.5 * suite_ok


class SshHostKey(TaskDef):
    key = "ssh-hostkey"
    title = "Fingerprint an SSH host key"
    points = 10
    placeholder = "SHA256:..."

    def generate(self, rng):
        key = deterministic_rsa_key(task_rng(rng.getrandbits(48), "l08-ssh"), bits=2048)
        pub = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        blob = base64.b64decode(pub.split()[1])
        fp = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        host = rng.choice(HOSTS)
        return {"line": pub.decode() + f" root@{host}", "host": host, "fp": fp}

    def files(self, p):
        return {"known_host.pub": (p["line"] + "\n").encode()}

    def prompt(self, p):
        return format_html(
            "<p>When you first <code>ssh</code> to a server, it offers a host key and the "
            "client shows you its fingerprint to accept. Here is the public host key of "
            "<code>{}</code> (also in <code>known_host.pub</code>):</p><pre>{}</pre>"
            "<p>What is its <strong>SHA-256 fingerprint</strong>, as OpenSSH prints it "
            "(the <code>SHA256:…</code> string)? Submit that string.</p>"
            "<p class=\"muted\">Run <code>ssh-keygen -lf known_host.pub</code>, or compute "
            "it yourself: base64 of the SHA-256 of the raw key blob, without the trailing "
            "<code>=</code> padding. Why does checking this fingerprint on first connect "
            "stop a man-in-the-middle, and what record stores it afterwards?</p>",
            p["host"], p["line"])

    def check(self, p, answer):
        ans = answer.strip().split()[0] if answer.strip() else ""
        ans = ans.removeprefix("SHA256:")
        return ans == p["fp"]


class TlsShortAnswer(ManualTask):
    key = "tls-ssh-summary"
    title = "Short answer: the handshake and what still leaks"
    rubric = (
        "10 marks. [2] Placement/guarantees: TLS sits between the application and TCP and "
        "gives confidentiality, integrity and server authentication (optionally client "
        "auth); HTTP over TLS = HTTPS. [4] Handshake as the course in miniature: agree a "
        "cipher suite + exchange randoms; server proves identity with its certificate "
        "(Lecture 6); ECDHE derives a fresh shared secret (Lecture 4); switch to symmetric "
        "AEAD / AES-GCM for data (Lecture 3). [2] Forward secrecy: ephemeral ECDHE keys "
        "mean a later key compromise can't decrypt past traffic; TLS 1.3 gives it by "
        "default and drops RC4/static-RSA/CBC. [2] Metadata: TLS hides contents, not that "
        "communication happened — SNI, the certificate, DNS and traffic volume still leak "
        "who talks to whom (the capture showed this), motivating encrypted DNS / ECH; SSH "
        "uses host keys for server identity and password or public-key for the user."
    )

    def prompt(self, p):
        return mark_safe(
            "<p>In 7–10 sentences, tying the semester together: (a) where does TLS sit and "
            "what does it guarantee? (b) walk through the handshake and name which earlier "
            "lecture each step comes from (certificate, key exchange, bulk encryption); "
            "(c) what is forward secrecy and which cipher suites in the first task "
            "provided it? (d) you read the SNI and cipher suite straight off the wire — so "
            "what does TLS <em>not</em> protect, and what hides that? (e) how does SSH "
            "establish server identity the first time you connect?</p>")


LAB = LabDef(
    slug="l08-transport",
    lecture=8,
    title="TLS, HTTPS and SSH",
    summary="Reason about cipher suites and forward secrecy, read a TLS handshake in "
            "Wireshark (SNI and suite leak in clear), and fingerprint an SSH host key.",
    intro=(
        "<p>The TLS handshake is the whole course in miniature: a certificate (Lecture 6), "
        "an ephemeral key exchange (Lecture 4) and fast authenticated encryption "
        "(Lecture 3). Here you'll see it on the wire, reason about which cipher suites are "
        "safe, and meet SSH — and notice how much TLS still leaks about who you talk to.</p>"
        "<p class=\"small muted\">You'll need Wireshark for the capture. "
        "<code>ssh-keygen</code> (or Python) handles the host-key fingerprint.</p>"
    ),
    tasks=[ForwardSecrecy(), TlsCapture(), SshHostKey(), TlsShortAnswer()],
)
