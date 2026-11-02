"""Labs 7 and 8 solved the way a student would, across many seeds. The TLS
capture is checked against tshark so the grader matches what Wireshark shows."""

import base64
import hashlib
import hmac
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from django.test import SimpleTestCase

from apps.labs import content
from apps.labs.content import tls
from apps.labs.content.l07_auth import ROLES, totp

SEEDS = range(25)


def task(slug, key):
    return content.get(slug).task(key)


class Lab7SolverTests(SimpleTestCase):
    def test_totp_matches_rfc6238(self):
        t = task("l07-auth", "totp")
        for seed in SEEDS:
            p = t.params_for(seed)
            # Independent recomputation (don't reuse the lab's own totp for the math).
            key = base64.b32decode(p["secret"])
            digest = hmac.new(key, struct.pack("!Q", p["t"] // 30), hashlib.sha1).digest()
            off = digest[-1] & 0x0F
            code = (struct.unpack("!I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 10**6
            expected = f"{code:06d}"
            self.assertEqual(expected, totp(p["secret"], p["t"]))
            self.assertTrue(t.check(p, expected), seed)
            self.assertTrue(t.check(p, f" {expected} "))
            self.assertFalse(t.check(p, "000000" if expected != "000000" else "111111"))

    def test_rbac_decisions(self):
        t = task("l07-auth", "rbac")
        for seed in SEEDS:
            p = t.params_for(seed)
            answer = ["A" if (q["action"], q["resource"]) in ROLES[q["role"]] else "D"
                      for q in p["people"]]
            self.assertEqual(t.check(p, ", ".join(answer)), 1.0, seed)
            flipped = answer[:]
            flipped[0] = "A" if flipped[0] == "D" else "D"
            self.assertAlmostEqual(t.check(p, "".join(flipped)), 5 / 6)

    def test_least_privilege_bad_mode_is_world_accessible(self):
        t = task("l07-auth", "least-privilege")
        for seed in SEEDS:
            p = t.params_for(seed)
            # The student reasons: the 'other' digit should be 0 on a secret.
            other_digit = int(p["bad_mode"][-1])
            self.assertGreater(other_digit, 0, seed)
            self.assertTrue(t.check(p, t.LABELS[p["bad"]]), seed)
            wrong = t.LABELS[(p["bad"] + 1) % 5]
            self.assertFalse(t.check(p, wrong))


TSHARK = shutil.which("tshark") or (
    "/Applications/Wireshark.app/Contents/MacOS/tshark"
    if Path("/Applications/Wireshark.app/Contents/MacOS/tshark").exists() else None)


class Lab8SolverTests(SimpleTestCase):
    def test_forward_secrecy_by_key_exchange(self):
        t = task("l08-transport", "forward-secrecy")
        for seed in SEEDS:
            p = t.params_for(seed)
            # A student reads the name: ECDHE/DHE or a TLS 1.3 suite => forward secrecy.
            def fs(name):
                return name.startswith("TLS_AES") or name.startswith("TLS_CHACHA") \
                    or "ECDHE" in name or "DHE" in name
            answer = "".join("Y" if fs(tls.CIPHER_SUITES[c][0]) else "N" for c in p["codes"])
            self.assertEqual(t.check(p, ", ".join(answer)), 1.0, seed)

    def test_ssh_fingerprint_matches_openssh_format(self):
        t = task("l08-transport", "ssh-hostkey")
        for seed in SEEDS:
            p = t.params_for(seed)
            line = t.files(p)["known_host.pub"].decode()
            blob = base64.b64decode(line.split()[1])
            fp = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
            self.assertTrue(t.check(p, f"SHA256:{fp}"), seed)
            self.assertTrue(t.check(p, fp))                      # without prefix
            self.assertFalse(t.check(p, "SHA256:deadbeef"))

    def test_tls_capture_matches_wireshark(self):
        if not TSHARK:
            self.skipTest("tshark not installed")
        t = task("l08-transport", "tls-wireshark")
        for seed in range(6):
            p = t.params_for(seed)
            data = next(iter(t.files(p).values()))
            with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
                f.write(data)
                f.flush()

                def sh(*args):
                    return subprocess.run([TSHARK, "-r", f.name, *args],
                                          capture_output=True, text=True, check=True).stdout

                bad = sh("-o", "tcp.check_checksum:TRUE", "-o", "ip.check_checksum:TRUE",
                         "-Y", "_ws.malformed or _ws.expert.severity >= warning")
                self.assertEqual(bad.strip(), "", f"seed {seed} has warnings")

                sni = sh("-Y", "tls.handshake.type == 1", "-T", "fields",
                         "-e", "tls.handshake.extensions_server_name").strip()
                suite = sh("-Y", "tls.handshake.type == 2", "-T", "fields",
                           "-e", "tls.handshake.ciphersuite").strip()
                self.assertEqual(sni, p["sni"])
                self.assertEqual(t.check(p, f"{sni}, {suite}"), 1.0, f"seed {seed}")


class RenderTests(SimpleTestCase):
    def test_file_names_match_files(self):
        for slug in ("l07-auth", "l08-transport"):
            for tdef in content.get(slug).tasks:
                p = tdef.params_for(1)
                self.assertEqual(tdef.file_names(p), sorted(tdef.files(p)),
                                 f"{slug}/{tdef.key}")
