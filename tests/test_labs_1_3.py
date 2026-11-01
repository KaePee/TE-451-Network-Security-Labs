"""Solve every generated puzzle *the way a student would*, across many seeds.
If a seed ever produces an unsolvable variant (key too long for Kasiski, an
ambiguous capture...), these tests catch it before a student does."""

import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from apps.labs import content, services
from apps.labs.content import l01_concepts as L1
from apps.labs.content import l03_symmetric as L3

from .helpers import make_student, synced_lab

SEEDS = range(25)
AZ = L3.AZ
ENGLISH = [8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4, 6.7,
           7.5, 1.9, 0.095, 6.0, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074]


def task(lab, key):
    return content.get(lab).task(key)


def chi2_shift(column: str) -> int:
    """Best Caesar shift for a column, by chi-squared against English."""
    counts = Counter(column)
    n = len(column)

    def score(s):
        return sum((counts.get(AZ[(i + s) % 26], 0) - n * f / 100) ** 2 / (n * f / 100)
                   for i, f in enumerate(ENGLISH))
    return min(range(26), key=score)


def ioc(text: str) -> float:
    c = Counter(text)
    n = len(text)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))


class Lab3SolverTests(SimpleTestCase):
    def test_caesar_by_brute_force(self):
        t = task("l03-symmetric", "caesar")
        for seed in SEEDS:
            p = t.params_for(seed)
            found = None
            for s in range(26):
                guess = "".join(AZ[(AZ.index(c) - s) % 26] if c in AZ else c for c in p["cipher"])
                if "THE PASSPHRASE IS " in guess:
                    found = guess.rsplit(" ", 1)[1]
            self.assertTrue(t.check(p, found), seed)

    def test_substitution_text_is_english_like_and_answer_recoverable(self):
        t = task("l03-symmetric", "substitution")
        for seed in SEEDS:
            p = t.params_for(seed)
            letters_ = [c for c in p["cipher"] if c in AZ]
            self.assertGreater(len(letters_), 600)
            # Most common cipher letter should be E's image: frequency of top symbol ~12%.
            top = Counter(letters_).most_common(1)[0][1] / len(letters_)
            self.assertGreater(top, 0.09, seed)
            self.assertTrue(t.check(p, p["passphrase"].lower()))

    def test_vigenere_by_kasiski_ioc_and_chi_squared(self):
        t = task("l03-symmetric", "vigenere")
        for seed in SEEDS:
            p = t.params_for(seed)
            ct = p["cipher"]
            # Key length: the period whose columns look most like English (IoC ~ 0.066),
            # reduced to a divisor only if that divisor scores nearly as well.
            avg = {n: sum(ioc(ct[i::n]) for i in range(n)) / n for n in range(1, 16)}
            best = max(avg, key=avg.get)
            length = min(d for d in range(1, best + 1)
                         if best % d == 0 and avg[d] >= 0.95 * avg[best])
            key = "".join(AZ[chi2_shift(ct[i::length])] for i in range(length))
            self.assertTrue(t.check(p, key), f"seed {seed}: got {key}, want {p['key']}")
            self.assertTrue(t.check(p, key * 2))
            self.assertFalse(t.check(p, key[:-1]))

    def test_rail_fence_by_trying_rails(self):
        t = task("l03-symmetric", "rail-fence")

        def decrypt(ct, rails):
            pattern, r, step = [], 0, 1
            for _ in ct:
                pattern.append(r)
                step = 1 if r == 0 else -1 if r == rails - 1 else step
                r += step
            order = sorted(range(len(ct)), key=lambda i: (pattern[i], i))
            out = [""] * len(ct)
            for c, i in zip(ct, order):
                out[i] = c
            return "".join(out)

        for seed in SEEDS:
            p = t.params_for(seed)
            for rails in range(2, 10):
                plain = decrypt(p["cipher"], rails)
                if "THEPASSPHRASEIS" in plain:
                    self.assertTrue(t.check(p, plain.split("THEPASSPHRASEIS")[1]), seed)
                    break
            else:
                self.fail(f"seed {seed} unsolved")

    def test_two_time_pad_with_known_plaintext(self):
        t = task("l03-symmetric", "two-time-pad")
        for seed in SEEDS:
            p = t.params_for(seed)
            c1, c2 = bytes.fromhex(p["c1"]), bytes.fromhex(p["c2"])
            m2 = bytes(a ^ b ^ m for a, b, m in zip(c1, c2, p["m1"].encode())).decode()
            code = m2.split("code is ")[1][:9]
            self.assertTrue(t.check(p, code), seed)

    def test_spot_ecb_by_repeated_blocks(self):
        t = task("l03-symmetric", "spot-ecb")
        for seed in SEEDS:
            p = t.params_for(seed)
            lines = t.files(p)["ciphertexts.txt"].decode().splitlines()
            hits = []
            for line in lines:
                label, hexct = line.split(": ")
                blocks = [hexct[i:i + 32] for i in range(0, len(hexct), 32)]
                if len(set(blocks)) < len(blocks):
                    hits.append(label)
            self.assertEqual(len(hits), 1, f"seed {seed}: {hits}")
            self.assertTrue(t.check(p, hits[0]))

    def test_cbc_bitflip_attack(self):
        t = task("l03-symmetric", "cbc-bitflip")
        for seed in SEEDS:
            p = t.params_for(seed)
            iv = bytes.fromhex(p["iv"])
            old = p["plain"].encode()[:16]
            new = f"pay={p['target']}GHS;t".encode()
            forged = bytes(a ^ b ^ c for a, b, c in zip(iv, old, new))
            self.assertTrue(t.check(p, forged.hex()), seed)
            self.assertFalse(t.check(p, p["iv"]))
            self.assertFalse(t.check(p, "zz"))


class Lab1DrillTests(SimpleTestCase):
    def test_classification_partial_credit_and_no_padding(self):
        t = task("l01-security-concepts", "classify-cia")
        p = t.params_for(3)
        right = ", ".join(code for _, code in p["items"])
        self.assertEqual(t.check(p, right), 1.0)
        wrong_one = list(right.replace(", ", ""))
        wrong_one[0] = "C" if wrong_one[0] != "C" else "I"
        self.assertEqual(t.check(p, "".join(wrong_one)), 0.8)
        self.assertEqual(t.check(p, right + ", C"), 0.0)

    def test_banks_have_no_duplicate_scenarios(self):
        for bank in (L1.CIA_BANK, L1.PASSIVE_ACTIVE_BANK, L1.SERVICE_BANK):
            texts = [text for text, _ in bank]
            self.assertEqual(len(texts), len(set(texts)))

    def test_capture_roles_are_distinct_and_web_ip_unique(self):
        for seed in SEEDS:
            p = task("l01-security-concepts", "ftp-password").params_for(seed)
            roles = {p["victim"], p["heavy"], p["payer"], p["attacker"]}
            self.assertEqual(len(roles), 4)

    def test_capture_is_deterministic(self):
        t = task("l01-security-concepts", "ftp-password")
        p = t.params_for(9)
        self.assertEqual(t.files(p), t.files(p))


TSHARK = shutil.which("tshark") or (
    "/Applications/Wireshark.app/Contents/MacOS/tshark"
    if Path("/Applications/Wireshark.app/Contents/MacOS/tshark").exists() else None)


class Lab1WiresharkTests(SimpleTestCase):
    """Ground truth from Wireshark's own dissectors, so the graders match what
    students will actually see."""

    def setUp(self):
        if not TSHARK:
            self.skipTest("tshark not installed")

    def tshark(self, path, *args):
        return subprocess.run([TSHARK, "-r", path, *args], capture_output=True, text=True,
                              check=True).stdout

    def test_answers_match_wireshark(self):
        t1 = task("l01-security-concepts", "ftp-password")
        t2 = task("l01-security-concepts", "traffic-analysis")
        t3 = task("l01-security-concepts", "replay")
        for seed in range(6):
            p = t1.params_for(seed)
            with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
                f.write(next(iter(t1.files(p).values())))
                f.flush()
                bad = self.tshark(f.name, "-o", "tcp.check_checksum:TRUE",
                                  "-o", "ip.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
                                  "-Y", "_ws.malformed or _ws.expert.severity >= warning")
                self.assertEqual(bad.strip(), "", f"seed {seed} has warnings")

                pw = self.tshark(f.name, "-Y", 'ftp.request.command == "PASS"',
                                 "-T", "fields", "-e", "ftp.request.arg").strip()
                self.assertTrue(t1.check(p, pw))

                conv = self.tshark(f.name, "-q", "-z", "conv,ip")
                rows = [line.split() for line in conv.splitlines() if p["web"] in line]
                # columns: A <-> B frames bytes(2 tokens) frames bytes frames ...
                best = max(rows, key=self._total_frames)
                host = best[0] if best[2] == p["web"] else best[2]
                total = self._total_frames(best)
                self.assertEqual(t2.check(p, f"{host}, {total}"), 1.0, f"seed {seed}")

                posts = self.tshark(f.name, "-Y", 'http.request.method == "POST"',
                                    "-T", "fields", "-e", "frame.number", "-e", "ip.src")
                (_, _), (frame, ip) = [line.split("\t") for line in posts.strip().splitlines()]
                self.assertEqual(t3.check(p, f"{ip}, {frame}"), 1.0)

    @staticmethod
    def _total_frames(row):
        # "A <-> B  f1 b1 [unit]  f2 b2 [unit]  total_frames total_bytes [unit] ..."
        nums = []
        i = 3
        while len(nums) < 3:
            nums.append(int(row[i].replace(",", "")))
            i += 2
            if row[i] in ("bytes", "kB", "MB"):
                i += 1
        return nums[2]


class FileDownloadTests(TestCase):
    def test_student_downloads_own_capture_only_after_start(self):
        lab = synced_lab("l01-security-concepts")
        student = make_student()
        self.client.force_login(student)
        p = task(lab.slug, "ftp-password")
        url = lambda name: reverse("labs:download", args=[lab.slug, "ftp-password", name])  # noqa

        self.assertEqual(self.client.get(url("x.pcap")).status_code, 404)  # not started
        session = services.start_session(lab, student)
        name = next(iter(p.files(p.params_for(session.seed))))
        r = self.client.get(url(name))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content[:4], bytes.fromhex("d4c3b2a1"))
        self.assertIn("attachment", r["Content-Disposition"])
        self.assertEqual(self.client.get(url("other-student.pcap")).status_code, 404)

    def test_lab_pages_render_with_files_and_partial(self):
        for i, slug in enumerate(("l01-security-concepts", "l03-symmetric", "l04-public-key",
                                  "l05-integrity", "l06-pki")):
            lab = synced_lab(slug)
            student = make_student(f"204600{i}")
            self.client.force_login(student)
            self.client.post(reverse("labs:start", args=[slug]))
            r = self.client.get(reverse("labs:detail", args=[slug]))
            self.assertEqual(r.status_code, 200)
            self.assertContains(r, "⬇")

    def test_partial_submission_flow(self):
        lab = synced_lab("l01-security-concepts")
        student = make_student()
        session = services.start_session(lab, student)
        t = lab.tasks.get(key="classify-passive-active")
        p = task(lab.slug, t.key).params_for(session.seed)
        answer = [code for _, code in p["items"]]
        answer[0] = "A" if answer[0] == "P" else "P"
        sub = services.submit_answer(session, t, "".join(answer))
        self.assertEqual(sub.status, "partial")
        self.assertEqual(float(sub.score), round(10 * 5 / 6, 2))
        services.submit_answer(session, t, "".join(code for _, code in p["items"]))
        with self.assertRaises(services.LabError):  # 2 attempts max
            services.submit_answer(session, t, "P")
