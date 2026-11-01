"""Lab 4 solved the way a student would, across many seeds (see test_labs_1_3)."""

import math
from itertools import combinations

from django.test import SimpleTestCase

from apps.labs import content
from apps.labs.content import l04_public_key as L4

SEEDS = range(25)
E = 65537


def task(key):
    return content.get("l04-public-key").task(key)


def to_text(m: int) -> str:
    return m.to_bytes((m.bit_length() + 7) // 8, "big").decode()


def icbrt(n: int) -> int:
    lo, hi = 0, 1 << (n.bit_length() // 3 + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


def fermat(n: int, limit: int = 10**6) -> tuple[int, int]:
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(limit):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    raise AssertionError("Fermat did not finish")


def bsgs(g: int, h: int, p: int) -> int:
    m = math.isqrt(p - 1) + 1
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * g % p
    step = pow(g, -m, p)
    y = h
    for i in range(m):
        if y in table:
            return i * m + table[y]
        y = y * step % p
    raise AssertionError("no log")


class Lab4SolverTests(SimpleTestCase):
    def test_rsa_by_hand_with_partial_credit(self):
        t = task("rsa-by-hand")
        for seed in SEEDS:
            p = t.params_for(seed)
            d = pow(E, -1, (p["p"] - 1) * (p["q"] - 1))
            m = pow(p["c"], d, p["p"] * p["q"])
            self.assertEqual(t.check(p, f"{d}, {m}"), 1.0)
            self.assertEqual(t.check(p, f"{d}, {m + 1}"), 0.5)
            self.assertEqual(t.check(p, f"{d}"), 0.0)

    def test_close_primes_fall_to_fermat(self):
        t = task("close-primes")
        for seed in SEEDS:
            p = t.params_for(seed)
            a, b = fermat(p["n"])
            self.assertEqual(a * b, p["n"])
            d = pow(E, -1, (a - 1) * (b - 1))
            text = to_text(pow(p["c"], d, p["n"]))
            self.assertTrue(t.check(p, text.rsplit(" ", 1)[1]), seed)

    def test_e3_cube_root_without_factoring(self):
        t = task("small-e")
        for seed in SEEDS:
            p = t.params_for(seed)
            self.assertGreater(p["n"].bit_length(), 1020)
            m = icbrt(p["c"])
            self.assertEqual(m ** 3, p["c"], f"seed {seed}: m^3 wrapped mod n")
            self.assertTrue(t.check(p, to_text(m).split()[-1]), seed)
            # The trap: floating-point cube roots give the wrong integer.
            self.assertNotEqual(round(p["c"] ** (1 / 3)), m)

    def test_shared_prime_by_pairwise_gcd(self):
        t = task("shared-prime")
        for seed in SEEDS:
            p = t.params_for(seed)
            lines = t.files(p)["device-keys.txt"].decode().split("\n")
            keys = dict(line.split() for line in lines if line)
            keys = {name: int(n) for name, n in keys.items()}
            hits = [(x, y) for x, y in combinations(keys, 2)
                    if math.gcd(keys[x], keys[y]) > 1]
            self.assertEqual(len(hits), 1, seed)
            self.assertIn(p["target"], hits[0])
            n = keys[p["target"]]
            other = next(x for x in hits[0] if x != p["target"])
            q1 = math.gcd(n, keys[other])
            d = pow(E, -1, (q1 - 1) * (n // q1 - 1))
            self.assertTrue(t.check(p, to_text(pow(p["c"], d, n)).split()[-1]))

    def test_small_dh_group_by_baby_step_giant_step(self):
        t = task("dh-small-group")
        for seed in range(10):
            p = t.params_for(seed)
            self.assertLess(p["p"], 2**36)
            a = bsgs(p["g"], p["A"], p["p"])
            self.assertTrue(t.check(p, str(pow(p["B"], a, p["p"]))), seed)
            self.assertFalse(t.check(p, str(p["A"] * p["B"] % p["p"])))

    def test_mitm_read_and_reencrypt_for_bob(self):
        t = task("dh-mitm")
        for seed in SEEDS:
            p = t.params_for(seed)
            values = {}
            for line in t.files(p)["mitm.txt"].decode().splitlines():
                if " = " in line:
                    name, value = line.split(" = ")
                    values[name] = value
            P, m = int(values["p"], 16), int(values["m"], 16)
            self.assertEqual(P, L4.OAKLEY_P)
            ct = bytes.fromhex(values["ct"])
            alice_key = L4.kdf(pow(int(values["A"], 16), m, P))
            message = L4.aes_ctr(alice_key, ct[:16], ct[16:]).decode()
            acct = message.split("acct ")[1].split(";")[0]
            forged = message.replace(acct, p["mallory"]).encode()
            bob_key = L4.kdf(pow(int(values["B"], 16), m, P))
            nonce = bytes(16)
            self.assertTrue(t.check(p, (nonce + L4.aes_ctr(bob_key, nonce, forged)).hex()))
            # Replaying Alice's ciphertext, or encrypting under Alice's key, fails.
            self.assertFalse(t.check(p, ct.hex()))
            self.assertFalse(t.check(p, (nonce + L4.aes_ctr(alice_key, nonce, forged)).hex()))
            self.assertFalse(t.check(p, "not hex"))

    def test_kdf_matches_prompt_snippet(self):
        # The prompt tells students s.to_bytes(96, "big").
        self.assertEqual(L4._SECRET_BYTES, 96)


class FileNamesTests(SimpleTestCase):
    def test_file_names_match_files_for_every_task(self):
        for lab in content.LABS:
            for t in lab.tasks:
                p = t.params_for(4)
                self.assertEqual(t.file_names(p), sorted(t.files(p)), f"{lab.slug}/{t.key}")
