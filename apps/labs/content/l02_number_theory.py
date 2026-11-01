"""Lab 2: the number theory toolkit that RSA and Diffie-Hellman are built on.

Mirrors the course repo's number_theory/ scripts (gcd_algorithm.py,
chinese_remainder_theorem.py, miller_rabin_algorithm.py): students may start
from those, but every student's numbers are different.
"""

import math

from .base import LabDef, ManualTask, TaskDef, format_html, mark_safe, parse_int
from .numtheory import CARMICHAEL, coprime_moduli, crt, is_prime, random_prime


class BigGcd(TaskDef):
    key = "gcd"
    title = "Euclid on big numbers"
    placeholder = "an integer"

    def generate(self, rng):
        g = random_prime(rng, 10**11, 10**12) * rng.randrange(2, 50)
        a = g * random_prime(rng, 10**14, 10**15)
        b = g * random_prime(rng, 10**14, 10**15)
        return {"a": a, "b": b}

    def prompt(self, p):
        return format_html(
            "<p>Compute <code>gcd(a, b)</code> using the Euclidean algorithm. Write your "
            "own loop; don't call <code>math.gcd</code> until you've checked it.</p>"
            "<pre>a = {}\nb = {}</pre>", p["a"], p["b"])

    def check(self, p, answer):
        return parse_int(answer) == math.gcd(p["a"], p["b"])


class ModInverse(TaskDef):
    key = "mod-inverse"
    title = "Modular inverse (extended Euclid)"
    placeholder = "an integer in [0, m)"

    def generate(self, rng):
        m = random_prime(rng, 10**12, 10**13)
        return {"a": rng.randrange(2, m - 1), "m": m}

    def prompt(self, p):
        return format_html(
            "<p>Find <code>x</code> with <code>a·x ≡ 1 (mod m)</code>, "
            "and <code>0 ≤ x &lt; m</code>.</p>"
            "<pre>a = {}\nm = {}</pre>"
            "<p class=\"muted\">This is exactly how RSA computes the private exponent d "
            "from e.</p>", p["a"], p["m"])

    def check(self, p, answer):
        return parse_int(answer) == pow(p["a"], -1, p["m"])


class ModExp(TaskDef):
    key = "mod-exp"
    title = "Square-and-multiply"
    placeholder = "an integer"

    def generate(self, rng):
        n = random_prime(rng, 10**15, 10**16) * random_prime(rng, 10**15, 10**16)
        return {"b": rng.randrange(2, n), "e": rng.getrandbits(200) | 1, "n": n}

    def prompt(self, p):
        return format_html(
            "<p>Compute <code>b<sup>e</sup> mod n</code>. Note that <code>e</code> has "
            "about 60 digits, so computing <code>b**e</code> first will never finish. "
            "Use square-and-multiply (or explain to yourself why <code>pow(b, e, n)</code> "
            "is fast).</p><pre>b = {}\ne = {}\nn = {}</pre>", p["b"], p["e"], p["n"])

    def check(self, p, answer):
        return parse_int(answer) == pow(p["b"], p["e"], p["n"])


class ChineseRemainder(TaskDef):
    key = "crt"
    title = "Chinese Remainder Theorem"
    placeholder = "smallest non-negative x"

    def generate(self, rng):
        moduli = coprime_moduli(rng, 3, 100, 1000)
        residues = [rng.randrange(m) for m in moduli]
        return {"m": moduli, "r": residues}

    def prompt(self, p):
        lines = "\n".join(f"x ≡ {r} (mod {m})" for r, m in zip(p["r"], p["m"]))
        return format_html(
            "<p>Find the smallest non-negative <code>x</code> satisfying all three:</p>"
            "<pre>{}</pre>", lines)

    def check(self, p, answer):
        return parse_int(answer) == crt(p["r"], p["m"])


class SpotThePrimes(TaskDef):
    key = "miller-rabin"
    title = "Spot the primes"
    points = 15
    placeholder = "e.g. B, D"
    LETTERS = "ABCDEF"

    def generate(self, rng):
        nums = [
            random_prime(rng, 10**12, 10**13),
            random_prime(rng, 10**15, 10**16),
            rng.choice(CARMICHAEL[6:]),                         # fools Fermat
            random_prime(rng, 10**6, 10**7) * random_prime(rng, 10**6, 10**7),
            random_prime(rng, 10**3, 10**4) ** 2,
            rng.randrange(10**13, 10**14) | 1,                  # probably composite
        ]
        rng.shuffle(nums)
        return {"nums": nums}

    def prompt(self, p):
        rows = "\n".join(f"{l} = {n}" for l, n in zip(self.LETTERS, p["nums"]))
        return format_html(
            "<p>Which of these are prime? Implement Miller–Rabin (see "
            "<code>number_theory/miller_rabin_algorithm.py</code>) and submit the letters "
            "of <strong>all</strong> primes, comma-separated.</p><pre>{}</pre>"
            "<p class=\"muted\">Try the plain Fermat test on each one too. Does it agree?</p>",
            rows)

    def check(self, p, answer):
        given = {c for c in answer.upper() if c in self.LETTERS}
        expected = {l for l, n in zip(self.LETTERS, p["nums"]) if is_prime(n)}
        return given == expected


class EulerPhi(TaskDef):
    key = "euler-phi"
    title = "Euler's totient"
    placeholder = "an integer"

    def generate(self, rng):
        p = random_prime(rng, 100, 1000)
        q = random_prime(rng, 1000, 5000)
        return {"n": p * p * q, "p": p, "q": q}

    def prompt(self, p):
        return format_html(
            "<p>Compute <code>φ(n)</code>. You will need to factor <code>n</code> first. "
            "Trial division is fine at this size.</p><pre>n = {}</pre>", p["n"])

    def check(self, p, answer):
        pp, q = p["p"], p["q"]
        return parse_int(answer) == pp * (pp - 1) * (q - 1)


class FermatVsMillerRabin(ManualTask):
    key = "explain-carmichael"
    title = "Short answer: why Fermat is fooled"
    rubric = (
        "Full marks (10): (a) defines a Carmichael number as a composite n with "
        "a^(n-1) ≡ 1 (mod n) for every a coprime to n, so the Fermat test passes for "
        "all such bases [4]; (b) explains that Miller–Rabin also checks the chain "
        "a^d, a^(2d), …, looking for a non-trivial square root of 1, which exposes "
        "Carmichael numbers [4]; (c) states that each random base has error ≤ 1/4, so k "
        "rounds give ≤ 4^-k [2]."
    )

    def prompt(self, p):
        return mark_safe(
            "<p>In 4–6 sentences: one of the numbers in “Spot the primes” passes the "
            "Fermat test for almost every base but is composite. What is this kind of "
            "number called, and what extra check does Miller–Rabin make that catches it? "
            "How does the error probability shrink with more rounds?</p>")


LAB = LabDef(
    slug="l02-number-theory",
    lecture=2,
    title="Number theory toolkit",
    summary="GCD, modular inverses, fast exponentiation, CRT, primality and φ(n), "
            "each with your own numbers.",
    intro=(
        "<p>Every public-key system in Lecture 4 is built from the operations in this "
        "lab. Use Python. You may reuse the course repo's <code>number_theory/</code> "
        "scripts, but you must understand every line you submit with.</p>"
    ),
    tasks=[BigGcd(), ModInverse(), ModExp(), ChineseRemainder(), SpotThePrimes(),
           EulerPhi(), FermatVsMillerRabin()],
)
