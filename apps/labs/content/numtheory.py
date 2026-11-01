"""Number-theory helpers used by lab generators and graders (not by students)."""

import math
import random

# Deterministic for n < 3.3e24 with these bases (Sorenson & Webster, 2015).
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41)


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _MR_BASES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in _MR_BASES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(rng: random.Random, lo: int, hi: int) -> int:
    while True:
        n = rng.randrange(lo, hi) | 1
        if is_prime(n):
            return n


def random_prime_bits(rng: random.Random, bits: int) -> int:
    """A prime of exactly `bits` bits (top bit set)."""
    return random_prime(rng, 1 << (bits - 1), 1 << bits)


def next_prime(n: int) -> int:
    n = n + 1 | 1
    while not is_prime(n):
        n += 2
    return n


def safe_prime(rng: random.Random, lo: int, hi: int) -> int:
    """p = 2q + 1 with q prime, so p - 1 has no small factors except 2
    (blocks Pohlig-Hellman shortcuts on the discrete log)."""
    while True:
        q = random_prime(rng, lo // 2, hi // 2)
        if is_prime(2 * q + 1):
            return 2 * q + 1


def crt(residues: list[int], moduli: list[int]) -> int:
    x, m = 0, 1
    for r, mi in zip(residues, moduli):
        # Solve x + m*t ≡ r (mod mi)
        t = ((r - x) * pow(m, -1, mi)) % mi
        x, m = x + m * t, m * mi
    return x % m


def coprime_moduli(rng: random.Random, count: int, lo: int, hi: int) -> list[int]:
    out: list[int] = []
    while len(out) < count:
        m = rng.randrange(lo, hi)
        if all(math.gcd(m, o) == 1 for o in out):
            out.append(m)
    return out


# Carmichael numbers: they fool the plain Fermat test for every coprime base.
CARMICHAEL = (561, 1105, 1729, 2465, 2821, 6601, 8911, 10585, 15841, 29341,
              41041, 46657, 52633, 62745, 63973, 75361, 101101, 115921, 126217)
