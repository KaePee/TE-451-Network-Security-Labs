"""Lab 4: public-key cryptography. Do RSA by hand, then break it three ways
(close primes, tiny exponent with no padding, a prime shared between devices).
Then break Diffie-Hellman twice: a small group, and a man in the middle.

Builds on the course repo's public_key/rsa_textbook.py and diffie_hellman.py;
the MITM task uses the same group as diffie_hellman.py.
"""

import hashlib
import math

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .base import LabDef, ManualTask, TaskDef, format_html, letters, mark_safe, parse_int
from .corpus import PASSPHRASES
from .numtheory import next_prime, random_prime, random_prime_bits, safe_prime

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
E = 65537


def _keypair(rng, bits: int, e: int = E, p: int | None = None) -> tuple[int, int, int]:
    """(p, q, n) with gcd(e, φ(n)) = 1. Pass `p` to force a shared prime."""
    half = bits // 2
    while True:
        pp = p or random_prime_bits(rng, half)
        q = random_prime_bits(rng, half)
        if pp != q and math.gcd(e, (pp - 1) * (q - 1)) == 1:
            return pp, q, pp * q


def _to_int(text: str) -> int:
    return int.from_bytes(text.encode(), "big")


def _passphrase_check(p, answer):
    return letters(answer, AZ) == p["passphrase"]


# ------------------------------------------------------------------------ RSA
class RsaByHand(TaskDef):
    key = "rsa-by-hand"
    title = "RSA key generation and decryption"
    placeholder = "d, m"

    def generate(self, rng):
        while True:
            p, q = random_prime(rng, 10**5, 10**6), random_prime(rng, 10**5, 10**6)
            if p != q and math.gcd(E, (p - 1) * (q - 1)) == 1:
                break
        n = p * q
        m = rng.randrange(10**9, n)
        return {"p": p, "q": q, "n": n, "c": pow(m, E, n), "m": m,
                "d": pow(E, -1, (p - 1) * (q - 1))}

    def prompt(self, p):
        return format_html(
            "<p>Follow the Lecture 4 recipe with your own primes. Compute the private "
            "exponent <code>d</code>, then decrypt the ciphertext <code>c</code>.</p>"
            "<pre>p = {}\nq = {}\ne = {}\nc = {}</pre>"
            "<p>Submit <code>d, m</code> (comma-separated). Half marks for each.</p>"
            "<p class=\"muted\">Check yourself: re-encrypt your m and you should get c back.</p>",
            p["p"], p["q"], E, p["c"])

    def check(self, p, answer):
        parts = [parse_int(x) for x in answer.replace(";", ",").split(",")]
        if len(parts) != 2:
            return 0.0
        return 0.5 * (parts[0] == p["d"]) + 0.5 * (parts[1] == p["m"])


class FermatFactor(TaskDef):
    key = "close-primes"
    title = "Weak key: primes too close together"
    points = 15
    placeholder = "the passphrase"

    def generate(self, rng):
        while True:
            p = random_prime_bits(rng, 256)
            q = next_prime(p + rng.randrange(2**20, 2**40))
            if math.gcd(E, (p - 1) * (q - 1)) == 1:
                break
        word = rng.choice(PASSPHRASES)
        n = p * q
        return {"n": n, "c": pow(_to_int(f"the passphrase is {word}"), E, n),
                "passphrase": word}

    def prompt(self, p):
        return format_html(
            "<p>A home-made key generator picked <code>p</code> at random, then took "
            "<code>q</code> as \"the next prime a little after p\". Here is a 512-bit public "
            "key and a message encrypted with it (plain UTF-8 text as a big-endian "
            "integer, no padding):</p><pre>n = {}\ne = {}\nc = {}</pre>"
            "<p>Factor <code>n</code>, build the private key and submit the passphrase.</p>"
            "<p class=\"muted\">If p and q are close, both are close to √n. Fermat's method: "
            "try a = ⌈√n⌉, a+1, … until a² − n is a perfect square b²; then "
            "n = (a − b)(a + b). Use <code>math.isqrt</code>: floats are far too imprecise "
            "at this size.</p>", p["n"], E, p["c"])

    check = staticmethod(_passphrase_check)


class SmallExponent(TaskDef):
    key = "small-e"
    title = "Textbook RSA: e = 3 and no padding"
    points = 10
    placeholder = "the passphrase"

    def generate(self, rng):
        _, _, n = _keypair(rng, 1024, e=3)
        word = rng.choice(PASSPHRASES)
        return {"n": n, "c": pow(_to_int(f"pin {word}"), 3, n), "passphrase": word}

    def prompt(self, p):
        return format_html(
            "<p>A 1024-bit key with the fast exponent <code>e = 3</code>. The sender "
            "encrypted a short PIN message with textbook RSA: no padding.</p>"
            "<pre>n = {}\ne = 3\nc = {}</pre>"
            "<p>You don't need to factor anything. Recover the message and submit the "
            "passphrase in it.</p>"
            "<p class=\"muted\">Compare the sizes of c and n. If m³ &lt; n, what does "
            "\"mod n\" do? You'll need an <em>integer</em> cube root (binary search or "
            "Newton's method); <code>c ** (1/3)</code> loses precision. Afterwards, think "
            "about what OAEP padding adds.</p>", p["n"], p["c"])

    check = staticmethod(_passphrase_check)


DEVICES = ["ap-library-1", "ap-library-2", "cam-main-gate", "printer-eng-3",
           "router-hall-7", "switch-core-a", "ups-server-room", "nvr-security",
           "ap-unity-hall", "router-ceng", "voip-gw-1", "badge-reader-4"]


class SharedPrime(TaskDef):
    key = "shared-prime"
    title = "Two devices, one prime"
    points = 15
    placeholder = "the passphrase"

    def generate(self, rng):
        names = rng.sample(DEVICES, 8)
        i, j = rng.sample(range(8), 2)
        shared = random_prime_bits(rng, 256)
        moduli = []
        for k in range(8):
            _, _, n = _keypair(rng, 512, p=shared if k in (i, j) else None)
            moduli.append(n)
        word = rng.choice(PASSPHRASES)
        c = pow(_to_int(f"the passphrase is {word}"), E, moduli[i])
        return {"names": names, "moduli": moduli, "target": names[i], "c": c,
                "passphrase": word}

    def files(self, p):
        lines = [f"{name} {n}" for name, n in zip(p["names"], p["moduli"])]
        return {"device-keys.txt": ("\n".join(lines) + "\n").encode()}

    def prompt(self, p):
        return format_html(
            "<p>You scanned the campus network and collected the 512-bit RSA public keys "
            "of eight embedded devices (all use <code>e = {}</code>). The devices booted "
            "with almost no randomness, and two of them ended up with one prime factor "
            "in common. A message to <code>{}</code> was captured:</p><pre>c = {}</pre>"
            "<p>Recover it and submit the passphrase.</p>"
            "<p class=\"muted\">Factoring one 512-bit n is hard. But what does "
            "<code>gcd(n₁, n₂)</code> cost? This exact flaw was found in tens of thousands "
            "of real devices in 2012 (\"Mining your Ps and Qs\").</p>",
            E, p["target"], p["c"])

    check = staticmethod(_passphrase_check)


# ---------------------------------------------------------------- Diffie-Hellman
class SmallGroupDH(TaskDef):
    key = "dh-small-group"
    title = "Eve vs. a small Diffie–Hellman group"
    points = 10
    placeholder = "the shared secret, an integer"

    def generate(self, rng):
        p = safe_prime(rng, 2**35, 2**36)
        q = (p - 1) // 2
        g = next(g for g in range(2, p) if pow(g, 2, p) != 1 and pow(g, q, p) != 1)
        a, b = rng.randrange(2, p - 1), rng.randrange(2, p - 1)
        return {"p": p, "g": g, "A": pow(g, a, p), "B": pow(g, b, p),
                "s": pow(g, a * b, p)}

    def prompt(self, p):
        return format_html(
            "<p>Alice and Bob ran Diffie–Hellman over a 36-bit group. As Eve, you saw "
            "everything on the wire:</p><pre>p = {}\ng = {}\nA = {}\nB = {}</pre>"
            "<p>Compute their shared secret <code>g<sup>ab</sup> mod p</code>.</p>"
            "<p class=\"muted\">Trying every exponent is about 2<sup>36</sup> steps: too "
            "slow. Baby-step giant-step finds the discrete log in about √p ≈ 2<sup>18</sup> "
            "steps with a dictionary. How many bits would p need before this is hopeless "
            "too? (p is a safe prime, so Pohlig–Hellman won't help.)</p>",
            p["p"], p["g"], p["A"], p["B"])

    def check(self, p, answer):
        return parse_int(answer) == p["s"]


# Oakley group 1 (RFC 2409), as in the course repo's public_key/diffie_hellman.py.
OAKLEY_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
    "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
OAKLEY_G = 2
_SECRET_BYTES = (OAKLEY_P.bit_length() + 7) // 8


def kdf(shared: int) -> bytes:
    return hashlib.sha256(shared.to_bytes(_SECRET_BYTES, "big")).digest()


def aes_ctr(key: bytes, nonce: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(data) + enc.finalize()


class DhMitm(TaskDef):
    key = "dh-mitm"
    title = "Man in the middle"
    points = 15
    placeholder = "hex: 16-byte nonce followed by ciphertext"

    def generate(self, rng):
        a, b, m = (rng.getrandbits(256) | 1 << 255 for _ in range(3))
        A, B = pow(OAKLEY_G, a, OAKLEY_P), pow(OAKLEY_G, b, OAKLEY_P)
        M = pow(OAKLEY_G, m, OAKLEY_P)
        amount = f"{rng.randrange(2, 90) * 500:,}"
        ref = f"{rng.getrandbits(32):08x}"
        acct, mallory = (f"{rng.randrange(10**9, 10**10)}" for _ in range(2))
        message = f"transfer GHS {amount} to acct {acct}; ref {ref}"
        nonce = rng.randbytes(16)
        ct = nonce + aes_ctr(kdf(pow(M, a, OAKLEY_P)), nonce, message.encode())
        return {"A": A, "B": B, "M": M, "m": m, "ct": ct.hex(), "mallory": mallory,
                "forged": f"transfer GHS {amount} to acct {mallory}; ref {ref}"}

    def files(self, p):
        text = (
            f"# Oakley group 1, as in public_key/diffie_hellman.py\n"
            f"p = 0x{OAKLEY_P:x}\ng = {OAKLEY_G}\n\n"
            f"# Intercepted: Alice -> Bob (you dropped it and sent M instead)\nA = 0x{p['A']:x}\n"
            f"# Intercepted: Bob -> Alice (you dropped it and sent M instead)\nB = 0x{p['B']:x}\n\n"
            f"# You (Mallory)\nm = 0x{p['m']:x}\nM = 0x{p['M']:x}\n\n"
            f"# Alice's first message, meant for Bob: nonce (16 bytes) || AES-256-CTR ciphertext\n"
            f"ct = {p['ct']}\n"
        )
        return {"mitm.txt": text.encode()}

    def prompt(self, p):
        return format_html(
            "<p>You are Mallory, sitting between Alice and Bob on the network. During their "
            "unauthenticated Diffie–Hellman exchange you replaced <em>both</em> public "
            "values with your own <code>M = g<sup>m</sup></code>, exactly like "
            "<code>mitm_exchange()</code> in the course repo. Alice now believes she shares "
            "a key with Bob, and has sent her first message. The file below has everything "
            "you intercepted.</p>"
            "<p>Both sides derive their AES key the same way:</p>"
            "<pre>from hashlib import sha256\n"
            "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n\n"
            "def kdf(s):  # s = the DH shared secret\n"
            "    return sha256(s.to_bytes(96, \"big\")).digest()\n\n"
            "def aes_ctr(key, nonce, data):  # encrypts and decrypts\n"
            "    c = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()\n"
            "    return c.update(data) + c.finalize()</pre>"
            "<p>Read Alice's message. Then forward it to Bob with one change: the account "
            "becomes yours, <code>{}</code>. Bob must be able to decrypt it with "
            "<em>his</em> key and see a message identical to Alice's except for the account "
            "number. Submit <code>nonce ‖ ciphertext</code> in hex.</p>"
            "<p class=\"muted\">Which shared secret does Alice hold? Which does Bob hold? "
            "Neither ever learns that the other is talking to you.</p>", p["mallory"])

    def check(self, p, answer):
        try:
            raw = bytes.fromhex(answer.strip().lower().removeprefix("0x"))
        except ValueError:
            return False
        if len(raw) <= 16:
            return False
        bob_key = kdf(pow(p["B"], p["m"], OAKLEY_P))  # Bob computed M^b = B^m
        return aes_ctr(bob_key, raw[:16], raw[16:]) == p["forged"].encode()


class HybridAndKeySizes(ManualTask):
    key = "hybrid-ecc"
    title = "Short answer: what real systems do"
    rubric = (
        "10 marks. [3] Fixes for what they broke: random independent primes from a "
        "CSPRNG with enough entropy (close primes, shared primes); OAEP padding, never "
        "textbook RSA (e=3 attack); DH groups ≥ 2048 bits or ECDH (small group). "
        "[3] MITM: DH must be authenticated, e.g. the server signs its DH share and the "
        "client checks the signature against a certificate (Lectures 5, 6, 8). "
        "[2] Hybrid: public key is slow, so it only agrees/moves a session key; bulk "
        "data uses fast symmetric AEAD (AES-GCM), as in TLS. [2] ECC: the elliptic-curve "
        "discrete log has no sub-exponential attack, so 256-bit ECC ≈ 3072-bit RSA; "
        "smaller keys mean less CPU, battery and bandwidth. Bonus credit within the 10 "
        "for forward secrecy (ephemeral keys)."
    )

    def prompt(self, p):
        return mark_safe(
            "<p>In 6–10 sentences: (a) for each attack in this lab, name the fix a real "
            "implementation uses; (b) how does TLS stop the man in the middle you just "
            "played? (c) why do real systems combine public-key and symmetric "
            "crypto instead of encrypting everything with RSA? (d) why does a phone "
            "prefer a 256-bit elliptic-curve key over a 3072-bit RSA key?</p>")


LAB = LabDef(
    slug="l04-public-key",
    lecture=4,
    title="Breaking public-key crypto",
    summary="RSA by hand, then three broken RSA keys (close primes, e = 3, a shared "
            "prime) and two broken Diffie–Hellman exchanges (small group, man in the "
            "middle).",
    intro=(
        "<p>RSA and Diffie–Hellman are only as strong as the way they're used. Each task "
        "here is a real mistake that has shipped in real products. Everything is a "
        "Lecture 2 tool: <code>pow(x, -1, m)</code>, <code>pow(b, e, n)</code>, "
        "<code>math.gcd</code> and <code>math.isqrt</code>. Start from the course repo's "
        "<code>public_key/</code> scripts.</p>"
        "<p class=\"small muted\">Text to integer and back: "
        "<code>int.from_bytes(s.encode(), \"big\")</code> and "
        "<code>m.to_bytes((m.bit_length() + 7) // 8, \"big\").decode()</code>. For the "
        "last auto-graded task, <code>pip install cryptography</code>.</p>"
    ),
    tasks=[RsaByHand(), FermatFactor(), SmallExponent(), SharedPrime(), SmallGroupDH(),
           DhMitm(), HybridAndKeySizes()],
)
