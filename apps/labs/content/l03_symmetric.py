"""Lab 3: symmetric encryption. Break the classical ciphers, then see why
modern block ciphers still need the right mode and authentication.

Builds on the course repo's symmetric_ciphers/one_time_pad.py (two-time pad).
"""

import random
import string

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .base import LabDef, ManualTask, TaskDef, format_html, letters, mark_safe
from .corpus import PARAGRAPHS, PASSPHRASES, SENTENCES, VIGENERE_KEYS

AZ = string.ascii_uppercase


def _letters_only(text: str) -> str:
    return "".join(c for c in text.upper() if c in AZ)


def _groups(text: str, n: int = 5, per_line: int = 10) -> str:
    chunks = [text[i:i + n] for i in range(0, len(text), n)]
    return "\n".join(" ".join(chunks[i:i + per_line]) for i in range(0, len(chunks), per_line))


def _passphrase_task_check(p, answer):
    return letters(answer, AZ) == p["passphrase"]


# ------------------------------------------------------------------ classical
class Caesar(TaskDef):
    key = "caesar"
    title = "Caesar: brute force"
    points = 5
    placeholder = "the passphrase"

    def generate(self, rng):
        word = rng.choice(PASSPHRASES)
        plain = f"{rng.choice(SENTENCES)}. The passphrase is {word}".upper()
        shift = rng.randrange(1, 26)
        cipher = "".join(AZ[(AZ.index(c) + shift) % 26] if c in AZ else c for c in plain)
        return {"cipher": cipher, "passphrase": word}

    def prompt(self, p):
        return format_html(
            "<p>Decrypt this Caesar ciphertext and submit the passphrase it contains.</p>"
            "<pre>{}</pre><p class=\"muted\">How many keys did you have to try, at most? "
            "What does that tell you about key-space size?</p>", p["cipher"])

    check = staticmethod(_passphrase_task_check)


class Substitution(TaskDef):
    key = "substitution"
    title = "Monoalphabetic substitution: frequency analysis"
    points = 15
    placeholder = "the passphrase"

    def generate(self, rng):
        word = rng.choice(PASSPHRASES)
        paras = rng.sample(PARAGRAPHS, 2)
        sentences = " ".join(paras).split(". ")
        at = rng.randrange(2, len(sentences) - 1)
        sentences.insert(at, f"The passphrase is {word.lower()}")
        plain = ". ".join(sentences).upper()
        perm = list(AZ)
        rng.shuffle(perm)
        table = str.maketrans(AZ, "".join(perm))
        return {"cipher": plain.translate(table), "passphrase": word}

    def files(self, p):
        return {"substitution.txt": (p["cipher"] + "\n").encode()}

    def prompt(self, p):
        return format_html(
            "<p>Every letter has been replaced by another, using one fixed (secret) "
            "scrambled alphabet. Spaces and punctuation were left alone. That's a gift: "
            "use it. With 26! ≈ 4×10<sup>26</sup> keys, brute force is hopeless.</p>"
            "<p>Count letter frequencies (a few lines of Python with "
            "<code>collections.Counter</code>), match them against English (E T A O I N …), "
            "and use short words like <code>THE</code> and <code>AND</code> to confirm "
            "guesses. Submit the passphrase hidden in the text.</p>"
            "<pre>{}</pre>", p["cipher"])

    check = staticmethod(_passphrase_task_check)


class Vigenere(TaskDef):
    key = "vigenere"
    title = "Vigenère: find the key (Kasiski)"
    points = 15
    placeholder = "the keyword"

    def generate(self, rng):
        key = rng.choice(VIGENERE_KEYS)
        plain = _letters_only(" ".join(rng.sample(PARAGRAPHS, 3)))
        shifts = [AZ.index(k) for k in key]
        cipher = "".join(AZ[(AZ.index(c) + shifts[i % len(key)]) % 26]
                         for i, c in enumerate(plain))
        return {"cipher": cipher, "key": key}

    def files(self, p):
        return {"vigenere.txt": (p["cipher"] + "\n").encode()}

    def prompt(self, p):
        return format_html(
            "<p>This English text was encrypted with a Vigenère cipher and then written in "
            "groups of five (spaces and punctuation removed). <strong>Find the "
            "keyword.</strong></p>"
            "<ol><li>Find repeated trigrams and the distances between them. Their common "
            "factor is likely the key length (Kasiski).</li>"
            "<li>Split the text into that many columns; each is a Caesar cipher.</li>"
            "<li>Solve each column by frequency analysis.</li></ol>"
            "<pre>{}</pre>", _groups(p["cipher"]))

    def check(self, p, answer):
        given = letters(answer, AZ)
        key = p["key"]
        # Accept the key repeated (e.g. CIPHERCIPHER): same cipher.
        return bool(given) and len(given) % len(key) == 0 and given == key * (len(given) // len(key))


class RailFence(TaskDef):
    key = "rail-fence"
    title = "Transposition: rail fence"
    points = 5
    placeholder = "the passphrase"

    def generate(self, rng):
        word = rng.choice(PASSPHRASES)
        plain = _letters_only(f"{rng.choice(SENTENCES)} the passphrase is {word}")
        rails = rng.randrange(3, 7)
        rows = [[] for _ in range(rails)]
        r, step = 0, 1
        for c in plain:
            rows[r].append(c)
            if r == 0:
                step = 1
            elif r == rails - 1:
                step = -1
            r += step
        return {"cipher": "".join("".join(row) for row in rows), "passphrase": word}

    def prompt(self, p):
        return format_html(
            "<p>Nothing was substituted here: the letters were only <em>reordered</em> by "
            "writing them in a zig-zag over several rails and reading off row by row. "
            "Recover the passphrase.</p><pre>{}</pre>"
            "<p class=\"muted\">Count the letters: are the frequencies still English? What "
            "does that tell you about using transposition on its own?</p>",
            _groups(p["cipher"]))

    check = staticmethod(_passphrase_task_check)


# --------------------------------------------------------------- two-time pad
NOTICES = [
    "PUBLIC NOTICE: the library will close early on Friday for maintenance of the air "
    "conditioning in the main reading room.",
    "PUBLIC NOTICE: all lecture halls in the engineering block will be closed on Saturday "
    "for fumigation. Please collect your belongings.",
    "PUBLIC NOTICE: the campus shuttle will run a reduced timetable during the vacation "
    "period starting next Monday morning at seven.",
]


class TwoTimePad(TaskDef):
    key = "two-time-pad"
    title = "One-time pad, used twice"
    points = 10
    placeholder = "the door code, e.g. 1234-5678"

    def generate(self, rng):
        code = f"{rng.randrange(1000, 10000)}-{rng.randrange(1000, 10000)}"
        m1 = rng.choice(NOTICES).encode()
        m2 = f"CONFIDENTIAL: the server room door code is {code}. Shred after reading.".encode()
        key = bytes(rng.randrange(256) for _ in range(len(m1)))
        c1 = bytes(a ^ b for a, b in zip(m1, key))
        c2 = bytes(a ^ b for a, b in zip(m2, key))
        return {"m1": m1.decode(), "c1": c1.hex(), "c2": c2.hex(), "code": code}

    def prompt(self, p):
        return format_html(
            "<p>An operator encrypted two messages with a one-time pad, but reused the "
            "<strong>same key</strong>. You intercepted both ciphertexts (hex):</p>"
            "<pre>c1 = {}\n\nc2 = {}</pre>"
            "<p>You also know <code>m1</code>: it was later pinned on a public noticeboard:</p>"
            "<blockquote>{}</blockquote>"
            "<p>Recover <code>m2</code> and submit the door code it contains.</p>"
            "<p class=\"muted\">Compare with <code>symmetric_ciphers/one_time_pad.py</code> "
            "in the course repo: why does <code>c1 ⊕ c2</code> not depend on the key?</p>",
            p["c1"], p["c2"], p["m1"])

    def check(self, p, answer):
        return "".join(c for c in answer if c.isdigit()) == p["code"].replace("-", "")


# ---------------------------------------------------------------- block modes
def _aes(key: bytes, mode) -> Cipher:
    return Cipher(algorithms.AES(key), mode)


def _pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


class SpotECB(TaskDef):
    key = "spot-ecb"
    title = "Which one is ECB?"
    points = 10
    placeholder = "a letter, A–F"
    max_attempts = 2
    LABELS = "ABCDEF"

    def generate(self, rng):
        key = rng.randbytes(16)
        ecb_index = rng.randrange(6)
        out = []
        for i in range(6):
            accounts = [f"ACCT {rng.randrange(10**9, 10**10)};" for _ in range(3)]
            # A ledger: 16-byte rows, many of them repeated. Realistic, and fatal for ECB.
            rows = [rng.choice(accounts).encode()[:16].ljust(16, b" ") for _ in range(16)]
            plain = b"".join(rows)
            if i == ecb_index:
                enc = _aes(key, modes.ECB()).encryptor()
                ct = enc.update(plain) + enc.finalize()
            elif rng.random() < 0.5:
                iv = rng.randbytes(16)
                enc = _aes(key, modes.CBC(iv)).encryptor()
                ct = iv + enc.update(plain) + enc.finalize()
            else:
                nonce = rng.randbytes(16)
                enc = _aes(key, modes.CTR(nonce)).encryptor()
                ct = nonce + enc.update(plain) + enc.finalize()
            out.append(ct.hex())
        return {"cts": out, "ecb": self.LABELS[ecb_index]}

    def files(self, p):
        lines = [f"{label}: {ct}" for label, ct in zip(self.LABELS, p["cts"])]
        return {"ciphertexts.txt": ("\n".join(lines) + "\n").encode()}

    def prompt(self, p):
        return mark_safe(
            "<p>The file below holds six AES-128 ciphertexts (hex), one per line, all "
            "encrypting similar ledgers under the same key. Five used CBC or CTR mode, "
            "with a random IV or nonce in front. <strong>One used ECB.</strong> Which one?</p>"
            "<p class=\"muted\">Split each into 16-byte blocks (32 hex characters) and look "
            "for something that should never happen. This is the \"ECB penguin\", without "
            "the penguin. 2 attempts.</p>")

    def check(self, p, answer):
        return letters(answer, self.LABELS) == p["ecb"]


class CbcBitFlip(TaskDef):
    key = "cbc-bitflip"
    title = "CBC bit-flipping: encryption is not integrity"
    points = 15
    placeholder = "32 hex characters"

    def generate(self, rng):
        key, iv = rng.randbytes(16), rng.randbytes(16)
        acct = f"{rng.randrange(10**9, 10**10)}"
        ref = f"{rng.getrandbits(32):08x}"
        plain = f"pay=0000100GHS;to={acct};ref={ref}".encode()
        enc = _aes(key, modes.CBC(iv)).encryptor()
        ct = enc.update(_pad(plain)) + enc.finalize()
        target = f"{rng.randrange(5_000_000, 9_999_999):07d}"
        return {"key": key.hex(), "iv": iv.hex(), "ct": ct.hex(), "plain": plain.decode(),
                "target": target}

    def prompt(self, p):
        return format_html(
            "<p>A payment gateway receives AES-128-CBC messages as <code>IV ‖ ciphertext</code> "
            "and trusts whatever decrypts correctly. The message format is public; you "
            "intercepted this one, whose plaintext you know:</p>"
            "<pre>plaintext  = {}\nIV         = {}\nciphertext = {}</pre>"
            "<p>Without the key, produce a new <strong>IV</strong> so that the same "
            "ciphertext decrypts to a payment of <code>{}</code> GHS instead of "
            "<code>0000100</code> (the rest of the message unchanged). Submit the new IV "
            "in hex.</p>"
            "<p class=\"muted\">In CBC, P<sub>1</sub> = D<sub>k</sub>(C<sub>1</sub>) ⊕ IV. "
            "What happens to P<sub>1</sub> if you flip a bit of the IV?</p>",
            p["plain"], p["iv"], p["ct"], p["target"])

    def check(self, p, answer):
        try:
            new_iv = bytes.fromhex(answer.strip().lower().removeprefix("0x"))
        except ValueError:
            return False
        if len(new_iv) != 16:
            return False
        key, ct = bytes.fromhex(p["key"]), bytes.fromhex(p["ct"])
        dec = _aes(key, modes.CBC(new_iv)).decryptor()
        first = (dec.update(ct) + dec.finalize())[:16]
        return first == f"pay={p['target']}GHS;t".encode()


class WhyAEAD(ManualTask):
    key = "why-aead"
    title = "Short answer: what should the gateway have used?"
    rubric = (
        "10 marks. [3] ECB: identical plaintext blocks give identical ciphertext blocks, "
        "so structure leaks (the task they solved). [3] CBC alone gives confidentiality, "
        "not integrity: flipping IV/ciphertext bits flips predictable plaintext bits "
        "(malleability), so an attacker without the key changed the amount. [4] "
        "Recommends authenticated encryption (AES-GCM or ChaCha20-Poly1305), or "
        "encrypt-then-MAC, and explains that the receiver verifies the tag *before* "
        "using the plaintext, so any modification is rejected. Mentions nonce/IV must "
        "never repeat under one key for full marks."
    )

    def prompt(self, p):
        return mark_safe(
            "<p>Using what you found in the last two tasks, explain in 5–8 sentences: "
            "(a) what ECB leaks and why; (b) why CBC kept the payment <em>secret</em> but "
            "still let you change it; (c) what the gateway should use instead, and how it "
            "would have stopped your attack.</p>")


LAB = LabDef(
    slug="l03-symmetric",
    lecture=3,
    title="Breaking symmetric ciphers",
    summary="Caesar, substitution, Vigenère, rail fence and a reused one-time pad by "
            "hand; then ECB's leak and a CBC bit-flipping attack on AES.",
    intro=(
        "<p>Lecture 3's lesson, made concrete: a huge key space is not enough if structure "
        "leaks, and a strong block cipher is not enough if you use it in the wrong mode. "
        "Use Python throughout. The tasks get harder as you go, so budget your time.</p>"
        "<p class=\"small muted\">Tip: <code>bytes.fromhex()</code>, "
        "<code>bytes(a ^ b for a, b in zip(x, y))</code> and <code>collections.Counter</code> "
        "will carry you a long way. For AES, <code>pip install cryptography</code>.</p>"
    ),
    tasks=[Caesar(), Substitution(), Vigenere(), RailFence(), TwoTimePad(), SpotECB(),
           CbcBitFlip(), WhyAEAD()],
)
