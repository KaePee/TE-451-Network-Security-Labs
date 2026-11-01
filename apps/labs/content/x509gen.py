"""Deterministic X.509 certificates for Lab 6, built with `cryptography`.

Everything is derived from a seeded RNG so a student's certificates — and their
fingerprints — are identical every time the files are regenerated. That needs:
  * deterministic RSA keys (primes from the seeded rng, not os.urandom);
  * a fixed serial number and fixed validity dates;
  * PKCS#1 v1.5 signatures, which (unlike PSS) are deterministic.

These are toy 1024-bit keys for reading and chain-validation exercises, not for
protecting anything.
"""

import datetime
import random

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from .numtheory import random_prime_bits

PEM = serialization.Encoding.PEM
_EPOCH = datetime.datetime(2026, 1, 1)


def deterministic_rsa_key(rng: random.Random, bits: int = 1024) -> rsa.RSAPrivateKey:
    half = bits // 2
    p = random_prime_bits(rng, half)
    q = random_prime_bits(rng, half)
    while q == p:
        q = random_prime_bits(rng, half)
    if q > p:                       # iqmp needs q < p
        p, q = q, p
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    numbers = rsa.RSAPrivateNumbers(
        p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p),
        rsa.RSAPublicNumbers(e, p * q))
    return numbers.private_key()


def _name(cn: str, org: str = "KNUST TE451 Lab") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GH"),
    ])


def make_cert(rng, subject_cn, issuer_cn, issuer_key, subject_key=None, *,
              is_ca=False, days_from=-30, days_to=365, san=None, self_signed=False):
    """Build and sign one certificate. `days_from`/`days_to` are offsets in days
    from a fixed epoch, so an expired or not-yet-valid cert is just a date shift."""
    subject_key = subject_key or deterministic_rsa_key(rng)
    not_before = _EPOCH + datetime.timedelta(days=days_from)
    not_after = _EPOCH + datetime.timedelta(days=days_to)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(_name(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(rng.getrandbits(120) | 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(h) for h in san]), critical=False)
    signing_key = subject_key if self_signed else issuer_key
    cert = builder.sign(signing_key, hashes.SHA256())
    return cert, subject_key


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(PEM)


def verify_signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """True if `parent`'s public key signed `child`. Used by the solver test."""
    try:
        parent.public_key().verify(
            child.signature, child.tbs_certificate_bytes,
            padding.PKCS1v15(), child.signature_hash_algorithm)
        return True
    except Exception:
        return False
