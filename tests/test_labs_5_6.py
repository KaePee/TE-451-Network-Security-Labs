"""Labs 5 and 6 solved the way a student would, across many seeds."""

import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from django.test import SimpleTestCase

from apps.labs import content
from apps.labs.content import x509gen
from apps.labs.content.corpus import LEAKED_PASSWORDS

SEEDS = range(25)
LAB6_SEEDS = range(8)  # each seed builds a full PKI (~0.3s), so fewer
WORDLIST = set(LEAKED_PASSWORDS)


def task(slug, key):
    return content.get(slug).task(key)


class Lab5SolverTests(SimpleTestCase):
    def test_identify_hash_by_length(self):
        t = task("l05-integrity", "identify-hash")
        by_len = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
        for seed in SEEDS:
            p = t.params_for(seed)
            answer = ", ".join(by_len[len(it["digest"])] for it in p["items"])
            self.assertEqual(t.check(p, answer), 1.0, seed)
            # One wrong label -> partial, never full.
            self.assertLess(t.check(p, "MD5, MD5, MD5"), 1.0)

    def test_crack_unsalted_from_wordlist(self):
        t = task("l05-integrity", "crack-unsalted")
        for seed in SEEDS:
            p = t.params_for(seed)
            cracked = next(w for w in WORDLIST
                           if hashlib.new(p["algo"], w.encode()).hexdigest() == p["digest"])
            self.assertTrue(t.check(p, cracked), seed)
            self.assertFalse(t.check(p, cracked + "x"))

    def test_crack_salted_needs_the_salt(self):
        t = task("l05-integrity", "crack-salted")
        for seed in SEEDS:
            p = t.params_for(seed)
            cracked = []
            for u in p["users"]:
                hit = next(w for w in WORDLIST
                           if hashlib.sha256((u["salt"] + w).encode()).hexdigest() == u["digest"])
                cracked.append(hit)
            self.assertEqual(t.check(p, ", ".join(cracked)), 1.0, seed)
            # The two users share a password but not a digest (that's the lesson).
            self.assertEqual(cracked[0], cracked[1])
            self.assertNotEqual(p["users"][0]["digest"], p["users"][1]["digest"])
            # The file carries the salts the student needs.
            shadow = t.files(p)["shadow.txt"].decode()
            for u in p["users"]:
                self.assertIn(u["salt"], shadow)

    def test_hmac_forge_with_leaked_key(self):
        t = task("l05-integrity", "hmac-verify")
        for seed in SEEDS:
            p = t.params_for(seed)
            # Verify the original tag first (what the prompt asks).
            good = hmac.new(bytes.fromhex(p["key"]), p["message"].encode(), "sha256").hexdigest()
            self.assertEqual(good, p["tag"])
            forged = p["message"].replace(p["acct"], p["target_acct"])
            tag = hmac.new(bytes.fromhex(p["key"]), forged.encode(), "sha256").hexdigest()
            self.assertTrue(t.check(p, f"{forged}:{tag}"), seed)
            # Replaying the original message/tag is not the forgery we asked for.
            self.assertFalse(t.check(p, f"{p['message']}:{p['tag']}"))
            # Right message, wrong tag -> rejected.
            self.assertFalse(t.check(p, f"{forged}:{'0' * 64}"))


class Lab6SolverTests(SimpleTestCase):
    def test_read_cert_fingerprint(self):
        t = task("l06-pki", "read-cert")
        for seed in LAB6_SEEDS:
            p = t.params_for(seed)
            pem = t.files(p)["server.pem"]
            cert = x509.load_pem_x509_certificate(pem)
            fp = cert.fingerprint(hashes.SHA256()).hex()
            self.assertTrue(t.check(p, fp), seed)
            self.assertTrue(t.check(p, ":".join(fp[i:i+2] for i in range(0, len(fp), 2))))
            self.assertFalse(t.check(p, "00"))

    def test_files_are_reproducible(self):
        t = task("l06-pki", "read-cert")
        p = t.params_for(5)
        self.assertEqual(t.files(p)["server.pem"], t.files(p)["server.pem"])

    def test_chain_by_verifying_signatures(self):
        t = task("l06-pki", "chain-of-trust")
        for seed in LAB6_SEEDS:
            p = t.params_for(seed)
            files = t.files(p)
            certs = {lab: x509.load_pem_x509_certificate(files[f"cert-{lab}.pem"])
                     for lab in "ABC"}
            # Root is self-signed; then find who signed each remaining cert.
            root = next(l for l, c in certs.items() if x509gen.verify_signed_by(c, c))
            pairs = []
            for parent in "ABC":
                for child in "ABC":
                    if parent != child and x509gen.verify_signed_by(certs[child], certs[parent]):
                        pairs.append((parent, child))
            self.assertEqual(len(pairs), 2, seed)                 # root->inter, inter->leaf
            answer = ", ".join(f"{a} signed {b}" for a, b in pairs)
            self.assertEqual(t.check(p, answer), 1.0, f"seed {seed}, root {root}")
            self.assertLessEqual(t.check(p, f"{pairs[0][0]} signed {pairs[0][1]}"), 0.5)

    def test_spot_bad_cert_by_dates_and_san(self):
        import datetime
        t = task("l06-pki", "spot-bad-cert")
        today = x509gen._EPOCH                                    # the lab's "today"
        for seed in LAB6_SEEDS:
            p = t.params_for(seed)
            files = t.files(p)
            host = f"{p['host']}.knust.edu.gh"
            valid = []
            for lab in "ABCD":
                cert = x509.load_pem_x509_certificate(files[f"cert-{lab}.pem"])
                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                ok = (cert.not_valid_before_utc.replace(tzinfo=None) <= today
                      <= cert.not_valid_after_utc.replace(tzinfo=None) and host in san)
                if ok:
                    valid.append(lab)
            self.assertEqual(len(valid), 1, f"seed {seed}: {valid}")
            self.assertTrue(t.check(p, f"{valid[0]} — the others are expired/invalid"))
            wrong = next(l for l in "ABCD" if l != valid[0])
            self.assertFalse(t.check(p, wrong))


class RenderTests(SimpleTestCase):
    def test_file_names_match_files(self):
        for slug in ("l05-integrity", "l06-pki"):
            for tdef in content.get(slug).tasks:
                p = tdef.params_for(2)
                self.assertEqual(tdef.file_names(p), sorted(tdef.files(p)),
                                 f"{slug}/{tdef.key}")
