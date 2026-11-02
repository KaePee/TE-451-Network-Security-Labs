"""Labs 9 and 10 solved the way a student would, across many seeds. The WPA2
dictionary attack is the expensive one, so it runs on fewer seeds."""

import base64
import hashlib
import ipaddress

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from django.test import SimpleTestCase

from apps.labs import content
from apps.labs.content import l09_wireless as L9

SEEDS = range(25)
CRACK_SEEDS = range(10)   # PBKDF2 over a wordlist is slow; a smaller sample is plenty.


def task(slug, key):
    return content.get(slug).task(key)


class Lab9SolverTests(SimpleTestCase):
    def test_pmk_matches_pbkdf2(self):
        t = task("l09-wireless", "wpa2-pmk")
        for seed in SEEDS:
            p = t.params_for(seed)
            pmk = hashlib.pbkdf2_hmac("sha1", p["passphrase"].encode(),
                                      p["ssid"].encode(), 4096, 32).hex()
            self.assertTrue(t.check(p, pmk), seed)
            self.assertTrue(t.check(p, pmk.upper()))             # case-insensitive
            self.assertFalse(t.check(p, "00" * 32))

    def test_crack_from_wordlist(self):
        t = task("l09-wireless", "crack-wifi")
        for seed in CRACK_SEEDS:
            p = t.params_for(seed)
            words = t.files(p)["wordlist.txt"].decode().split()
            target = L9._pmk(p["passphrase"], p["ssid"]).hex()
            found = next(w for w in words if L9._pmk(w, p["ssid"]).hex() == target)
            self.assertTrue(t.check(p, found), seed)
            self.assertIn(p["passphrase"], words)                # answer is in the list
            self.assertFalse(t.check(p, "not-in-list"))

    def test_evil_twin_is_the_duplicate_campus_ssid(self):
        t = task("l09-wireless", "rogue-ap")
        for seed in SEEDS:
            p = t.params_for(seed)
            rows = p["rows"]
            # A student reasons: two rows named KNUST-Secure; the real one is
            # WPA2-Enterprise, so the impostor is the other one.
            campus = [i for i, r in enumerate(rows) if r["ssid"] == L9.RogueAp.CAMPUS]
            self.assertEqual(len(campus), 2, seed)
            evil = next(i for i in campus if rows[i]["sec"] != "WPA2-Enterprise")
            self.assertEqual(evil, p["bad"], seed)
            self.assertTrue(t.check(p, t.LABELS[evil]), seed)
            self.assertFalse(t.check(p, t.LABELS[(evil + 1) % 5]))


class Lab10SolverTests(SimpleTestCase):
    def test_spf_membership(self):
        t = task("l10-email-ip", "spf-check")
        for seed in SEEDS:
            p = t.params_for(seed)
            nets = [ipaddress.ip_network(f"{o1}.{o2}.{o3}.0/24")
                    for o1, o2, o3 in p["blocks"]]
            answer = "".join(
                "Y" if any(ipaddress.ip_address(m["ip"]) in n for n in nets) else "N"
                for m in p["msgs"])
            self.assertEqual(t.check(p, ", ".join(answer)), 1.0, seed)
            # The intended answer always matches the generator's own labelling.
            self.assertEqual(answer,
                             "".join("Y" if m["role"] == "pass" else "N" for m in p["msgs"]))

    def test_verify_signature_finds_authentic_only(self):
        t = task("l10-email-ip", "verify-signature")
        for seed in SEEDS:
            p = t.params_for(seed)
            files = t.files(p)
            pub = serialization.load_pem_public_key(files["sender-public.pem"])
            authentic = []
            for lab in t.LABELS:
                msg, sig = files[f"email-{lab}.txt"], files[f"email-{lab}.sig"]
                try:
                    pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
                    authentic.append(lab)
                except Exception:
                    pass
            self.assertEqual(len(authentic), 2, seed)
            self.assertEqual(t.check(p, ", ".join(authentic)), 1.0, seed)
            # Naming one bad email as authentic costs a quarter.
            self.assertAlmostEqual(t.check(p, ", ".join(authentic + [
                next(c for c in t.LABELS if c not in authentic)])), 3 / 4)

    def test_ipsec_mode_by_endpoints(self):
        t = task("l10-email-ip", "ipsec-mode")
        for seed in SEEDS:
            p = t.params_for(seed)
            answer = "".join(mode for _, mode in p["items"])
            self.assertEqual(t.check(p, ", ".join(answer)), 1.0, seed)
            self.assertIn(set(answer) - {"T", "U"}, ({}, set()))


class RenderTests(SimpleTestCase):
    def test_file_names_match_files(self):
        for slug in ("l09-wireless", "l10-email-ip"):
            for tdef in content.get(slug).tasks:
                p = tdef.params_for(1)
                self.assertEqual(tdef.file_names(p), sorted(tdef.files(p)),
                                 f"{slug}/{tdef.key}")
