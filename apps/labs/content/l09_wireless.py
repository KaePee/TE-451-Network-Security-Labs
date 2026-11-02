"""Lab 9: wireless and mobile security. Derive the WPA2 pairwise master key
the way the standard does (PBKDF2 over the passphrase and SSID), run an offline
dictionary attack against a weak Wi-Fi passphrase, and spot an evil-twin access
point in a scan.

Covers Lecture 9: WEP's failure, WPA2-PSK (the 4-way handshake and PMK/PTK),
WPA3-SAE, and wireless/mobile threats (rogue APs, deauthentication, BYOD).

Lawful use only: the dictionary attack here is against a passphrase in a lab
you own. Attacking a network you are not authorised to test is an offence.
"""

import hashlib

from .base import (LabDef, ManualTask, TaskDef, fraction_matching, format_html,
                   mark_safe, normalise)
from . import corpus
from .pcap import random_mac

SSIDS = ["KNUST-Secure", "KNUST-Guest", "CoE-WiFi", "Hall6-WiFi",
         "Library-Net", "Engineering"]

# 8+ character passphrases (WPA2 requires at least 8) that a careless user
# might pick — all weak enough to sit in a wordlist.
WIFI_PASSPHRASES = ["sunshine99", "kumasi2024", "blackstars7", "ashantigold",
                    "obuasi123", "greenhill88", "palmwine22", "harmattan9",
                    "kente4life", "baobabtree", "sankofa21", "goldcoast88"]


def _pmk(passphrase: str, ssid: str) -> bytes:
    """WPA2-PSK pairwise master key: PBKDF2-HMAC-SHA1, 4096 iters, SSID as salt."""
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode(), ssid.encode(), 4096, 32)


class Wpa2Pmk(TaskDef):
    key = "wpa2-pmk"
    title = "Derive the WPA2 pairwise master key"
    points = 15
    placeholder = "64 hex characters"

    def generate(self, rng):
        return {"ssid": rng.choice(SSIDS), "passphrase": rng.choice(WIFI_PASSPHRASES)}

    def prompt(self, p):
        return format_html(
            "<p>On a WPA2-Personal (WPA2-PSK) network, every device turns the Wi-Fi "
            "passphrase into a 256-bit <strong>pairwise master key (PMK)</strong> before "
            "the 4-way handshake even starts. The standard defines it as:</p>"
            "<pre>PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096, 256 bits)</pre>"
            "<p>The SSID is used as the salt and the work factor is 4096 iterations. For "
            "this network:</p><pre>SSID       = {}\npassphrase = {}</pre>"
            "<p>Compute the PMK and submit it as 64 hex characters.</p>"
            "<p class=\"muted\">One line of Python does it: "
            "<code>hashlib.pbkdf2_hmac(\"sha1\", passphrase, ssid, 4096, 32).hex()</code>. "
            "Notice the SSID is the salt — so two networks with the same passphrase but "
            "different names produce different PMKs. Why does that matter?</p>",
            p["ssid"], p["passphrase"])

    def check(self, p, answer):
        clean = "".join(c for c in answer.lower() if c in "0123456789abcdef")
        return clean == _pmk(p["passphrase"], p["ssid"]).hex()


class CrackWifi(TaskDef):
    key = "crack-wifi"
    title = "Crack a WPA2 passphrase offline"
    points = 15
    placeholder = "the Wi-Fi passphrase"

    def generate(self, rng):
        ssid = rng.choice(SSIDS)
        passphrase = rng.choice(WIFI_PASSPHRASES)
        decoys = rng.sample([w for w in WIFI_PASSPHRASES if w != passphrase], 7)
        decoys += rng.sample([w for w in corpus.LEAKED_PASSWORDS if len(w) >= 8], 4)
        words = decoys + [passphrase]
        rng.shuffle(words)
        return {"ssid": ssid, "passphrase": passphrase, "words": words}

    def files(self, p):
        return {"wordlist.txt": ("\n".join(p["words"]) + "\n").encode()}

    def prompt(self, p):
        target = _pmk(p["passphrase"], p["ssid"]).hex()
        return format_html(
            "<p>Because the PMK is derived <em>only</em> from the passphrase and the SSID "
            "(previous task), an attacker who captures a 4-way handshake can guess "
            "passphrases <strong>offline</strong>, at full CPU/GPU speed, with no further "
            "contact with the network. Here the recovered PMK for a network is:</p>"
            "<pre>SSID = {}\nPMK  = {}</pre>"
            "<p>The owner reused a weak passphrase. Using the candidate list "
            "<code>wordlist.txt</code>, find which one produces this PMK and submit that "
            "passphrase.</p>"
            "<p class=\"muted\">For each candidate, recompute "
            "<code>PBKDF2(HMAC-SHA1, candidate, SSID, 4096, 32)</code> and compare. This is "
            "exactly what <code>aircrack-ng</code> or <code>hashcat -m 2500</code> do. The "
            "lesson for the short answer: what makes this attack feasible, and how does "
            "WPA3 stop it? <strong>Lawful use only — this is a passphrase you own.</strong></p>",
            p["ssid"], target)

    def check(self, p, answer):
        cand = answer.strip()
        if not cand:
            return False
        return _pmk(cand, p["ssid"]).hex() == _pmk(p["passphrase"], p["ssid"]).hex()


class RogueAp(TaskDef):
    key = "rogue-ap"
    title = "Spot the evil twin"
    points = 10
    max_attempts = 2
    placeholder = "a letter, A–E"
    LABELS = "ABCDE"
    CAMPUS = "KNUST-Secure"

    OTHERS = [("KNUST-Guest", "Open"), ("eduroam", "WPA2-Enterprise"),
              ("CoE-Staff", "WPA2-Personal"), ("Hall6-WiFi", "WPA2-Personal"),
              ("TP-Link_2.4G", "WPA2-Personal"), ("Printer-Direct", "Open")]

    def generate(self, rng):
        evil_sec = rng.choice(["Open", "WPA2-Personal"])
        nets = [("legit", self.CAMPUS, "WPA2-Enterprise"),
                ("evil", self.CAMPUS, evil_sec)]
        nets += [("other", s, sec) for s, sec in rng.sample(self.OTHERS, 3)]
        rng.shuffle(nets)
        rows = []
        for role, ssid, sec in nets:
            rows.append({"role": role, "ssid": ssid, "sec": sec,
                         "bssid": random_mac(rng),
                         "channel": rng.choice([1, 6, 11, 36, 44]),
                         "signal": rng.randrange(-78, -38)})
        bad = next(i for i, r in enumerate(rows) if r["role"] == "evil")
        return {"rows": rows, "bad": bad}

    def prompt(self, p):
        header = f"{'':2}{'SSID':<16}{'Security':<18}{'BSSID':<19}{'Ch':<4}{'Signal'}"
        lines = [header]
        for lab, r in zip(self.LABELS, p["rows"]):
            lines.append(f"{lab}. {r['ssid']:<16}{r['sec']:<18}{r['bssid']:<19}"
                         f"{r['channel']:<4}{r['signal']} dBm")
        return format_html(
            "<p>You run a Wi-Fi scan near campus. The official network "
            "<code>KNUST-Secure</code> uses <strong>WPA2-Enterprise</strong> (802.1X — you "
            "authenticate to a RADIUS server, there is no shared passphrase). Here is the "
            "scan:</p><pre>{}</pre>"
            "<p>Exactly one access point is an <strong>evil twin</strong>: it advertises "
            "the campus SSID to lure devices, but it is really an attacker's AP. Which "
            "letter is it?</p>"
            "<p class=\"muted\">Two rows share the name <code>KNUST-Secure</code>. Which one "
            "is impersonating the real network — and what about its security setting gives "
            "it away? A different BSSID (MAC) with the same name is the tell. 2 attempts.</p>",
            "\n".join(lines))

    def check(self, p, answer):
        picked = next((c for c in answer.upper() if c in self.LABELS), None)
        return picked == self.LABELS[p["bad"]]


class WirelessShortAnswer(ManualTask):
    key = "wireless-models"
    title = "Short answer: WEP to WPA3, and wireless threats"
    rubric = (
        "10 marks. [2] Why WEP failed: RC4 with a 24-bit IV that repeats, IVs sent in "
        "clear, no real integrity (CRC-32 is malleable) — key recovery in minutes. [3] "
        "WPA2-PSK: passphrase -> PMK via PBKDF2 (the first task); the 4-way handshake "
        "derives a fresh per-session PTK from PMK + nonces + MACs and proves both sides "
        "hold the PMK; bulk traffic uses AES-CCMP. [3] Offline dictionary attack: capturing "
        "the handshake lets an attacker test passphrases offline at GPU speed (the crack "
        "task); feasible because the PMK depends only on passphrase+SSID and weak "
        "passphrases are common. WPA3-SAE (Dragonfly) replaces the PSK exchange with a PAKE "
        "so each guess needs a fresh online interaction, giving forward secrecy and killing "
        "the offline attack. [2] Threats/mobile: evil-twin/rogue APs (the scan task) and "
        "the need for mutual auth / 802.1X-Enterprise and certificate checking, deauth and "
        "jamming (availability), KRACK; BYOD controls — MDM, NAC, segmentation, always use "
        "a VPN on open Wi-Fi. Credit for noting WPA2-Enterprise authenticates the user to a "
        "RADIUS server, so there is no shared passphrase to crack."
    )

    def prompt(self, p):
        return mark_safe(
            "<p>In 7–10 sentences, tying the tasks together: (a) name two concrete reasons "
            "WEP was broken; (b) in WPA2-PSK, what is the PMK (you computed one) and what "
            "does the 4-way handshake add on top of it? (c) the crack task guessed a "
            "passphrase offline — what makes that attack possible, and how does WPA3-SAE "
            "stop it? (d) in the scan, the evil twin copied the campus SSID — why does "
            "WPA2-Enterprise (802.1X) make that lure far less dangerous than an open or "
            "PSK network? (e) name two things a phone should do on untrusted public "
            "Wi-Fi.</p>")


LAB = LabDef(
    slug="l09-wireless",
    lecture=9,
    title="Wireless & mobile security",
    summary="Derive a WPA2 pairwise master key, run an offline dictionary attack on a "
            "weak Wi-Fi passphrase, and pick the evil-twin access point out of a scan.",
    intro=(
        "<p>Lecture 9, on the air. Radio is a shared medium: anyone nearby can listen and "
        "anyone can pretend to be your access point. You'll see how WPA2 turns a passphrase "
        "into keys, why a weak passphrase falls to an offline attack (and how WPA3 fixes "
        "it), and how to recognise a rogue access point impersonating the campus network.</p>"
        "<p class=\"small muted\">Python's <code>hashlib</code> is all you need for the key "
        "work; no wireless hardware required. <strong>Lawful use only:</strong> the "
        "passphrase you attack here is one you own.</p>"
    ),
    tasks=[Wpa2Pmk(), CrackWifi(), RogueAp(), WirelessShortAnswer()],
)
