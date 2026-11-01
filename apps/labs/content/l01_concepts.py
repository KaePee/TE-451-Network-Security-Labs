"""Lab 1: security concepts. The X.800 vocabulary, applied to real traffic.

Part A (Wireshark): one per-student capture of a small office network in which
three things go wrong: a plaintext FTP login (passive attack on
confidentiality), a heavy user visible by traffic analysis alone, and a
replayed money transfer (active attack).

Part B: classification drills drawn from scenario banks, with partial credit
and limited attempts so they can't be brute-forced.
"""

import random

from . import pcap
from django.utils.html import format_html_join

from .base import (LabDef, ManualTask, TaskDef, format_html, fraction_matching, letters,
                   mark_safe)

FTP_USERS = ["kmensah", "aowusu", "yboateng", "efosu", "nasante", "pkoranteng", "aaddo"]
PASSWORD_WORDS = ["harmattan", "kente", "adinkra", "baobab", "volta", "kakum", "tamale",
                  "kejetia", "sankofa", "fufu", "ashanti", "nkrumah", "lakebosomtwe"]
DOMAINS = ["update.vendor.example", "mail.campus.example", "cdn.news.example",
           "time.campus.example", "api.weather.example", "fonts.static.example"]


# ---------------------------------------------------------------------- capture
def build_scenario(rng: random.Random) -> dict:
    subnet = rng.randrange(10, 250)
    hosts = rng.sample(range(10, 200), 6)
    clients = [f"192.168.{subnet}.{h}" for h in hosts]
    victim, heavy, payer, attacker = clients[0], clients[1], clients[2], clients[3]
    rng.shuffle(clients)
    return {
        "subnet": subnet,
        "clients": clients,
        "router": f"192.168.{subnet}.1",
        "web": f"198.51.100.{rng.randrange(2, 250)}",
        "ftp": f"203.0.113.{rng.randrange(2, 250)}",
        "bank": f"192.0.2.{rng.randrange(2, 250)}",
        "victim": victim, "heavy": heavy, "payer": payer, "attacker": attacker,
        "ftp_user": rng.choice(FTP_USERS),
        "ftp_pass": rng.choice(PASSWORD_WORDS).capitalize() + str(rng.randrange(10, 9999)),
        "amount": rng.randrange(200, 5000),
        "to_acct": f"{rng.randrange(10**9, 10**10)}",
        "nonce": f"{rng.getrandbits(48):012x}",
        "noise_seed": rng.getrandbits(32),
    }


def build_capture(p: dict) -> pcap.Capture:
    rng = random.Random(p["noise_seed"])
    cap = pcap.Capture()
    router = pcap.Host(p["router"], pcap.random_mac(rng))
    lan = {ip: pcap.Host(ip, pcap.random_mac(rng)) for ip in p["clients"]}
    remote = lambda ip: pcap.Host(ip, router.mac)  # noqa: E731
    web, ftp, bank = remote(p["web"]), remote(p["ftp"]), remote(p["bank"])
    t0 = 1789462800.0 + rng.randrange(0, 86400 * 30)  # September 2026, office hours-ish
    ports = iter(rng.sample(range(49152, 65535), 64))

    # DNS chatter (noise, and the names the HTTP Host headers use).
    names = {"portal.campus.example": p["web"], "files.campus.example": p["ftp"],
             "pay.bank.example": p["bank"]}
    taken = {p["web"], p["ftp"], p["bank"]}
    for d in DOMAINS:
        addr = p["web"]
        while addr in taken:
            addr = f"198.51.100.{rng.randrange(2, 250)}"
        taken.add(addr)
        names[d] = addr
    for i, (name, addr) in enumerate(names.items()):
        c = lan[rng.choice(p["clients"])]
        t = t0 + i * rng.uniform(0.5, 2.5)
        qid, sport = rng.getrandbits(16), next(ports)
        cap.add(t, pcap.udp(c, router, sport, 53, pcap.dns_query(qid, name)))
        cap.add(t + rng.uniform(0.002, 0.03),
                pcap.udp(router, c, 53, sport, pcap.dns_response(qid, name, addr)))

    def http_get(client: pcap.Host, path: str, size: int, start: float):
        conv = pcap.TcpConversation(cap, rng, client, web, next(ports), 80, start).open()
        conv.send(True, (f"GET {path} HTTP/1.1\r\nHost: portal.campus.example\r\n"
                         "User-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n").encode())
        body = bytes(rng.randrange(256) for _ in range(size))
        conv.send(False, (f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                          f"Content-Length: {size}\r\n\r\n").encode() + body)
        conv.close()

    # Ordinary browsing by everyone; one user pulls far more data.
    for c in p["clients"]:
        for _ in range(rng.randrange(2, 5)):
            http_get(lan[c], f"/course/{rng.randrange(100, 999)}", rng.randrange(1500, 9000),
                     t0 + rng.uniform(5, 70))
    for i in range(3):
        http_get(lan[p["heavy"]], f"/media/lecture-{i + 1}.mp4", rng.randrange(70_000, 110_000),
                 t0 + 10 + i * rng.uniform(8, 15))

    # Plaintext FTP login.
    conv = pcap.TcpConversation(cap, rng, lan[p["victim"]], ftp, next(ports), 21,
                                t0 + rng.uniform(18, 25)).open()
    for line, from_client in [
        ("220 (vsFTPd 3.0.5)", False), (f"USER {p['ftp_user']}", True),
        ("331 Please specify the password.", False), (f"PASS {p['ftp_pass']}", True),
        ("230 Login successful.", False), ("PWD", True),
        (f'257 "/home/{p["ftp_user"]}" is the current directory', False),
        ("QUIT", True), ("221 Goodbye.", False),
    ]:
        conv.send(from_client, (line + "\r\n").encode())
        conv.wait(rng.uniform(0.2, 1.5))
    conv.close()

    # A transfer, then the attacker replays the identical request.
    body = f"to={p['to_acct']}&amount={p['amount']}.00&currency=GHS&nonce={p['nonce']}"
    request = (f"POST /api/transfer HTTP/1.1\r\nHost: pay.bank.example\r\n"
               f"Cookie: session=7f3a9c{p['nonce'][:6]}e1\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\n\r\n{body}").encode()
    ok = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"completed"}'
    for who, start, tag in [(p["payer"], t0 + rng.uniform(30, 40), "original"),
                            (p["attacker"], t0 + rng.uniform(55, 65), "replay")]:
        conv = pcap.TcpConversation(cap, rng, lan[who], bank, next(ports), 80, start).open()
        conv.send(True, request, tag=tag)
        conv.send(False, ok)
        conv.close()
    return cap


class CaptureTask(TaskDef):
    seed_key = "capture"

    def generate(self, rng):
        return build_scenario(rng)


class FtpPassword(CaptureTask):
    key = "ftp-password"
    title = "Eavesdropping: a plaintext login"
    placeholder = "the password"

    def files(self, p):
        return {self.file_names(p)[0]: build_capture(p).to_pcap()}

    def file_names(self, p):
        return [f"office-{p['subnet']}.pcap"]

    def prompt(self, p):
        return format_html(
            "<p>Download the capture below and open it in Wireshark. It was recorded on "
            "the switch of a small office network, <code>192.168.{}.0/24</code>. Tasks 1–3 "
            "all use this one file.</p>"
            "<p>Someone logged in to the file server <code>{}</code> using FTP. "
            "<strong>What password did they use?</strong></p>"
            "<p class=\"muted\">Hint: try the display filter <code>ftp</code>, or right-click "
            "a packet → Follow → TCP Stream. Ask yourself which X.800 service was missing, "
            "and whether the victim could ever have noticed.</p>", p["subnet"], p["ftp"])

    def check(self, p, answer):
        return answer.strip() == p["ftp_pass"]


class TrafficAnalysis(CaptureTask):
    key = "traffic-analysis"
    title = "Traffic analysis: who talks the most?"
    placeholder = "e.g. 192.168.1.20, 250"
    max_attempts = 3

    def prompt(self, p):
        return format_html(
            "<p>Without reading a single payload, you can learn a lot from <em>who talks to "
            "whom, and how much</em>. Use <strong>Statistics → Conversations → IPv4</strong>.</p>"
            "<p>Which LAN host exchanged the most data with the web server <code>{}</code>, "
            "and how many <strong>packets</strong> did that conversation contain in total "
            "(both directions)?</p>"
            "<p>Answer as <code>IP, packets</code>. Half marks for each part.</p>", p["web"])

    def check(self, p, answer):
        parts = [x.strip() for x in answer.replace(";", ",").split(",") if x.strip()]
        if len(parts) != 2:
            return False
        expected = build_capture(p).packets_between(p["heavy"], p["web"])
        score = 0.5 if parts[0] == p["heavy"] else 0.0
        if parts[1].replace(" ", "") == str(expected):
            score += 0.5
        return score


class Replay(CaptureTask):
    key = "replay"
    title = "Active attack: a replayed transfer"
    points = 15
    placeholder = "e.g. 192.168.1.66, 512"
    max_attempts = 3

    def prompt(self, p):
        return format_html(
            "<p>The bank's server at <code>{}</code> processed the <em>same</em> money "
            "transfer twice. The second request came from a different machine, which "
            "had captured and re-sent the first one.</p>"
            "<p>Give the <strong>attacker's IP address</strong> and the <strong>frame "
            "number</strong> of the replayed <code>POST</code> request. Answer as "
            "<code>IP, frame</code>.</p>"
            "<p class=\"muted\">Filter: <code>http.request.method == \"POST\"</code>. Compare "
            "the two requests byte for byte. The request even carries a nonce. Why didn't "
            "that stop the replay? Which side was supposed to check it?</p>", p["bank"])

    def check(self, p, answer):
        parts = [x.strip() for x in answer.replace(";", ",").split(",") if x.strip()]
        if len(parts) != 2:
            return False
        frame = build_capture(p).frame_number("replay")
        return (0.5 if parts[0] == p["attacker"] else 0.0) + (
            0.5 if parts[1].lstrip("#") == str(frame) else 0.0)


# -------------------------------------------------------------- scenario drills
CIA_BANK = [
    ("An attacker on the hostel Wi-Fi reads a classmate's unencrypted emails.", "C"),
    ("A misconfigured cloud storage bucket exposes thousands of scanned student ID cards.", "C"),
    ("A shoulder-surfer watches a customer type their mobile-money PIN.", "C"),
    ("A hospital clerk browses a famous patient's medical file out of curiosity.", "C"),
    ("Malware swaps the recipient's number in a mobile-money transfer before it is sent.", "I"),
    ("A student edits their own exam score in the results database.", "I"),
    ("A disgruntled employee changes product prices in a shop's database.", "I"),
    ("A tampered firmware update quietly adds a hidden admin account to every router.", "I"),
    ("A botnet floods the course-registration portal so nobody can log in.", "A"),
    ("Construction work cuts the fibre link to the campus data centre.", "A"),
    ("A jammer stops every phone in a lecture hall from reaching the cell tower.", "A"),
    ("Ransomware encrypts a clinic's file server; staff cannot open any records.", "A"),
]

PASSIVE_ACTIVE_BANK = [
    ("Recording an unencrypted VoIP call on a shared network.", "P"),
    ("Noting how often, and when, a manager's laptop contacts a competitor's server.", "P"),
    ("Inferring which website someone visits from the sizes and timing of their "
     "encrypted packets.", "P"),
    ("Capturing Wi-Fi frames to read them at leisure later.", "P"),
    ("Re-sending a captured 'unlock' radio signal to open a car.", "A"),
    ("Using ARP spoofing to pose as the default gateway.", "A"),
    ("Changing the amount in a payment message while it is in transit.", "A"),
    ("Flooding a server with half-open TCP connections (SYN flood).", "A"),
    ("Emailing students while pretending to be the Registrar.", "A"),
    ("Deleting entries from a server's log files to hide an intrusion.", "A"),
]

SERVICE_LETTERS = {
    "A": "Authentication", "C": "Access control", "D": "Data confidentiality",
    "I": "Data integrity", "N": "Non-repudiation", "V": "Availability",
}
SERVICE_BANK = [
    ("A bank must be able to prove later that a customer really authorised a transfer, "
     "even if the customer denies it.", "N"),
    ("A court needs evidence that a contractor received a legal notice and cannot claim "
     "otherwise.", "N"),
    ("Only lecturers may open the exam-papers folder, although students log in to the "
     "same server.", "C"),
    ("A student database lets TAs read marks but only the lecturer change them.", "C"),
    ("The portal must be sure the person logging in really is the student with that "
     "index number.", "A"),
    ("An engineer's SSH client must confirm it is talking to the real router, not an "
     "impostor.", "A"),
    ("A sensor network must detect if any reading was changed in transit.", "I"),
    ("Customers need to know a software update has not been altered since it was built.",
     "I"),
    ("Salary data sent from HR to the bank must not be readable by anyone on the network.",
     "D"),
    ("Two embassies want to hide even the fact that they are communicating heavily.", "D"),
    ("The registration portal must stay usable when thousands of students log in at 8 am.",
     "V"),
    ("A hospital's systems must keep working through a power cut.", "V"),
]


def _scenario_list(items):
    return format_html("<ol>{}</ol>",
                       format_html_join("", "<li>{}</li>", ((text,) for text, _ in items)))


class Classify(TaskDef):
    bank: list = []
    count = 5
    alphabet = ""
    max_attempts = 2
    points = 10

    def generate(self, rng):
        return {"items": rng.sample(self.bank, self.count)}

    def check(self, p, answer):
        expected = "".join(code for _, code in p["items"])
        return fraction_matching(letters(answer, self.alphabet), expected)


class ClassifyCIA(Classify):
    key = "classify-cia"
    title = "Which dial broke? C, I or A"
    bank = CIA_BANK
    alphabet = "CIA"
    placeholder = "e.g. C, A, I, I, C"

    def prompt(self, p):
        return format_html(
            "<p>For each incident, which property was <strong>primarily</strong> violated: "
            "<strong>C</strong>onfidentiality, <strong>I</strong>ntegrity or "
            "<strong>A</strong>vailability? Answer with one letter per incident, in order.</p>"
            "{}<p class=\"small muted\">Partial credit per item. 2 attempts.</p>",
            _scenario_list(p["items"]))


class ClassifyPassiveActive(Classify):
    key = "classify-passive-active"
    title = "Passive or active?"
    bank = PASSIVE_ACTIVE_BANK
    alphabet = "PA"
    count = 6
    placeholder = "e.g. P, A, A, P, A, P"

    def prompt(self, p):
        return format_html(
            "<p>Classify each attack as <strong>P</strong>assive (learns, doesn't alter) "
            "or <strong>A</strong>ctive (alters or disrupts). One letter each, in order.</p>"
            "{}<p class=\"small muted\">Then ask: which kind should you try to "
            "<em>prevent</em>, and which can you realistically only <em>detect</em>?</p>",
            _scenario_list(p["items"]))


class ClassifyService(Classify):
    key = "classify-service"
    title = "Which X.800 service is needed?"
    bank = SERVICE_BANK
    alphabet = "ACDINV"
    placeholder = "e.g. N, A, D, I, C"

    def prompt(self, p):
        legend = ", ".join(f"<strong>{k}</strong> = {v}" for k, v in SERVICE_LETTERS.items())
        return format_html(
            "<p>Name the <strong>one</strong> X.800 security service each requirement calls "
            "for. Codes: {}.</p>{}", mark_safe(legend), _scenario_list(p["items"]))


DESIGN_SCENARIOS = [
    "A router vendor ships every unit with the same admin password, printed in the "
    "public manual. The web interface is reachable from the internet by default, "
    "\"so customers can get support\".",
    "A school's web app hides the 'Edit marks' button from students, but the URL "
    "/marks/edit?id=… itself never checks who is asking.",
    "Every service on a campus server (the website, the library system, the payroll "
    "export) connects to one database account that has full administrator rights.",
    "A company forces 20-character passwords that must change every week. Most "
    "staff now keep them on sticky notes on their monitors.",
]


class DesignPrinciples(ManualTask):
    key = "design-principles"
    title = "Short answer: spot the broken principle"
    rubric = (
        "10 marks. [4] Names at least one fitting Saltzer & Schroeder principle (router: "
        "fail-safe defaults / least privilege / open design misread as obscurity; web app: "
        "complete mediation; shared DB account: least privilege / least common mechanism; "
        "passwords: psychological acceptability). Other well-argued principles may earn "
        "credit. [3] Explains concretely how the design violates it. [3] Proposes a "
        "realistic fix that doesn't break a different principle."
    )

    def generate(self, rng):
        return {"scenario": rng.choice(DESIGN_SCENARIOS)}

    def prompt(self, p):
        return format_html(
            "<blockquote>{}</blockquote>"
            "<p>In 5–8 sentences: which <strong>design principle(s)</strong> from Lecture 1 "
            "does this violate, how exactly, and what would you change? Be concrete.</p>",
            p["scenario"])


LAB = LabDef(
    slug="l01-security-concepts",
    lecture=1,
    title="Security concepts in real traffic",
    summary="Find a plaintext password, a heavy user and a replay attack in your own "
            "capture; then classify attacks, services and broken designs.",
    intro=(
        "<p>Lecture 1 gave you a vocabulary: <em>attacks</em> threaten, <em>services</em> "
        "defend, <em>mechanisms</em> implement. Today you use it on evidence. You need "
        "<strong>Wireshark</strong> for tasks 1–3.</p>"
        "<p class=\"small muted\">The capture is synthetic. Every address in it is from a "
        "documentation or private range, and every name is fictional.</p>"
    ),
    tasks=[FtpPassword(), TrafficAnalysis(), Replay(), ClassifyCIA(),
           ClassifyPassiveActive(), ClassifyService(), DesignPrinciples()],
)
