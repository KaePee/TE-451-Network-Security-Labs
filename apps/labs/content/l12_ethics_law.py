"""Lab 12: legal, ethical and professional issues — the capstone. Decide which
security activities are lawful and authorised and which are offences, put the
steps of responsible vulnerability disclosure in order, and map incidents to
the kind of offence they are. One reflective short answer ties the whole
semester's techniques back to the law and to professional codes of conduct.

Covers Lecture 12: computer-misuse / unauthorised-access law (in Ghana, the
Cybersecurity Act, 2020 (Act 1038) and the Data Protection Act, 2012 (Act
843)), responsible vs full disclosure, and professional ethics (ACM, IEEE-CS,
(ISC)² codes). Grading is on the *category* of offence, not on statute
sections, so nothing here is legal advice.
"""

from .base import (LabDef, ManualTask, TaskDef, fraction_matching, format_html,
                   mark_safe)


class LawfulOrNot(TaskDef):
    key = "lawful-or-not"
    title = "Authorised, or an offence?"
    points = 15
    placeholder = "e.g. A, O, O, A, A, O"

    # (scenario, verdict) — A = lawful & authorised, O = a likely offence.
    SCENARIOS = [
        ("You run a port scan against a company's servers after signing a written "
         "penetration-test agreement that puts those servers in scope.", "A"),
        ("You scan a bank's public servers out of curiosity, with no permission.", "O"),
        ("You try a password from a public breach dump on someone's login page "
         "\"just to see if it works\".", "O"),
        ("You notice a flaw in the university portal, report it privately to the IT "
         "office, and wait for a fix before telling anyone else.", "A"),
        ("After finding a portal bug, you keep a copy of another student's results that "
         "it exposed.", "O"),
        ("You practise cracking the WPA2 handshake of your own home router.", "A"),
        ("You deauthenticate other guests off a café's Wi-Fi to free up bandwidth for "
         "yourself.", "O"),
        ("You test exploits only inside the KNUST lab's isolated sandbox, on the accounts "
         "issued to you.", "A"),
        ("You sell a working exploit for a government website to an anonymous buyer.", "O"),
        ("You log into a friend's email with their saved password, without asking, \"just "
         "to check something\".", "O"),
    ]

    def generate(self, rng):
        return {"items": rng.sample(self.SCENARIOS, 6)}

    def prompt(self, p):
        rows = "\n".join(f"{chr(65 + i)}. {text}" for i, (text, _) in enumerate(p["items"]))
        return format_html(
            "<p>The techniques you learned this semester are lawful or not depending almost "
            "entirely on <strong>authorisation and scope</strong>. For each situation, "
            "decide whether it is <strong>authorised and lawful</strong> (<code>A</code>) "
            "or a <strong>likely offence</strong> (<code>O</code> — the kind of "
            "unauthorised access, interception or misuse that laws such as Ghana's "
            "Cybersecurity Act, 2020 address). Submit one letter per item, in order.</p>"
            "<pre>{}</pre>"
            "<p class=\"muted\">Ask: did the owner give permission, is the activity within "
            "the agreed scope, and is personal data being misused? \"I was only curious\" "
            "and \"the door was unlocked\" are not defences.</p>", rows)

    def check(self, p, answer):
        given = "".join(c for c in answer.upper() if c in "AO")
        want = "".join(v for _, v in p["items"])
        return fraction_matching(given, want)


class DisclosureOrder(TaskDef):
    key = "disclosure-order"
    title = "Order the steps of responsible disclosure"
    points = 15
    placeholder = "e.g. C, A, E, B, D"
    LABELS = "ABCDE"

    # In correct chronological order.
    STEPS = [
        "Confirm the vulnerability with the least access needed — do not exploit it "
        "further or pull more data than it takes to prove it is real.",
        "Report it privately to the vendor (or a national CERT such as Ghana's CERT-GH / "
        "Cyber Security Authority), with enough detail to reproduce it.",
        "Agree a remediation timeline and a coordinated disclosure date, and keep the "
        "details confidential in the meantime.",
        "Give the vendor time to develop, test and ship a fix, and users time to apply it.",
        "Publish the advisory (and get a CVE assigned) once the fix is out, or once the "
        "agreed deadline has passed.",
    ]

    def generate(self, rng):
        perm = list(range(len(self.STEPS)))
        rng.shuffle(perm)
        return {"perm": perm}

    def _correct(self, p):
        # The label sequence that puts the shown steps back into true order.
        return "".join(self.LABELS[p["perm"].index(r)] for r in range(len(self.STEPS)))

    def prompt(self, p):
        rows = "\n".join(f"{self.LABELS[i]}. {self.STEPS[step]}"
                         for i, step in enumerate(p["perm"]))
        return format_html(
            "<p>You have found a serious vulnerability in a live system. The steps of "
            "<strong>coordinated (responsible) disclosure</strong> are listed below, but "
            "shuffled. Put them in the right order.</p><pre>{}</pre>"
            "<p>Submit the letters in chronological order, e.g. <code>C, A, E, B, D</code>.</p>"
            "<p class=\"muted\">The guiding idea: prove the bug with minimal intrusion, give "
            "the people who can fix it a private head start, and only go public once users "
            "can actually protect themselves. How does this differ from \"full disclosure\" "
            "and from selling the exploit?</p>", rows)

    def check(self, p, answer):
        given = "".join(c for c in answer.upper() if c in self.LABELS)
        return fraction_matching(given, self._correct(p))


class MapToLaw(TaskDef):
    key = "map-to-law"
    title = "What kind of offence is it?"
    points = 15
    placeholder = "e.g. U, I, D, F, P"

    CATEGORIES = {
        "U": "unauthorised access to a computer system",
        "I": "unlawful interception of data in transit",
        "D": "a personal-data / privacy violation",
        "F": "computer-related fraud or forgery",
        "P": "intellectual-property infringement (piracy)",
    }

    SCENARIOS = [
        ("An attacker guesses an administrator's password and logs into a server they "
         "have no right to use.", "U"),
        ("Someone sniffs an open Wi-Fi link and records other people's web sessions as "
         "they travel.", "I"),
        ("A company exposes its customers' names, national IDs and phone numbers through "
         "an unsecured database.", "D"),
        ("A phisher forges a bank's email and tricks a victim into transferring money.", "F"),
        ("A shop sells computers pre-loaded with cracked, unlicensed commercial software.",
         "P"),
        ("An employee copies the firm's entire customer personal-data list intending to "
         "sell it.", "D"),
        ("A fraudster clones a login page to capture credentials and reuse them for "
         "financial gain.", "F"),
        ("A student uses a stolen staff account to reach systems they were never granted "
         "access to.", "U"),
    ]

    def generate(self, rng):
        return {"items": rng.sample(self.SCENARIOS, 5)}

    def prompt(self, p):
        legend = "\n".join(f"  {code} = {name}" for code, name in self.CATEGORIES.items())
        rows = "\n".join(f"{i + 1}. {text}" for i, (text, _) in enumerate(p["items"]))
        return format_html(
            "<p>Each incident below is, in substance, a different kind of wrong — the sort "
            "of conduct addressed by laws like Ghana's Cybersecurity Act, 2020 (Act 1038) "
            "and Data Protection Act, 2012 (Act 843). Label each with the category it most "
            "squarely fits:</p><pre>{}</pre><pre>{}</pre>"
            "<p>Submit one code per incident, in order.</p>"
            "<p class=\"muted\">Focus on the <em>core</em> harm: Was a system entered "
            "without right? Was traffic intercepted? Was personal data misused? Was there "
            "deception for gain? (This is about categories, not statute sections — it isn't "
            "legal advice.)</p>", legend, rows)

    def check(self, p, answer):
        given = "".join(c for c in answer.upper() if c in self.CATEGORIES)
        want = "".join(code for _, code in p["items"])
        return fraction_matching(given, want)


class EthicsCapstone(ManualTask):
    key = "ethics-capstone"
    title = "Short answer: ethics, law and the work you did this semester"
    points = 10
    rubric = (
        "10 marks. [3] Authorisation & scope: the same action (port scan, WPA2 crack, "
        "password cracking) is a professional service or a crime depending on written "
        "permission and staying in scope; the lab was lawful because it was an isolated "
        "sandbox on issued accounts and the student's own devices; 'curiosity' and an "
        "'unlocked door' are not defences. [3] Responsible disclosure: confirm with minimal "
        "intrusion, report privately to the vendor/CERT, coordinate a timeline, publish only "
        "after a fix — contrast with full disclosure (public immediately) and the "
        "clearly-wrong path of selling/weaponising; bug bounties formalise the good path. "
        "[2] Law: unauthorised access, interception and data-protection violations are "
        "offences (in Ghana, the Cybersecurity Act, 2020 (Act 1038), the Data Protection "
        "Act, 2012 (Act 843), and the Cyber Security Authority / CERT-GH); personal data "
        "carries duties of lawful basis, minimisation and security. [2] Professional ethics: "
        "ACM / IEEE-CS / (ISC)² codes — act in the public interest, avoid harm, respect "
        "privacy and confidentiality, be honest about competence; dual-use — the same skill "
        "defends or attacks, and the defender's duty is to use it to protect. Credit for a "
        "concrete, honest reflection on a specific task from the course."
    )

    def prompt(self, p):
        return mark_safe(
            "<p>In 8–12 sentences, reflecting on the whole course: (a) you cracked password "
            "hashes (Lab 5), a WPA2 passphrase (Lab 9) and ran a port scan (Lab 11) — what "
            "made doing those things <em>here</em> lawful and ethical, and what single "
            "change would have turned each into an offence? (b) you have found a real, "
            "serious bug in a production system — walk through what a responsible "
            "professional does, and contrast it with full disclosure and with selling the "
            "exploit; (c) name the kinds of conduct the law treats as offences (you may "
            "cite Ghana's Cybersecurity Act, 2020 and Data Protection Act, 2012) and one "
            "duty you owe when you hold other people's personal data; (d) name one "
            "professional code of ethics (ACM, IEEE-CS or (ISC)²) and state one principle "
            "from it that constrains how you will use everything you learned this "
            "semester.</p>")


LAB = LabDef(
    slug="l12-ethics-law",
    lecture=12,
    title="Legal, ethical & professional practice",
    summary="Tell lawful, authorised security work from an offence; order the steps of "
            "responsible disclosure; map incidents to the kind of offence they are; and "
            "reflect on the law and ethics behind the whole course.",
    intro=(
        "<p>The final lecture is the one that governs all the others. Every technique in "
        "this course is dual-use: the difference between a security professional and a "
        "criminal is authorisation, scope, intent and how you handle what you find. Here "
        "you'll reason about where the line sits, how to disclose a vulnerability "
        "responsibly, and how incidents map onto the law — in Ghana, the Cybersecurity "
        "Act, 2020 and the Data Protection Act, 2012.</p>"
        "<p class=\"small muted\">No tools and no downloads — this lab is judgement and "
        "professional practice. The short answer is graded by a TA; nothing here is legal "
        "advice.</p>"
    ),
    tasks=[LawfulOrNot(), DisclosureOrder(), MapToLaw(), EthicsCapstone()],
)
