"""Lab 11 solved the way a student would, across many seeds. The SYN-scan
capture is checked against tshark so the grader matches what Wireshark shows."""

import shutil
import subprocess
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from apps.labs import content
from apps.labs.content import l11_malware_firewall as L11

SEEDS = range(25)


def task(key):
    return content.get("l11-malware-firewall").task(key)


class FirewallTests(SimpleTestCase):
    def test_first_match_and_default_deny(self):
        t = task("firewall-ruleset")
        for seed in SEEDS:
            p = t.params_for(seed)
            want = "".join("A" if L11._evaluate(z, pr, po) == "ACCEPT" else "D"
                           for z, pr, po, _ in p["packets"])
            self.assertEqual(t.check(p, ", ".join(want)), 1.0, seed)
            flipped = ("D" if want[0] == "A" else "A") + want[1:]
            self.assertAlmostEqual(t.check(p, flipped), (len(want) - 1) / len(want))

    def test_shadowing_and_default_cases(self):
        # Internal Telnet is accepted by the broad rule 1 before the Telnet DROP.
        self.assertEqual(L11._evaluate("internal", "tcp", 23), "ACCEPT")
        self.assertEqual(L11._evaluate("external", "tcp", 23), "DROP")
        # A port no rule mentions falls through to the default policy.
        self.assertEqual(L11._evaluate("external", "tcp", 3306), "DROP")
        self.assertEqual(L11._evaluate("external", "tcp", 443), "ACCEPT")


class MalwareTests(SimpleTestCase):
    def test_triage_partial_credit(self):
        t = task("malware-triage")
        for seed in SEEDS:
            p = t.params_for(seed)
            want = "".join(code for _, code in p["specimens"])
            self.assertEqual(t.check(p, ", ".join(want)), 1.0, seed)
            self.assertEqual(t.check(p, want), 1.0)
            self.assertEqual(t.check(p, ""), 0.0)


class PortScanTests(SimpleTestCase):
    def test_scanner_and_open_count(self):
        t = task("port-scan")
        for seed in SEEDS:
            p = t.params_for(seed)
            self.assertEqual(t.check(p, f"{p['scanner']}, {len(p['open'])}"), 1.0, seed)
            self.assertEqual(t.check(p, f"{p['scanner']}, {len(p['open']) + 1}"), 0.5)
            self.assertEqual(t.check(p, f"41.204.0.0, {len(p['open'])}"), 0.5)


TSHARK = shutil.which("tshark") or (
    "/Applications/Wireshark.app/Contents/MacOS/tshark"
    if Path("/Applications/Wireshark.app/Contents/MacOS/tshark").exists() else None)


class PortScanWiresharkTests(SimpleTestCase):
    def setUp(self):
        if not TSHARK:
            self.skipTest("tshark not installed")

    def test_capture_matches_wireshark(self):
        t = task("port-scan")
        for seed in range(6):
            p = t.params_for(seed)
            data = next(iter(t.files(p).values()))
            with tempfile.NamedTemporaryFile(suffix=".pcap") as f:
                f.write(data)
                f.flush()

                def sh(*args):
                    return subprocess.run([TSHARK, "-r", f.name, *args],
                                          capture_output=True, text=True, check=True).stdout

                # No structurally broken packets or bad checksums.
                bad = sh("-o", "tcp.check_checksum:TRUE", "-o", "ip.check_checksum:TRUE",
                         "-Y", "_ws.malformed or tcp.checksum.status==\"Bad\" "
                               "or ip.checksum.status==\"Bad\"")
                self.assertEqual(bad.strip(), "", f"seed {seed} has malformed packets")
                # The only expert warnings are the closed-port RSTs the scan provokes.
                msgs = sh("-Y", "_ws.expert.severity >= warning",
                          "-T", "fields", "-e", "_ws.expert.message").split("\n")
                self.assertTrue(all(m in ("", "Connection reset (RST)") for m in msgs),
                                f"seed {seed}: unexpected expert info {msgs}")

                # SYN-ACKs sent to the scanner == the open-port count.
                synack = sh("-Y", f"tcp.flags.syn==1 && tcp.flags.ack==1 && ip.dst=={p['scanner']}",
                            "-T", "fields", "-e", "tcp.srcport")
                open_ports = {int(x) for x in synack.split()}
                self.assertEqual(open_ports, set(p["open"]), f"seed {seed}")

                # The scanner is the busiest source of SYN-only packets.
                syns = sh("-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
                          "-T", "fields", "-e", "ip.src")
                srcs = syns.split()
                busiest = max(set(srcs), key=srcs.count)
                self.assertEqual(busiest, p["scanner"], f"seed {seed}")


class RenderTests(SimpleTestCase):
    def test_file_names_match_files(self):
        for tdef in content.get("l11-malware-firewall").tasks:
            p = tdef.params_for(1)
            self.assertEqual(tdef.file_names(p), sorted(tdef.files(p)), tdef.key)
