"""Lab 12 (legal/ethical capstone): reasoning tasks, no artefacts. Solve each
the way a student would and confirm the page renders even with no downloads."""

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from apps.labs import content, services
from apps.labs.content import l12_ethics_law as L12

from .helpers import make_student, synced_lab

SEEDS = range(25)


def task(key):
    return content.get("l12-ethics-law").task(key)


class Lab12SolverTests(SimpleTestCase):
    def test_lawful_or_not(self):
        t = task("lawful-or-not")
        for seed in SEEDS:
            p = t.params_for(seed)
            want = "".join(v for _, v in p["items"])
            self.assertEqual(t.check(p, ", ".join(want)), 1.0, seed)
            flipped = ("A" if want[0] == "O" else "O") + want[1:]
            self.assertAlmostEqual(t.check(p, flipped), (len(want) - 1) / len(want))
            self.assertEqual(t.check(p, want[:-1]), 0.0)          # wrong length

    def test_disclosure_order(self):
        t = task("disclosure-order")
        for seed in SEEDS:
            p = t.params_for(seed)
            correct = t._correct(p)
            self.assertEqual(t.check(p, ", ".join(correct)), 1.0, seed)
            # Sanity: the correct sequence really re-sorts the shown steps into order.
            shown_in_answer_order = [p["perm"][t.LABELS.index(c)] for c in correct]
            self.assertEqual(shown_in_answer_order, sorted(shown_in_answer_order))
            if len(correct) >= 2:                                 # swapping two is partial
                swapped = correct[1] + correct[0] + correct[2:]
                self.assertLess(t.check(p, swapped), 1.0)

    def test_map_to_law(self):
        t = task("map-to-law")
        for seed in SEEDS:
            p = t.params_for(seed)
            want = "".join(code for _, code in p["items"])
            self.assertEqual(t.check(p, ", ".join(want)), 1.0, seed)
            self.assertEqual(t.check(p, "ZZZZZ"), 0.0)            # no valid codes

    def test_capstone_is_manual(self):
        self.assertEqual(task("ethics-capstone").kind, "manual")


class Lab12PageTests(TestCase):
    def test_page_renders_without_downloads(self):
        lab = synced_lab("l12-ethics-law")
        student = make_student()
        self.client.force_login(student)
        self.client.post(reverse("labs:start", args=[lab.slug]))
        r = self.client.get(reverse("labs:detail", args=[lab.slug]))
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "⬇")                           # this lab has no files
        self.assertContains(r, "responsible disclosure")


class RenderTests(SimpleTestCase):
    def test_no_task_declares_files(self):
        for tdef in content.get("l12-ethics-law").tasks:
            p = tdef.params_for(1)
            self.assertEqual(tdef.files(p), {})
            self.assertEqual(tdef.file_names(p), [])
