import hashlib
import math
from decimal import Decimal

from django.test import TestCase, override_settings

from apps.labs import content, scoring, services
from apps.labs.content.numtheory import crt, is_prime
from apps.labs.models import Lab, Submission

from .helpers import ago, make_staff, make_student, synced_lab

# Reference solutions, written independently of the graders' check() methods.
SOLVERS = {
    "gcd": lambda p: math.gcd(p["a"], p["b"]),
    "mod-inverse": lambda p: pow(p["a"], -1, p["m"]),
    "mod-exp": lambda p: pow(p["b"], p["e"], p["n"]),
    "crt": lambda p: crt(p["r"], p["m"]),
    "miller-rabin": lambda p: ", ".join(
        l for l, n in zip("ABCDEF", p["nums"]) if is_prime(n)),
    "euler-phi": lambda p: p["p"] * (p["p"] - 1) * (p["q"] - 1),
    "python-sha256": lambda p: hashlib.sha256(p["text"].encode()).hexdigest()[:16],
    "ethics-pledge": lambda p: content.l00_orientation.PLEDGE + ".",
}


class ContentTests(TestCase):
    def test_every_auto_task_accepts_its_reference_answer(self):
        for labdef in content.LABS:
            for task in labdef.tasks:
                if task.kind != "auto" or task.key not in SOLVERS:
                    continue
                for seed in (1, 42, 2**62):
                    p = task.params_for(seed)
                    with self.subTest(task=task.key, seed=seed):
                        self.assertTrue(task.check(p, str(SOLVERS[task.key](p))))
                        self.assertFalse(task.check(p, "12345"))

    def test_params_are_deterministic_and_per_student(self):
        task = content.get("l02-number-theory").task("gcd")
        self.assertEqual(task.params_for(7), task.params_for(7))
        self.assertNotEqual(task.params_for(7), task.params_for(8))

    def test_spot_the_primes_always_has_a_carmichael_decoy(self):
        task = content.get("l02-number-theory").task("miller-rabin")
        for seed in range(20):
            nums = task.params_for(seed)["nums"]
            self.assertTrue(any(not is_prime(n) and pow(2, n - 1, n) == 1 for n in nums))

    def test_answer_parsing_is_forgiving(self):
        task = content.get("l02-number-theory").task("gcd")
        p = task.params_for(3)
        g = math.gcd(p["a"], p["b"])
        self.assertTrue(task.check(p, f"  {g:,} "))
        self.assertTrue(task.check(p, hex(g)))
        self.assertFalse(task.check(p, "not a number"))

    @override_settings(ROOT_CA_FINGERPRINT="AB:CD:01")
    def test_root_ca_fingerprint_ignores_separators(self):
        task = content.get("l00-orientation").task("root-ca")
        self.assertTrue(task.check({}, "ab cd 01"))
        self.assertFalse(task.check({}, "ab cd 02"))


class SubmitTests(TestCase):
    def setUp(self):
        self.student = make_student()
        self.lab = synced_lab()
        self.session = services.start_session(self.lab, self.student)
        self.task = self.lab.tasks.get(key="gcd")
        self.params = content.get(self.lab.slug).task("gcd").params_for(self.session.seed)
        self.answer = str(math.gcd(self.params["a"], self.params["b"]))

    def test_correct_answer_scores_full_points(self):
        sub = services.submit_answer(self.session, self.task, self.answer)
        self.assertEqual(sub.status, Submission.Status.CORRECT)
        self.assertEqual(sub.score, self.task.points)

    def test_cannot_resubmit_once_solved(self):
        services.submit_answer(self.session, self.task, self.answer)
        with self.assertRaises(services.LabError):
            services.submit_answer(self.session, self.task, self.answer)

    def test_another_students_answer_is_wrong(self):
        other = make_student("2045099")
        other_session = services.start_session(self.lab, other)
        sub = services.submit_answer(other_session, self.task, self.answer)
        self.assertEqual(sub.status, Submission.Status.INCORRECT)

    def test_attempt_limit(self):
        self.lab.max_attempts = 2
        self.lab.save()
        for _ in range(2):
            services.submit_answer(self.session, self.task, "1")
        with self.assertRaises(services.LabError):
            services.submit_answer(self.session, self.task, self.answer)

    def test_no_submissions_after_time_up(self):
        self.lab.mode = Lab.Mode.TIMED
        self.lab.duration_minutes = 30
        self.lab.save()
        self.session.started_at = ago(minutes=31)
        self.session.save()
        with self.assertRaises(services.LabError):
            services.submit_answer(self.session, self.task, self.answer)

    def test_no_submissions_after_finish(self):
        services.finish_session(self.session)
        with self.assertRaises(services.LabError):
            services.submit_answer(self.session, self.task, self.answer)

    def test_blind_mode_latest_answer_counts(self):
        self.lab.show_feedback = False
        self.lab.save()
        services.submit_answer(self.session, self.task, self.answer)
        services.submit_answer(self.session, self.task, "1")  # allowed, overrides
        scores = scoring.lab_scores([self.student], [self.lab])
        self.assertEqual(scores.get((self.student.id, self.lab.id), Decimal("0")), 0)

    def test_grader_crash_counts_as_incorrect_not_500(self):
        taskdef = content.get(self.lab.slug).task("gcd")
        original = taskdef.check
        taskdef.check = lambda p, a: 1 / 0
        try:
            sub = services.submit_answer(self.session, self.task, self.answer)
        finally:
            taskdef.check = original
        self.assertEqual(sub.status, Submission.Status.INCORRECT)

    def test_start_is_idempotent(self):
        self.assertEqual(services.start_session(self.lab, self.student).pk, self.session.pk)


class ManualGradingTests(TestCase):
    def setUp(self):
        self.student = make_student()
        self.ta = make_staff()
        self.lab = synced_lab()
        self.session = services.start_session(self.lab, self.student)
        self.task = self.lab.tasks.get(key="explain-carmichael")

    def test_resubmitting_supersedes_pending(self):
        first = services.submit_answer(self.session, self.task, "draft")
        second = services.submit_answer(self.session, self.task, "final")
        first.refresh_from_db()
        self.assertEqual(first.status, Submission.Status.SUPERSEDED)
        self.assertEqual(second.status, Submission.Status.PENDING)

    def test_grade_counts_toward_score_and_locks(self):
        sub = services.submit_answer(self.session, self.task, "answer")
        services.grade_submission(sub, Decimal("7.5"), "good", self.ta)
        scores = scoring.lab_scores([self.student], [self.lab])
        self.assertEqual(scores[(self.student.id, self.lab.id)], Decimal("7.5"))
        with self.assertRaises(services.LabError):
            services.submit_answer(self.session, self.task, "changed my mind")

    def test_score_above_max_rejected(self):
        sub = services.submit_answer(self.session, self.task, "answer")
        with self.assertRaises(services.LabError):
            services.grade_submission(sub, Decimal("11"), "", self.ta)


class WeightedTotalTests(TestCase):
    def test_weighted_percent(self):
        a = synced_lab("l00-orientation", weight=Decimal("1"))
        b = synced_lab("l02-number-theory", weight=Decimal("3"))
        maxima = {a.id: Decimal("20"), b.id: Decimal("100")}
        # 50% on a (w1), 100% on b (w3) -> (0.5 + 3) / 4 = 87.5%
        pct = scoring.weighted_percent({a.id: Decimal("10"), b.id: Decimal("100")},
                                       [a, b], maxima)
        self.assertEqual(pct, Decimal("87.50"))
