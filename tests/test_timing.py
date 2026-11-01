from datetime import timedelta

from django.test import TestCase

from apps.labs.models import Accommodation, Lab, LabSession
from apps.labs.timing import Status, lab_state

from .helpers import ago, ahead, make_student, synced_lab


class DeadlineModeTests(TestCase):
    def setUp(self):
        self.student = make_student()

    def test_unpublished_is_hidden_from_students(self):
        lab = synced_lab(published=False)
        self.assertEqual(lab_state(lab, self.student).status, Status.UNPUBLISHED)

    def test_not_open_yet(self):
        lab = synced_lab(opens_at=ahead(hours=1))
        self.assertEqual(lab_state(lab, self.student).status, Status.NOT_OPEN)

    def test_open_then_missed(self):
        lab = synced_lab(opens_at=ago(days=1), closes_at=ahead(hours=1))
        self.assertTrue(lab_state(lab, self.student).can_start)
        lab.closes_at = ago(minutes=1)
        lab.save()
        self.assertEqual(lab_state(lab, self.student).status, Status.MISSED)

    def test_session_locks_at_deadline(self):
        lab = synced_lab(closes_at=ago(minutes=1))
        session = LabSession.objects.create(lab=lab, student=self.student, seed=1,
                                            started_at=ago(hours=2))
        self.assertEqual(lab_state(lab, self.student, session).status, Status.TIME_UP)

    def test_extra_minutes_extend_deadline(self):
        lab = synced_lab(closes_at=ago(minutes=10))
        Accommodation.objects.create(student=self.student, lab=lab, extra_minutes=30,
                                     reason="medical")
        state = lab_state(lab, self.student)
        self.assertTrue(state.can_start)
        self.assertEqual(state.deadline, lab.closes_at + timedelta(minutes=30))

    def test_deadline_override_and_global_extra_stack(self):
        lab = synced_lab(closes_at=ago(days=1))
        new_close = ahead(days=1)
        Accommodation.objects.create(student=self.student, lab=lab,
                                     closes_at_override=new_close, reason="bereavement")
        Accommodation.objects.create(student=self.student, lab=None, extra_minutes=15,
                                     reason="standing accommodation")
        self.assertEqual(lab_state(lab, self.student).deadline,
                         new_close + timedelta(minutes=15))

    def test_other_students_accommodation_does_not_apply(self):
        lab = synced_lab(closes_at=ago(minutes=5))
        other = make_student("2045002")
        Accommodation.objects.create(student=other, lab=lab, extra_minutes=60, reason="x")
        self.assertEqual(lab_state(lab, self.student).status, Status.MISSED)


class TimedModeTests(TestCase):
    def setUp(self):
        self.student = make_student()

    def test_timer_runs_from_start(self):
        lab = synced_lab(mode=Lab.Mode.TIMED, duration_minutes=120)
        session = LabSession.objects.create(lab=lab, student=self.student, seed=1,
                                            started_at=ago(minutes=119))
        state = lab_state(lab, self.student, session)
        self.assertEqual(state.status, Status.IN_PROGRESS)
        self.assertLessEqual(state.seconds_left, 60)

        session.started_at = ago(minutes=121)
        self.assertEqual(lab_state(lab, self.student, session).status, Status.TIME_UP)

    def test_window_close_caps_the_timer(self):
        lab = synced_lab(mode=Lab.Mode.TIMED, duration_minutes=120, closes_at=ahead(minutes=5))
        session = LabSession.objects.create(lab=lab, student=self.student, seed=1)
        self.assertEqual(lab_state(lab, self.student, session).deadline, lab.closes_at)

    def test_extra_time_granted_mid_session_applies_immediately(self):
        lab = synced_lab(mode=Lab.Mode.TIMED, duration_minutes=60)
        session = LabSession.objects.create(lab=lab, student=self.student, seed=1,
                                            started_at=ago(minutes=61))
        self.assertEqual(lab_state(lab, self.student, session).status, Status.TIME_UP)
        Accommodation.objects.create(student=self.student, lab=lab, extra_minutes=20,
                                     reason="power cut")
        self.assertEqual(lab_state(lab, self.student, session).status, Status.IN_PROGRESS)

    def test_finished_is_final(self):
        lab = synced_lab(mode=Lab.Mode.TIMED)
        session = LabSession.objects.create(lab=lab, student=self.student, seed=1,
                                            finished_at=ago(minutes=1))
        self.assertEqual(lab_state(lab, self.student, session).status, Status.FINISHED)
