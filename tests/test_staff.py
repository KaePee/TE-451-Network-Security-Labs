import csv
import io

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.accounts.models import LoginEvent, User
from apps.audit.models import AuditLog
from apps.labs import services
from apps.labs.models import Accommodation
from apps.staffpanel import roster

from .helpers import make_staff, make_student, synced_lab

FAST_HASHER = override_settings(
    PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"],
    SECURE=False, SESSION_COOKIE_SECURE=False, CSRF_COOKIE_SECURE=False,
)


@FAST_HASHER
class RosterImportTests(TestCase):
    def test_import_with_excel_bom_and_header_aliases(self):
        data = ("﻿Index No,Surname,Other Names,Email\n"
                "2045001,Mensah,Ama,ama@st.knust.edu.gh\n"
                "2045002,Boateng,Kofi,\n\n").encode("utf-8")
        result = roster.parse_and_create(data)
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.created), 2)
        u = User.objects.get(username="2045001")
        self.assertEqual((u.last_name, u.first_name, u.role), ("Mensah", "Ama", "student"))
        self.assertTrue(u.must_change_password)
        self.assertTrue(u.check_password(result.created[0]["password"]))

    def test_errors_import_nothing(self):
        data = b"index_number,first_name,last_name\n2045001,Ama,Mensah\n2045002,,Boateng\n"
        result = roster.parse_and_create(data)
        self.assertTrue(result.errors)
        self.assertFalse(User.objects.exists())

    def test_existing_students_skipped_and_duplicates_rejected(self):
        make_student("2045001")
        ok = roster.parse_and_create(b"index_number,first_name,last_name\n2045001,A,B\n")
        self.assertEqual(ok.skipped, ["2045001"])
        dup = roster.parse_and_create(
            b"index_number,first_name,last_name\n2045009,A,B\n2045009,C,D\n")
        self.assertTrue(any("twice" in e for e in dup.errors))

    def test_missing_columns_reported(self):
        result = roster.parse_and_create(b"name,email\nAma,x@y\n")
        self.assertIn("Missing column", result.errors[0])

    def test_generated_passwords_are_unique_and_strong(self):
        pws = {roster.generate_password() for _ in range(200)}
        self.assertEqual(len(pws), 200)
        self.assertTrue(all(len(p) == 14 for p in pws))


@FAST_HASHER
class AccessControlTests(TestCase):
    def setUp(self):
        self.student = make_student()
        self.ta = make_staff()

    def test_students_cannot_reach_staff_pages(self):
        self.client.force_login(self.student)
        for name in ("staff:dashboard", "staff:students", "staff:export_marks",
                     "staff:grading"):
            self.assertEqual(self.client.get(reverse(name)).status_code, 403, name)

    def test_ta_cannot_read_audit_log_but_lecturer_can(self):
        self.client.force_login(self.ta)
        self.assertEqual(self.client.get(reverse("staff:audit")).status_code, 403)
        self.client.force_login(make_staff("lect", User.Role.LECTURER))
        self.assertEqual(self.client.get(reverse("staff:audit")).status_code, 200)

    def test_staff_pages_render(self):
        lab = synced_lab()
        session = services.start_session(lab, self.student)
        sub = services.submit_answer(session, lab.tasks.get(key="explain-carmichael"), "x")
        self.client.force_login(self.ta)
        for url in (reverse("staff:dashboard"), reverse("staff:students"),
                    reverse("staff:student", args=[self.student.pk]),
                    reverse("staff:lab_list"), reverse("staff:lab_progress", args=[lab.slug]),
                    reverse("staff:lab_edit", args=[lab.slug]), reverse("staff:grading"),
                    reverse("staff:grade", args=[sub.pk]), reverse("staff:logins"),
                    reverse("staff:student_import"), reverse("staff:student_add")):
            self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_student_pages_render(self):
        lab = synced_lab()
        self.client.force_login(self.student)
        self.assertEqual(self.client.get(reverse("home")).status_code, 200)
        self.client.post(reverse("labs:start", args=[lab.slug]))
        r = self.client.get(reverse("labs:detail", args=[lab.slug]))
        self.assertContains(r, "Euclid on big numbers")


@FAST_HASHER
class AccountStateTests(TestCase):
    def setUp(self):
        self.student = make_student()

    def test_login_is_recorded(self):
        self.client.post(reverse("accounts:login"),
                         {"username": "2045001", "password": "correct-horse-battery"})
        self.assertTrue(LoginEvent.objects.filter(user=self.student, kind="login").exists())
        self.client.logout()
        self.client.post(reverse("accounts:login"), {"username": "2045001", "password": "x"})
        self.assertTrue(LoginEvent.objects.filter(username="2045001", kind="failed").exists())

    def test_suspension_logs_out_mid_session(self):
        self.client.force_login(self.student)
        self.assertEqual(self.client.get(reverse("home")).status_code, 200)
        self.student.suspend("academic misconduct")
        r = self.client.get(reverse("home"))
        self.assertRedirects(r, reverse("accounts:login") + "?suspended=1")
        self.assertEqual(self.client.get(reverse("home")).status_code, 302)  # still out

    def test_suspended_cannot_log_in(self):
        self.student.suspend("x")
        r = self.client.post(reverse("accounts:login"),
                             {"username": "2045001", "password": "correct-horse-battery"})
        self.assertContains(r, "suspended")

    def test_forced_password_change(self):
        self.student.must_change_password = True
        self.student.save()
        self.client.force_login(self.student)
        self.assertRedirects(self.client.get(reverse("home")), reverse("accounts:password_change"))
        r = self.client.post(reverse("accounts:password_change"), {
            "old_password": "correct-horse-battery",
            "new_password1": "a-much-better-passphrase", "new_password2": "a-much-better-passphrase"})
        self.assertRedirects(r, reverse("home"))
        self.student.refresh_from_db()
        self.assertFalse(self.student.must_change_password)


@FAST_HASHER
class StaffActionTests(TestCase):
    def setUp(self):
        self.student = make_student()
        self.ta = make_staff()
        self.client.force_login(self.ta)

    def test_suspend_requires_reason_and_is_audited(self):
        url = reverse("staff:student_suspend", args=[self.student.pk])
        self.client.post(url, {"reason": ""})
        self.student.refresh_from_db()
        self.assertFalse(self.student.suspended)
        self.client.post(url, {"reason": "shared account"})
        self.student.refresh_from_db()
        self.assertTrue(self.student.suspended)
        self.assertTrue(AuditLog.objects.filter(action="suspend", target=self.student).exists())

    def test_grant_extra_time(self):
        lab = synced_lab()
        self.client.post(reverse("staff:accommodation_add", args=[self.student.pk]),
                         {"lab": lab.pk, "extra_minutes": 30, "reason": "medical"})
        acc = Accommodation.objects.get(student=self.student)
        self.assertEqual((acc.extra_minutes, acc.granted_by), (30, self.ta))

    def test_import_then_credentials_downloadable_once(self):
        f = SimpleUploadedFile("c.csv", b"index_number,first_name,last_name\n2045777,Yaw,Asante\n")
        self.client.post(reverse("staff:student_import"), {"file": f})
        r = self.client.get(reverse("staff:student_import_credentials"))
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual(rows[1][0], "2045777")
        self.assertTrue(User.objects.get(username="2045777").check_password(rows[1][3]))
        again = self.client.get(reverse("staff:student_import_credentials"))
        self.assertEqual(again.status_code, 302)

    def test_export_escapes_formulas(self):
        synced_lab()
        evil = make_student("2045555")
        evil.first_name = '=HYPERLINK("http://evil")'
        evil.save()
        r = self.client.get(reverse("staff:export_marks"))
        body = r.content.decode()
        self.assertIn("'=HYPERLINK", body)
        self.assertNotIn(',=HYPERLINK', body)
        header = next(csv.reader(io.StringIO(body)))
        self.assertEqual(header[-2:], ["weighted_percent", "suspended"])


@FAST_HASHER
@override_settings(BEHIND_PROXY=True, AXES_FAILURE_LIMIT=3)
class LockoutTests(TestCase):
    def setUp(self):
        self.student = make_student()

    def _login(self, ip, password):
        return self.client.post(reverse("accounts:login"),
                                {"username": "2045001", "password": password},
                                HTTP_X_FORWARDED_FOR=ip, REMOTE_ADDR="172.18.0.5")

    def test_classmate_cannot_lock_out_victim_from_another_laptop(self):
        for _ in range(4):
            self._login("10.10.30.66", "guess")
        self.assertEqual(self._login("10.10.30.66", "correct-horse-battery").status_code, 429)
        r = self._login("10.10.30.44", "correct-horse-battery")
        self.assertEqual(r.status_code, 302)
