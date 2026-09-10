"""Authentication & login-flow tests (spec §53, items 1–8, 10, 19)."""
from __future__ import annotations

from django.test import Client, TestCase
from django.urls import reverse

from accounts import constants as C
from audit.models import AuditEvent, SecurityEvent

from .base import BaseAuthTestCase, PASSWORD


class LoginTests(BaseAuthTestCase):
    def test_valid_login(self):
        resp = self.login_as(self.field_officer)
        self.assertRedirects(resp, "/general/", fetch_redirect_response=False)
        self.assertEqual(self.client.session[C.SESSION_PORTAL_KEY], C.PORTAL_GENERAL)
        self.assertTrue(AuditEvent.objects.filter(
            event_type=C.EVENT_LOGIN_SUCCESS, officer=self.field_officer).exists())

    def test_invalid_password(self):
        resp = self.login_as(self.field_officer, password="wrong-password-1")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid credentials or account status.")
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.failed_login_attempts, 1)
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_LOGIN_FAILURE).exists())

    def test_invalid_officer_id(self):
        resp = self.login_via_view("OFF-0000", code="whatever")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid credentials or account status.")

    def test_invalid_secret_code(self):
        resp = self.login_as(self.field_officer, code="WRONG-CODE")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid credentials or account status.")
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.failed_login_attempts, 1)

    def test_locked_account_blocked(self):
        self.login_protection_lock(self.field_officer)
        resp = self.login_as(self.field_officer)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid credentials or account status.")
        self.assertFalse("_auth_user_id" in self.client.session)

    def test_disabled_account(self):
        resp = self.login_as(self.disabled_officer)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid credentials or account status.")

    def test_inactive_account(self):
        resp = self.login_as(self.inactive_officer)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid credentials or account status.")

    def test_invited_account_requires_activation(self):
        resp = self.login_as(self.invited_officer)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Invalid credentials or account status.")

    def test_unauthorized_portal_selection(self):
        # Field officer (general only) attempts the classified portal.
        resp = self.login_as(self.field_officer, portal=C.PORTAL_CLASSIFIED)
        self.assertEqual(resp.status_code, 403)
        self.assertTrue(AuditEvent.objects.filter(
            event_type=C.EVENT_PORTAL_ACCESS_DENIED, officer=self.field_officer).exists())

    def test_generic_message_no_enumeration(self):
        # Unknown ID and wrong password must yield the *same* message text.
        r1 = self.login_via_view("OFF-0000", code="x")
        r2 = self.login_as(self.field_officer, password="wrong-password-1")
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)
        self.assertIn(b"Invalid credentials or account status.", r1.content)
        self.assertIn(b"Invalid credentials or account status.", r2.content)

    def test_lockout_after_max_failures(self):
        from accounts.services import login_protection_service

        officer = self.field_officer
        for _ in range(5):
            self.login_as(officer, password="wrong-password-1")
        officer.refresh_from_db()
        self.assertEqual(officer.account_status, C.ACCOUNT_STATUS_LOCKED)
        self.assertIsNotNone(officer.locked_until)
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_ACCOUNT_LOCKED).exists())
        self.assertTrue(SecurityEvent.objects.filter(event_type=C.EVENT_ACCOUNT_LOCKED).exists())

    def test_portal_selector_shows_three_portals(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Classified")
        self.assertContains(resp, "IT Department")
        self.assertContains(resp, "General Officer")

    # -- helper ---------------------------------------------------------------
    def login_protection_lock(self, officer):
        from django.utils import timezone

        officer.account_status = C.ACCOUNT_STATUS_LOCKED
        officer.is_active = False
        officer.locked_until = timezone.now() + timezone.timedelta(minutes=10)
        officer.save()


class CSRFProtectionTests(BaseAuthTestCase):
    def test_login_post_without_csrf_is_rejected(self):
        client = Client(enforce_csrf_checks=True)
        resp = client.post(
            reverse("accounts:login", kwargs={"portal_key": C.PORTAL_GENERAL}),
            {"officer_id": "OFF-101", "password": PASSWORD, "secret_code": "CODE-101"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_logout_requires_post_and_csrf(self):
        self.login_as(self.field_officer)
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.field_officer)
        resp = client.get(reverse("accounts:logout"))
        self.assertEqual(resp.status_code, 405)
