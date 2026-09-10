"""Session security tests (spec §53, items 17–19)."""
from __future__ import annotations

from django.test import Client
from django.utils import timezone

from accounts import constants as C
from accounts.services import account_service, session_service
from audit.models import AuditEvent

from .base import BaseAuthTestCase


class SessionTests(BaseAuthTestCase):
    def test_session_key_rotation_on_login(self):
        self.client.get("/")  # establish a session
        before = self.client.session.session_key
        self.login_as(self.field_officer)
        after = self.client.session.session_key
        self.assertIsNotNone(before)
        self.assertIsNotNone(after)
        self.assertNotEqual(before, after)

    def test_logout_flushes_session(self):
        self.login_as(self.field_officer)
        self.assertTrue(self.client.session.items())
        resp = self.client.post("/auth/logout/")
        self.assertRedirects(resp, "/", fetch_redirect_response=False)
        self.assertEqual(list(self.client.session.items()), [])
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_LOGOUT).exists())

    def test_inactivity_timeout(self):
        self.login_as(self.field_officer)
        session = self.client.session
        session["last_activity"] = (timezone.now() - timezone.timedelta(minutes=60)).isoformat()
        session.save()
        resp = self.client.get("/general/")
        self.assertRedirects(resp, "/", fetch_redirect_response=False)
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_SESSION_EXPIRED).exists())

    def test_absolute_session_age_timeout(self):
        self.login_as(self.field_officer)
        session = self.client.session
        session[C.SESSION_LOGIN_AT] = (timezone.now() - timezone.timedelta(hours=12)).isoformat()
        session.save()
        resp = self.client.get("/general/")
        self.assertRedirects(resp, "/", fetch_redirect_response=False)

    def test_disabled_account_loses_session(self):
        self.login_as(self.field_officer)
        self.assertEqual(self.client.get("/general/").status_code, 200)
        account_service.disable(self.field_officer, self.it_admin)
        resp = self.client.get("/general/")
        # The session rows were revoked server-side, so the next request is
        # anonymous and bounces to the login screen (either directly or via
        # the middleware's portal-selection redirect).
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp["Location"].startswith("/auth/login/") or resp["Location"] == "/")

    def test_reauth_gate_for_sensitive_operations(self):
        self.login_as(self.it_admin, portal=C.PORTAL_IT_ADMIN)
        # Force the re-auth window to have passed.
        session = self.client.session
        session[C.SESSION_REAUTH_AT] = (timezone.now() - timezone.timedelta(minutes=30)).isoformat()
        session.save()
        resp = self.client.get("/admin-portal/officers/new/")
        self.assertRedirects(resp, "/auth/reauth/", fetch_redirect_response=False)

    def test_reauth_success_resumes(self):
        self.login_as(self.it_admin, portal=C.PORTAL_IT_ADMIN)
        session = self.client.session
        session[C.SESSION_REAUTH_AT] = (timezone.now() - timezone.timedelta(minutes=30)).isoformat()
        session["reauth_next"] = "/admin-portal/officers/new/"
        session.save()
        resp = self.client.post(
            "/auth/reauth/",
            {"password": "TestPassword!123", "secret_code": self.code_for(self.it_admin)},
        )
        self.assertRedirects(resp, "/admin-portal/officers/new/", fetch_redirect_response=False)
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_REAUTH_SUCCESS).exists())
