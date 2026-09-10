"""Secure account activation tests (spec §11)."""
from __future__ import annotations

from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from accounts import constants as C
from audit.models import AuditEvent

from .base import BaseAuthTestCase, PASSWORD


class ActivationTests(BaseAuthTestCase):
    def _activation_url(self, officer):
        uidb64 = urlsafe_base64_encode(force_bytes(officer.pk))
        token = default_token_generator.make_token(officer)
        return reverse("accounts:activate", kwargs={"uidb64": uidb64, "token": token})

    def test_invited_officer_completes_activation(self):
        officer = self.invited_officer
        url = self._activation_url(officer)

        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)

        resp = self.client.post(url, {
            "provisional_password": PASSWORD,
            "new_password": "BrandNewPass!9",
            "confirm_password": "BrandNewPass!9",
            "new_secret_code": "MY-NEW-CODE",
        })
        self.assertRedirects(resp, "/auth/login/general/", fetch_redirect_response=False)

        officer.refresh_from_db()
        self.assertEqual(officer.account_status, C.ACCOUNT_STATUS_ACTIVE)
        self.assertTrue(officer.is_active)
        self.assertTrue(officer.check_password("BrandNewPass!9"))
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_ACCOUNT_ACTIVATED).exists())

        # Officer can now sign in with the new credentials.
        resp = self.login_via_view(officer.officer_id, password="BrandNewPass!9", code="MY-NEW-CODE")
        self.assertRedirects(resp, "/general/", fetch_redirect_response=False)

    def test_invalid_token_rejected(self):
        url = reverse("accounts:activate", kwargs={"uidb64": "AAAA", "token": "bad-token"})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 400)

    def test_wrong_provisional_password_rejected(self):
        officer = self.invited_officer
        url = self._activation_url(officer)
        resp = self.client.post(url, {
            "provisional_password": "WRONG-PROVISIONAL",
            "new_password": "BrandNewPass!9",
            "confirm_password": "BrandNewPass!9",
            "new_secret_code": "MY-NEW-CODE",
        })
        self.assertEqual(resp.status_code, 200)
        officer.refresh_from_db()
        self.assertEqual(officer.account_status, C.ACCOUNT_STATUS_INVITED)
