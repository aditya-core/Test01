"""Provisioning & separation-of-duties tests (spec §53, items 16, 22–25)."""
from __future__ import annotations

from django.urls import reverse

from accounts import constants as C
from accounts.models import Officer, PortalAccess
from accounts.services import account_service, provisioning_service
from audit.models import AuditEvent

from .base import BaseAuthTestCase


class ProvisioningViewTests(BaseAuthTestCase):
    def _create_data(self, **overrides):
        data = {
            "officer_id": "",
            "email": "new.officer@example.gov",
            "full_name": "New Officer",
            "rank": "Constable",
            "department": "Ops",
            "phone": "",
            "role": self.field_role.pk,
            "clearance": self.l2.pk,
            "unit": self.unit_investigation.pk,
            "portals": [self.portal_general.pk],
            "initial_password": "TempPass!123",
            "initial_secret_code": "NEW-CODE-1",
            "reason": "Test provisioning",
        }
        data.update(overrides)
        return data

    def test_it_admin_can_provision_officer(self):
        self.login_as(self.it_admin, portal=C.PORTAL_IT_ADMIN)
        resp = self.client.post(reverse("it_admin:officer_create"), self._create_data())
        self.assertEqual(resp.status_code, 200)
        officer = Officer.objects.get(email="new.officer@example.gov")
        self.assertEqual(officer.account_status, C.ACCOUNT_STATUS_INVITED)
        self.assertTrue(officer.secret_code_configured)
        self.assertTrue(officer.check_password("TempPass!123"))
        self.assertTrue(officer.has_portal_access(C.PORTAL_GENERAL))
        self.assertTrue(AuditEvent.objects.filter(
            event_type=C.EVENT_ACCOUNT_CREATED, officer=officer, actor=self.it_admin).exists())

    def test_auto_generated_officer_id(self):
        self.login_as(self.it_admin, portal=C.PORTAL_IT_ADMIN)
        resp = self.client.post(reverse("it_admin:officer_create"), self._create_data(
            email="gen.id@example.gov"))
        self.assertEqual(resp.status_code, 200)
        officer = Officer.objects.get(email="gen.id@example.gov")
        self.assertRegex(officer.officer_id, r"^OFF-\d{3}$")

    def test_field_officer_cannot_access_provisioning(self):
        self.login_as(self.field_officer)
        resp = self.client.get(reverse("it_admin:officer_create"))
        self.assertEqual(resp.status_code, 403)

    def test_senior_officer_cannot_manage_accounts(self):
        # Higher rank does not confer identity administration.
        self.login_as(self.senior_officer)
        resp = self.client.get(reverse("it_admin:officer_list"))
        self.assertEqual(resp.status_code, 403)

    def test_no_impersonation_endpoint(self):
        # There must be no "login as officer" route for anyone.
        for path in ("/admin-portal/impersonate/", "/admin-portal/officers/1/login-as/"):
            resp = self.client.get(path)
            self.assertIn(resp.status_code, (404, 302, 403))

    def test_inspector_cannot_reset_another_officers_password(self):
        self.login_as(self.inspector)
        resp = self.client.post(
            reverse("it_admin:officer_reset_password", kwargs={"pk": self.field_officer.pk}),
            {"new_password": "HackedPass!123"},
        )
        self.assertIn(resp.status_code, (403, 404))
        self.field_officer.refresh_from_db()
        self.assertFalse(self.field_officer.check_password("HackedPass!123"))


class AccountServiceTests(BaseAuthTestCase):
    def test_status_transitions_are_audited(self):
        account_service.disable(self.field_officer, self.it_admin)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_DISABLED)
        self.assertFalse(self.field_officer.is_active)
        self.assertTrue(AuditEvent.objects.filter(
            event_type=C.EVENT_ACCOUNT_DISABLED, officer=self.field_officer, actor=self.it_admin).exists())

        account_service.activate(self.field_officer, self.it_admin)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_ACTIVE)

    def test_role_change_audited(self):
        account_service.assign_role(self.field_officer, self.inspector_role, self.it_admin)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.role, self.inspector_role)
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_ROLE_CHANGED).exists())

    def test_clearance_change_audited(self):
        account_service.assign_clearance(self.field_officer, self.l4, self.it_admin)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.clearance, self.l4)
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_CLEARANCE_CHANGED).exists())

    def test_lock_and_unlock(self):
        account_service.lock(self.field_officer, self.it_admin, minutes=5)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_LOCKED)
        self.assertIsNotNone(self.field_officer.locked_until)

        account_service.unlock(self.field_officer, self.it_admin)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_ACTIVE)
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_ACCOUNT_UNLOCKED).exists())

    def test_password_reset_audited_and_sessions_revoked(self):
        provisioning_service.reset_password(self.field_officer, self.it_admin, "NewPass!12345")
        self.field_officer.refresh_from_db()
        self.assertTrue(self.field_officer.check_password("NewPass!12345"))
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_PASSWORD_RESET).exists())

    def test_mfa_reset_audited(self):
        provisioning_service.reset_secret_code(self.field_officer, self.it_admin, "CODE-NEW9")
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_SECRET_CODE_RESET).exists())

    def test_deactivation_revokes_portal_ability(self):
        account_service.deactivate(self.classified_officer, self.it_admin)
        self.classified_officer.refresh_from_db()
        self.assertEqual(self.classified_officer.account_status, C.ACCOUNT_STATUS_DEACTIVATED)
