"""PHASE 5–7 — Account lifecycle, devices & sessions, audit log."""
from __future__ import annotations

from django.contrib.sessions.models import Session
from django.urls import reverse

from accounts import constants as C
from accounts.models import Officer, OfficerSession, RegisteredDevice
from audit.models import AuditEvent
from audit.services import audit_service

from ..models import ApprovalRequest
from .base import AdminPortalTestCase


class LifecycleTests(AdminPortalTestCase):
    def _lifecycle(self, officer, action, reason="Documented reason", follow=True):
        return self.client.post(reverse("it_admin:officer_lifecycle", args=[officer.pk]),
                                {"action": action, "reason": reason}, follow=follow)

    def test_suspend_requires_reason_and_terminates_sessions(self):
        # Give the field officer a live session first.
        self.login_as(self.field_officer)
        self.assertEqual(Session.objects.count(), 1)
        self.login_admin(self.security_admin2)
        resp = self._lifecycle(self.field_officer, "suspend", reason="x")
        self.assertIn("Please provide a meaningful reason (at least 5 characters).", self.messages_of(resp))
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_ACTIVE)

        resp = self._lifecycle(self.field_officer, "suspend", reason="Pending departmental enquiry")
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_SUSPENDED)
        ev = AuditEvent.objects.get(event_type=C.EVENT_ACCOUNT_SUSPENDED, officer=self.field_officer)
        self.assertEqual(ev.actor, self.security_admin2)
        self.assertEqual(ev.previous_state["account_status"], C.ACCOUNT_STATUS_ACTIVE)
        self.assertEqual(ev.new_state["account_status"], C.ACCOUNT_STATUS_SUSPENDED)
        self.assertEqual(ev.reason, "Pending departmental enquiry")
        # Only the admin's own session survives.
        remaining = [Session.objects.get(pk=k).get_decoded().get("_auth_user_id") for k in Session.objects.values_list("pk", flat=True)]
        self.assertNotIn(str(self.field_officer.pk), remaining)
        # Suspended officer cannot sign in.
        self.client.logout()
        resp = self.login_as(self.field_officer)
        self.assertEqual(resp.status_code, 200)

    def test_reactivate_and_invalid_transitions(self):
        self.login_admin(self.security_admin2)
        resp = self._lifecycle(self.field_officer, "reactivate")
        self.assertIn("Cannot reactivate an account in status ACTIVE.", self.messages_of(resp))
        self._lifecycle(self.field_officer, "suspend")
        self._lifecycle(self.field_officer, "reactivate", reason="Enquiry closed")
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_ACTIVE)
        self.assertTrue(self.field_officer.is_active)
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_ACCOUNT_REACTIVATED, officer=self.field_officer).exists())

    def test_emergency_lock_blocks_login_kills_sessions_revokes_devices(self):
        self.login_as(self.field_officer)
        self.assertEqual(RegisteredDevice.objects.filter(officer=self.field_officer, status=C.DEVICE_STATUS_ACTIVE).count(), 1)
        self.login_admin(self.security_admin2)
        resp = self.client.post(reverse("it_admin:officer_lock", args=[self.field_officer.pk]),
                                {"reason": "Credential compromise reported"}, follow=True)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_LOCKED)
        self.assertIsNone(self.field_officer.locked_until)  # indefinite
        self.assertEqual(RegisteredDevice.objects.filter(officer=self.field_officer, status=C.DEVICE_STATUS_ACTIVE).count(), 0)
        self.assertFalse(OfficerSession.objects.filter(officer=self.field_officer, ended_at__isnull=True).exists())
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_ACCOUNT_EMERGENCY_LOCKED, officer=self.field_officer).exists())
        self.client.logout()
        self.assertEqual(self.login_as(self.field_officer).status_code, 200)
        # unlock restores
        self.login_admin(self.security_admin2)
        self.client.post(reverse("it_admin:officer_unlock", args=[self.field_officer.pk]), {"reason": "Investigation cleared"})
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_ACTIVE)

    def test_cannot_lock_or_deactivate_self(self):
        self.login_admin(self.security_admin2)
        resp = self._lifecycle(self.security_admin2, "deactivate")
        self.assertIn("You cannot suspend, lock or deactivate your own account.", self.messages_of(resp))
        self.security_admin2.refresh_from_db()
        self.assertEqual(self.security_admin2.account_status, C.ACCOUNT_STATUS_ACTIVE)

    def test_deactivate_regular_officer_preserves_history(self):
        self.login_admin(self.security_admin2)
        self._lifecycle(self.field_officer, "deactivate", reason="Left service")
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_DEACTIVATED)
        self.assertTrue(Officer.objects.filter(pk=self.field_officer.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(officer=self.field_officer).exists())

    def test_deactivating_privileged_account_needs_second_admin(self):
        self.login_admin(self.security_admin2)
        resp = self._lifecycle(self.identity_admin, "deactivate", reason="Transferred out")
        self.assertTrue(any("second-administrator approval" in m for m in self.messages_of(resp)))
        self.identity_admin.refresh_from_db()
        self.assertEqual(self.identity_admin.account_status, C.ACCOUNT_STATUS_ACTIVE)
        self.assertTrue(ApprovalRequest.objects.filter(action=ApprovalRequest.ACTION_PRIVILEGED_DEACTIVATE,
                                                       target_id=self.identity_admin.officer_id, status="PENDING").exists())

    def test_identity_admin_can_suspend_but_auditor_cannot(self):
        self.login_admin(self.auditor)
        resp = self._lifecycle(self.field_officer, "suspend", follow=False)
        self.assertEqual(resp.status_code, 403)
        self.login_admin(self.identity_admin)
        self._lifecycle(self.field_officer, "suspend")
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_SUSPENDED)

    def test_legacy_status_endpoint_requires_reason(self):
        self.login_admin(self.security_admin2)
        resp = self.client.post(reverse("it_admin:officer_status", args=[self.field_officer.pk]),
                                {"status": C.ACCOUNT_STATUS_SUSPENDED}, follow=True)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.account_status, C.ACCOUNT_STATUS_ACTIVE)
        self.assertTrue(any("reason" in m for m in self.messages_of(resp)))


class DeviceSessionTests(AdminPortalTestCase):
    def test_login_registers_device_and_session(self):
        self.login_as(self.field_officer)
        device = RegisteredDevice.objects.get(officer=self.field_officer)
        self.assertEqual(device.status, C.DEVICE_STATUS_ACTIVE)
        self.assertIn("sdms_device", self.client.cookies)
        row = OfficerSession.objects.get(officer=self.field_officer)
        self.assertIsNone(row.ended_at)
        self.assertEqual(row.device, device)
        # Logout closes the session row.
        self.client.post(reverse("accounts:logout"))
        row.refresh_from_db()
        self.assertIsNotNone(row.ended_at)
        self.assertEqual(row.end_reason, C.SESSION_END_LOGOUT)

    def test_terminate_session_signs_officer_out(self):
        self.login_as(self.field_officer)
        victim_cookies = self.client.cookies.copy()
        row = OfficerSession.objects.get(officer=self.field_officer)
        self.login_admin(self.security_admin2)
        resp = self.client.post(reverse("it_admin:session_terminate", args=[row.pk]), {"reason": "Suspicious location"})
        self.assertEqual(resp.status_code, 302)
        row.refresh_from_db()
        self.assertEqual(row.end_reason, C.SESSION_END_TERMINATED)
        self.assertEqual(row.ended_by, self.security_admin2)
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_SESSION_TERMINATED, officer=self.field_officer).exists())
        # The victim's session cookie no longer authenticates.
        self.client.cookies = victim_cookies
        resp = self.client.get(reverse("general:dashboard"))
        self.assertEqual(resp.status_code, 302)

    def test_revoke_device_ends_its_sessions(self):
        self.login_as(self.field_officer)
        device = RegisteredDevice.objects.get(officer=self.field_officer)
        self.login_admin(self.system_admin)
        resp = self.client.post(reverse("it_admin:device_revoke", args=[device.pk]), {"reason": "Lost laptop"}, follow=True)
        device.refresh_from_db()
        self.assertEqual(device.status, C.DEVICE_STATUS_REVOKED)
        self.assertEqual(device.revoked_by, self.system_admin)
        self.assertFalse(OfficerSession.objects.filter(officer=self.field_officer, ended_at__isnull=True).exists())
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_DEVICE_REVOKED, officer=self.field_officer).exists())

    def test_terminate_all_and_permissions(self):
        self.login_as(self.field_officer)
        self.login_admin(self.auditor)  # device.view / session.view only
        self.assertEqual(self.client.get(reverse("it_admin:device_session_overview")).status_code, 200)
        row = OfficerSession.objects.get(officer=self.field_officer)
        self.assertEqual(self.client.post(reverse("it_admin:session_terminate", args=[row.pk])).status_code, 403)
        self.login_admin(self.security_admin2)
        resp = self.client.post(reverse("it_admin:session_terminate_all", args=[self.field_officer.pk]), {"reason": "Incident response"})
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(OfficerSession.objects.filter(officer=self.field_officer, ended_at__isnull=True).exists())

    def test_overview_lists_only_real_sessions(self):
        self.login_admin(self.security_admin2)
        resp = self.client.get(reverse("it_admin:device_session_overview"))
        ids = {s.officer.officer_id for s in resp.context["sessions"].object_list}
        self.assertEqual(ids, {"OFF-403"})


class AuditLogTests(AdminPortalTestCase):
    def test_audit_log_shows_prev_new_and_reason(self):
        self.login_admin(self.security_admin2)
        self.client.post(reverse("it_admin:officer_lifecycle", args=[self.field_officer.pk]),
                         {"action": "suspend", "reason": "Enquiry 77"})
        resp = self.client.get(reverse("it_admin:audit_dashboard"), {"type": C.EVENT_ACCOUNT_SUSPENDED})
        html = resp.content.decode()
        self.assertIn("Enquiry 77", html)
        self.assertIn("SUSPENDED", html)
        self.assertNotIn("Delete", html)
        self.assertNotIn("Edit event", html)

    def test_audit_events_are_immutable(self):
        from audit.models import AuditImmutableError

        ev = audit_service.record_event(C.EVENT_ACCOUNT_CREATED, officer=self.field_officer, actor=self.system_admin)
        ev.reason = "tampered"
        with self.assertRaises(AuditImmutableError):
            ev.save()
        with self.assertRaises(AuditImmutableError):
            ev.delete()

    def test_chain_verification_detects_tampering(self):
        self.login_admin(self.auditor)
        resp = self.client.post(reverse("it_admin:audit_verify"), follow=True)
        self.assertTrue(any("intact" in m for m in self.messages_of(resp)))
        ev = AuditEvent.objects.order_by("sequence").last()
        AuditEvent.objects.filter(pk=ev.pk).update(reason="tampered after the fact")
        result = audit_service.verify_chain()
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_break"], ev.sequence)

    def test_only_audit_view_can_open_log(self):
        self.login_admin(self.identity_admin)
        self.assertEqual(self.client.get(reverse("it_admin:audit_dashboard")).status_code, 403)
        self.login_admin(self.auditor)
        self.assertEqual(self.client.get(reverse("it_admin:audit_dashboard")).status_code, 200)
