"""PHASE 8–13 — Explainability, temporary access, reviews, admin roles,
four-eyes approvals, timeline, bulk import."""
from __future__ import annotations

from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils import timezone

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.models import Officer, Permission, Role, TemporaryCapability
from audit.models import AuditEvent

from ..models import AccessReview, ApprovalRequest
from ..services import access_review_service, temporary_access_service
from .base import AdminPortalTestCase


class ExplainabilityTests(AdminPortalTestCase):
    def test_why_page_explains_role_and_temporary_sources(self):
        temporary_access_service.grant(
            self.identity_admin, self.perms[C.PERM_AUDIT_VIEW], reason="Audit cover", starts_at=timezone.now(),
            expires_at=timezone.now() + timezone.timedelta(hours=2), actor=self.system_admin)
        self.login_admin(self.auditor)
        url = reverse("it_admin:officer_access", args=[self.identity_admin.pk])
        resp = self.client.get(url, {"capability": C.PERM_OFFICER_CREATE})
        single = resp.context["single"]
        self.assertTrue(single["granted"])
        self.assertEqual(single["source"], "role:IDENTITY_ADMIN")
        resp = self.client.get(url, {"capability": C.PERM_AUDIT_VIEW})
        self.assertEqual(resp.context["single"]["status"], "TEMPORARY")
        self.assertIn("Audit cover", resp.context["single"]["why"])
        resp = self.client.get(url, {"capability": "case.view"})
        self.assertEqual(resp.context["single"]["why"], "Operational authorization is managed separately.")

    def test_legacy_umbrella_is_explained_as_implication(self):
        self.login_admin(self.auditor)
        resp = self.client.get(reverse("it_admin:officer_access", args=[self.it_admin.pk]), {"capability": C.PERM_OFFICER_SUSPEND})
        self.assertTrue(resp.context["single"]["granted"])
        self.assertIn("officer.manage", resp.context["single"]["source"])


class TemporaryAccessTests(AdminPortalTestCase):
    def _grant(self, officer, codename, hours=2, start_offset=0):
        now = timezone.now()
        return self.client.post(reverse("it_admin:temporary_access_create"), {
            "officer": officer.pk, "permission": Permission.objects.get(codename=codename).pk,
            "starts_at": (now + timezone.timedelta(minutes=start_offset)).strftime("%Y-%m-%dT%H:%M"),
            "expires_at": (now + timezone.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M"),
            "reason": "Leave cover for audit desk",
        }, follow=True)

    def test_grant_is_effective_and_expires(self):
        self.login_admin(self.system_admin)
        self._grant(self.identity_admin, C.PERM_AUDIT_VIEW)
        grant = TemporaryCapability.objects.get(officer=self.identity_admin)
        self.assertTrue(authorization_service.has_permission(self.identity_admin, C.PERM_AUDIT_VIEW))
        self.login_admin(self.identity_admin)
        self.assertEqual(self.client.get(reverse("it_admin:audit_dashboard")).status_code, 200)
        TemporaryCapability.objects.filter(pk=grant.pk).update(expires_at=timezone.now() - timezone.timedelta(minutes=1))
        self.assertFalse(authorization_service.has_permission(self.identity_admin, C.PERM_AUDIT_VIEW))
        self.assertEqual(self.client.get(reverse("it_admin:audit_dashboard")).status_code, 403)
        grant.refresh_from_db()
        self.assertEqual(grant.effective_status, "EXPIRED")

    def test_operational_capability_cannot_be_granted(self):
        self.login_admin(self.system_admin)
        resp = self._grant(self.identity_admin, "case.view")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(TemporaryCapability.objects.filter(officer=self.identity_admin).exists())
        with self.assertRaises(Exception):
            temporary_access_service.grant(self.identity_admin, self.perms["case.view"], reason="x",
                                           starts_at=timezone.now(), expires_at=timezone.now() + timezone.timedelta(hours=1),
                                           actor=self.system_admin)

    def test_revoke_and_audit(self):
        self.login_admin(self.system_admin)
        self._grant(self.identity_admin, C.PERM_AUDIT_VIEW)
        grant = TemporaryCapability.objects.get(officer=self.identity_admin)
        self.client.post(reverse("it_admin:temporary_access_revoke", args=[grant.pk]), {"reason": "Cover no longer needed"})
        grant.refresh_from_db()
        self.assertEqual(grant.status, C.TEMP_ACCESS_REVOKED)
        self.assertFalse(authorization_service.has_permission(self.identity_admin, C.PERM_AUDIT_VIEW))
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_TEMPORARY_ACCESS_GRANTED, officer=self.identity_admin).exists())
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_TEMPORARY_ACCESS_REVOKED, officer=self.identity_admin).exists())

    def test_security_admin_cannot_grant(self):
        self.login_admin(self.security_admin2)
        self.assertEqual(self.client.get(reverse("it_admin:temporary_access_create")).status_code, 403)


class AccessReviewTests(AdminPortalTestCase):
    def test_review_lifecycle_keep(self):
        self.login_admin(self.security_admin2)
        resp = self.client.post(reverse("it_admin:access_review_raise", args=[self.identity_admin.pk]),
                                {"trigger": "Periodic access review"})
        review = AccessReview.objects.get(officer=self.identity_admin)
        self.assertEqual(review.status, AccessReview.STATUS_PENDING)
        self.assertIn(C.PERM_OFFICER_CREATE, review.snapshot["capabilities"])
        resp = self.client.post(reverse("it_admin:access_review_decide", args=[review.pk]),
                                {"decision": "KEEP", "note": "Still on IT desk"}, follow=True)
        review.refresh_from_db()
        self.assertEqual(review.status, AccessReview.STATUS_COMPLETED)
        self.assertEqual(review.decision, "KEEP")
        self.assertEqual(review.reviewed_by, self.security_admin2)
        self.assertNotIn(self.identity_admin, access_review_service.officers_due())

    def test_revoke_strips_admin_role_only(self):
        temporary_access_service.grant(
            self.identity_admin, self.perms[C.PERM_AUDIT_VIEW], reason="x", starts_at=timezone.now(),
            expires_at=timezone.now() + timezone.timedelta(hours=2), actor=self.system_admin)
        self.login_admin(self.security_admin2)
        self.client.post(reverse("it_admin:access_review_raise", args=[self.identity_admin.pk]), {"trigger": "Transfer"})
        review = AccessReview.objects.get(officer=self.identity_admin)
        self.client.post(reverse("it_admin:access_review_decide", args=[review.pk]), {"decision": "REVOKE", "note": "Moved out"})
        self.identity_admin.refresh_from_db()
        self.assertIsNone(self.identity_admin.role)
        self.assertEqual(self.identity_admin.account_status, C.ACCOUNT_STATUS_ACTIVE)
        self.assertEqual(TemporaryCapability.objects.get(officer=self.identity_admin).status, C.TEMP_ACCESS_REVOKED)
        self.assertEqual(authorization_service.get_user_permissions(self.identity_admin), set())

    def test_cannot_review_own_access(self):
        review = access_review_service.ensure_pending(self.security_admin2, trigger="Periodic", created_by=self.system_admin)
        self.login_admin(self.security_admin2)
        resp = self.client.post(reverse("it_admin:access_review_decide", args=[review.pk]), {"decision": "KEEP"}, follow=True)
        review.refresh_from_db()
        self.assertEqual(review.status, AccessReview.STATUS_PENDING)
        self.assertTrue(any("own" in m for m in self.messages_of(resp)))

    def test_due_list_uses_interval(self):
        due_ids = {o.officer_id for o in access_review_service.officers_due()}
        self.assertIn("OFF-402", due_ids)
        self.assertNotIn("OFF-101", due_ids)  # no admin capabilities


class AdminRoleAndApprovalTests(AdminPortalTestCase):
    def test_role_capability_change_needs_second_admin_and_preserves_operational(self):
        self.login_admin(self.system_admin)
        role = self.auditor_role
        role.permissions.add(self.perms["case.view"])  # operational perm must survive
        wanted = [self.perms[C.PERM_AUDIT_VIEW].pk, self.perms[C.PERM_OFFICER_VIEW].pk, self.perms[C.PERM_APPROVAL_REVIEW].pk]
        resp = self.client.post(reverse("it_admin:admin_role_detail", args=[role.pk]),
                                {"capabilities": wanted, "reason": "Auditors to review approvals"})
        self.assertEqual(resp.status_code, 302)
        req = ApprovalRequest.objects.get(action=ApprovalRequest.ACTION_ROLE_CAPABILITIES)
        self.assertFalse(role.permissions.filter(codename=C.PERM_APPROVAL_REVIEW).exists())
        # Requester cannot approve.
        resp = self.client.post(reverse("it_admin:approval_decide", args=[req.pk]),
                                {"decision": "approve", "decision_reason": "self"}, follow=True)
        self.assertIn("You cannot approve your own request.", self.messages_of(resp))
        req.refresh_from_db()
        self.assertEqual(req.status, ApprovalRequest.STATUS_PENDING)
        # Second admin approves → executed.
        self.login_admin(self.security_admin2)
        resp = self.client.post(reverse("it_admin:approval_decide", args=[req.pk]),
                                {"decision": "approve", "decision_reason": "Agreed with CISO"}, follow=True)
        req.refresh_from_db()
        self.assertEqual(req.status, ApprovalRequest.STATUS_APPROVED)
        self.assertEqual(req.decided_by, self.security_admin2)
        codenames = set(role.permissions.values_list("codename", flat=True))
        self.assertEqual(codenames, {C.PERM_AUDIT_VIEW, C.PERM_OFFICER_VIEW, C.PERM_APPROVAL_REVIEW, "case.view"})
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_APPROVAL_GRANTED).exists())
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_ADMIN_ROLE_CHANGED, resource_type="role").exists())

    def test_admin_role_assignment_via_authorization_page_is_deferred(self):
        self.login_admin(self.system_admin)
        resp = self.client.post(reverse("it_admin:officer_authorization", args=[self.field_officer.pk]), {
            "role": self.identity_admin_role.pk, "clearance": self.l1.pk, "portals": [self.portal_general.pk],
            "reason": "Joining IT desk",
        }, follow=True)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.role, self.field_role)  # not yet
        req = ApprovalRequest.objects.get(action=ApprovalRequest.ACTION_ADMIN_ROLE_CHANGE, target_id="OFF-101")
        self.login_admin(self.security_admin2)
        self.client.post(reverse("it_admin:approval_decide", args=[req.pk]), {"decision": "approve", "decision_reason": "OK by SOP"})
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.role, self.identity_admin_role)
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_ROLE_CHANGED, officer=self.field_officer, actor=self.security_admin2).exists())

    def test_non_admin_role_change_applies_immediately(self):
        self.login_admin(self.system_admin)
        self.client.post(reverse("it_admin:officer_authorization", args=[self.field_officer.pk]), {
            "role": self.inspector_role.pk, "clearance": self.l3.pk, "portals": [self.portal_general.pk], "reason": "Promotion",
        })
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.role, self.inspector_role)
        self.assertEqual(self.field_officer.clearance, self.l3)
        self.assertFalse(ApprovalRequest.objects.exists())

    def test_reject_and_cancel_paths(self):
        self.login_admin(self.system_admin)
        self.client.post(reverse("it_admin:admin_role_assign"), {"officer": self.field_officer.pk, "role": self.auditor_role.pk,
                                                                  "reason": "Trial audit access"})
        req = ApprovalRequest.objects.get()
        # Duplicate pending request blocked.
        resp = self.client.post(reverse("it_admin:admin_role_assign"), {"officer": self.field_officer.pk, "role": self.auditor_role.pk,
                                                                         "reason": "again"})
        self.assertEqual(ApprovalRequest.objects.count(), 1)
        # Other admin rejects.
        self.login_admin(self.security_admin2)
        self.client.post(reverse("it_admin:approval_decide", args=[req.pk]), {"decision": "reject", "decision_reason": "Not justified"})
        req.refresh_from_db()
        self.assertEqual(req.status, ApprovalRequest.STATUS_REJECTED)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.role, self.field_role)
        # Cancel own
        self.login_admin(self.system_admin)
        self.client.post(reverse("it_admin:admin_role_assign"), {"officer": self.field_officer.pk, "role": self.auditor_role.pk,
                                                                  "reason": "Second attempt"})
        req2 = ApprovalRequest.objects.get(status=ApprovalRequest.STATUS_PENDING)
        self.login_admin(self.security_admin2)
        resp = self.client.post(reverse("it_admin:approval_cancel", args=[req2.pk]), follow=True)
        self.assertIn("Only the requester can cancel a pending request.", self.messages_of(resp))
        self.login_admin(self.system_admin)
        self.client.post(reverse("it_admin:approval_cancel", args=[req2.pk]))
        req2.refresh_from_db()
        self.assertEqual(req2.status, ApprovalRequest.STATUS_CANCELLED)

    def test_superuser_cannot_bypass_four_eyes(self):
        self.system_admin.is_superuser = True
        self.system_admin.save()
        self.login_admin(self.system_admin)
        self.client.post(reverse("it_admin:admin_role_assign"), {"officer": self.field_officer.pk, "role": self.auditor_role.pk,
                                                                  "reason": "Superuser attempt"})
        req = ApprovalRequest.objects.get()
        resp = self.client.post(reverse("it_admin:approval_decide", args=[req.pk]),
                                {"decision": "approve", "decision_reason": "I am superuser"}, follow=True)
        self.assertIn("You cannot approve your own request.", self.messages_of(resp))

    def test_approval_center_visibility(self):
        self.login_admin(self.identity_admin)  # no approval.review, but can request
        self.assertEqual(self.client.get(reverse("it_admin:approval_list")).status_code, 200)
        self.login_admin(self.auditor)
        self.assertEqual(self.client.get(reverse("it_admin:approval_list")).status_code, 403)


class TimelineTests(AdminPortalTestCase):
    def test_timeline_merges_real_records(self):
        self.login_admin(self.system_admin)
        self.client.post(reverse("it_admin:officer_lifecycle", args=[self.field_officer.pk]), {"action": "suspend", "reason": "Enquiry"})
        self.client.post(reverse("it_admin:officer_lifecycle", args=[self.field_officer.pk]), {"action": "reactivate", "reason": "Closed"})
        resp = self.client.get(reverse("it_admin:officer_timeline", args=[self.field_officer.pk]))
        events = resp.context["events"]
        labels = [e.event for e in events]
        self.assertIn("Account suspended", labels)
        self.assertIn("Account reactivated", labels)
        self.assertEqual(labels[0], "Account reactivated")  # newest first
        self.assertEqual(events[0].actor, "OFF-401")
        self.assertIn("Reason: Closed", events[0].detail)


class BulkImportTests(AdminPortalTestCase):
    CSV = ("full_name,email,officer_id,employee_id,phone,designation,department,unit,role,joining_date,portals\n"
           "Bulk One,bulk1@example.gov,,EMP-B1,,SI,INV,Investigation Unit,,2026-09-01,general\n"
           "Bulk Two,bulk2@example.gov,OFF-101,,,,,,,,\n"
           "Bad Three,not-an-email,,,,NOPE,,,,,\n")

    def _upload(self, csv=None):
        return self.client.post(reverse("it_admin:bulk_import"),
                                {"file": SimpleUploadedFile("officers.csv", (csv or self.CSV).encode()), "reason": "Batch onboarding"},
                                follow=True)

    def _identity_admin_with_bulk(self):
        # Bulk import is not part of the identity bundle by default; grant it
        # explicitly so the "cannot authorize" branch is exercised.
        self.identity_admin_role.permissions.add(self.perms[C.PERM_OFFICER_BULK_IMPORT])
        self.login_admin(self.identity_admin)

    def test_validate_preview_commit_with_row_errors(self):
        self._identity_admin_with_bulk()
        resp = self._upload()
        report = resp.context["report"]
        self.assertEqual(report.total, 3)
        self.assertEqual(len(report.valid), 1)
        errors = {r.line: r.errors for r in report.invalid}
        self.assertIn("Officer ID already exists.", errors[3])
        self.assertTrue(any("email" in e.lower() for e in errors[4]))
        self.assertFalse(Officer.objects.filter(email="bulk1@example.gov").exists())
        resp = self.client.post(reverse("it_admin:bulk_commit"), {"confirm": "1"})
        result = resp.context["result"]
        self.assertEqual(result.created_count, 1)
        self.assertEqual(result.failed_count, 2)
        officer = Officer.objects.get(email="bulk1@example.gov")
        self.assertEqual(officer.designation, self.desig_si)
        self.assertEqual(officer.department, self.dept_inv)
        self.assertEqual(officer.account_status, C.ACCOUNT_STATUS_INVITED)
        self.assertFalse(officer.has_portal_access(C.PORTAL_GENERAL))  # identity admin can't authorize
        ev = AuditEvent.objects.get(event_type=C.EVENT_BULK_OPERATION)
        self.assertEqual(ev.context["created"], 1)
        self.assertEqual(ev.new_state["created"], [officer.officer_id])

    def test_missing_column_and_permission(self):
        self._identity_admin_with_bulk()
        resp = self._upload("name,email\nX,y@example.gov\n")
        self.assertIn("Missing required column", resp.content.decode())
        self.login_admin(self.security_admin2)
        self.assertEqual(self.client.get(reverse("it_admin:bulk_import")).status_code, 403)
        self.identity_admin_role.permissions.remove(self.perms[C.PERM_OFFICER_BULK_IMPORT])
        self.login_admin(self.identity_admin)
        self.assertEqual(self.client.get(reverse("it_admin:bulk_import")).status_code, 403)

    def test_system_admin_applies_portals(self):
        self.login_admin(self.system_admin)
        self._upload()
        self.client.post(reverse("it_admin:bulk_commit"), {"confirm": "1"})
        self.assertTrue(Officer.objects.get(email="bulk1@example.gov").has_portal_access(C.PORTAL_GENERAL))
