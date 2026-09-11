"""PHASE 3 & 4 — Designation / department / unit registries and transfers."""
from __future__ import annotations

from django.urls import reverse

from accounts import constants as C
from accounts.models import Department, Designation, OrganizationUnit, PostingHistory
from audit.models import AuditEvent

from ..models import AccessReview
from .base import AdminPortalTestCase


class DesignationRegistryTests(AdminPortalTestCase):
    def test_create_edit_toggle(self):
        self.login_admin(self.identity_admin)
        resp = self.client.post(reverse("it_admin:designation_create"),
                                {"code": "hc", "name": "Head Constable", "rank_level": 20, "description": ""})
        self.assertEqual(resp.status_code, 302)
        d = Designation.objects.get(name="Head Constable")
        self.assertEqual(d.code, "HC")
        resp = self.client.post(reverse("it_admin:designation_toggle", args=[d.pk]))
        d.refresh_from_db()
        self.assertFalse(d.is_active)
        self.assertEqual(AuditEvent.objects.filter(event_type=C.EVENT_DESIGNATION_REGISTRY_CHANGED, resource_id="HC").count(), 2)

    def test_duplicate_designation_rejected(self):
        self.login_admin(self.identity_admin)
        resp = self.client.post(reverse("it_admin:designation_create"),
                                {"code": "CONST", "name": "constable", "rank_level": 10})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(Designation.objects.filter(name__iexact="constable").count(), 1)

    def test_delete_blocked_when_assigned(self):
        self.field_officer.designation = self.desig_const
        self.field_officer.save()
        self.login_admin(self.identity_admin)
        resp = self.client.post(reverse("it_admin:designation_delete", args=[self.desig_const.pk]), follow=True)
        self.assertIn("This designation is currently assigned and cannot be removed.", self.messages_of(resp))
        self.assertTrue(Designation.objects.filter(pk=self.desig_const.pk).exists())

    def test_delete_allowed_when_unused(self):
        spare = Designation.objects.create(code="SPARE", name="Spare", rank_level=1)
        self.login_admin(self.identity_admin)
        self.client.post(reverse("it_admin:designation_delete", args=[spare.pk]))
        self.assertFalse(Designation.objects.filter(pk=spare.pk).exists())

    def test_auditor_cannot_manage(self):
        self.login_admin(self.auditor)
        self.assertEqual(self.client.get(reverse("it_admin:designation_list")).status_code, 200)
        self.assertEqual(self.client.get(reverse("it_admin:designation_create")).status_code, 403)
        self.assertEqual(self.client.post(reverse("it_admin:designation_toggle", args=[self.desig_const.pk])).status_code, 403)

    def test_designation_confers_no_permission(self):
        from accounts.authorization import authorization_service

        self.field_officer.designation = self.desig_si
        self.field_officer.save()
        self.assertFalse(authorization_service.has_permission(self.field_officer, C.PERM_OFFICER_VIEW))


class DepartmentUnitTests(AdminPortalTestCase):
    def test_create_department_and_unit_assignment(self):
        self.login_admin(self.identity_admin)
        resp = self.client.post(reverse("it_admin:department_create"), {"code": "FOR", "name": "Forensics", "description": ""})
        self.assertEqual(resp.status_code, 302)
        dept = Department.objects.get(code="FOR")
        resp = self.client.post(reverse("it_admin:unit_create"), {
            "organization": self.org_a.pk, "name": "Forensic Lab", "kind": C.UNIT_KIND_FORENSIC,
            "department": dept.pk, "parent": "",
        })
        self.assertEqual(resp.status_code, 302, resp.context["form"].errors if resp.context else "")
        unit = OrganizationUnit.objects.get(name="Forensic Lab")
        self.assertEqual(unit.department, dept)
        # Reassign unit to another department
        resp = self.client.post(reverse("it_admin:unit_edit", args=[unit.pk]), {
            "organization": self.org_a.pk, "name": "Forensic Lab", "kind": C.UNIT_KIND_FORENSIC,
            "department": self.dept_cyber.pk, "parent": "",
        })
        unit.refresh_from_db()
        self.assertEqual(unit.department, self.dept_cyber)

    def test_department_page_lists_units_and_officer_counts(self):
        self.login_admin(self.auditor)
        resp = self.client.get(reverse("it_admin:department_list"))
        self.assertEqual(resp.status_code, 200)
        html = resp.content.decode()
        self.assertIn("Investigation Unit", html)
        self.assertNotIn("Closed Department", html)  # inactive hidden by default
        resp = self.client.get(reverse("it_admin:department_list") + "?inactive=1")
        self.assertIn("Closed Department", resp.content.decode())

    def test_cannot_assign_unit_to_inactive_department(self):
        self.login_admin(self.identity_admin)
        resp = self.client.post(reverse("it_admin:unit_edit", args=[self.unit_b.pk]), {
            "organization": self.org_b.pk, "name": self.unit_b.name, "kind": self.unit_b.kind,
            "department": self.dept_closed.pk, "parent": "",
        })
        self.assertEqual(resp.status_code, 200)
        self.unit_b.refresh_from_db()
        self.assertEqual(self.unit_b.department, self.dept_cyber)


class TransferTests(AdminPortalTestCase):
    def setUp(self):
        super().setUp()
        self.field_officer.department = self.dept_inv
        self.field_officer.designation = self.desig_const
        self.field_officer.save()

    def _payload(self, **overrides):
        data = {"to_department": self.dept_cyber.pk, "to_unit": self.unit_b.pk, "to_designation": self.desig_const.pk,
                "effective_date": "2026-09-15", "reason": "Posting order 12/2026"}
        data.update(overrides)
        return data

    def test_preview_then_apply_preserves_history_and_flags_review(self):
        self.login_admin(self.identity_admin)
        url = reverse("it_admin:officer_transfer", args=[self.field_officer.pk])
        resp = self.client.post(url, self._payload())
        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(resp.context["plan"])
        self.assertTrue(resp.context["plan"].authorization_review_required)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.unit, self.unit_investigation)  # preview didn't apply

        resp = self.client.post(url, self._payload(confirm="1"))
        self.assertEqual(resp.status_code, 302)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.unit, self.unit_b)
        self.assertEqual(self.field_officer.department, self.dept_cyber)
        row = PostingHistory.objects.get(officer=self.field_officer, kind=C.POSTING_TRANSFER)
        self.assertEqual(row.from_unit, self.unit_investigation)
        self.assertEqual(row.to_unit, self.unit_b)
        self.assertEqual(str(row.effective_date), "2026-09-15")
        self.assertEqual(row.recorded_by, self.identity_admin)
        self.assertTrue(row.authorization_review_required)
        self.assertTrue(AccessReview.objects.filter(officer=self.field_officer, status=AccessReview.STATUS_PENDING).exists())
        ev = AuditEvent.objects.get(event_type=C.EVENT_TRANSFER_COMPLETED, officer=self.field_officer)
        self.assertEqual(ev.previous_state["unit"], "Investigation Unit")
        self.assertEqual(ev.reason, "Posting order 12/2026")
        # Operational authorization untouched.
        self.assertEqual(self.field_officer.role, self.field_role)

    def test_transfer_requires_reason_and_changes(self):
        self.login_admin(self.identity_admin)
        url = reverse("it_admin:officer_transfer", args=[self.field_officer.pk])
        resp = self.client.post(url, self._payload(reason="", confirm="1"))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(PostingHistory.objects.filter(officer=self.field_officer).exists())
        resp = self.client.post(url, self._payload(to_department=self.dept_inv.pk, to_unit=self.unit_investigation.pk, confirm="1"))
        self.assertEqual(resp.status_code, 200)
        self.assertIn("No changes", resp.content.decode())

    def test_transfer_to_inactive_department_rejected(self):
        self.login_admin(self.identity_admin)
        url = reverse("it_admin:officer_transfer", args=[self.field_officer.pk])
        resp = self.client.post(url, self._payload(to_department=self.dept_closed.pk, confirm="1"))
        self.assertEqual(resp.status_code, 200)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.department, self.dept_inv)

    def test_security_admin_cannot_transfer(self):
        self.login_admin(self.security_admin2)
        resp = self.client.get(reverse("it_admin:officer_transfer", args=[self.field_officer.pk]))
        self.assertEqual(resp.status_code, 403)

    def test_posting_list_visible(self):
        self.login_admin(self.identity_admin)
        self.client.post(reverse("it_admin:officer_transfer", args=[self.field_officer.pk]), self._payload(confirm="1"))
        resp = self.client.get(reverse("it_admin:posting_list"), {"q": "OFF-101"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Posting order 12/2026", resp.content.decode())
