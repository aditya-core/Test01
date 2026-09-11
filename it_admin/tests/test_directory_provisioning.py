"""PHASE 2 — Officer directory + provisioning wizard."""
from __future__ import annotations

from django.urls import reverse

from accounts import constants as C
from accounts.models import Officer, PostingHistory
from audit.models import AuditEvent

from .base import AdminPortalTestCase

SUCCESS = "Officer identity created successfully. Operational authorization is managed separately."


class DirectoryTests(AdminPortalTestCase):
    def test_directory_lists_officers_with_identity_columns(self):
        self.field_officer.designation = self.desig_const
        self.field_officer.department = self.dept_inv
        self.field_officer.employee_id = "EMP-101"
        self.field_officer.save()
        self.login_admin(self.identity_admin)
        resp = self.client.get(reverse("it_admin:officer_list"))
        self.assertEqual(resp.status_code, 200)
        html = resp.content.decode()
        for needle in ("OFF-101", "Constable", "Investigation", "EMP-101", "Designation", "Department", "MFA", "Last login"):
            self.assertIn(needle, html)

    def test_directory_filters_by_status_department_and_search(self):
        self.field_officer.department = self.dept_inv
        self.field_officer.save()
        self.login_admin(self.identity_admin)
        url = reverse("it_admin:officer_list")
        resp = self.client.get(url, {"status": C.ACCOUNT_STATUS_DISABLED})
        ids = [o.officer_id for o in resp.context["page"].object_list]
        self.assertEqual(ids, ["OFF-501"])
        resp = self.client.get(url, {"department": self.dept_inv.pk})
        self.assertEqual([o.officer_id for o in resp.context["page"].object_list], ["OFF-101"])
        resp = self.client.get(url, {"q": "insp@example"})
        self.assertEqual([o.officer_id for o in resp.context["page"].object_list], ["OFF-102"])

    def test_auditor_can_view_but_not_edit(self):
        self.login_admin(self.auditor)
        self.assertEqual(self.client.get(reverse("it_admin:officer_list")).status_code, 200)
        self.assertEqual(self.client.get(reverse("it_admin:officer_detail", args=[self.field_officer.pk])).status_code, 200)
        self.assertEqual(self.client.get(reverse("it_admin:officer_edit", args=[self.field_officer.pk])).status_code, 403)
        self.assertEqual(self.client.get(reverse("it_admin:officer_create")).status_code, 403)

    def test_profile_shows_sections_and_no_operational_data(self):
        self.login_admin(self.system_admin)
        resp = self.client.get(reverse("it_admin:officer_detail", args=[self.inspector.pk]))
        html = resp.content.decode()
        for section in ("Identity", "Service", "Account", "Security", "Admin history"):
            self.assertIn(section, html)
        self.assertIn("Operational authorization", html)
        # Operational permission codenames of the role must not be enumerated here.
        self.assertNotIn("case.approve", html)

    def test_sidebar_only_shows_authorized_items(self):
        self.login_admin(self.auditor)
        html = self.client.get(reverse("it_admin:dashboard")).content.decode()
        self.assertIn("Audit Log", html)
        self.assertNotIn("Provision Officer", html)
        self.assertNotIn("Approval Center", html)
        self.login_admin(self.identity_admin)
        html = self.client.get(reverse("it_admin:dashboard")).content.decode()
        self.assertIn("Provision Officer", html)
        self.assertNotIn("Audit Log", html)

    def test_dashboard_counts_come_from_database(self):
        self.login_admin(self.system_admin)
        resp = self.client.get(reverse("it_admin:dashboard"))
        stats = {s["label"]: s["value"] for s in resp.context["stats"]}
        self.assertEqual(stats["Total officers"], Officer.objects.count())
        self.assertEqual(stats["Active"], Officer.objects.filter(account_status=C.ACCOUNT_STATUS_ACTIVE).count())


class ProvisioningWizardTests(AdminPortalTestCase):
    def _run_wizard(self, admin, *, identity=None, service=None, account=None):
        url = reverse("it_admin:officer_create")
        identity = {"step": "identity", "full_name": "Wizard Officer", "officer_id": "", "employee_id": "EMP-W1",
                    "email": "wizard@example.gov", "phone": "", **(identity or {})}
        resp = self.client.post(url, identity)
        if resp.status_code != 302:
            return resp
        service = {"step": "service", "designation": self.desig_const.pk, "department": self.dept_inv.pk,
                   "unit": self.unit_investigation.pk, "joining_date": "2026-09-01", **(service or {})}
        resp = self.client.post(url, service)
        if resp.status_code != 302:
            return resp
        account = {"step": "account", "initial_password": "TempPass!12345", "initial_secret_code": "",
                   "reason": "New posting", **(account or {})}
        resp = self.client.post(url, account)
        if resp.status_code != 302:
            return resp
        return self.client.post(url, {"step": "review", "confirm": "1"})

    def test_wizard_creates_identity_without_operational_authorization(self):
        self.login_admin(self.identity_admin)
        resp = self._run_wizard(self.identity_admin, account={"role": self.inspector_role.pk, "portals": [self.portal_general.pk]})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(SUCCESS, resp.content.decode())
        officer = Officer.objects.get(email="wizard@example.gov")
        self.assertEqual(officer.account_status, C.ACCOUNT_STATUS_INVITED)
        self.assertEqual(officer.designation, self.desig_const)
        self.assertEqual(officer.department, self.dept_inv)
        self.assertEqual(officer.rank, "Constable")
        self.assertEqual(officer.employee_id, "EMP-W1")
        # Identity admin lacks officer.authorization → posted role/portals are discarded server-side.
        self.assertIsNone(officer.role)
        self.assertFalse(officer.has_portal_access(C.PORTAL_GENERAL))
        self.assertTrue(PostingHistory.objects.filter(officer=officer, kind=C.POSTING_INITIAL).exists())
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_ACCOUNT_CREATED, officer=officer, actor=self.identity_admin).exists())

    def test_system_admin_may_assign_role_and_portals(self):
        self.login_admin(self.system_admin)
        resp = self._run_wizard(self.system_admin, account={"role": self.field_role.pk, "clearance": self.l1.pk,
                                                             "portals": [self.portal_general.pk]})
        self.assertEqual(resp.status_code, 200)
        officer = Officer.objects.get(email="wizard@example.gov")
        self.assertEqual(officer.role, self.field_role)
        self.assertTrue(officer.has_portal_access(C.PORTAL_GENERAL))

    def test_duplicate_officer_id_employee_id_and_email_rejected(self):
        self.login_admin(self.identity_admin)
        url = reverse("it_admin:officer_create")
        resp = self.client.post(url, {"step": "identity", "full_name": "Dup", "officer_id": "off-101", "employee_id": "",
                                      "email": "dup@example.gov"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Officer ID already exists.", resp.content.decode())
        self.field_officer.employee_id = "EMP-DUP"
        self.field_officer.save()
        resp = self.client.post(url, {"step": "identity", "full_name": "Dup", "officer_id": "", "employee_id": "emp-dup",
                                      "email": "dup@example.gov"})
        self.assertIn("Employee ID already exists.", resp.content.decode())
        resp = self.client.post(url, {"step": "identity", "full_name": "Dup", "officer_id": "", "employee_id": "",
                                      "email": "FIELD@example.gov"})
        self.assertIn("already exists", resp.content.decode())

    def test_inactive_department_or_designation_rejected(self):
        self.login_admin(self.identity_admin)
        resp = self._run_wizard(self.identity_admin, service={"department": self.dept_closed.pk})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Officer.objects.filter(email="wizard@example.gov").exists())
        resp = self._run_wizard(self.identity_admin, service={"designation": self.desig_retired.pk})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Officer.objects.filter(email="wizard@example.gov").exists())

    def test_unit_must_belong_to_department(self):
        self.login_admin(self.identity_admin)
        resp = self._run_wizard(self.identity_admin, service={"department": self.dept_cyber.pk, "unit": self.unit_investigation.pk})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("does not belong", resp.content.decode())

    def test_cannot_skip_ahead_to_review(self):
        self.login_admin(self.identity_admin)
        resp = self.client.get(reverse("it_admin:officer_create") + "?step=review")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context["step"], "identity")

    def test_field_officer_forbidden(self):
        self.login_as(self.field_officer)
        self.assertEqual(self.client.get(reverse("it_admin:officer_create")).status_code, 403)


class OfficerEditTests(AdminPortalTestCase):
    def test_edit_identity_records_delta_and_designation_history(self):
        self.login_admin(self.identity_admin)
        resp = self.client.post(reverse("it_admin:officer_edit", args=[self.field_officer.pk]), {
            "full_name": "Field Officer Renamed", "employee_id": "EMP-R1", "email": self.field_officer.email,
            "phone": "", "supervisor": "", "joining_date": "", "designation": self.desig_si.pk, "reason": "Promotion order",
        })
        self.assertEqual(resp.status_code, 302)
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.full_name, "Field Officer Renamed")
        self.assertEqual(self.field_officer.designation, self.desig_si)
        self.assertEqual(self.field_officer.rank, "Sub-Inspector")
        ev = AuditEvent.objects.get(event_type=C.EVENT_OFFICER_UPDATED, officer=self.field_officer)
        self.assertEqual(ev.previous_state["full_name"], "Field Officer")
        self.assertEqual(ev.new_state["full_name"], "Field Officer Renamed")
        self.assertTrue(PostingHistory.objects.filter(officer=self.field_officer, kind=C.POSTING_DESIGNATION,
                                                      to_designation=self.desig_si).exists())
        self.assertTrue(AuditEvent.objects.filter(event_type=C.EVENT_DESIGNATION_CHANGED, officer=self.field_officer).exists())

    def test_edit_does_not_touch_role_or_portals(self):
        self.login_admin(self.identity_admin)
        self.client.post(reverse("it_admin:officer_edit", args=[self.field_officer.pk]), {
            "full_name": "X Y", "employee_id": "", "email": self.field_officer.email, "phone": "", "supervisor": "",
            "joining_date": "", "designation": "", "reason": "", "role": self.inspector_role.pk,
        })
        self.field_officer.refresh_from_db()
        self.assertEqual(self.field_officer.role, self.field_role)
