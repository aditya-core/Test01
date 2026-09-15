"""Case workflow tests — every one of them is an authorization test.

The point of this module is deny-by-default: an officer sees a case only when
clearance, jurisdiction, capability, assignment *and* the assignment's action
ceiling all agree. Test uploads are written to a temporary MEDIA_ROOT so the
repository is never polluted.
"""
from __future__ import annotations

import tempfile

from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.tests.base import BaseAuthTestCase
from general.models import CaseAssignment, CaseEvidenceFile, CaseRecord


def _pdf(name: str = "fir.pdf", content: bytes = b"fir content") -> SimpleUploadedFile:
    return SimpleUploadedFile(name, content, content_type="application/pdf")


@override_settings(MEDIA_ROOT=tempfile.mkdtemp(prefix="sdms-test-media-"))
class GeneralCasePortalTests(BaseAuthTestCase):

    # -- helpers ------------------------------------------------------------
    def register_case(self, officer=None, classification=None, title="Theft in Market"):
        officer = officer or self.field_officer
        self.login_as(officer)
        return self.client.post(
            reverse("general:register_case"),
            {
                "title": title,
                "case_type": "Theft",
                "police_station": "Central Police Station",
                "investigating_agency": "CID",
                "incident_date": "2026-09-10",
                "location": "Market Road",
                "summary": "A theft occurred during night hours.",
                "complainant_name": "Ravi Kumar",
                "complainant_contact": "9876543210",
                "status": "Open",
                "classification": (classification or self.l1).pk,
                "fir_document": _pdf(),
                "evidence_files": [_pdf("evidence.pdf", b"evidence content")],
            },
            follow=True,
        )

    def make_case(self, owner, classification=None, organization=None, title="Case Alpha"):
        case = CaseRecord.objects.create(
            title=title,
            case_type="Theft",
            incident_date="2026-09-10",
            created_by=owner,
            classification=classification or self.l1,
            organization=organization or (owner.unit.organization if owner.unit_id else None),
        )
        case.fir_document.save("fir.pdf", ContentFile(b"fir content"), save=True)
        CaseEvidenceFile.objects.create(
            case=case, file=SimpleUploadedFile("evidence.pdf", b"evidence content", content_type="application/pdf")
        )
        return case

    def assign(self, case, officer, role=C.ASSIGNMENT_OWNER, actor=None):
        return CaseAssignment.objects.create(
            case=case, officer=officer, role=role, granted_by=actor or case.created_by
        )

    # -- portal surface -------------------------------------------------------
    def test_general_dashboard_shows_register_and_view_case_actions(self):
        self.login_as(self.field_officer)
        response = self.client.get(reverse("general:dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Register Case")
        self.assertContains(response, "View Cases")
        self.assertContains(response, "Recent cases")

    def test_general_officer_can_register_case_with_fir_and_evidence(self):
        response = self.register_case()

        self.assertEqual(response.status_code, 200)
        case = CaseRecord.objects.get(title="Theft in Market")
        self.assertEqual(case.created_by, self.field_officer)
        self.assertTrue(case.case_id.startswith("CASE-"))
        self.assertIn("cases/", case.fir_document.name)
        self.assertEqual(case.evidence_files.count(), 1)
        self.assertContains(response, case.case_id)

    def test_registration_records_case_security_attributes(self):
        """Jurisdiction comes from the officer's posting, not from the client."""
        self.register_case(classification=self.l2)

        case = CaseRecord.objects.get(title="Theft in Market")
        self.assertEqual(case.classification, self.l2)
        self.assertEqual(case.organization, self.field_officer.unit.organization)

    def test_registration_grants_owner_assignment(self):
        """Access after registering flows through the normal assignment path."""
        self.register_case()

        case = CaseRecord.objects.get(title="Theft in Market")
        assignment = CaseAssignment.objects.get(case=case, officer=self.field_officer)
        self.assertEqual(assignment.role, C.ASSIGNMENT_OWNER)
        self.assertTrue(assignment.is_active)
        self.assertIn(C.ACTION_CASE_DOWNLOAD, assignment.allowed_actions)

    def test_officer_without_case_create_cannot_register(self):
        # The senior officer's role carries no case.create capability.
        self.login_as(self.senior_officer)
        response = self.client.post(
            reverse("general:register_case"),
            {
                "title": "Blocked", "case_type": "Theft", "incident_date": "2026-09-10",
                "status": "Open", "classification": self.l1.pk,
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(CaseRecord.objects.filter(title="Blocked").exists())

    # -- deny by default --------------------------------------------------------
    def test_unassigned_officer_cannot_see_case(self):
        case = self.make_case(self.inspector)
        self.assign(case, self.inspector)

        self.login_as(self.field_officer)
        response = self.client.get(reverse("general:view_cases"))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, case.case_id)
        self.assertFalse(authorization_service.can_access_case(self.field_officer, case))

    def test_assignment_alone_is_not_enough_without_clearance(self):
        case = self.make_case(self.inspector, classification=self.l5)
        self.assign(case, self.field_officer)  # L1 officer assigned to an L5 case

        self.assertFalse(authorization_service.can_access_case(self.field_officer, case))

    def test_assignment_alone_is_not_enough_without_capability(self):
        # senior_officer's role has no case.view at all.
        case = self.make_case(self.inspector)
        self.assign(case, self.senior_officer)

        self.assertFalse(authorization_service.can_access_case(self.senior_officer, case))

    def test_cross_district_case_is_denied(self):
        case = self.make_case(self.inspector, organization=self.org_b)
        self.assign(case, self.inspector)  # posted in District A

        self.assertFalse(authorization_service.can_access_case(self.inspector, case))

    def test_authorized_officer_sees_case(self):
        case = self.make_case(self.inspector)
        self.assign(case, self.inspector)

        self.login_as(self.inspector)
        response = self.client.get(reverse("general:view_cases"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, case.case_id)

    def test_revoked_assignment_removes_access(self):
        case = self.make_case(self.inspector)
        assignment = self.assign(case, self.field_officer, role=C.ASSIGNMENT_VIEWER)
        self.assertTrue(authorization_service.can_access_case(self.field_officer, case))

        assignment.revoked_at = assignment.granted_at
        assignment.save(update_fields=["revoked_at"])

        self.assertFalse(authorization_service.can_access_case(self.field_officer, case))

    # -- action ceiling ----------------------------------------------------------
    def test_viewer_assignment_cannot_download(self):
        """The assignment role caps actions even when the role has the capability."""
        case = self.make_case(self.inspector)
        self.assign(case, self.field_officer, role=C.ASSIGNMENT_VIEWER)

        # field_officer holds case.download, but VIEWER may only view.
        self.assertTrue(authorization_service.can_access_case(self.field_officer, case, C.ACTION_CASE_VIEW))
        self.assertFalse(authorization_service.can_access_case(self.field_officer, case, C.ACTION_CASE_DOWNLOAD))

    def test_owner_assignment_may_download(self):
        case = self.make_case(self.inspector)
        self.assign(case, self.inspector, role=C.ASSIGNMENT_OWNER)
        self.assertTrue(authorization_service.can_access_case(self.inspector, case, C.ACTION_CASE_DOWNLOAD))

    # -- protected file delivery ----------------------------------------------------
    def test_assigned_officer_can_download_fir(self):
        case = self.make_case(self.inspector)
        self.assign(case, self.inspector)
        self.login_as(self.inspector)

        response = self.client.get(reverse("general:download_fir", kwargs={"case_id": case.case_id}))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.streaming)

    def test_unassigned_officer_cannot_download_fir(self):
        case = self.make_case(self.inspector)
        self.assign(case, self.inspector)
        self.login_as(self.field_officer)

        response = self.client.get(reverse("general:download_fir", kwargs={"case_id": case.case_id}))

        self.assertEqual(response.status_code, 403)

    def test_download_denial_is_audited(self):
        from audit.models import AuditEvent

        case = self.make_case(self.inspector)
        self.assign(case, self.inspector)
        self.login_as(self.field_officer)

        self.client.get(reverse("general:download_fir", kwargs={"case_id": case.case_id}))

        self.assertTrue(
            AuditEvent.objects.filter(
                event_type=C.EVENT_ACCESS_DENIED,
                resource_type="case",
                resource_id=case.case_id,
                officer=self.field_officer,
            ).exists()
        )

    def test_case_list_does_not_leak_raw_media_urls(self):
        """Files must be served by the authorized view, never by media URL."""
        case = self.make_case(self.inspector)
        self.assign(case, self.inspector)
        self.login_as(self.inspector)

        response = self.client.get(reverse("general:view_cases"))
        content = response.content.decode()

        self.assertNotIn(case.fir_document.url, content)
        self.assertIn(reverse("general:download_fir", kwargs={"case_id": case.case_id}), content)
