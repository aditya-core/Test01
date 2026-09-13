from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from accounts.tests.base import BaseAuthTestCase
from general.models import CaseRecord


class GeneralCasePortalTests(BaseAuthTestCase):
    def test_general_dashboard_shows_register_and_view_case_actions(self):
        self.login_as(self.field_officer)
        response = self.client.get(reverse("general:dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Register Case")
        self.assertContains(response, "View Cases")
        self.assertContains(response, "Recent cases")

    def test_general_officer_can_register_case_with_fir_and_evidence(self):
        self.login_as(self.field_officer)

        fir_file = SimpleUploadedFile("fir.pdf", b"fir content", content_type="application/pdf")
        evidence_file = SimpleUploadedFile("evidence.pdf", b"evidence content", content_type="application/pdf")

        response = self.client.post(
            reverse("general:register_case"),
            {
                "title": "Theft in Market",
                "case_type": "Theft",
                "police_station": "Central Police Station",
                "investigating_agency": "CID",
                "incident_date": "2026-09-10",
                "location": "Market Road",
                "summary": "A theft occurred during night hours.",
                "complainant_name": "Ravi Kumar",
                "complainant_contact": "9876543210",
                "status": "Open",
                "fir_document": fir_file,
                "evidence_files": [evidence_file],
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        case = CaseRecord.objects.get(title="Theft in Market")
        self.assertEqual(case.created_by, self.field_officer)
        self.assertTrue(case.case_id.startswith("CASE-"))
        self.assertIn("cases/", case.fir_document.name)
        self.assertEqual(case.evidence_files.count(), 1)
        self.assertContains(response, case.case_id)
