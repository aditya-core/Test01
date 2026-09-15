"""Authorization tests for the hierarchical case-access system (directive §34).

Every test here is a security assertion. They are written against the
directive's own example organisation:

    District A
    ├── DSP C                       (supervises both inspectors)
    ├── Station X ── Inspector A
    └── Station Y ── Inspector B
"""
from __future__ import annotations

import tempfile

from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.models import Department
from accounts.tests.base import BaseAuthTestCase
from general.models import (
    AccessGrant,
    AccessRequest,
    CaseAssignment,
    CaseEvidenceFile,
    CaseRecord,
)
from general.services import (
    access_grant_service,
    access_request_service,
    case_access_service,
    case_transfer_service,
)


@override_settings(MEDIA_ROOT=tempfile.mkdtemp(prefix="sdms-access-media-"))
class AccessControlTests(BaseAuthTestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.dept_crime = Department.objects.create(code="CRIME", name="Crime Branch")
        cls.dept_traffic = Department.objects.create(code="TRAFFIC", name="Traffic")

        for officer, department in (
            (cls.inspector_a, cls.dept_crime),
            (cls.inspector_b, cls.dept_traffic),
            (cls.field_officer, cls.dept_traffic),
            (cls.dsp, cls.dept_crime),
        ):
            officer.department = department
            officer.save(update_fields=["department"])

    # -- helpers ------------------------------------------------------------
    def make_case(self, owner, classification=None, unit=None, organization=None, title="Case"):
        unit = unit if unit is not None else owner.unit
        case = CaseRecord.objects.create(
            title=title,
            case_type="Theft",
            incident_date="2026-09-10",
            created_by=owner,
            classification=classification or self.l1,
            organization=organization or (unit.organization if unit else None),
            unit=unit,
        )
        case.fir_document.save("fir.pdf", ContentFile(b"fir content"), save=True)
        CaseEvidenceFile.objects.create(
            case=case,
            file=SimpleUploadedFile("evidence.pdf", b"evidence", content_type="application/pdf"),
            uploaded_by=owner,
        )
        return case

    def grant(self, grantor, case, recipient_officer=None, department=None,
              actions=None, days=7, scope=C.GRANT_SCOPE_CASE):
        from datetime import timedelta

        return access_grant_service.grant(
            grantor=grantor,
            resource_type=C.RESOURCE_CASE,
            resource_ids=[case.case_id],
            actions=actions or [C.ACTION_VIEW],
            reason="test grant",
            scope=scope,
            recipient_officer=recipient_officer,
            recipient_department=department,
            expires_at=timezone.now() + timedelta(days=days),
        )[0]

    # -- A. Ownership --------------------------------------------------------
    def test_owner_can_view_and_download(self):
        case = self.make_case(self.inspector_a)

        self.assertTrue(authorization_service.can_access_resource(self.inspector_a, case, C.ACTION_VIEW))
        self.assertTrue(authorization_service.can_access_resource(self.inspector_a, case, C.ACTION_DOWNLOAD))
        self.assertTrue(
            authorization_service.can_access_resource(self.inspector_a, case, C.ACTION_MANAGE_ACCESS)
        )

    # -- B. Peer officer ------------------------------------------------------
    def test_peer_officer_cannot_access_other_station_case(self):
        case = self.make_case(self.inspector_b)

        self.assertTrue(authorization_service.can_access_resource(self.inspector_b, case, C.ACTION_VIEW))
        self.assertFalse(authorization_service.can_access_resource(self.inspector_a, case, C.ACTION_VIEW))

    def test_peer_officer_cannot_open_case_detail_by_url(self):
        case = self.make_case(self.inspector_b)
        self.login_as(self.inspector_a)

        response = self.client.get(reverse("general:case_detail", kwargs={"case_id": case.case_id}))
        self.assertEqual(response.status_code, 403)

    # -- C. Supervisor / hierarchy --------------------------------------------
    def test_supervisor_inherits_access_to_subordinate_cases(self):
        case_x = self.make_case(self.inspector_a, title="X-001")
        case_y = self.make_case(self.inspector_b, title="Y-001")

        # DSP C sits above both inspectors in the supervisory tree.
        self.assertTrue(authorization_service.can_access_resource(self.dsp, case_x, C.ACTION_VIEW))
        self.assertTrue(authorization_service.can_access_resource(self.dsp, case_y, C.ACTION_VIEW))

    def test_supervisor_access_requires_a_real_reporting_link(self):
        """§7 — seniority alone grants nothing; the tree is what matters."""
        case = self.make_case(self.inspector_a)

        # senior_officer outranks an Inspector by designation but supervises nobody.
        self.assertFalse(authorization_service.can_access_resource(self.senior_officer, case, C.ACTION_VIEW))
        self.assertFalse(self.senior_officer.is_supervisor_of(self.inspector_a))
        self.assertTrue(self.dsp.is_supervisor_of(self.inspector_a))

    def test_hierarchy_reaches_cases_of_assigned_officers(self):
        case = self.make_case(self.dsp, title="DSP case")
        CaseAssignment.objects.create(
            case=case, officer=self.inspector_a, role=C.ASSIGNMENT_INVESTIGATOR, granted_by=self.dsp
        )
        # A DSP above Inspector A can reach the case through the assignment too.
        self.assertTrue(authorization_service.can_access_resource(self.dsp, case, C.ACTION_VIEW))

    # -- D. Explicit grants -----------------------------------------------------
    def test_explicit_grant_then_expiry_then_revocation(self):
        case = self.make_case(self.inspector_a)
        self.assertFalse(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))

        grant = self.grant(self.inspector_a, case, recipient_officer=self.field_officer,
                           actions=[C.ACTION_VIEW])
        self.assertTrue(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))
        self.assertFalse(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_DOWNLOAD))

        # Expired.
        grant.expires_at = timezone.now()
        grant.save(update_fields=["expires_at"])
        self.assertFalse(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))

        # Re-granted, then revoked.
        grant.expires_at = timezone.now() + timezone.timedelta(days=1)
        grant.save(update_fields=["expires_at"])
        self.assertTrue(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))
        access_grant_service.revoke(grant, self.inspector_a, reason="test")
        self.assertFalse(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))

    def test_grant_does_not_bypass_clearance(self):
        """§25 — a grant is an additional path, never an override."""
        case = self.make_case(self.inspector_a, classification=self.l5)
        self.grant(self.inspector_a, case, recipient_officer=self.field_officer)

        self.assertEqual(self.field_officer.clearance.code, "L1")
        self.assertFalse(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))

    def test_grant_does_not_bypass_account_state(self):
        """§23 — a disabled officer keeps no access, grant or not."""
        case = self.make_case(self.inspector_a)
        self.grant(self.inspector_a, case, recipient_officer=self.disabled_officer)

        self.assertFalse(authorization_service.can_access_resource(self.disabled_officer, case, C.ACTION_VIEW))

    def test_grant_cannot_delegate_an_action_the_grantor_lacks(self):
        case = self.make_case(self.inspector_a)
        allowed, reason = access_grant_service.can_grant(
            self.inspector_a, case, C.GRANT_SCOPE_CASE, [C.ACTION_MANAGE_ACCESS]
        )
        self.assertTrue(allowed)  # inspector role holds manage_access

        # A constable has no manage_access at all.
        allowed, reason = access_grant_service.can_grant(
            self.field_officer, case, C.GRANT_SCOPE_CASE, [C.ACTION_VIEW]
        )
        self.assertFalse(allowed)

    # -- E. Department grants ----------------------------------------------------
    def test_department_grant_reaches_members_only(self):
        case = self.make_case(self.inspector_a)
        self.grant(self.inspector_a, case, department=self.dept_traffic)

        # field_officer is Traffic; inspector_b is not (inspector_b is Traffic too — see below).
        self.assertTrue(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))

    def test_unrelated_department_is_denied(self):
        from accounts.models import Department

        other = Department.objects.create(code="OTHER", name="Other Branch")
        case = self.make_case(self.inspector_a)
        self.grant(self.inspector_a, case, department=other)

        self.assertFalse(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))

    # -- F. Station / jurisdiction scopes ------------------------------------------
    def test_station_scope_grant_covers_officers_posted_at_that_station(self):
        # A case owned by DSP C and held at Station X: Inspector A is posted at
        # Station X but is neither owner nor supervisor of the case.
        case_x = self.make_case(self.dsp, unit=self.unit_station_x, title="Station X case")

        # Officer posted at the station that *holds* the case sees it (§6:
        # Inspector A -> X-001 allowed). This is the station-local rule.
        self.assertTrue(authorization_service.can_access_resource(self.inspector_a, case_x, C.ACTION_VIEW))

        # An officer at another station does not — until a station-scope grant
        # names their station, which is what isolates the grant from that rule.
        self.assertFalse(authorization_service.can_access_resource(self.inspector_b, case_x, C.ACTION_VIEW))

        allowed, reason = access_grant_service.can_grant(
            self.dsp, case_x, C.GRANT_SCOPE_STATION, [C.ACTION_VIEW]
        )
        self.assertTrue(allowed, reason)

        access_grant_service.grant(
            grantor=self.dsp, resource_type=C.RESOURCE_CASE, resource_ids=[case_x.case_id],
            actions=[C.ACTION_VIEW], reason="station cover", scope=C.GRANT_SCOPE_STATION,
            recipient_unit=self.unit_station_y, starts_at=timezone.now(),
        )

        # Station Y is now covered, even though the case is held at Station X.
        self.assertTrue(authorization_service.can_access_resource(self.inspector_b, case_x, C.ACTION_VIEW))

    def test_jurisdiction_scope_grant_covers_the_whole_jurisdiction(self):
        case_x = self.make_case(self.dsp, unit=self.unit_station_x, title="District case")

        access_grant_service.grant(
            grantor=self.dsp, resource_type=C.RESOURCE_CASE, resource_ids=[case_x.case_id],
            actions=[C.ACTION_VIEW], reason="jurisdiction cover",
            scope=C.GRANT_SCOPE_JURISDICTION, recipient_organization=self.org_a,
            starts_at=timezone.now(),
        )
        # Both inspectors are posted inside District A.
        self.assertTrue(authorization_service.can_access_resource(self.inspector_a, case_x, C.ACTION_VIEW))
        self.assertTrue(authorization_service.can_access_resource(self.inspector_b, case_x, C.ACTION_VIEW))
        # An officer in District B is not covered.
        self.assertFalse(
            authorization_service.can_access_resource(self.district_b_officer, case_x, C.ACTION_VIEW)
        )

    def test_broad_scope_requires_hierarchical_authority(self):
        """§14 — only an owner/supervisor may grant station-wide access."""
        case = self.make_case(self.inspector_a)
        # Inspector B carries case.manage_access in their role and is a peer of
        # Inspector A — same district, same rank, no supervisory relationship.
        # Give them resource-level manage_access through an explicit grant so
        # the only thing left to fail is the broad-scope authority check.
        self.grant(self.inspector_a, case, recipient_officer=self.inspector_b,
                   actions=[C.ACTION_VIEW, C.ACTION_MANAGE_ACCESS])
        self.assertTrue(
            authorization_service.can_access_resource(self.inspector_b, case, C.ACTION_MANAGE_ACCESS)
        )

        allowed, reason = access_grant_service.can_grant(
            self.inspector_b, case, C.GRANT_SCOPE_JURISDICTION, [C.ACTION_VIEW]
        )
        self.assertFalse(allowed)
        self.assertIn("supervising", reason)


    # -- G. Clearance / account state -----------------------------------------
    def test_insufficient_clearance_is_denied(self):
        case = self.make_case(self.inspector_a, classification=self.l5)

        # Even the creator is denied: clearance is a hard restriction.
        self.assertEqual(self.inspector_a.clearance.code, "L3")
        self.assertFalse(authorization_service.can_access_resource(self.inspector_a, case, C.ACTION_VIEW))

    def test_inactive_and_blocked_accounts_are_denied(self):
        case = self.make_case(self.inspector_a)
        CaseAssignment.objects.create(
            case=case, officer=self.inactive_officer, role=C.ASSIGNMENT_OWNER, granted_by=self.inspector_a
        )
        CaseAssignment.objects.create(
            case=case, officer=self.disabled_officer, role=C.ASSIGNMENT_OWNER, granted_by=self.inspector_a
        )

        self.assertFalse(authorization_service.can_access_resource(self.inactive_officer, case, C.ACTION_VIEW))
        self.assertFalse(authorization_service.can_access_resource(self.disabled_officer, case, C.ACTION_VIEW))

    # -- H. Jurisdiction ---------------------------------------------------------
    def test_officer_from_another_district_is_denied(self):
        case = self.make_case(self.inspector_a)

        self.assertFalse(
            authorization_service.can_access_resource(self.district_b_officer, case, C.ACTION_VIEW)
        )

    # -- I. Transfer --------------------------------------------------------------
    def test_transferred_officer_loses_place_scoped_grants(self):
        """§22 — station/jurisdiction grants derive from where you are posted."""
        case = self.make_case(self.inspector_a)
        AccessGrant.objects.create(
            grantor=self.dsp, recipient_officer=self.inspector_a,
            scope=C.GRANT_SCOPE_STATION, resource_type=C.RESOURCE_CASE,
            resource_id=case.case_id, actions=[C.ACTION_VIEW], reason="cover",
            starts_at=timezone.now(),
        )
        # Officer-specific, case-scoped grant must survive (explicit delegation).
        explicit = self.grant(self.dsp, case, recipient_officer=self.inspector_a)

        revoked = access_grant_service.revoke_place_scopes_on_transfer(
            self.inspector_a, actor=self.dsp, reason="transferred"
        )
        self.assertEqual(revoked, 1)
        explicit.refresh_from_db()
        self.assertTrue(explicit.is_currently_active)

    def test_access_is_recomputed_after_officer_moves_district(self):
        """§22 — inherited access follows the *current* posting."""
        self.inspector_a.unit = self.unit_b          # District B
        self.inspector_a.save(update_fields=["unit"])

        new_case = self.make_case(self.inspector_a)
        self.assertEqual(new_case.organization, self.org_b)

        # DSP C's jurisdiction is District A, so the new case is out of reach
        # even though the supervisory link is unchanged.
        self.assertTrue(self.dsp.is_supervisor_of(self.inspector_a))
        self.assertFalse(authorization_service.can_access_resource(self.dsp, new_case, C.ACTION_VIEW))

    # -- J. Case transfer ------------------------------------------------------------
    def test_case_transfer_moves_access_to_the_new_jurisdiction(self):
        """§24 — access follows the case's current location."""
        case = self.make_case(self.inspector_a)
        self.assertTrue(authorization_service.can_access_resource(self.inspector_b, case, C.ACTION_VIEW) is False)

        case_transfer_service.transfer(
            case,
            to_unit=self.unit_station_y,
            to_organization=self.org_a,
            actor=self.dsp,
            reason="reassignment",
        )
        case.refresh_from_db()
        self.assertEqual(case.unit, self.unit_station_y)
        self.assertEqual(case.transfers.count(), 1)

        # Inspector B now reaches it through the station unit tree.
        self.assertTrue(authorization_service.can_access_resource(self.inspector_b, case, C.ACTION_VIEW))

    def test_transfer_requires_manage_access(self):
        case = self.make_case(self.inspector_a)
        with self.assertRaises(PermissionError):
            case_transfer_service.transfer(
                case, to_unit=self.unit_station_y, to_organization=self.org_a,
                actor=self.field_officer, reason="no authority",
            )

    # -- K. File access -----------------------------------------------------------
    def test_authorized_officer_can_download_files(self):
        case = self.make_case(self.inspector_a)
        self.login_as(self.inspector_a)

        fir = self.client.get(reverse("general:download_fir", kwargs={"case_id": case.case_id}))
        self.assertEqual(fir.status_code, 200)

        evidence = case.evidence_files.first()
        ev = self.client.get(
            reverse("general:download_evidence", kwargs={"case_id": case.case_id, "pk": evidence.pk})
        )
        self.assertEqual(ev.status_code, 200)

    def test_unauthorized_officer_cannot_download_files(self):
        case = self.make_case(self.inspector_a)
        evidence = case.evidence_files.first()
        self.login_as(self.inspector_b)

        self.assertEqual(
            self.client.get(reverse("general:download_fir", kwargs={"case_id": case.case_id})).status_code, 403
        )
        self.assertEqual(
            self.client.get(reverse(
                "general:download_evidence", kwargs={"case_id": case.case_id, "pk": evidence.pk}
            )).status_code, 403
        )

    def test_viewing_a_case_does_not_imply_downloading_its_files(self):
        """§20 — case access and file access are decided independently."""
        case = self.make_case(self.inspector_a)
        CaseAssignment.objects.create(
            case=case, officer=self.inspector_b, role=C.ASSIGNMENT_VIEWER, granted_by=self.inspector_a
        )

        self.assertTrue(authorization_service.can_access_resource(self.inspector_b, case, C.ACTION_VIEW))
        self.assertFalse(
            authorization_service.can_access_resource(self.inspector_b, case.fir_resource, C.ACTION_DOWNLOAD)
        )

    def test_file_download_denial_is_audited(self):
        from audit.models import AuditEvent

        case = self.make_case(self.inspector_a)
        self.login_as(self.inspector_b)
        self.client.get(reverse("general:download_fir", kwargs={"case_id": case.case_id}))

        self.assertTrue(
            AuditEvent.objects.filter(
                event_type=C.EVENT_ACCESS_DENIED,
                resource_id=case.case_id,
                officer=self.inspector_b,
            ).exists()
        )

    # -- L. Access requests -----------------------------------------------------------
    def test_access_request_then_approval_grants_access(self):
        case = self.make_case(self.inspector_a)
        self.assertFalse(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))

        request = access_request_service.create(
            requester=self.field_officer, resource_type=C.RESOURCE_CASE,
            resource_id=case.case_id, actions=[C.ACTION_VIEW], reason="investigation",
        )
        self.assertTrue(request.is_pending)
        self.assertFalse(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))

        access_request_service.approve(request, self.inspector_a, "approved")
        self.assertTrue(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))
        self.assertEqual(AccessRequest.objects.get(pk=request.pk).status, C.REQUEST_APPROVED)

    def test_requester_cannot_approve_their_own_request(self):
        """§18 — four-eyes for operational access too."""
        case = self.make_case(self.inspector_a)
        request = access_request_service.create(
            requester=self.inspector_a, resource_type=C.RESOURCE_CASE,
            resource_id=case.case_id, actions=[C.ACTION_VIEW], reason="self",
        )
        self.assertFalse(access_request_service.can_decide(self.inspector_a, request))
        with self.assertRaises(PermissionError):
            access_request_service.approve(request, self.inspector_a, "self approval")

    def test_unauthorized_officer_cannot_decide_a_request(self):
        case = self.make_case(self.inspector_a)
        request = access_request_service.create(
            requester=self.field_officer, resource_type=C.RESOURCE_CASE,
            resource_id=case.case_id, actions=[C.ACTION_VIEW], reason="need it",
        )
        # inspector_b has no relationship to inspector_a's case.
        self.assertFalse(access_request_service.can_decide(self.inspector_b, request))

    def test_rejected_request_grants_nothing(self):
        case = self.make_case(self.inspector_a)
        request = access_request_service.create(
            requester=self.field_officer, resource_type=C.RESOURCE_CASE,
            resource_id=case.case_id, actions=[C.ACTION_VIEW], reason="need it",
        )
        access_request_service.reject(request, self.inspector_a, "not required")
        self.assertFalse(authorization_service.can_access_resource(self.field_officer, case, C.ACTION_VIEW))

    # -- M. Listing / leakage -------------------------------------------------------------
    def test_case_list_shows_only_authorized_cases(self):
        mine = self.make_case(self.inspector_a, title="Mine")
        theirs = self.make_case(self.inspector_b, title="Theirs")

        self.login_as(self.inspector_a)
        response = self.client.get(reverse("general:view_cases"))
        content = response.content.decode()

        self.assertIn(mine.case_id, content)
        self.assertNotIn(theirs.case_id, content)

    def test_search_does_not_leak_unauthorized_cases(self):
        theirs = self.make_case(self.inspector_b, title="Secret Investigation")

        self.login_as(self.inspector_a)
        response = self.client.get(reverse("general:view_cases"), {"q": "Secret"})
        self.assertNotIn(theirs.case_id, response.content.decode())

    def test_authorized_queryset_respects_jurisdiction(self):
        case = self.make_case(self.inspector_a)
        qs = case_access_service.authorized_queryset(self.district_b_officer)
        self.assertNotIn(case, list(qs))

    def test_dashboard_excludes_unauthorized_cases(self):
        theirs = self.make_case(self.inspector_b, title="Not Mine")
        self.login_as(self.inspector_a)

        response = self.client.get(reverse("general:dashboard"))
        self.assertNotIn(theirs.case_id, response.content.decode())

    # -- N. IT / admin separation --------------------------------------------------------
    def test_it_admin_cannot_read_operational_cases(self):
        """§26 — administrative authority is not investigation authority."""
        case = self.make_case(self.inspector_a)

        self.assertFalse(authorization_service.can_access_resource(self.it_admin, case, C.ACTION_VIEW))
        self.assertFalse(authorization_service.can_access_resource(self.security_admin, case, C.ACTION_VIEW))

        self.login_as(self.it_admin, portal="it_admin")
        self.assertEqual(
            self.client.get(reverse("general:case_detail", kwargs={"case_id": case.case_id})).status_code, 403
        )

    def test_it_admin_still_reaches_identity_administration(self):
        self.login_as(self.it_admin, portal="it_admin")
        self.assertEqual(self.client.get(reverse("it_admin:officer_list")).status_code, 200)

    def test_it_admin_cannot_grant_case_access(self):
        case = self.make_case(self.inspector_a)
        allowed, _reason = access_grant_service.can_grant(self.it_admin, case, C.GRANT_SCOPE_CASE, [C.ACTION_VIEW])
        self.assertFalse(allowed)
