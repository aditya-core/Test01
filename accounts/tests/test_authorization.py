"""Authorization engine tests (spec §53, items 9, 11–15, 20–21)."""
from __future__ import annotations

from accounts import constants as C
from accounts.authorization import ResourceRequirement, authorization_service

from .base import BaseAuthTestCase


class ResourceRequirementTests(BaseAuthTestCase):
    """The engine's future-facing resource protocol: clearance + scope + case +
    permission + allowed actions."""

    def test_junior_attempting_senior_resource_denied(self):
        # FIELD_OFFICER has no case.review / case.assign permissions.
        req = ResourceRequirement(required_permission="case.review")
        self.assertFalse(authorization_service.authorize(self.field_officer, "view", requirement=req))
        self.assertTrue(authorization_service.authorize(self.inspector, "view", requirement=req))

    def test_cross_district_denied(self):
        req = ResourceRequirement(organization_id=self.org_b.pk)
        # District A officer vs District B resource.
        self.assertFalse(authorization_service.authorize(self.field_officer, "view", requirement=req))
        officer_b = self.field_officer
        officer_b.unit = self.unit_b
        officer_b.save()
        self.assertTrue(authorization_service.authorize(self.field_officer, "view", requirement=req))

    def test_insufficient_clearance_denied(self):
        req = ResourceRequirement(classification_code="L4")
        self.assertFalse(authorization_service.authorize(self.senior_officer, "view", requirement=req))
        self.assertTrue(authorization_service.authorize(self.classified_officer, "view", requirement=req))

    def test_clearance_ok_but_wrong_case_denied(self):
        req = ResourceRequirement(classification_code="L5", case_id="CASE-003")
        self.assertFalse(authorization_service.authorize(self.classified_officer, "view", requirement=req))

    def test_correct_case_but_action_not_allowed_denied(self):
        req = ResourceRequirement(
            classification_code="L3",
            case_id="CASE-001",
            allowed_actions=frozenset({"view", "edit"}),
        )
        # monkeypatch the future case resolver onto the officer.
        self.inspector.is_assigned_to_case = lambda case_id: case_id == "CASE-001"
        self.assertTrue(authorization_service.authorize(self.inspector, "view", requirement=req))
        self.assertFalse(authorization_service.authorize(self.inspector, "download", requirement=req))
        self.assertFalse(authorization_service.authorize(self.inspector, "delete", requirement=req))

    def test_action_level_matrix(self):
        req = ResourceRequirement(
            classification_code="L1",
            organization_id=self.org_a.pk,
            allowed_actions=frozenset({"view", "edit"}),
        )
        self.assertTrue(authorization_service.authorize(self.field_officer, "view", requirement=req))
        self.assertTrue(authorization_service.authorize(self.field_officer, "edit", requirement=req))
        self.assertFalse(authorization_service.authorize(self.field_officer, "download", requirement=req))
        self.assertFalse(authorization_service.authorize(self.field_officer, "delete", requirement=req))

    def test_deny_by_default_when_no_policy(self):
        # No requirement at all ⇒ fail closed.
        self.assertFalse(authorization_service.authorize(self.inspector, "view"))
        # Empty allowed actions ⇒ fail closed.
        self.assertFalse(
            authorization_service.authorize(self.inspector, "view", requirement=ResourceRequirement())
        )

    def test_inactive_identity_always_denied(self):
        req = ResourceRequirement(classification_code="L1")
        self.assertFalse(authorization_service.authorize(self.inactive_officer, "view", requirement=req))
        self.assertFalse(authorization_service.can_access_portal(self.inactive_officer, C.PORTAL_GENERAL))


class ClearanceVsRankTests(BaseAuthTestCase):
    def test_clearance_is_independent_of_rank(self):
        # Inspector has L3; senior officer has L2. Rank does not raise clearance.
        self.assertTrue(authorization_service.has_clearance(self.inspector, "L3"))
        self.assertFalse(authorization_service.has_clearance(self.senior_officer, "L3"))
        # And a higher-ranked officer cannot see L3 material merely by rank.
        req = ResourceRequirement(classification_code="L3")
        self.assertFalse(authorization_service.authorize(self.senior_officer, "view", requirement=req))
        self.assertTrue(authorization_service.authorize(self.inspector, "view", requirement=req))


class PortalAccessMatrixTests(BaseAuthTestCase):
    def test_field_officer_general_only(self):
        svc = authorization_service
        self.assertTrue(svc.can_access_portal(self.field_officer, C.PORTAL_GENERAL))
        self.assertFalse(svc.can_access_portal(self.field_officer, C.PORTAL_CLASSIFIED))
        self.assertFalse(svc.can_access_portal(self.field_officer, C.PORTAL_IT_ADMIN))

    def test_it_admin_cannot_enter_general_or_classified(self):
        svc = authorization_service
        self.assertTrue(svc.can_access_portal(self.it_admin, C.PORTAL_IT_ADMIN))
        self.assertFalse(svc.can_access_portal(self.it_admin, C.PORTAL_GENERAL))
        self.assertFalse(svc.can_access_portal(self.it_admin, C.PORTAL_CLASSIFIED))

    def test_classified_requires_clearance(self):
        svc = authorization_service
        # inspector has classified role? No — inspector has no classified grant.
        self.assertTrue(svc.can_access_portal(self.classified_officer, C.PORTAL_CLASSIFIED))
        self.assertTrue(svc.can_access_portal(self.security_admin, C.PORTAL_CLASSIFIED))

    def test_multiple_portals_for_one_identity(self):
        svc = authorization_service
        portals = svc.list_authorized_portals(self.security_admin)
        self.assertIn(C.PORTAL_IT_ADMIN, portals)
        self.assertIn(C.PORTAL_CLASSIFIED, portals)

    def test_disabled_identity_denied_everywhere(self):
        svc = authorization_service
        self.assertFalse(svc.can_access_portal(self.disabled_officer, C.PORTAL_GENERAL))


class PermissionTests(BaseAuthTestCase):
    def test_get_user_permissions(self):
        svc = authorization_service
        self.assertIn("document.view", svc.get_user_permissions(self.field_officer))
        self.assertNotIn("officer.manage", svc.get_user_permissions(self.field_officer))
        self.assertIn("officer.manage", svc.get_user_permissions(self.it_admin))

    def test_portal_capabilities(self):
        caps = authorization_service.portal_capabilities(self.field_officer, C.PORTAL_GENERAL)
        self.assertEqual(caps["clearance"], "L1")
        self.assertEqual(caps["role"], "FIELD_OFFICER")
        self.assertIn("document.view", caps["permissions"])
