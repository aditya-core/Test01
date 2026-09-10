"""Shared test fixtures: a minimal configurable security structure."""
from __future__ import annotations

from django.core.cache import cache
from django.test import TestCase

from accounts import constants as C
from accounts.models import (
    ClearanceLevel,
    Officer,
    Organization,
    OrganizationUnit,
    Permission,
    Portal,
    PortalAccess,
    Role,
)
from accounts.services import security_code_service

PASSWORD = "TestPassword!123"


def make_officer(officer_id, email, full_name, role, clearance, unit, portal_keys,
                 code, status=C.ACCOUNT_STATUS_ACTIVE, active=True, rank=""):
    officer = Officer.objects.create_officer(
        officer_id=officer_id,
        email=email,
        password=PASSWORD,
        full_name=full_name,
        role=role,
        clearance=clearance,
        unit=unit,
        rank=rank,
        account_status=status,
        is_active=active,
    )
    security_code_service.set_secret_code(officer, code, actor=None)
    for key in portal_keys:
        PortalAccess.objects.get_or_create(officer=officer, portal=Portal.objects.get(key=key))
    return officer


class BaseAuthTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls._build_clearances()
        cls._build_org()
        cls._build_portals()
        cls._build_permissions()
        cls._build_roles()
        cls._build_officers()

    @classmethod
    def _build_clearances(cls):
        specs = [
            ("L1", "General", 1, False),
            ("L2", "Restricted", 2, False),
            ("L3", "Confidential", 3, False),
            ("L4", "Highly Confidential", 4, True),
            ("L5", "Classified", 5, True),
            ("L6", "Special", 6, True),
        ]
        for code, label, weight, classified in specs:
            ClearanceLevel.objects.get_or_create(
                code=code, defaults={"label": label, "weight": weight, "is_classified": classified}
            )
        cls.l1 = ClearanceLevel.objects.get(code="L1")
        cls.l2 = ClearanceLevel.objects.get(code="L2")
        cls.l3 = ClearanceLevel.objects.get(code="L3")
        cls.l4 = ClearanceLevel.objects.get(code="L4")
        cls.l5 = ClearanceLevel.objects.get(code="L5")

    @classmethod
    def _build_org(cls):
        cls.org_a = Organization.objects.get_or_create(name="District A", kind=C.ORG_DISTRICT)[0]
        cls.org_b = Organization.objects.get_or_create(name="District B", kind=C.ORG_DISTRICT)[0]
        cls.unit_investigation = OrganizationUnit.objects.get_or_create(
            organization=cls.org_a, name="Investigation Unit", defaults={"kind": C.UNIT_KIND_INVESTIGATION}
        )[0]
        cls.unit_admin = OrganizationUnit.objects.get_or_create(
            organization=cls.org_a, name="Administration Unit", defaults={"kind": C.UNIT_KIND_ADMIN}
        )[0]
        cls.unit_b = OrganizationUnit.objects.get_or_create(
            organization=cls.org_b, name="Investigation Unit B", defaults={"kind": C.UNIT_KIND_INVESTIGATION}
        )[0]

    @classmethod
    def _build_portals(cls):
        cls.portal_classified = Portal.objects.get_or_create(
            key=C.PORTAL_CLASSIFIED,
            defaults={"name": "Classified", "is_restricted": True, "min_clearance": cls.l4},
        )[0]
        cls.portal_it_admin = Portal.objects.get_or_create(
            key=C.PORTAL_IT_ADMIN, defaults={"name": "IT / Admin"}
        )[0]
        cls.portal_general = Portal.objects.get_or_create(
            key=C.PORTAL_GENERAL, defaults={"name": "General"}
        )[0]

    @classmethod
    def _build_permissions(cls):
        codenames = [
            C.PERM_OFFICER_VIEW, C.PERM_OFFICER_MANAGE,
            C.PERM_SECURITY_VIEW_EVENTS, C.PERM_AUDIT_VIEW, C.PERM_ACCOUNT_MANAGE_SECURITY,
            "case.view", "case.assign", "case.review", "case.approve",
            "document.view", "document.upload", "document.download",
        ]
        cls.perms = {}
        for codename in codenames:
            p, _ = Permission.objects.get_or_create(codename=codename, defaults={"description": codename})
            cls.perms[codename] = p

    @classmethod
    def _build_roles(cls):
        def role(name, perms, portals):
            r, _ = Role.objects.get_or_create(name=name, defaults={"is_system_role": True})
            r.permissions.set(perms)
            r.allowed_portals.set(portals)
            return r

        cls.field_role = role("FIELD_OFFICER",
                              [cls.perms["document.view"], cls.perms["document.upload"]],
                              [cls.portal_general])
        cls.inspector_role = role("INSPECTOR",
                                  [cls.perms["case.view"], cls.perms["case.assign"],
                                   cls.perms["case.review"], cls.perms["case.approve"],
                                   cls.perms["document.view"]],
                                  [cls.portal_general])
        cls.senior_role = role("SENIOR_OFFICER",
                               [cls.perms["case.review"], cls.perms["document.view"]],
                               [cls.portal_general])
        cls.it_role = role("IT_ADMIN",
                           [cls.perms[C.PERM_OFFICER_VIEW], cls.perms[C.PERM_OFFICER_MANAGE],
                            cls.perms[C.PERM_ACCOUNT_MANAGE_SECURITY]],
                           [cls.portal_it_admin])
        cls.sec_role = role("SECURITY_ADMIN",
                            [cls.perms[C.PERM_OFFICER_VIEW], cls.perms[C.PERM_SECURITY_VIEW_EVENTS],
                             cls.perms[C.PERM_AUDIT_VIEW]],
                            [cls.portal_it_admin])

    @classmethod
    def _build_officers(cls):
        cls.field_officer = make_officer(
            "OFF-101", "field@example.gov", "Field Officer", cls.field_role, cls.l1,
            cls.unit_investigation, [C.PORTAL_GENERAL], "CODE-101", rank="Constable")
        cls.inspector = make_officer(
            "OFF-102", "insp@example.gov", "Inspector", cls.inspector_role, cls.l3,
            cls.unit_investigation, [C.PORTAL_GENERAL], "CODE-102", rank="Inspector")
        cls.senior_officer = make_officer(
            "OFF-103", "senior@example.gov", "Senior Officer", cls.senior_role, cls.l2,
            cls.unit_investigation, [C.PORTAL_GENERAL], "CODE-103", rank="Senior Officer")
        cls.classified_officer = make_officer(
            "OFF-201", "class@example.gov", "Classified Officer", cls.inspector_role, cls.l5,
            cls.unit_investigation, [C.PORTAL_CLASSIFIED, C.PORTAL_GENERAL], "CODE-201")
        cls.it_admin = make_officer(
            "OFF-301", "it@example.gov", "IT Admin", cls.it_role, cls.l2,
            cls.unit_admin, [C.PORTAL_IT_ADMIN], "CODE-301")
        cls.security_admin = make_officer(
            "OFF-302", "sec@example.gov", "Security Admin", cls.sec_role, cls.l5,
            cls.unit_admin, [C.PORTAL_IT_ADMIN, C.PORTAL_CLASSIFIED], "CODE-302")
        cls.disabled_officer = make_officer(
            "OFF-501", "disabled@example.gov", "Disabled Officer", cls.field_role, cls.l1,
            cls.unit_investigation, [C.PORTAL_GENERAL], "CODE-501", status=C.ACCOUNT_STATUS_DISABLED, active=False)
        cls.inactive_officer = make_officer(
            "OFF-502", "inactive@example.gov", "Inactive Officer", cls.field_role, cls.l1,
            cls.unit_investigation, [C.PORTAL_GENERAL], "CODE-502", status=C.ACCOUNT_STATUS_ACTIVE, active=False)
        cls.invited_officer = make_officer(
            "OFF-503", "invited@example.gov", "Invited Officer", cls.field_role, cls.l1,
            cls.unit_investigation, [C.PORTAL_GENERAL], "CODE-503", status=C.ACCOUNT_STATUS_INVITED, active=False)

    def setUp(self):
        cache.clear()
        self.client.logout()

    # -- helpers ----------------------------------------------------------------
    def login_via_view(self, officer_id, password=PASSWORD, code=None, portal="general"):
        """POST the login form; return the response."""
        return self.client.post(
            f"/auth/login/{portal}/",
            {"officer_id": officer_id, "password": password, "secret_code": code},
        )

    def login_as(self, officer, code=None, portal="general", password=PASSWORD):
        if code is None:
            code = f"CODE-{officer.officer_id.split('-')[1]}"
        return self.login_via_view(officer.officer_id, password=password, code=code, portal=portal)

    def code_for(self, officer):
        return f"CODE-{officer.officer_id.split('-')[1]}"
