"""Fixtures for IT / Admin portal tests.

Extends the shared ``BaseAuthTestCase`` with the identity registries and a
set of administrators holding *different* capability bundles so
separation-of-duties can be asserted.
"""
from __future__ import annotations

from accounts import constants as C
from accounts.models import Department, Designation, Permission, Portal, Role
from accounts.tests.base import BaseAuthTestCase, make_officer


class AdminPortalTestCase(BaseAuthTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls._build_admin_capabilities()
        cls._build_registries()
        cls._build_admin_roles()
        cls._build_admins()

    @classmethod
    def _build_admin_capabilities(cls):
        for codename, description in C.ADMIN_CAPABILITY_DESCRIPTIONS.items():
            p, _ = Permission.objects.get_or_create(codename=codename, defaults={"description": description})
            cls.perms[codename] = p

    @classmethod
    def _build_registries(cls):
        cls.dept_inv = Department.objects.create(code="INV", name="Investigation")
        cls.dept_cyber = Department.objects.create(code="CYBER", name="Cyber Crime")
        cls.dept_closed = Department.objects.create(code="OLD", name="Closed Department", is_active=False)
        cls.desig_const = Designation.objects.create(code="CONST", name="Constable", rank_level=10)
        cls.desig_si = Designation.objects.create(code="SI", name="Sub-Inspector", rank_level=40)
        cls.desig_retired = Designation.objects.create(code="RET", name="Retired Grade", rank_level=1, is_active=False)
        cls.unit_investigation.department = cls.dept_inv
        cls.unit_investigation.save(update_fields=["department"])
        cls.unit_b.department = cls.dept_cyber
        cls.unit_b.save(update_fields=["department"])

    @classmethod
    def _build_admin_roles(cls):
        def role(name, codenames):
            r, _ = Role.objects.get_or_create(name=name, defaults={"is_system_role": True})
            r.permissions.set([cls.perms[c] for c in codenames])
            r.allowed_portals.set([cls.portal_it_admin])
            return r

        cls.system_admin_role = role("SYSTEM_ADMIN", C.SYSTEM_ADMIN_CAPABILITIES)
        cls.identity_admin_role = role("IDENTITY_ADMIN", C.IDENTITY_ADMIN_CAPABILITIES)
        cls.security_admin_role = role("SECURITY_ADMIN_FULL", C.SECURITY_ADMIN_CAPABILITIES)
        cls.auditor_role = role("AUDITOR", C.AUDITOR_CAPABILITIES)

    @classmethod
    def _build_admins(cls):
        cls.system_admin = make_officer(
            "OFF-401", "sysadmin@example.gov", "System Admin", cls.system_admin_role, cls.l2,
            cls.unit_admin, [C.PORTAL_IT_ADMIN], "CODE-401")
        cls.identity_admin = make_officer(
            "OFF-402", "identity@example.gov", "Identity Admin", cls.identity_admin_role, cls.l2,
            cls.unit_admin, [C.PORTAL_IT_ADMIN], "CODE-402")
        cls.security_admin2 = make_officer(
            "OFF-403", "secops@example.gov", "Security Ops", cls.security_admin_role, cls.l3,
            cls.unit_admin, [C.PORTAL_IT_ADMIN], "CODE-403")
        cls.auditor = make_officer(
            "OFF-404", "auditor@example.gov", "Auditor", cls.auditor_role, cls.l2,
            cls.unit_admin, [C.PORTAL_IT_ADMIN], "CODE-404")

    # -- helpers ----------------------------------------------------------------
    def login_admin(self, officer):
        self.client.logout()
        resp = self.login_as(officer, portal=C.PORTAL_IT_ADMIN)
        self.assertEqual(resp.status_code, 302, "admin login should redirect into the portal")
        return resp

    def messages_of(self, response):
        return [str(m) for m in response.context["messages"]] if response.context else []
