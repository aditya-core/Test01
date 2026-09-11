"""Idempotent demo seed.

Creates the configurable RBAC/clearance/org structure and a small set of demo
officers so the system can be exercised end-to-end out of the box.

Everything seeded here is *data*, not policy — roles, clearances, portals and
permissions are all editable by Central IT / Django admin afterwards.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from accounts import constants as C
from accounts.models import (
    ClearanceLevel,
    Department,
    Designation,
    Organization,
    OrganizationUnit,
    Permission,
    Portal,
    PortalAccess,
    Role,
)
from accounts.services import security_code_service

Officer = get_user_model()

DEMO_PASSWORD = "ChangeMe!123"


class Command(BaseCommand):
    help = "Seed demo roles, clearances, org structure and officers (idempotent)."

    def handle(self, *args, **options):
        self._seed_permissions()
        self._seed_clearances()
        self._seed_registries()
        self._seed_org()
        self._seed_portals()
        self._seed_roles()
        self._seed_officers()
        self.stdout.write(self.style.SUCCESS("Demo data seeded."))

    # -- permissions ---------------------------------------------------------
    def _seed_permissions(self):
        specs = {
            # Identity administration.
            "officer.view": "View officer accounts.",
            "officer.manage": "Create, edit, activate, suspend, disable and lock officer accounts.",
            # Security administration.
            "security.view_events": "View security events (failed logins, lockouts, denials).",
            "security.manage_settings": "Manage system-level security settings.",
            "audit.view": "View the audit trail.",
            "account.manage_security": "Configure MFA / secret codes for officers.",
            # Future domain capabilities (reserved; no case/document apps yet).
            "case.view": "View authorized investigation cases.",
            "case.assign": "Assign/reassign cases within policy.",
            "case.review": "Review subordinate work.",
            "case.approve": "Approve actions within policy.",
            "document.view": "View authorized documents.",
            "document.upload": "Upload documents into authorized cases.",
            "document.download": "Download authorized documents.",
            "report.view": "View reports.",
            "district.report": "View district-level reporting.",
            "notification.view": "View notifications.",
            "task.view": "View assigned tasks.",
        }
        # Granular IT-administration capabilities are defined once, in code.
        specs.update(C.ADMIN_CAPABILITY_DESCRIPTIONS)
        for codename, description in specs.items():
            Permission.objects.get_or_create(codename=codename, defaults={"description": description})

    # -- clearances ------------------------------------------------------------
    def _seed_clearances(self):
        specs = [
            ("L1", "General", 1, False, "General (unclassified) information."),
            ("L2", "Restricted", 2, False, "Restricted — limited distribution."),
            ("L3", "Confidential", 3, False, "Confidential information."),
            ("L4", "Highly Confidential", 4, True, "Highly confidential information."),
            ("L5", "Classified", 5, True, "Classified information."),
            ("L6", "Special / Top Restricted", 6, True, "Special access required."),
        ]
        for code, label, weight, classified, desc in specs:
            ClearanceLevel.objects.update_or_create(
                code=code,
                defaults={"label": label, "weight": weight, "is_classified": classified, "description": desc},
            )

    # -- designation & department registries --------------------------------------
    def _seed_registries(self):
        designations = [
            ("CONST", "Constable", 10), ("HC", "Head Constable", 20), ("ASI", "Assistant Sub-Inspector", 30),
            ("SI", "Sub-Inspector", 40), ("INSP", "Inspector", 50), ("SO", "Senior Officer", 60),
            ("DSP", "Deputy Superintendent", 70), ("SP", "Superintendent", 80),
            ("ADMIN", "Administrator", 5), ("SUPER", "Superuser", 1),
        ]
        for code, name, level in designations:
            Designation.objects.get_or_create(
                name=name, defaults={"code": code, "rank_level": level, "description": f"{name} (rank level {level})"}
            )
        departments = [
            ("INV", "Investigation", "Criminal investigation."),
            ("CYBER", "Cyber Crime", "Cyber crime and digital forensics."),
            ("FOR", "Forensics", "Forensic science services."),
            ("ADM", "Administration", "Administration, IT and support."),
        ]
        for code, name, desc in departments:
            Department.objects.get_or_create(name=name, defaults={"code": code, "description": desc})

    # -- organization ----------------------------------------------------------
    def _seed_org(self):
        national, _ = Organization.objects.get_or_create(
            name="National", kind=C.ORG_NATIONAL
        )
        state, _ = Organization.objects.get_or_create(
            name="State", kind=C.ORG_STATE, defaults={"parent": national}
        )
        district, _ = Organization.objects.get_or_create(
            name="District A", kind=C.ORG_DISTRICT, defaults={"parent": state}
        )
        depts = {d.name: d for d in Department.objects.all()}
        unit_specs = [
            ("Investigation Unit", C.UNIT_KIND_INVESTIGATION, "Investigation"),
            ("Cyber Unit", C.UNIT_KIND_CYBER, "Cyber Crime"),
            ("Forensic Unit", C.UNIT_KIND_FORENSIC, "Forensics"),
            ("Administration Unit", C.UNIT_KIND_ADMIN, "Administration"),
        ]
        for name, kind, dept in unit_specs:
            unit, _ = OrganizationUnit.objects.get_or_create(
                organization=district, name=name, defaults={"kind": kind}
            )
            if unit.department_id is None and dept in depts:
                unit.department = depts[dept]
                unit.save(update_fields=["department"])
        self._district = district

    # -- portals ------------------------------------------------------------------
    def _seed_portals(self):
        classified, _ = Portal.objects.get_or_create(
            key=C.PORTAL_CLASSIFIED,
            defaults={
                "name": "Classified",
                "description": "Highly restricted access.",
                "is_restricted": True,
                "min_clearance": ClearanceLevel.objects.get(code="L4"),
            },
        )
        it_admin, _ = Portal.objects.get_or_create(
            key=C.PORTAL_IT_ADMIN,
            defaults={"name": "IT / Admin", "description": "Identity & system administration."},
        )
        general, _ = Portal.objects.get_or_create(
            key=C.PORTAL_GENERAL,
            defaults={"name": "General", "description": "Authorized officer access."},
        )

    # -- roles ----------------------------------------------------------------------
    def _seed_roles(self):
        portal_general = Portal.objects.get(key=C.PORTAL_GENERAL)
        portal_admin = Portal.objects.get(key=C.PORTAL_IT_ADMIN)
        portal_classified = Portal.objects.get(key=C.PORTAL_CLASSIFIED)

        def perms(*names):
            return list(Permission.objects.filter(codename__in=names))

        specs = [
            (
                "FIELD_OFFICER",
                "Front-line field officer.",
                10,
                ["document.view", "document.upload", "task.view", "notification.view"],
                [portal_general],
            ),
            (
                "INVESTIGATING_OFFICER",
                "Investigating officer.",
                20,
                ["case.view", "document.view", "document.upload", "task.view", "notification.view"],
                [portal_general],
            ),
            (
                "FORENSIC_OFFICER",
                "Forensic officer.",
                21,
                ["case.view", "document.view", "document.upload"],
                [portal_general],
            ),
            (
                "INSPECTOR",
                "Inspector — manage authorized investigations.",
                30,
                ["case.view", "case.assign", "case.review", "case.approve",
                 "document.view", "document.upload", "report.view"],
                [portal_general],
            ),
            (
                "SENIOR_OFFICER",
                "Senior officer — oversight and approvals.",
                40,
                ["case.view", "case.review", "case.approve", "document.view",
                 "report.view", "district.report"],
                [portal_general],
            ),
            (
                "COMMISSIONER",
                "Commissioner — command-level oversight.",
                50,
                ["case.view", "case.review", "case.approve", "document.view",
                 "report.view", "district.report"],
                [portal_general],
            ),
            # IT administration roles: capability bundles are data-driven and
            # deliberately unequal — not every administrator gets everything.
            (
                "IT_ADMIN",
                "Central IT — system administration (full identity & security administration).",
                60,
                list(C.SYSTEM_ADMIN_CAPABILITIES),
                [portal_admin],
            ),
            (
                "IDENTITY_ADMIN",
                "Identity administration — officers, designations, departments, transfers.",
                62,
                list(C.IDENTITY_ADMIN_CAPABILITIES),
                [portal_admin],
            ),
            (
                "SECURITY_ADMIN",
                "Security operations — account security, devices & sessions, reviews, approvals, audit.",
                61,
                list(C.SECURITY_ADMIN_CAPABILITIES),
                [portal_admin],
            ),
            (
                "AUDITOR",
                "Read-only audit and oversight.",
                63,
                list(C.AUDITOR_CAPABILITIES),
                [portal_admin],
            ),
        ]
        for name, desc, weight, perm_names, portals in specs:
            role, created = Role.objects.get_or_create(
                name=name,
                defaults={"description": desc, "rank_weight": weight, "is_system_role": True},
            )
            if created or role.is_system_role:
                role.permissions.set(perms(*perm_names))
                role.allowed_portals.set(portals)

    # -- officers ---------------------------------------------------------------------
    def _seed_officers(self):
        district = Organization.objects.get(name="District A")
        units = {u.name: u for u in OrganizationUnit.objects.filter(organization=district)}
        roles = {r.name: r for r in Role.objects.all()}
        clearances = {c.code: c for c in ClearanceLevel.objects.all()}
        portals = {p.key: p for p in Portal.objects.all()}

        designations = {d.name: d for d in Designation.objects.all()}

        def make(officer_id, email, full_name, role, clearance, unit, portal_keys,
                 code, rank="", department="", active=True, superuser=False):
            unit_obj = units[unit]
            officer, created = Officer.objects.get_or_create(
                officer_id=officer_id,
                defaults={
                    "email": email,
                    "full_name": full_name,
                    "role": roles[role],
                    "clearance": clearances[clearance],
                    "unit": unit_obj,
                    "rank": rank,
                    "designation": designations.get(rank),
                    "department": unit_obj.department,
                    "legacy_department": department,
                    "employee_id": f"EMP-{officer_id.split('-')[-1]}",
                },
            )
            if created:
                officer.set_password(DEMO_PASSWORD)
                officer.account_status = C.ACCOUNT_STATUS_ACTIVE if active else C.ACCOUNT_STATUS_INVITED
                officer.is_active = active
                officer.save()
            else:
                # Backfill registry links for officers seeded before the
                # identity registries existed (demo data only).
                fields = []
                if officer.department_id is None and unit_obj.department_id:
                    officer.department = unit_obj.department
                    fields.append("department")
                if officer.designation_id is None and designations.get(officer.rank):
                    officer.designation = designations[officer.rank]
                    fields.append("designation")
                if not officer.employee_id:
                    officer.employee_id = f"EMP-{officer_id.split('-')[-1]}"
                    fields.append("employee_id")
                if fields:
                    officer.save(update_fields=fields + ["updated_at"])
            security_code_service.set_secret_code(officer, code, actor=None)
            for key in portal_keys:
                PortalAccess.objects.get_or_create(officer=officer, portal=portals[key])
            if superuser:
                officer.is_staff = True
                officer.is_superuser = True
                officer.account_status = C.ACCOUNT_STATUS_ACTIVE
                officer.is_active = True
                officer.save(update_fields=["is_staff", "is_superuser", "account_status", "is_active"])
            return officer

        make("OFF-101", "field.one@example.gov", "Field Officer One", "FIELD_OFFICER",
             "L1", "Investigation Unit", [C.PORTAL_GENERAL], "CODE-101", rank="Constable")
        make("OFF-102", "insp.two@example.gov", "Inspector Two", "INSPECTOR",
             "L3", "Investigation Unit", [C.PORTAL_GENERAL], "CODE-102", rank="Inspector")
        make("OFF-201", "class.three@example.gov", "Classified Officer Three", "INVESTIGATING_OFFICER",
             "L5", "Cyber Unit", [C.PORTAL_CLASSIFIED, C.PORTAL_GENERAL], "CODE-201", rank="Senior Officer")
        make("OFF-301", "it.admin@example.gov", "IT Administrator", "IT_ADMIN",
             "L2", "Administration Unit", [C.PORTAL_IT_ADMIN], "CODE-301", rank="Administrator")
        make("OFF-302", "sec.admin@example.gov", "Security Administrator", "SECURITY_ADMIN",
             "L5", "Administration Unit", [C.PORTAL_IT_ADMIN, C.PORTAL_CLASSIFIED], "CODE-302", rank="Administrator")
        make("SU-900", "dev.super@example.gov", "Development Superuser", "IT_ADMIN",
             "L6", "Administration Unit", [C.PORTAL_IT_ADMIN, C.PORTAL_CLASSIFIED, C.PORTAL_GENERAL],
             "CODE-900", rank="Superuser", superuser=True)

        # One INVITED officer to demonstrate the activation flow.
        make("OFF-999", "pending.officer@example.gov", "Pending Officer", "FIELD_OFFICER",
             "L1", "Investigation Unit", [C.PORTAL_GENERAL], "CODE-999",
             rank="Constable", active=False)
