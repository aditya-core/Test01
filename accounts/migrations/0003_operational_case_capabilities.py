"""Grant the operational (case) capabilities to the operational roles.

Case authorization is evaluated by the central engine but is *operational*
authorization: it is granted by the operational domain, never by IT
administration. This migration only creates the codenames and attaches them to
the roles that legitimately work cases — it grants no administrative
capability and no access to any individual case (that still requires an
explicit ``CaseAssignment``).

Safe to re-run and safe on databases where the roles do not exist yet.
"""
from __future__ import annotations

from django.db import migrations

from accounts import constants as C


def grant_operational_capabilities(apps, schema_editor):
    Permission = apps.get_model("accounts", "Permission")
    Role = apps.get_model("accounts", "Role")

    permission_by_code = {}
    for codename, description in C.OPERATIONAL_CAPABILITY_DESCRIPTIONS.items():
        permission, _ = Permission.objects.get_or_create(
            codename=codename, defaults={"description": description}
        )
        permission_by_code[codename] = permission

    for role_name, grants in C.ROLE_OPERATIONAL_CAPABILITIES.items():
        role = Role.objects.filter(name=role_name).first()
        if role is None:
            continue
        # Preserve everything the role already carries; only add.
        existing = set(role.permissions.values_list("codename", flat=True))
        to_add = [permission_by_code[c] for c in grants if c not in existing]
        if to_add:
            role.permissions.add(*to_add)


def revoke_operational_capabilities(apps, schema_editor):
    """Reverse: detach the case capabilities (the codenames themselves stay)."""
    Role = apps.get_model("accounts", "Role")
    for role_name, grants in C.ROLE_OPERATIONAL_CAPABILITIES.items():
        role = Role.objects.filter(name=role_name).first()
        if role is None:
            continue
        role.permissions.remove(
            *role.permissions.filter(codename__in=list(grants))
        )


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0002_identity_registries"),
    ]

    operations = [
        migrations.RunPython(grant_operational_capabilities, revoke_operational_capabilities),
    ]
