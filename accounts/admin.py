"""Django admin registration for the identity authority.

The Django admin is a development/emergency surface. Production provisioning
flows through the IT portal (``it_admin``) and its audited services — never
through silent admin edits.
"""
from __future__ import annotations

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group

from . import constants as C
from .models import (
    AuthenticationFactor,
    ClearanceLevel,
    Officer,
    Organization,
    OrganizationUnit,
    Permission,
    Portal,
    PortalAccess,
    Role,
)

admin.site.unregister(Group)


@admin.register(Officer)
class OfficerAdmin(BaseUserAdmin):
    ordering = ["officer_id"]
    list_display = (
        "officer_id",
        "full_name",
        "email",
        "account_status",
        "role",
        "clearance",
        "unit",
        "mfa_enabled",
        "failed_login_attempts",
        "is_active",
    )
    list_filter = (
        "account_status",
        "is_active",
        "is_staff",
        "mfa_enabled",
        "role",
        "clearance",
        "unit",
    )
    search_fields = ("officer_id", "full_name", "email")
    readonly_fields = ("last_login", "created_at", "updated_at", "failed_login_attempts")

    fieldsets = (
        ("Identity", {"fields": ("officer_id", "full_name", "email", "phone", "password")}),
        ("Authorization attributes", {"fields": ("role", "clearance", "unit", "rank", "department")}),
        ("Account state", {"fields": ("account_status", "is_active", "is_staff", "is_superuser")}),
        ("Second factor", {"fields": ("mfa_enabled", "secret_code_configured")}),
        ("Login protection", {"fields": ("failed_login_attempts", "last_failed_login", "locked_until")}),
        ("Timestamps", {"fields": ("last_login", "created_at", "updated_at")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "officer_id",
                    "email",
                    "full_name",
                    "password1",
                    "password2",
                    "account_status",
                    "role",
                    "clearance",
                    "unit",
                    "is_staff",
                    "is_superuser",
                ),
            },
        ),
    )


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("name", "rank_weight", "is_system_role")
    filter_horizontal = ("permissions", "allowed_portals")


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ("codename", "description")


@admin.register(ClearanceLevel)
class ClearanceLevelAdmin(admin.ModelAdmin):
    list_display = ("code", "label", "weight", "is_classified")


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "parent")


@admin.register(OrganizationUnit)
class OrganizationUnitAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "organization", "parent")
    list_filter = ("organization", "kind")


@admin.register(Portal)
class PortalAdmin(admin.ModelAdmin):
    list_display = ("key", "name", "is_restricted", "min_clearance")


@admin.register(PortalAccess)
class PortalAccessAdmin(admin.ModelAdmin):
    list_display = ("officer", "portal", "granted_by", "granted_at", "revoked_at")
    list_filter = ("portal",)


@admin.register(AuthenticationFactor)
class AuthenticationFactorAdmin(admin.ModelAdmin):
    list_display = ("officer", "factor_type", "enabled", "created_at", "last_verified_at")
    list_filter = ("factor_type", "enabled")
    # secret_hash is intentionally NOT displayed/editable to avoid leakage.
    exclude = ("secret_hash",)
