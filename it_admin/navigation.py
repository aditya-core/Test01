"""Capability-driven sidebar for the IT / Admin portal.

The sidebar is *decoration*: it only lists what the officer is authorized to
open. Every target view re-checks authorization server-side.
"""
from __future__ import annotations

from django.urls import reverse

from accounts import constants as C
from accounts.authorization import authorization_service

# (section, [(label, url_name, required_any_of, active_url_names)])
NAV_SPEC = (
    ("Overview", (
        ("Dashboard", "it_admin:dashboard", None, {"dashboard"}),
    )),
    ("Identity", (
        ("Officer Management", "it_admin:officer_list", {C.PERM_OFFICER_VIEW},
         {"officer_list", "officer_detail", "officer_edit", "officer_authorization", "officer_timeline",
          "officer_access", "officer_devices_sessions", "officer_reset_password", "officer_reset_code"}),
        ("Provision Officer", "it_admin:officer_create", {C.PERM_OFFICER_CREATE}, {"officer_create"}),
        ("Designations", "it_admin:designation_list", {C.PERM_DESIGNATION_VIEW},
         {"designation_list", "designation_create", "designation_edit"}),
        ("Departments & Units", "it_admin:department_list", {C.PERM_DEPARTMENT_VIEW},
         {"department_list", "department_create", "department_edit", "unit_create", "unit_edit"}),
        ("Transfers / Postings", "it_admin:posting_list", {C.PERM_OFFICER_VIEW, C.PERM_OFFICER_TRANSFER},
         {"posting_list", "officer_transfer"}),
        ("Bulk Operations", "it_admin:bulk_import", {C.PERM_OFFICER_BULK_IMPORT},
         {"bulk_import", "bulk_preview", "bulk_commit", "bulk_template"}),
    )),
    ("Security", (
        ("Account Security", "it_admin:account_security", {C.PERM_OFFICER_SUSPEND, C.PERM_OFFICER_REACTIVATE},
         {"account_security"}),
        ("Devices & Sessions", "it_admin:device_session_overview", {C.PERM_DEVICE_VIEW, C.PERM_SESSION_VIEW},
         {"device_session_overview"}),
        ("Security Monitoring", "it_admin:security_dashboard", {C.PERM_SECURITY_VIEW_EVENTS}, {"security_dashboard"}),
        ("Access Reviews", "it_admin:access_review_list", {C.PERM_ACCESS_REVIEW},
         {"access_review_list", "access_review_detail"}),
        ("Temporary Access", "it_admin:temporary_access_list", {C.PERM_ACCESS_GRANT_TEMPORARY, C.PERM_ACCESS_REVIEW},
         {"temporary_access_list", "temporary_access_create"}),
        ("Audit Log", "it_admin:audit_dashboard", {C.PERM_AUDIT_VIEW}, {"audit_dashboard"}),
    )),
    ("Administration", (
        ("Admin Roles", "it_admin:admin_role_list", {C.PERM_ADMIN_ROLE_MANAGE, C.PERM_APPROVAL_REVIEW, C.PERM_AUDIT_VIEW},
         {"admin_role_list", "admin_role_create", "admin_role_detail", "admin_role_assign"}),
        ("Approval Center", "it_admin:approval_list",
         {C.PERM_APPROVAL_REVIEW, C.PERM_ADMIN_ROLE_MANAGE, C.PERM_OFFICER_AUTHORIZATION, C.PERM_OFFICER_SUSPEND},
         {"approval_list", "approval_detail"}),
    )),
    ("Account", (
        ("My Account", "account_profile", None, set()),
    )),
)


def build_nav(perms: set, current_url_name: str | None) -> list:
    sections = []
    for title, items in NAV_SPEC:
        rendered = []
        for label, url_name, required, active_names in items:
            if required is not None and not (perms & required):
                continue
            rendered.append({
                "name": label,
                "url": reverse(url_name),
                "active": current_url_name in active_names,
            })
        if rendered:
            sections.append({"title": title, "items": rendered})
    return sections


def admin_portal_context(request):
    """Context processor: sidebar + capability set for IT / Admin pages only."""
    match = getattr(request, "resolver_match", None)
    user = getattr(request, "user", None)
    if match is None or match.namespace != "it_admin" or user is None or not user.is_authenticated:
        return {}
    perms = authorization_service.get_user_permissions(user)
    return {
        "admin_perms": perms,
        "admin_nav": build_nav(perms, match.url_name),
        "pending_approval_count": _pending_approvals(perms),
    }


def _pending_approvals(perms: set) -> int:
    if C.PERM_APPROVAL_REVIEW not in perms:
        return 0
    from .models import ApprovalRequest

    return ApprovalRequest.objects.filter(status=ApprovalRequest.STATUS_PENDING).count()
