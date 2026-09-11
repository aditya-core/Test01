"""Execution handlers for approved four-eyes requests.

Each handler receives the approved ``ApprovalRequest`` and the approver, and
performs the change through the normal audited services. Handlers must be
idempotent enough to fail *safely* (raise ``AdminActionError``) rather than
half-apply a change.
"""
from __future__ import annotations

from accounts import constants as C
from accounts.models import Officer, Permission, Role
from accounts.services import account_service
from audit.services import audit_service

from .exceptions import AdminActionError
from .models import ApprovalRequest


def _admin_role_change(req: ApprovalRequest, approver: Officer, request=None) -> str:
    officer = Officer.objects.filter(pk=req.payload.get("officer_pk")).first()
    if officer is None:
        raise AdminActionError("Target officer no longer exists.")
    role_pk = req.payload.get("role_pk")
    role = Role.objects.filter(pk=role_pk).first() if role_pk else None
    if role_pk and role is None:
        raise AdminActionError("Target role no longer exists.")
    old = officer.role.name if officer.role else None
    account_service.assign_role(officer, role, approver, reason=f"Approved request #{req.pk}: {req.reason}", request=request)
    audit_service.record_admin_action(
        C.EVENT_ADMIN_ROLE_CHANGED, actor=approver, target=officer,
        reason=req.reason, previous_state={"role": old}, new_state={"role": role.name if role else None},
        context={"approval": req.pk, "requested_by": req.requested_by.officer_id}, request=request,
    )
    return f"Role changed {old or '—'} → {role.name if role else '—'}"


def _role_capability_change(req: ApprovalRequest, approver: Officer, request=None) -> str:
    role = Role.objects.filter(pk=req.payload.get("role_pk")).first()
    if role is None:
        raise AdminActionError("Target role no longer exists.")
    wanted = [c for c in req.payload.get("capabilities", []) if C.is_admin_capability(c)]
    # Never let a role-capability approval touch operational permissions: the
    # request may only add/remove admin capabilities; everything else the
    # role already carries is preserved untouched.
    current_admin = set(p for p in role.permissions.values_list("codename", flat=True) if C.is_admin_capability(p))
    keep_operational = list(role.permissions.exclude(codename__in=current_admin))
    new_admin = list(Permission.objects.filter(codename__in=wanted))
    role.permissions.set(keep_operational + new_admin)
    audit_service.record_admin_action(
        C.EVENT_ADMIN_ROLE_CHANGED, actor=approver, target=role, target_type="role", target_id=role.name,
        action="role_capabilities", reason=req.reason,
        previous_state={"capabilities": sorted(current_admin)},
        new_state={"capabilities": sorted(p.codename for p in new_admin)},
        context={"approval": req.pk, "requested_by": req.requested_by.officer_id}, request=request,
    )
    return f"Capabilities of {role.name} updated ({len(new_admin)} administrative capabilities)."


def _privileged_deactivate(req: ApprovalRequest, approver: Officer, request=None) -> str:
    officer = Officer.objects.filter(pk=req.payload.get("officer_pk")).first()
    if officer is None:
        raise AdminActionError("Target officer no longer exists.")
    if officer.pk == approver.pk:
        raise AdminActionError("An approver cannot deactivate their own account.")
    account_service.deactivate(officer, approver, reason=f"Approved request #{req.pk}: {req.reason}", request=request)
    return f"Account {officer.officer_id} deactivated."


HANDLERS = {
    ApprovalRequest.ACTION_ADMIN_ROLE_CHANGE: _admin_role_change,
    ApprovalRequest.ACTION_ROLE_CAPABILITIES: _role_capability_change,
    ApprovalRequest.ACTION_PRIVILEGED_DEACTIVATE: _privileged_deactivate,
}


def execute(req: ApprovalRequest, approver: Officer, request=None) -> str:
    handler = HANDLERS.get(req.action)
    if handler is None:
        raise AdminActionError("No executor registered for this action.")
    return handler(req, approver, request=request)
