"""IT admin roles & capabilities and the four-eyes Approval Center."""
from __future__ import annotations

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST, require_http_methods

from accounts import constants as C
from accounts.decorators import any_permission_required, permission_required, portal_required, reauth_required
from accounts.models import Officer, Permission, Role

from ..exceptions import AdminActionError
from ..forms import AdminRoleAssignRequestForm, AdminRoleForm, ApprovalDecisionForm, RoleCapabilitiesRequestForm
from ..models import ApprovalRequest
from ..services import approval_service
from ._common import PORTAL, actor_can

__all__ = [
    "admin_role_list", "admin_role_create", "admin_role_detail", "admin_role_assign",
    "approval_list", "approval_detail", "approval_decide", "approval_cancel",
]


def _admin_roles():
    admin_codenames = [p.codename for p in Permission.objects.all() if C.is_admin_capability(p.codename)]
    return (Role.objects.filter(permissions__codename__in=admin_codenames).distinct()
            .annotate(officer_total=Count("officers", distinct=True)).prefetch_related("permissions"))


# --------------------------------------------------------------------------- roles
@portal_required(PORTAL)
@any_permission_required(C.PERM_ADMIN_ROLE_MANAGE, C.PERM_APPROVAL_REVIEW, C.PERM_AUDIT_VIEW)
def admin_role_list(request):
    roles = list(_admin_roles())
    for role in roles:
        role.admin_caps = sorted(p.codename for p in role.permissions.all() if C.is_admin_capability(p.codename))
        role.operational_count = sum(1 for p in role.permissions.all() if not C.is_admin_capability(p.codename))
    return render(request, "it_admin/admin_role_list.html", {
        "roles": roles, "can_manage": actor_can(request, C.PERM_ADMIN_ROLE_MANAGE),
        "capabilities": C.ADMIN_CAPABILITY_DESCRIPTIONS,
    })


@portal_required(PORTAL)
@permission_required(C.PERM_ADMIN_ROLE_MANAGE)
@reauth_required
@require_http_methods(["GET", "POST"])
def admin_role_create(request):
    """Creating an empty administrative role is immediate; attaching
    capabilities goes through four-eyes approval (see admin_role_detail)."""
    form = AdminRoleForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        role = form.save()
        from audit.services import audit_service

        audit_service.record_admin_action(
            C.EVENT_ADMIN_ROLE_CHANGED, actor=request.user, target_type="role", target_id=str(role.pk),
            action="create", new_state={"name": role.name, "capabilities": []}, reason=form.cleaned_data.get("reason", ""),
            request=request,
        )
        messages.success(request, "Role created. Submit a capability change request to attach administrative capabilities.")
        return redirect("it_admin:admin_role_detail", pk=role.pk)
    return render(request, "it_admin/admin_role_form.html", {"form": form})


@portal_required(PORTAL)
@any_permission_required(C.PERM_ADMIN_ROLE_MANAGE, C.PERM_APPROVAL_REVIEW, C.PERM_AUDIT_VIEW)
@require_http_methods(["GET", "POST"])
def admin_role_detail(request, pk):
    role = get_object_or_404(Role.objects.prefetch_related("permissions"), pk=pk)
    current = sorted(p.codename for p in role.permissions.all() if C.is_admin_capability(p.codename))
    operational = sorted(p.codename for p in role.permissions.all() if not C.is_admin_capability(p.codename))
    can_manage = actor_can(request, C.PERM_ADMIN_ROLE_MANAGE)
    form = RoleCapabilitiesRequestForm(request.POST or None, role=role) if can_manage else None
    if request.method == "POST":
        if not can_manage:
            messages.error(request, "You are not authorized to perform this action.")
            return redirect("it_admin:admin_role_detail", pk=role.pk)
        if form.is_valid():
            wanted = sorted(p.codename for p in form.cleaned_data["capabilities"])
            if wanted == current:
                messages.info(request, "No capability changes requested.")
            else:
                try:
                    approval_service.request(
                        action=ApprovalRequest.ACTION_ROLE_CAPABILITIES, target_type="role", target_id=str(role.pk),
                        target_label=role.name, payload={"role_pk": role.pk, "capabilities": wanted},
                        summary=f"Capabilities {len(current)} → {len(wanted)} on {role.name}",
                        reason=form.cleaned_data["reason"], requested_by=request.user, request=request,
                    )
                except AdminActionError as exc:
                    messages.error(request, str(exc))
                else:
                    messages.success(request, "Capability change submitted for second-administrator approval.")
                    return redirect("it_admin:approval_list")
    holders = role.officers.select_related("department", "designation").order_by("officer_id")
    pending = ApprovalRequest.objects.filter(target_type="role", target_id=str(role.pk), status=ApprovalRequest.STATUS_PENDING)
    return render(request, "it_admin/admin_role_detail.html", {
        "role": role, "current": current, "operational": operational, "form": form, "holders": holders,
        "pending": pending, "can_manage": can_manage, "descriptions": C.ADMIN_CAPABILITY_DESCRIPTIONS,
    })


@portal_required(PORTAL)
@permission_required(C.PERM_ADMIN_ROLE_MANAGE)
@reauth_required
@require_http_methods(["GET", "POST"])
def admin_role_assign(request):
    form = AdminRoleAssignRequestForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        officer: Officer = form.cleaned_data["officer"]
        role = form.cleaned_data["role"]
        try:
            approval_service.request(
                action=ApprovalRequest.ACTION_ADMIN_ROLE_CHANGE, target_type="officer", target_id=officer.officer_id,
                target_label=str(officer), payload={"officer_pk": officer.pk, "role_pk": role.pk if role else None},
                summary=f"Role {officer.role.name if officer.role else '—'} → {role.name if role else '—'}",
                reason=form.cleaned_data["reason"], requested_by=request.user, request=request,
            )
        except AdminActionError as exc:
            form.add_error(None, str(exc))
        else:
            messages.success(request, "Administrative role change submitted for second-administrator approval.")
            return redirect("it_admin:approval_list")
    return render(request, "it_admin/admin_role_assign.html", {"form": form})


# --------------------------------------------------------------------------- approvals
@portal_required(PORTAL)
@any_permission_required(C.PERM_APPROVAL_REVIEW, C.PERM_ADMIN_ROLE_MANAGE, C.PERM_OFFICER_SUSPEND,
                         C.PERM_OFFICER_AUTHORIZATION)
def approval_list(request):
    base = ApprovalRequest.objects.select_related("requested_by", "decided_by")
    pending = base.filter(status=ApprovalRequest.STATUS_PENDING)
    can_review = actor_can(request, C.PERM_APPROVAL_REVIEW)
    if not can_review:
        # Requesters can track their own submissions even without review rights.
        base = base.filter(requested_by=request.user)
        pending = pending.filter(requested_by=request.user)
    history = Paginator(base.exclude(status=ApprovalRequest.STATUS_PENDING), 25).get_page(request.GET.get("page"))
    return render(request, "it_admin/approval_list.html", {"pending": pending, "history": history, "can_review": can_review})


@portal_required(PORTAL)
@any_permission_required(C.PERM_APPROVAL_REVIEW, C.PERM_ADMIN_ROLE_MANAGE, C.PERM_OFFICER_SUSPEND,
                         C.PERM_OFFICER_AUTHORIZATION)
def approval_detail(request, pk):
    req = get_object_or_404(ApprovalRequest.objects.select_related("requested_by", "decided_by"), pk=pk)
    can_review = actor_can(request, C.PERM_APPROVAL_REVIEW)
    if not can_review and req.requested_by_id != request.user.pk:
        messages.error(request, "You are not authorized to perform this action.")
        return redirect("it_admin:approval_list")
    return render(request, "it_admin/approval_detail.html", {
        "req": req, "form": ApprovalDecisionForm(), "can_review": can_review,
        "is_requester": req.requested_by_id == request.user.pk,
        "payload_items": sorted(req.payload.items()) if isinstance(req.payload, dict) else [],
    })


@portal_required(PORTAL)
@permission_required(C.PERM_APPROVAL_REVIEW)
@reauth_required
@require_POST
def approval_decide(request, pk):
    req = get_object_or_404(ApprovalRequest, pk=pk)
    form = ApprovalDecisionForm(request.POST)
    if not form.is_valid():
        messages.error(request, "A decision and a reason are required.")
        return redirect("it_admin:approval_detail", pk=req.pk)
    decision, reason = form.cleaned_data["decision"], form.cleaned_data["decision_reason"]
    try:
        if decision == "approve":
            approval_service.approve(req, request.user, decision_reason=reason, request=request)
            if req.status == ApprovalRequest.STATUS_FAILED:
                messages.error(request, f"Approved, but execution failed: {req.result}")
            else:
                messages.success(request, "Request approved and executed.")
        else:
            approval_service.reject(req, request.user, decision_reason=reason, request=request)
            messages.success(request, "Request rejected.")
    except AdminActionError as exc:
        messages.error(request, str(exc))
    return redirect("it_admin:approval_detail", pk=req.pk)


@portal_required(PORTAL)
@any_permission_required(C.PERM_APPROVAL_REVIEW, C.PERM_ADMIN_ROLE_MANAGE, C.PERM_OFFICER_SUSPEND,
                         C.PERM_OFFICER_AUTHORIZATION)
@require_POST
def approval_cancel(request, pk):
    req = get_object_or_404(ApprovalRequest, pk=pk)
    try:
        approval_service.cancel(req, request.user, request=request)
    except AdminActionError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "Request withdrawn.")
    return redirect("it_admin:approval_detail", pk=req.pk)
