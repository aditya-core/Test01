"""Account lifecycle, devices & sessions, security monitoring, audit log."""
from __future__ import annotations

from django.contrib import messages
from django.core.paginator import Paginator
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from accounts import constants as C
from accounts.decorators import any_permission_required, permission_required, portal_required
from accounts.devices import device_session_service
from accounts.models import Officer, OfficerSession, RegisteredDevice
from accounts.services import account_service
from audit.models import AuditEvent, SecurityEvent
from audit.services import audit_service

from ..exceptions import AdminActionError
from ..forms import LifecycleActionForm, OptionalReasonForm, ReasonForm
from ..models import ApprovalRequest
from ..services import approval_service
from ._common import PORTAL, actor_can, officer_queryset

__all__ = [
    "account_security", "officer_lifecycle", "device_session_overview", "officer_devices_sessions",
    "device_revoke", "session_terminate", "session_terminate_all", "security_dashboard", "audit_dashboard",
    "audit_verify",
]

LIFECYCLE_PERMISSION = {
    "suspend": C.PERM_OFFICER_SUSPEND,
    "deactivate": C.PERM_OFFICER_SUSPEND,
    "emergency_lock": C.PERM_OFFICER_SUSPEND,
    "reactivate": C.PERM_OFFICER_REACTIVATE,
    "unlock": C.PERM_OFFICER_REACTIVATE,
}


def _redirect_next(request, default_name: str, **kwargs):
    """Redirect to a same-origin ``next`` path if supplied, else the default."""
    nxt = request.POST.get("next", "")
    if nxt and url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return redirect(nxt)
    return redirect(default_name, **kwargs)


def _is_privileged(officer: Officer) -> bool:
    """Privileged = holds any administrative capability. Deactivating such an
    account is a four-eyes operation."""
    if officer.is_superuser:
        return True
    if officer.role is None:
        return False
    return any(C.is_admin_capability(c) for c in officer.role.permissions.values_list("codename", flat=True))


def _perform_lifecycle(request, officer: Officer, action: str, reason: str) -> bool:
    """Shared executor for every lifecycle endpoint. Returns True on success."""
    required = LIFECYCLE_PERMISSION.get(action)
    if required is None or not actor_can(request, required):
        messages.error(request, "You are not authorized to perform this action.")
        return False
    reason = (reason or "").strip()
    if len(reason) < 5:
        messages.error(request, "A reason (at least 5 characters) is required for this action.")
        return False
    if officer.pk == request.user.pk and action in ("suspend", "deactivate", "emergency_lock"):
        # Self-lockout is never allowed from the portal: it would leave the
        # organisation without the acting administrator mid-incident.
        messages.error(request, "You cannot suspend, lock or deactivate your own account.")
        return False
    try:
        if action == "suspend":
            if not account_service.can_transition(officer, "suspend"):
                raise AdminActionError(f"Cannot suspend an account in status {officer.account_status}.")
            account_service.suspend(officer, request.user, reason=reason, request=request)
            messages.success(request, f"Account {officer.officer_id} suspended. Active sessions were terminated.")
        elif action == "reactivate":
            if not account_service.can_transition(officer, "reactivate"):
                raise AdminActionError(f"Cannot reactivate an account in status {officer.account_status}.")
            account_service.reactivate(officer, request.user, reason=reason, request=request)
            messages.success(request, f"Account {officer.officer_id} reactivated.")
        elif action == "deactivate":
            if not account_service.can_transition(officer, "deactivate"):
                raise AdminActionError(f"Cannot deactivate an account in status {officer.account_status}.")
            if _is_privileged(officer):
                approval_service.request(
                    action=ApprovalRequest.ACTION_PRIVILEGED_DEACTIVATE,
                    target_type="officer", target_id=officer.officer_id, target_label=str(officer),
                    payload={"officer_pk": officer.pk}, summary=f"Deactivate privileged account {officer.officer_id}",
                    reason=reason, requested_by=request.user, request=request,
                )
                messages.warning(request, "This is a privileged account: deactivation has been submitted for second-administrator approval.")
            else:
                account_service.deactivate(officer, request.user, reason=reason, request=request)
                messages.success(request, f"Account {officer.officer_id} deactivated. History has been preserved.")
        elif action == "emergency_lock":
            if officer.account_status == C.ACCOUNT_STATUS_LOCKED and not officer.locked_until:
                raise AdminActionError("Account is already under emergency lock.")
            account_service.emergency_lock(officer, request.user, reason=reason, request=request)
            messages.success(request, f"Emergency lock applied to {officer.officer_id}: authentication blocked, sessions and devices revoked.")
        elif action == "unlock":
            if officer.account_status != C.ACCOUNT_STATUS_LOCKED and not officer.locked_until:
                raise AdminActionError("Account is not locked.")
            account_service.unlock(officer, request.user, reason=reason, request=request)
            messages.success(request, f"Account {officer.officer_id} unlocked.")
        else:
            raise AdminActionError("Unknown lifecycle action.")
    except AdminActionError as exc:
        messages.error(request, str(exc))
        return False
    return True


@portal_required(PORTAL)
@any_permission_required(C.PERM_OFFICER_SUSPEND, C.PERM_OFFICER_REACTIVATE)
def account_security(request):
    """Overview of accounts needing attention (suspended / locked / disabled)."""
    blocked = officer_queryset().filter(account_status__in=C.BLOCKING_STATUSES).order_by("-updated_at")
    from django.utils import timezone

    locked_out = officer_queryset().filter(locked_until__gt=timezone.now())
    q = request.GET.get("q", "").strip()
    results = None
    if q:
        from django.db.models import Q

        results = officer_queryset().filter(Q(officer_id__icontains=q) | Q(full_name__icontains=q))[:20]
    return render(request, "it_admin/account_security.html", {
        "blocked": blocked, "locked_out": locked_out, "q": q, "results": results,
        "can_suspend": actor_can(request, C.PERM_OFFICER_SUSPEND),
        "can_reactivate": actor_can(request, C.PERM_OFFICER_REACTIVATE),
        "suspend_hidden": {"action": "suspend"},
        "reactivate_hidden": {"action": "reactivate"},
    })


@portal_required(PORTAL)
@any_permission_required(C.PERM_OFFICER_SUSPEND, C.PERM_OFFICER_REACTIVATE)
@require_POST
def officer_lifecycle(request, pk):
    officer = get_object_or_404(officer_queryset(), pk=pk)
    form = LifecycleActionForm(request.POST)
    if not form.is_valid():
        for errs in form.errors.values():
            for e in errs:
                messages.error(request, e)
    else:
        _perform_lifecycle(request, officer, form.cleaned_data["action"], form.cleaned_data["reason"])
    return _redirect_next(request, "it_admin:officer_detail", pk=officer.pk)


# --------------------------------------------------------------------------- devices & sessions
@portal_required(PORTAL)
@any_permission_required(C.PERM_DEVICE_VIEW, C.PERM_SESSION_VIEW)
def device_session_overview(request):
    q = request.GET.get("q", "").strip()
    sessions = OfficerSession.objects.filter(ended_at__isnull=True).select_related("officer", "device")
    devices = RegisteredDevice.objects.filter(status=C.DEVICE_STATUS_ACTIVE).select_related("officer")
    if q:
        from django.db.models import Q

        flt = Q(officer__officer_id__icontains=q) | Q(officer__full_name__icontains=q)
        sessions, devices = sessions.filter(flt), devices.filter(flt)
    # Drop ghost sessions whose Django session already expired.
    for officer in Officer.objects.filter(pk__in=sessions.values_list("officer_id", flat=True).distinct()):
        device_session_service.reconcile(officer)
    sessions = sessions.filter(ended_at__isnull=True)
    return render(request, "it_admin/devices_sessions.html", {
        "q": q, "querystring": f"q={q}" if q else "",
        "sessions": Paginator(sessions, 25).get_page(request.GET.get("spage")),
        "devices": Paginator(devices, 25).get_page(request.GET.get("dpage")),
        "can_view_devices": actor_can(request, C.PERM_DEVICE_VIEW),
        "can_view_sessions": actor_can(request, C.PERM_SESSION_VIEW),
        "can_revoke": actor_can(request, C.PERM_DEVICE_REVOKE),
        "can_terminate": actor_can(request, C.PERM_SESSION_TERMINATE),
    })


@portal_required(PORTAL)
@any_permission_required(C.PERM_DEVICE_VIEW, C.PERM_SESSION_VIEW)
def officer_devices_sessions(request, pk):
    officer = get_object_or_404(officer_queryset(), pk=pk)
    device_session_service.reconcile(officer)
    return render(request, "it_admin/officer_devices_sessions.html", {
        "officer": officer,
        "devices": officer.devices.all() if actor_can(request, C.PERM_DEVICE_VIEW) else None,
        "sessions": officer.sessions.select_related("device")[:50] if actor_can(request, C.PERM_SESSION_VIEW) else None,
        "can_revoke": actor_can(request, C.PERM_DEVICE_REVOKE),
        "can_terminate": actor_can(request, C.PERM_SESSION_TERMINATE),
    })


@portal_required(PORTAL)
@permission_required(C.PERM_DEVICE_REVOKE)
@require_POST
def device_revoke(request, pk):
    device = get_object_or_404(RegisteredDevice.objects.select_related("officer"), pk=pk)
    form = ReasonForm(request.POST)
    if not form.is_valid():
        messages.error(request, "A reason is required to revoke a device.")
    else:
        ended = device_session_service.revoke_device(device, request.user, reason=form.cleaned_data["reason"], request=request)
        messages.success(request, f"Device revoked; {ended} session(s) terminated.")
    return _redirect_next(request, "it_admin:officer_devices_sessions", pk=device.officer_id)


@portal_required(PORTAL)
@permission_required(C.PERM_SESSION_TERMINATE)
@require_POST
def session_terminate(request, pk):
    row = get_object_or_404(OfficerSession.objects.select_related("officer"), pk=pk)
    form = OptionalReasonForm(request.POST)
    reason = form.cleaned_data["reason"] if form.is_valid() else ""
    if row.ended_at is not None:
        messages.info(request, "That session had already ended.")
    else:
        device_session_service.terminate_session(row, request.user, reason=reason, request=request)
        messages.success(request, "Session terminated.")
    return _redirect_next(request, "it_admin:officer_devices_sessions", pk=row.officer_id)


@portal_required(PORTAL)
@permission_required(C.PERM_SESSION_TERMINATE)
@require_POST
def session_terminate_all(request, pk):
    officer = get_object_or_404(Officer, pk=pk)
    form = ReasonForm(request.POST)
    if not form.is_valid():
        messages.error(request, "A reason is required to terminate all sessions.")
    else:
        removed = device_session_service.terminate_all(officer, request.user, reason=form.cleaned_data["reason"], request=request)
        messages.success(request, f"All sessions for {officer.officer_id} terminated ({removed} server session(s) removed).")
    return _redirect_next(request, "it_admin:officer_devices_sessions", pk=officer.pk)


# --------------------------------------------------------------------------- monitoring & audit
@portal_required(PORTAL)
@permission_required(C.PERM_SECURITY_VIEW_EVENTS)
def security_dashboard(request):
    qs = SecurityEvent.objects.select_related("officer").order_by("-occurred_at")
    severity = request.GET.get("severity", "")
    if severity in dict(C.SEVERITY_CHOICES):
        qs = qs.filter(severity=severity)
    page = Paginator(qs, 50).get_page(request.GET.get("page"))
    return render(request, "it_admin/security_dashboard.html", {
        "page": page, "events": page.object_list, "severity": severity, "severities": C.SEVERITY_CHOICES,
        "querystring": f"severity={severity}" if severity else "",
    })


@portal_required(PORTAL)
@permission_required(C.PERM_AUDIT_VIEW)
def audit_dashboard(request):
    qs = AuditEvent.objects.select_related("officer", "actor").order_by("-occurred_at")
    event_type = request.GET.get("type", "").strip()
    q = request.GET.get("q", "").strip()
    admin_only = request.GET.get("admin") == "1"
    if event_type:
        qs = qs.filter(event_type=event_type)
    if admin_only:
        qs = qs.filter(event_type__in=C.ADMIN_TIMELINE_EVENT_TYPES)
    if q:
        from django.db.models import Q

        qs = qs.filter(Q(officer_id_snapshot__icontains=q) | Q(actor__officer_id__icontains=q)
                       | Q(resource_id__icontains=q) | Q(reason__icontains=q))
    page = Paginator(qs, 50).get_page(request.GET.get("page"))
    types = AuditEvent.objects.order_by().values_list("event_type", flat=True).distinct()
    query = request.GET.copy(); query.pop("page", None)
    return render(request, "it_admin/audit_dashboard.html", {
        "page": page, "events": page.object_list, "q": q, "event_type": event_type, "admin_only": admin_only,
        "types": sorted(types), "querystring": query.urlencode(),
        "chain": request.session.pop("audit_chain_result", None),
    })


@portal_required(PORTAL)
@permission_required(C.PERM_AUDIT_VIEW)
@require_POST
def audit_verify(request):
    result = audit_service.verify_chain()
    audit_service.record_event(
        C.EVENT_AUDIT_CHAIN_VERIFIED, officer=request.user, actor=request.user, portal=PORTAL,
        result=C.RESULT_SUCCESS if result["ok"] else C.RESULT_FAILURE, context=result, request=request,
    )
    request.session["audit_chain_result"] = result
    if result["ok"]:
        messages.success(request, f"Audit chain intact — {result['checked']} event(s) verified.")
    else:
        messages.error(request, f"Audit chain BROKEN at sequence {result['first_break']}. Investigate immediately.")
    return redirect("it_admin:audit_dashboard")
