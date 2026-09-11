"""Officer directory, profile, provisioning wizard, edit, transfer, timeline."""
from __future__ import annotations

from django.contrib import messages
from django.core.paginator import Paginator
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods, require_POST

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.decorators import any_permission_required, permission_required, portal_required, reauth_required
from accounts.models import (
    ClearanceLevel,
    Department,
    Designation,
    Officer,
    OrganizationUnit,
    Portal,
    PortalAccess,
    PostingHistory,
    Role,
    TemporaryCapability,
)
from accounts.services import account_service, provisioning_service
from audit.models import AuditEvent

from ..exceptions import AdminActionError
from ..forms import (
    OfficerAuthorizationForm,
    OfficerFilterForm,
    OfficerIdentityForm,
    ProvisionAccountForm,
    ProvisionIdentityForm,
    ProvisionServiceForm,
    TransferForm,
)
from ..models import AccessReview, ApprovalRequest
from ..services import officer_admin_service, transfer_service
from ..timeline import build_timeline
from ._common import PORTAL, activation_link, actor_can, officer_queryset

__all__ = [
    "officer_list", "officer_detail", "officer_create", "officer_edit", "officer_authorization",
    "officer_transfer", "officer_timeline", "officer_reset_password", "officer_reset_code",
    "officer_status", "officer_lock", "officer_unlock", "posting_list",
]


# --------------------------------------------------------------------------- directory
@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_VIEW)
def officer_list(request):
    form = OfficerFilterForm(request.GET or None)
    qs = form.apply(officer_queryset().order_by("officer_id"))
    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))
    query = request.GET.copy()
    query.pop("page", None)
    return render(request, "it_admin/officer_list.html", {
        "page": page,
        "form": form,
        "q": request.GET.get("q", ""),
        "querystring": query.urlencode(),
        "filtered": any(v for k, v in request.GET.items() if k != "page"),
        "total": paginator.count,
    })


# --------------------------------------------------------------------------- profile
@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_VIEW)
def officer_detail(request, pk):
    officer = get_object_or_404(officer_queryset(), pk=pk)
    perms = authorization_service.get_user_permissions(request.user)
    portals = PortalAccess.objects.filter(officer=officer).select_related("portal")
    devices = officer.devices.all()[:10] if C.PERM_DEVICE_VIEW in perms else None
    sessions = None
    if C.PERM_SESSION_VIEW in perms:
        from accounts.devices import device_session_service

        device_session_service.reconcile(officer)
        sessions = officer.sessions.select_related("device")[:10]
    security_events = officer.security_events.all()[:10] if C.PERM_SECURITY_VIEW_EVENTS in perms else None
    recent_changes = (
        AuditEvent.objects.filter(officer=officer, event_type__in=C.ADMIN_TIMELINE_EVENT_TYPES)
        .select_related("actor").order_by("-occurred_at")[:8]
    )
    return render(request, "it_admin/officer_detail.html", {
        "officer": officer,
        "portals": portals,
        "devices": devices,
        "sessions": sessions,
        "security_events": security_events,
        "recent_changes": recent_changes,
        "postings": officer.posting_history.select_related(
            "from_department", "to_department", "from_unit", "to_unit", "from_designation", "to_designation")[:6],
        "temporary_grants": TemporaryCapability.objects.filter(officer=officer).select_related("permission")[:6],
        "pending_review": AccessReview.objects.filter(officer=officer, status=AccessReview.STATUS_PENDING).first(),
        "pending_approvals": ApprovalRequest.objects.filter(
            target_type="officer", target_id=officer.officer_id, status=ApprovalRequest.STATUS_PENDING),
        "activation_link": activation_link(request, officer) if officer.account_status in (
            C.ACCOUNT_STATUS_INVITED, C.ACCOUNT_STATUS_PENDING) and C.PERM_OFFICER_CREATE in perms else None,
        "explanations": authorization_service.explain_all(officer),
        "transitions": {a: account_service.can_transition(officer, a) for a in ("suspend", "reactivate", "deactivate")},
        "suspend_hidden": {"action": "suspend"},
        "reactivate_hidden": {"action": "reactivate"},
        "deactivate_hidden": {"action": "deactivate"},
        "is_self": officer.pk == request.user.pk,
    })


# --------------------------------------------------------------------------- provisioning wizard
WIZARD_KEY = "provision_wizard"
WIZARD_STEPS = ("identity", "service", "account", "review")


def _wizard_data(request) -> dict:
    return request.session.get(WIZARD_KEY, {})


def _wizard_store(request, data: dict):
    request.session[WIZARD_KEY] = data
    request.session.modified = True


def _wizard_clear(request):
    request.session.pop(WIZARD_KEY, None)
    request.session.modified = True


def _serialise(cleaned: dict) -> dict:
    out = {}
    for k, v in cleaned.items():
        if hasattr(v, "pk"):
            out[k] = v.pk
        elif hasattr(v, "__iter__") and not isinstance(v, str):
            out[k] = [x.pk if hasattr(x, "pk") else x for x in v]
        elif hasattr(v, "isoformat"):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


def _review_context(data: dict) -> dict:
    """Resolve stored PKs back into objects for the review step / creation."""
    ident = data.get("identity", {})
    svc = data.get("service", {})
    acct = data.get("account", {})

    def get(model, pk):
        return model.objects.filter(pk=pk).first() if pk else None

    return {
        "identity": ident,
        "service": {
            "designation": get(Designation, svc.get("designation")),
            "department": get(Department, svc.get("department")),
            "unit": get(OrganizationUnit, svc.get("unit")),
            "supervisor": get(Officer, svc.get("supervisor")),
            "joining_date": svc.get("joining_date"),
        },
        "account": {
            "role": get(Role, acct.get("role")),
            "clearance": get(ClearanceLevel, acct.get("clearance")),
            "portals": list(Portal.objects.filter(pk__in=acct.get("portals", []))),
            "reason": acct.get("reason", ""),
            "has_secret_code": bool(acct.get("initial_secret_code")),
        },
    }


@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_CREATE)
@reauth_required
@require_http_methods(["GET", "POST"])
def officer_create(request):
    """Five-step provisioning: identity → service → account → review → create.

    Step state lives in the server session; nothing is written to the
    officer table until the final confirmation. Every step re-validates
    against the database (duplicate IDs, inactive registries…).
    """
    if request.GET.get("reset") == "1":
        _wizard_clear(request)
        return redirect("it_admin:officer_create")
    if request.method == "POST" and "step" not in request.POST:
        # Backwards-compatible single-request provisioning (API clients and
        # the pre-wizard test-suite). Same validation and audit path.
        return _officer_create_single(request)

    data = _wizard_data(request)
    step = request.POST.get("step") or request.GET.get("step") or "identity"
    if step not in WIZARD_STEPS:
        step = "identity"
    # Don't allow skipping ahead past unfinished steps.
    for idx, name in enumerate(WIZARD_STEPS):
        if name == step:
            break
        if name not in data:
            step = name
            break

    may_authorize = actor_can(request, C.PERM_OFFICER_AUTHORIZATION)
    ctx = {"step": step, "steps": WIZARD_STEPS, "may_authorize": may_authorize, "data": data}

    if step == "identity":
        form = ProvisionIdentityForm(request.POST or None, initial=data.get("identity"))
        if request.method == "POST" and form.is_valid():
            data["identity"] = _serialise(form.cleaned_data)
            _wizard_store(request, data)
            return redirect(f"{request.path}?step=service")
        ctx["form"] = form

    elif step == "service":
        form = ProvisionServiceForm(request.POST or None, initial=data.get("service"))
        if request.method == "POST" and form.is_valid():
            data["service"] = _serialise(form.cleaned_data)
            _wizard_store(request, data)
            return redirect(f"{request.path}?step=account")
        ctx["form"] = form

    elif step == "account":
        initial = {k: v for k, v in data.get("account", {}).items() if k not in ("initial_password", "initial_secret_code")}
        form = ProvisionAccountForm(request.POST or None, initial=initial, may_authorize=may_authorize)
        if request.method == "POST" and form.is_valid():
            cleaned = dict(form.cleaned_data)
            if not may_authorize:
                # Server-side guarantee: no authorization attributes can be
                # smuggled in by an administrator who lacks the capability.
                cleaned.pop("role", None); cleaned.pop("clearance", None); cleaned.pop("portals", None)
            data["account"] = _serialise(cleaned)
            _wizard_store(request, data)
            return redirect(f"{request.path}?step=review")
        ctx["form"] = form

    elif step == "review":
        review = _review_context(data)
        ctx["review"] = review
        if request.method == "POST" and request.POST.get("confirm") == "1":
            # Re-run identity validation right before creation: the database
            # may have changed while the wizard was open.
            ident_form = ProvisionIdentityForm(data.get("identity"))
            if not ident_form.is_valid():
                for field, errs in ident_form.errors.items():
                    for e in errs:
                        messages.error(request, f"{field}: {e}")
                return redirect(f"{request.path}?step=identity")
            ident = ident_form.cleaned_data
            acct = data.get("account", {})
            try:
                with transaction.atomic():
                    officer = provisioning_service.provision_officer(
                        actor=request.user,
                        officer_id=ident["officer_id"] or provisioning_service.generate_officer_id(),
                        email=ident["email"],
                        full_name=ident["full_name"],
                        initial_password=acct["initial_password"],
                        role=review["account"]["role"] if may_authorize else None,
                        clearance=review["account"]["clearance"] if may_authorize else None,
                        unit=review["service"]["unit"],
                        department=review["service"]["department"],
                        designation=review["service"]["designation"],
                        employee_id=ident.get("employee_id", ""),
                        supervisor=review["service"]["supervisor"],
                        joining_date=review["service"]["joining_date"] or None,
                        phone=ident.get("phone", ""),
                        portals=review["account"]["portals"] if may_authorize else (),
                        initial_secret_code=acct.get("initial_secret_code", ""),
                        reason=acct.get("reason", ""),
                        request=request,
                    )
            except Exception:  # pragma: no cover — defensive; details go to logs, not the user
                messages.error(request, "Officer could not be created. No changes were saved.")
                return redirect(f"{request.path}?step=review")
            _wizard_clear(request)
            messages.success(request, "Officer identity created successfully. Operational authorization is managed separately.")
            return render(request, "it_admin/officer_created.html", {
                "officer": officer,
                "activation_link": activation_link(request, officer),
                "initial_password": acct["initial_password"],
                "initial_secret_code": acct.get("initial_secret_code", ""),
            })

    return render(request, "it_admin/officer_form.html", ctx)


def _officer_create_single(request):
    from accounts.forms import OfficerCreateForm

    may_authorize = actor_can(request, C.PERM_OFFICER_AUTHORIZATION)
    form = OfficerCreateForm(request.POST)
    if not form.is_valid():
        return render(request, "it_admin/officer_form.html", {
            "step": "identity", "steps": WIZARD_STEPS, "may_authorize": may_authorize, "data": {},
            "form": ProvisionIdentityForm(initial={k: request.POST.get(k, "") for k in ("full_name", "officer_id", "employee_id", "email", "phone")}),
            "legacy_errors": form.errors,
        }, status=200)
    data = form.cleaned_data
    officer = provisioning_service.provision_officer(
        actor=request.user,
        officer_id=data["officer_id"] or provisioning_service.generate_officer_id(),
        email=data["email"],
        full_name=data["full_name"],
        initial_password=data["initial_password"],
        role=data["role"] if may_authorize else None,
        clearance=data["clearance"] if may_authorize else None,
        unit=data["unit"],
        rank=data.get("rank", ""),
        department=data.get("department"),
        designation=data.get("designation"),
        employee_id=data.get("employee_id", ""),
        phone=data["phone"],
        portals=data["portals"] if may_authorize else (),
        initial_secret_code=data["initial_secret_code"],
        reason=data["reason"],
        request=request,
    )
    messages.success(request, "Officer identity created successfully. Operational authorization is managed separately.")
    return render(request, "it_admin/officer_created.html", {
        "officer": officer,
        "activation_link": activation_link(request, officer),
        "initial_password": data["initial_password"],
        "initial_secret_code": data["initial_secret_code"],
    })


# --------------------------------------------------------------------------- edit identity / service
@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_UPDATE)
@reauth_required
@require_http_methods(["GET", "POST"])
def officer_edit(request, pk):
    officer = get_object_or_404(officer_queryset(), pk=pk)
    form = OfficerIdentityForm(request.POST or None, instance=officer)
    if request.method == "POST" and form.is_valid():
        reason = form.cleaned_data.get("reason", "")
        # The ModelForm has already mutated ``officer`` in memory; the service
        # needs the persisted state to compute an honest before/after delta.
        persisted = officer_queryset().get(pk=officer.pk)
        try:
            with transaction.atomic():
                changed = officer_admin_service.update_identity(
                    persisted, form.cleaned_data, request.user, reason=reason, request=request)
                if officer_admin_service.change_designation(
                        persisted, form.cleaned_data.get("designation"), request.user, reason=reason, request=request):
                    changed.append("designation")
        except AdminActionError as exc:
            messages.error(request, str(exc))
        else:
            if changed:
                messages.success(request, f"Officer updated ({', '.join(changed)}).")
            else:
                messages.info(request, "No changes detected.")
            return redirect("it_admin:officer_detail", pk=officer.pk)
    return render(request, "it_admin/officer_edit.html", {"form": form, "officer": officer})


# --------------------------------------------------------------------------- authorization attributes
@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_AUTHORIZATION)
@reauth_required
@require_http_methods(["GET", "POST"])
def officer_authorization(request, pk):
    """Role / clearance / portal grants. Changing an *administrative* role
    requires four-eyes approval; everything else applies immediately."""
    officer = get_object_or_404(officer_queryset(), pk=pk)
    form = OfficerAuthorizationForm(request.POST or None, officer=officer)
    if request.method == "POST" and form.is_valid():
        reason = form.cleaned_data["reason"]
        role = form.cleaned_data["role"]
        notes = []
        with transaction.atomic():
            role_is_admin = lambda r: r is not None and any(  # noqa: E731
                C.is_admin_capability(c) for c in r.permissions.values_list("codename", flat=True))
            if (role.pk if role else None) != officer.role_id:
                if role_is_admin(role) or role_is_admin(officer.role):
                    from ..services import approval_service

                    try:
                        approval_service.request(
                            action=ApprovalRequest.ACTION_ADMIN_ROLE_CHANGE,
                            target_type="officer", target_id=officer.officer_id, target_label=str(officer),
                            payload={"officer_pk": officer.pk, "role_pk": role.pk if role else None},
                            summary=f"Role {officer.role.name if officer.role else '—'} → {role.name if role else '—'}",
                            reason=reason, requested_by=request.user, request=request,
                        )
                        notes.append("Administrative role change submitted for second-administrator approval.")
                    except AdminActionError as exc:
                        messages.error(request, str(exc))
                else:
                    account_service.assign_role(officer, role, request.user, reason=reason, request=request)
                    notes.append("role updated")
            if (form.cleaned_data["clearance"].pk if form.cleaned_data["clearance"] else None) != officer.clearance_id:
                account_service.assign_clearance(officer, form.cleaned_data["clearance"], request.user, reason=reason, request=request)
                notes.append("clearance updated")

            wanted = {p.pk for p in form.cleaned_data["portals"]}
            current = set(officer.portal_accesses.filter(revoked_at__isnull=True).values_list("portal_id", flat=True))
            for portal in form.cleaned_data["portals"]:
                if portal.pk not in current:
                    provisioning_service.grant_portal(officer, portal, request.user, reason)
                    notes.append(f"{portal.key} granted")
            for portal_id in current - wanted:
                provisioning_service.revoke_portal(officer, Portal.objects.get(pk=portal_id), request.user, reason)
                notes.append(f"{Portal.objects.get(pk=portal_id).key} revoked")
        if notes:
            messages.success(request, "; ".join(notes) + ".")
        else:
            messages.info(request, "No changes detected.")
        return redirect("it_admin:officer_detail", pk=officer.pk)
    return render(request, "it_admin/officer_authorization.html", {"form": form, "officer": officer})


# --------------------------------------------------------------------------- transfer
@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_TRANSFER)
@reauth_required
@require_http_methods(["GET", "POST"])
def officer_transfer(request, pk):
    officer = get_object_or_404(officer_queryset(), pk=pk)
    form = TransferForm(request.POST or None, officer=officer)
    plan = None
    if request.method == "POST" and form.is_valid():
        plan = transfer_service.plan(
            officer,
            to_department=form.cleaned_data["to_department"],
            to_unit=form.cleaned_data["to_unit"],
            to_designation=form.cleaned_data["to_designation"],
            effective_date=form.cleaned_data["effective_date"],
            reason=form.cleaned_data["reason"],
        )
        try:
            transfer_service.validate(plan)
        except AdminActionError as exc:
            form.add_error(None, str(exc))
            plan = None
        else:
            if request.POST.get("confirm") == "1":
                try:
                    transfer_service.apply(plan, request.user, request=request)
                except AdminActionError as exc:
                    form.add_error(None, str(exc))
                else:
                    msg = "Transfer recorded and posting history updated."
                    if plan.authorization_review_required:
                        msg += " Organizational scope changed — an access review has been raised; operational authorization is managed separately."
                    messages.success(request, msg)
                    return redirect("it_admin:officer_detail", pk=officer.pk)
    return render(request, "it_admin/officer_transfer.html", {"form": form, "officer": officer, "plan": plan})


@portal_required(PORTAL)
@any_permission_required(C.PERM_OFFICER_VIEW, C.PERM_OFFICER_TRANSFER)
def posting_list(request):
    qs = PostingHistory.objects.select_related(
        "officer", "from_department", "to_department", "from_unit", "to_unit",
        "from_designation", "to_designation", "recorded_by").order_by("-recorded_at")
    q = request.GET.get("q", "").strip()
    if q:
        from django.db.models import Q

        qs = qs.filter(Q(officer__officer_id__icontains=q) | Q(officer__full_name__icontains=q))
    page = Paginator(qs, 25).get_page(request.GET.get("page"))
    return render(request, "it_admin/posting_list.html", {"page": page, "q": q, "querystring": f"q={q}" if q else ""})


# --------------------------------------------------------------------------- timeline
@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_VIEW)
def officer_timeline(request, pk):
    officer = get_object_or_404(officer_queryset(), pk=pk)
    events = build_timeline(officer)
    return render(request, "it_admin/officer_timeline.html", {"officer": officer, "events": events})


# --------------------------------------------------------------------------- credentials (existing behaviour)
@portal_required(PORTAL)
@permission_required(C.PERM_ACCOUNT_MANAGE_SECURITY)
@reauth_required
@require_http_methods(["GET", "POST"])
def officer_reset_password(request, pk):
    officer = get_object_or_404(Officer, pk=pk)
    if request.method == "POST":
        new_password = request.POST.get("new_password", "")
        if len(new_password) >= 8:
            provisioning_service.reset_password(officer, request.user, new_password)
            messages.success(request, "Password reset. Officer must activate the new credential.")
            return redirect("it_admin:officer_detail", pk=officer.pk)
        messages.error(request, "Password must be at least 8 characters.")
    return render(request, "it_admin/officer_reset.html", {"officer": officer, "mode": "password"})


@portal_required(PORTAL)
@permission_required(C.PERM_ACCOUNT_MANAGE_SECURITY)
@reauth_required
@require_http_methods(["GET", "POST"])
def officer_reset_code(request, pk):
    officer = get_object_or_404(Officer, pk=pk)
    if request.method == "POST":
        new_code = request.POST.get("new_code", "")
        if 6 <= len(new_code) <= 32:
            provisioning_service.reset_secret_code(officer, request.user, new_code)
            messages.success(request, "Security code reset.")
            return redirect("it_admin:officer_detail", pk=officer.pk)
        messages.error(request, "Security code must be 6–32 characters.")
    return render(request, "it_admin/officer_reset.html", {"officer": officer, "mode": "code"})


# --------------------------------------------------------------------------- legacy status endpoints
# Kept so existing links keep working; they delegate to the lifecycle view
# with the same reason/confirmation rules.
@portal_required(PORTAL)
@any_permission_required(C.PERM_OFFICER_SUSPEND, C.PERM_OFFICER_REACTIVATE)
@require_POST
def officer_status(request, pk):
    from .security import _perform_lifecycle

    officer = get_object_or_404(Officer, pk=pk)
    mapping = {
        C.ACCOUNT_STATUS_ACTIVE: "reactivate",
        C.ACCOUNT_STATUS_SUSPENDED: "suspend",
        C.ACCOUNT_STATUS_DEACTIVATED: "deactivate",
        C.ACCOUNT_STATUS_DISABLED: "deactivate",
    }
    action = mapping.get(request.POST.get("status", ""))
    if action is None:
        messages.error(request, "Unknown account transition.")
        return redirect("it_admin:officer_detail", pk=officer.pk)
    _perform_lifecycle(request, officer, action, request.POST.get("reason", ""))
    return redirect("it_admin:officer_detail", pk=officer.pk)


@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_SUSPEND)
@require_POST
def officer_lock(request, pk):
    from .security import _perform_lifecycle

    officer = get_object_or_404(Officer, pk=pk)
    _perform_lifecycle(request, officer, "emergency_lock", request.POST.get("reason", ""))
    return redirect("it_admin:officer_detail", pk=officer.pk)


@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_REACTIVATE)
@require_POST
def officer_unlock(request, pk):
    from .security import _perform_lifecycle

    officer = get_object_or_404(Officer, pk=pk)
    _perform_lifecycle(request, officer, "unlock", request.POST.get("reason", ""))
    return redirect("it_admin:officer_detail", pk=officer.pk)
