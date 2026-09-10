"""IT / Admin portal — Central IT is the root identity authority.

Provisioning, account state management, credential resets, portal grants and
security/audit monitoring. Accessing accounts is completely separate from
accessing investigation data: these views only touch identity/security data.
"""
from __future__ import annotations

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.decorators.http import require_http_methods, require_POST

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.decorators import permission_required, portal_required, reauth_required
from accounts.forms import OfficerCreateForm, OfficerEditForm, OfficerStatusForm
from accounts.models import Officer, PortalAccess
from accounts.services import (
    account_service,
    provisioning_service,
)
from audit.models import AuditEvent, SecurityEvent

Officer = get_user_model()


def _activation_link(request, officer: Officer) -> str:
    uidb64 = urlsafe_base64_encode(force_bytes(officer.pk))
    token = default_token_generator.make_token(officer)
    return request.build_absolute_uri(
        reverse("accounts:activate", kwargs={"uidb64": uidb64, "token": token})
    )


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@portal_required(C.PORTAL_IT_ADMIN)
def dashboard(request):
    user = request.user
    caps = authorization_service.portal_capabilities(user, C.PORTAL_IT_ADMIN)
    context = {"caps": caps}
    if "officer.view" in caps["permissions"]:
        context["officer_count"] = Officer.objects.count()
        context["active_count"] = Officer.objects.filter(
            account_status=C.ACCOUNT_STATUS_ACTIVE
        ).count()
    if "security.view_events" in caps["permissions"]:
        context["open_alerts"] = SecurityEvent.objects.filter(
            severity__in=[C.SEVERITY_ALERT, C.SEVERITY_CRITICAL]
        ).count()
    return render(request, "it_admin/dashboard.html", context)


# ---------------------------------------------------------------------------
# Officer account management
# ---------------------------------------------------------------------------
@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_OFFICER_VIEW)
def officer_list(request):
    qs = Officer.objects.select_related("role", "clearance", "unit").order_by("officer_id")
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(officer_id__icontains=q) | qs.filter(full_name__icontains=q)
    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "it_admin/officer_list.html", {"page": page, "q": q})


@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_OFFICER_MANAGE)
@reauth_required
@require_http_methods(["GET", "POST"])
def officer_create(request):
    form = OfficerCreateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        officer_id = data["officer_id"] or provisioning_service.generate_officer_id()
        officer = provisioning_service.provision_officer(
            actor=request.user,
            officer_id=officer_id,
            email=data["email"],
            full_name=data["full_name"],
            initial_password=data["initial_password"],
            role=data["role"],
            clearance=data["clearance"],
            unit=data["unit"],
            rank=data["rank"],
            department=data["department"],
            phone=data["phone"],
            portals=data["portals"],
            initial_secret_code=data["initial_secret_code"],
            reason=data["reason"],
        )
        messages.success(request, f"Officer {officer.officer_id} provisioned (status INVITED).")
        return render(
            request,
            "it_admin/officer_created.html",
            {
                "officer": officer,
                "activation_link": _activation_link(request, officer),
                "initial_password": data["initial_password"],
                "initial_secret_code": data["initial_secret_code"],
            },
        )
    return render(request, "it_admin/officer_form.html", {"form": form, "creating": True})


@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_OFFICER_VIEW)
def officer_detail(request, pk):
    officer = get_object_or_404(Officer.objects.select_related("role", "clearance", "unit"), pk=pk)
    portals = PortalAccess.objects.filter(officer=officer).select_related("portal")
    return render(
        request,
        "it_admin/officer_detail.html",
        {
            "officer": officer,
            "portals": portals,
            "activation_link": _activation_link(request, officer),
        },
    )


@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_OFFICER_MANAGE)
@reauth_required
@require_http_methods(["GET", "POST"])
def officer_edit(request, pk):
    officer = get_object_or_404(Officer, pk=pk)
    if request.method == "POST":
        form = OfficerEditForm(request.POST, instance=officer)
        if form.is_valid():
            form.save()
            account_service.assign_role(officer, form.cleaned_data["role"], request.user)
            account_service.assign_clearance(officer, form.cleaned_data["clearance"], request.user)
            account_service.assign_unit(officer, form.cleaned_data["unit"], request.user)

            # Reconcile portal grants (explicit — default deny).
            wanted = set(p.pk for p in form.cleaned_data["portals"])
            current = set(
                officer.portal_accesses.filter(revoked_at__isnull=True).values_list(
                    "portal_id", flat=True
                )
            )
            for portal in form.cleaned_data["portals"]:
                if portal.pk not in current:
                    provisioning_service.grant_portal(officer, portal, request.user, "assigned by IT")
            for portal_id in current - wanted:
                from accounts.models import Portal

                provisioning_service.revoke_portal(
                    officer, Portal.objects.get(pk=portal_id), request.user, "revoked by IT"
                )

            messages.success(request, "Officer updated.")
            return redirect("it_admin:officer_detail", pk=officer.pk)
    else:
        form = OfficerEditForm(instance=officer)
    return render(request, "it_admin/officer_form.html", {"form": form, "creating": False, "officer": officer})


@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_OFFICER_MANAGE)
@require_POST
def officer_status(request, pk):
    officer = get_object_or_404(Officer, pk=pk)
    form = OfficerStatusForm(request.POST)
    if form.is_valid():
        account_service.set_status(
            officer, form.cleaned_data["status"], request.user, form.cleaned_data["reason"]
        )
        messages.success(request, f"Account status set to {officer.account_status}.")
    return redirect("it_admin:officer_detail", pk=officer.pk)


@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_OFFICER_MANAGE)
@require_POST
def officer_lock(request, pk):
    officer = get_object_or_404(Officer, pk=pk)
    account_service.lock(officer, request.user, reason=request.POST.get("reason", ""))
    messages.success(request, "Account locked.")
    return redirect("it_admin:officer_detail", pk=officer.pk)


@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_OFFICER_MANAGE)
@require_POST
def officer_unlock(request, pk):
    officer = get_object_or_404(Officer, pk=pk)
    account_service.unlock(officer, request.user)
    messages.success(request, "Account unlocked.")
    return redirect("it_admin:officer_detail", pk=officer.pk)


@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_OFFICER_MANAGE)
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


@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_OFFICER_MANAGE)
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


# ---------------------------------------------------------------------------
# Security & audit monitoring
# ---------------------------------------------------------------------------
@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_SECURITY_VIEW_EVENTS)
def security_dashboard(request):
    events = SecurityEvent.objects.select_related("officer").order_by("-occurred_at")[:200]
    return render(request, "it_admin/security_dashboard.html", {"events": events})


@portal_required(C.PORTAL_IT_ADMIN)
@permission_required(C.PERM_AUDIT_VIEW)
def audit_dashboard(request):
    events = AuditEvent.objects.select_related("officer").order_by("-occurred_at")[:200]
    return render(request, "it_admin/audit_dashboard.html", {"events": events})
