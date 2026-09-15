"""General Officer portal — operational case workflow.

Every view here follows the same shape:

    portal access → object authorization → action authorization → audit

Nothing trusts the URL, and nothing trusts the template. A media URL is never
a capability: files are streamed only after the engine authorizes them.

Logic lives in ``general.services``; this module only orchestrates.
"""
from __future__ import annotations

from django.contrib import messages
from django.http import FileResponse, Http404, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.decorators import permission_required, portal_required, reauth_required
from audit.services import audit_service
from general.forms import (
    AccessGrantForm,
    AccessRequestForm,
    CaseRegistrationForm,
    CaseTransferForm,
)
from general.models import (
    AccessGrant,
    AccessRequest,
    CaseDocument,
    CaseEvidenceFile,
    CaseRecord,
)
from general.services import (
    access_grant_service,
    access_request_service,
    case_access_service,
    case_transfer_service,
)

PORTAL = C.PORTAL_GENERAL


# ---------------------------------------------------------------------------
# Authorization helpers — object level, audited denials (§30)
# ---------------------------------------------------------------------------
def _authorize(request, resource, action: str):
    """Return ``(decision, error_response)``; exactly one is meaningful."""
    decision = authorization_service.authorize_resource(
        request.user, resource, action, portal=PORTAL
    )
    if decision:
        return decision, None

    case_id = getattr(resource, "case_id", None) or getattr(
        getattr(resource, "case", None), "case_id", ""
    )
    audit_service.record_denied(
        officer=request.user,
        action=action,
        resource_type=decision.resource_type or "case",
        resource_id=decision.resource_id or str(case_id or ""),
        portal=PORTAL,
        reason=decision.reason,
        request=request,
    )
    audit_service.record_security_event(
        C.EVENT_CASE_ACCESS_DENIED,
        severity=C.SEVERITY_WARNING,
        officer=request.user,
        details={
            "resource_type": decision.resource_type,
            "resource_id": decision.resource_id,
            "action": action,
            "stage": decision.stage,
        },
        request=request,
    )
    return decision, HttpResponseForbidden("You are not authorized to access this resource.")


def _case_or_403(request, case_id: str, action: str = C.ACTION_VIEW):
    case = get_object_or_404(CaseRecord, case_id=case_id)
    decision, error = _authorize(request, case, action)
    return (None, error) if error else (case, None)


def _grantable_actions(user, resource) -> list:
    """Actions ``user`` is allowed to delegate on ``resource``."""
    ceiling = getattr(getattr(resource, "security_requirement", None), "allowed_actions", None)
    return [
        action
        for action, required in C.CASE_ACTION_PERMISSIONS.items()
        if (ceiling is None or action in ceiling)
        and authorization_service.has_permission(user, required)
    ]


# ---------------------------------------------------------------------------
# Dashboard & listing (§27 / §28)
# ---------------------------------------------------------------------------
@portal_required(PORTAL)
def dashboard(request):
    caps = authorization_service.portal_capabilities(request.user, PORTAL)
    page = case_access_service.authorized_page(
        request.user, C.ACTION_VIEW, page_number=1, per_page=5
    )
    pending = AccessRequest.objects.filter(status=C.REQUEST_PENDING)
    return render(request, "general/dashboard.html", {
        "caps": caps,
        "nav": build_nav(caps),
        "recent_cases": getattr(page, "authorized", []),
        "pending_requests": sum(
            1 for r in pending if access_request_service.can_decide(request.user, r)
        ),
    })


@portal_required(PORTAL)
def view_cases(request):
    search = request.GET.get("q", "").strip()
    page = case_access_service.authorized_page(
        request.user, C.ACTION_VIEW, search=search,
        page_number=request.GET.get("page"), per_page=20,
    )
    return render(request, "general/case_list.html", {
        "page": page,
        "cases": getattr(page, "authorized", []),
        "query": search,
        "querystring": f"q={search}" if search else "",
    })


@portal_required(PORTAL)
@permission_required(C.PERM_CASE_CREATE)
def register_case(request):
    form = CaseRegistrationForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        case = form.save(commit=False)
        case.created_by = request.user
        # Jurisdiction and station come from the officer's own posting — never
        # from the client (§8 / §30).
        case.organization = request.user.jurisdiction
        case.unit = request.user.unit if request.user.unit_id else None
        case.save()

        for evidence in request.FILES.getlist("evidence_files"):
            CaseEvidenceFile.objects.create(
                case=case, file=evidence, uploaded_by=request.user
            )
        for document in request.FILES.getlist("document_files"):
            CaseDocument.objects.create(
                case=case, file=document, title=document.name, uploaded_by=request.user
            )

        from general.models import CaseAssignment

        CaseAssignment.objects.create(
            case=case, officer=request.user, role=C.ASSIGNMENT_OWNER,
            granted_by=request.user, reason="Case registration",
        )

        audit_service.record_event(
            C.EVENT_CASE_REGISTERED,
            officer=request.user, actor=request.user, portal=PORTAL,
            resource_type="case", resource_id=case.case_id, action="register_case",
            result=C.RESULT_SUCCESS,
            new_state={
                "case_id": case.case_id,
                "classification": case.classification.code if case.classification_id else None,
                "organization": case.organization.name if case.organization_id else None,
                "unit": case.unit.name if case.unit_id else None,
            },
            request=request,
        )

        messages.success(
            request,
            f"Case {case.case_id} registered successfully."
            if case.fir_document else
            f"Case {case.case_id} registered successfully without FIR upload.",
        )
        return redirect("general:view_cases")

    return render(request, "general/case_form.html", {"form": form, "title": "Register Case"})


@portal_required(PORTAL)
def case_detail(request, case_id: str):
    case, error = _case_or_403(request, case_id, C.ACTION_VIEW)
    if error:
        return error

    audit_service.record_event(
        C.EVENT_CASE_VIEWED, officer=request.user, actor=request.user, portal=PORTAL,
        resource_type="case", resource_id=case.case_id, action=C.ACTION_VIEW,
        result=C.RESULT_ALLOW, request=request,
    )

    can_manage = authorization_service.can_access_resource(
        request.user, case, C.ACTION_MANAGE_ACCESS, portal=PORTAL
    )
    return render(request, "general/case_detail.html", {
        "case": case,
        "can_download": authorization_service.can_access_resource(
            request.user, case, C.ACTION_DOWNLOAD, portal=PORTAL),
        "can_upload": authorization_service.can_access_resource(
            request.user, case, C.ACTION_UPLOAD, portal=PORTAL),
        "can_edit": authorization_service.can_access_resource(
            request.user, case, C.ACTION_EDIT, portal=PORTAL),
        "can_manage_access": can_manage,
        "can_transfer": case_transfer_service.can_transfer(request.user, case),
        "actions": sorted(authorization_service.case_actions(request.user, case)),
        "caps": authorization_service.portal_capabilities(request.user, PORTAL),
    })


# ---------------------------------------------------------------------------
# Protected file delivery (§19 / §20)
# ---------------------------------------------------------------------------
@portal_required(PORTAL)
def download_fir(request, case_id: str):
    case, error = _case_or_403(request, case_id, C.ACTION_VIEW)
    if error:
        return error
    return _serve(request, case, case.fir_resource, case.fir_document,
                  filename=f"{case.case_id}-FIR", label="fir")


@portal_required(PORTAL)
def download_evidence(request, case_id: str, pk: int):
    case, error = _case_or_403(request, case_id, C.ACTION_VIEW)
    if error:
        return error
    evidence = get_object_or_404(CaseEvidenceFile, pk=pk, case=case)
    return _serve(request, case, evidence, evidence.file,
                  filename=_basename(evidence.file.name), label="evidence")


@portal_required(PORTAL)
def download_document(request, case_id: str, pk: int):
    case, error = _case_or_403(request, case_id, C.ACTION_VIEW)
    if error:
        return error
    document = get_object_or_404(CaseDocument, pk=pk, case=case)
    return _serve(request, case, document, document.file,
                  filename=_basename(document.file.name), label="document")


def _basename(name: str) -> str:
    return (name or "file").rsplit("/", 1)[-1]


def _serve(request, case, resource, field, filename: str, label: str):
    """Authorize the *file* independently, then stream it."""
    if not field:
        raise Http404("No such file.")
    decision, error = _authorize(request, resource, C.ACTION_DOWNLOAD)
    if error:
        return error

    audit_service.record_event(
        C.EVENT_FILE_DOWNLOAD, officer=request.user, actor=request.user, portal=PORTAL,
        resource_type=decision.resource_type or label,
        resource_id=decision.resource_id or filename,
        action=C.ACTION_DOWNLOAD, result=C.RESULT_ALLOW,
        context={"case_id": case.case_id, "file": filename},
        request=request,
    )
    return FileResponse(field.open("rb"), as_attachment=True, filename=filename)


# ---------------------------------------------------------------------------
# Access management (§15)
# ---------------------------------------------------------------------------
@portal_required(PORTAL)
def case_access(request, case_id: str):
    case, error = _case_or_403(request, case_id, C.ACTION_VIEW)
    if error:
        return error

    can_manage = authorization_service.can_access_resource(
        request.user, case, C.ACTION_MANAGE_ACCESS, portal=PORTAL
    )
    grants = AccessGrant.objects.filter(
        resource_type=C.RESOURCE_CASE, resource_id=case.case_id
    ).select_related("recipient_officer", "recipient_department", "grantor").order_by("-created_at")

    requests_qs = (
        AccessRequest.objects.filter(resource_type=C.RESOURCE_CASE, resource_id=case.case_id)
        .select_related("requester", "decided_by")
        .order_by("-created_at")
        if can_manage else AccessRequest.objects.none()
    )

    return render(request, "general/case_access.html", {
        "case": case,
        "assignments": case.officers_with_access(),
        "grants": grants,
        "requests": requests_qs,
        "can_manage_access": can_manage,
        "actions": sorted(authorization_service.case_actions(request.user, case)),
        "my_request": AccessRequest.objects.filter(
            resource_type=C.RESOURCE_CASE, resource_id=case.case_id,
            requester=request.user, status=C.REQUEST_PENDING,
        ).first(),
    })


@portal_required(PORTAL)
@reauth_required
def grant_access(request, case_id: str):
    case, error = _case_or_403(request, case_id, C.ACTION_MANAGE_ACCESS)
    if error:
        return error

    resource_ids = request.GET.getlist("ids") or [case.case_id]
    scope = request.POST.get("scope") or (
        C.GRANT_SCOPE_SELECTED if len(resource_ids) > 1 else C.GRANT_SCOPE_CASE
    )

    grantable = _grantable_actions(request.user, case)
    form = AccessGrantForm(
        request.POST or None, grantor=request.user, grantable_actions=grantable
    )
    allowed, why = access_grant_service.can_grant(request.user, case, scope, grantable)
    if not allowed:
        return HttpResponseForbidden(why)

    if request.method == "POST" and form.is_valid():
        expires_at = None
        days = form.cleaned_data["duration_days"]
        if days:
            from django.utils import timezone

            expires_at = timezone.now() + timezone.timedelta(days=days)

        targets = resource_ids if scope == C.GRANT_SCOPE_SELECTED else [case.case_id]
        access_grant_service.grant(
            grantor=request.user,
            resource_type=C.RESOURCE_CASE,
            resource_ids=targets,
            actions=form.cleaned_data["actions"],
            reason=form.cleaned_data["reason"],
            scope=scope,
            expires_at=expires_at,
            **form.recipient_kwargs(),
            request=request,
        )
        messages.success(request, "Access granted and recorded in the audit trail.")
        return redirect("general:case_access", case_id=case.case_id)

    return render(request, "general/grant_access.html", {
        "form": form, "case": case, "scope": scope,
        "targets": resource_ids, "grantable_actions": grantable,
    })


@portal_required(PORTAL)
@reauth_required
@require_POST
def revoke_grant(request, pk: int):
    grant = get_object_or_404(AccessGrant, pk=pk)
    case = get_object_or_404(CaseRecord, case_id=grant.resource_id) \
        if grant.resource_type == C.RESOURCE_CASE else None
    if case is None:
        return HttpResponseForbidden("Unsupported resource.")
    _decision, error = _authorize(request, case, C.ACTION_MANAGE_ACCESS)
    if error:
        return error

    access_grant_service.revoke(
        grant, request.user, reason=request.POST.get("reason", ""), request=request
    )
    messages.success(request, "Access revoked.")
    return redirect("general:case_access", case_id=case.case_id)


# ---------------------------------------------------------------------------
# Access requests (§17 / §18)
# ---------------------------------------------------------------------------
@portal_required(PORTAL)
def request_access(request, case_id: str):
    """Ask for access. Available to officers who cannot currently view a case."""
    case = get_object_or_404(CaseRecord, case_id=case_id)
    if authorization_service.can_access_resource(request.user, case, C.ACTION_VIEW, portal=PORTAL):
        messages.info(request, "You already have access to this case.")
        return redirect("general:case_detail", case_id=case.case_id)

    requestable = [C.ACTION_VIEW, C.ACTION_DOWNLOAD, C.ACTION_COMMENT]
    form = AccessRequestForm(request.POST or None, requestable_actions=requestable)
    if request.method == "POST" and form.is_valid():
        access_request_service.create(
            requester=request.user,
            resource_type=C.RESOURCE_CASE,
            resource_id=case.case_id,
            actions=form.cleaned_data["actions"],
            reason=form.cleaned_data["reason"],
            duration_days=form.cleaned_data["duration_days"],
            request=request,
        )
        messages.success(request, "Access request submitted for review.")
        return redirect("general:view_cases")

    return render(request, "general/request_access.html", {
        "form": form, "case": {"case_id": case.case_id},
    })


@portal_required(PORTAL)
def access_requests(request):
    """Inbox of requests the current officer is authorized to decide."""
    pending = [r for r in AccessRequest.objects.filter(status=C.REQUEST_PENDING)
               .select_related("requester")
               if access_request_service.can_decide(request.user, r)]
    decided = AccessRequest.objects.filter(decided_by=request.user).exclude(
        status=C.REQUEST_PENDING
    ).select_related("requester")[:20]
    return render(request, "general/access_requests.html", {
        "pending": pending, "decided": decided,
    })


@portal_required(PORTAL)
@reauth_required
@require_POST
def decide_request(request, pk: int, decision: str):
    access_request = get_object_or_404(AccessRequest, pk=pk)
    if not access_request_service.can_decide(request.user, access_request):
        audit_service.record_denied(
            officer=request.user, action=f"decide_request:{decision}",
            resource_type=access_request.resource_type,
            resource_id=access_request.resource_id, portal=PORTAL,
            reason="Not authorized to decide this request", request=request,
        )
        return HttpResponseForbidden("You are not authorized to decide this request.")

    reason = request.POST.get("reason", "")
    if decision == "approve":
        access_request_service.approve(access_request, request.user, reason, request=request)
        messages.success(request, "Request approved — access granted.")
    else:
        access_request_service.reject(access_request, request.user, reason, request=request)
        messages.success(request, "Request rejected.")
    return redirect("general:access_requests")


@portal_required(PORTAL)
@require_POST
def cancel_request(request, pk: int):
    access_request = get_object_or_404(AccessRequest, pk=pk, requester=request.user)
    access_request_service.cancel(access_request, request.user, request=request)
    messages.success(request, "Request cancelled.")
    return redirect("general:view_cases")


# ---------------------------------------------------------------------------
# Case transfer (§24)
# ---------------------------------------------------------------------------
@portal_required(PORTAL)
@reauth_required
def case_transfer(request, case_id: str):
    case, error = _case_or_403(request, case_id, C.ACTION_MANAGE_ACCESS)
    if error:
        return error

    form = CaseTransferForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        case_transfer_service.transfer(
            case,
            to_unit=form.cleaned_data["to_unit"],
            to_organization=form.cleaned_data["to_organization"],
            actor=request.user,
            reason=form.cleaned_data["reason"],
            request=request,
        )
        messages.success(request, "Case transferred. Access has been recalculated.")
        return redirect("general:case_detail", case_id=case.case_id)

    return render(request, "general/case_transfer.html", {"form": form, "case": case})


# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------
def build_nav(caps: dict):
    """Capability-driven navigation — only destinations that exist."""
    permissions = set(caps.get("permissions", []))
    items = []

    def add(name, url_name, icon, required):
        if required in permissions:
            items.append({"name": name, "url": reverse(url_name), "icon": icon})

    add("Register Case", "general:register_case", "case", C.PERM_CASE_CREATE)
    add("View Cases", "general:view_cases", "folder", C.PERM_CASE_VIEW)
    if C.PERM_CASE_MANAGE_ACCESS in permissions:
        items.append({
            "name": "Access Requests", "url": reverse("general:access_requests"),
            "icon": "key",
        })
    items.append({"name": "My Account", "url": reverse("account_profile"), "icon": "account"})
    return items
