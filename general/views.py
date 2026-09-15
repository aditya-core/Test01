"""General Officer portal shell with operational case workflow.

Every case read and every file download is decided by the central
``AuthorizationService`` — never by filtering in a template or trusting that
the officer "must be" allowed because they created the record. Registration
grants access by creating an ``OWNER`` assignment, so the registering officer
is authorized through exactly the same path as everyone else.
"""
from __future__ import annotations

from django.contrib import messages
from django.db.models import Q
from django.http import FileResponse, Http404, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.decorators import permission_required, portal_required
from audit.services import audit_service
from general.forms import CaseRegistrationForm
from general.models import CaseAssignment, CaseEvidenceFile, CaseRecord


# ---------------------------------------------------------------------------
# Authorization helpers
# ---------------------------------------------------------------------------
def _visible_cases(user, action: str = C.ACTION_CASE_VIEW, queryset=None):
    """Cases ``user`` may perform ``action`` on.

    The database narrows to cases the officer is assigned to (cheap); the
    engine then re-decides clearance, jurisdiction, capability and the
    per-officer action ceiling (authoritative). Both are required — the query
    is an optimisation, never the decision.
    """
    qs = queryset if queryset is not None else CaseRecord.objects.all()
    qs = (
        qs.filter(assignments__officer=user, assignments__revoked_at__isnull=True)
        .select_related("classification", "organization", "created_by")
        .prefetch_related("evidence_files")
        .distinct()
    )
    return [case for case in qs if authorization_service.can_access_case(user, case, action)]


def _denied(request, case, action: str):
    """Record the denial and return a 403 without revealing case contents."""
    audit_service.record_denied(
        officer=request.user,
        action=action,
        resource_type="case",
        resource_id=getattr(case, "case_id", ""),
        portal=C.PORTAL_GENERAL,
        reason="Case authorization failed",
        request=request,
    )
    return HttpResponseForbidden("You are not authorized to access this case.")


# ---------------------------------------------------------------------------
# Portal views
# ---------------------------------------------------------------------------
@portal_required(C.PORTAL_GENERAL)
def dashboard(request):
    caps = authorization_service.portal_capabilities(request.user, C.PORTAL_GENERAL)
    nav = build_nav(caps)
    recent_cases = _visible_cases(request.user)[:5]
    return render(
        request,
        "general/dashboard.html",
        {"caps": caps, "nav": nav, "recent_cases": recent_cases},
    )


@portal_required(C.PORTAL_GENERAL)
@permission_required(C.PERM_CASE_CREATE)
def register_case(request):
    form = CaseRegistrationForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        case = form.save(commit=False)
        case.created_by = request.user
        # Security attributes are decided server-side from the officer's own
        # posting — never taken from the client.
        case.organization = request.user.unit.organization if request.user.unit_id else None
        case.save()

        for evidence in request.FILES.getlist("evidence_files"):
            CaseEvidenceFile.objects.create(case=case, file=evidence)

        # Registration is also the first authorization grant: the officer is
        # recorded as the case owner so access flows through the normal path.
        CaseAssignment.objects.create(
            case=case,
            officer=request.user,
            role=C.ASSIGNMENT_OWNER,
            granted_by=request.user,
            reason="Case registration",
        )

        audit_service.record_event(
            C.EVENT_CASE_REGISTERED,
            officer=request.user,
            actor=request.user,
            portal=C.PORTAL_GENERAL,
            resource_type="case",
            resource_id=case.case_id,
            action="register_case",
            result=C.RESULT_SUCCESS,
            new_state={
                "case_id": case.case_id,
                "classification": case.classification.code if case.classification_id else None,
                "organization": case.organization.name if case.organization_id else None,
                "evidence_files": case.evidence_files.count(),
            },
            request=request,
        )

        if case.fir_document:
            messages.success(request, f"Case {case.case_id} registered successfully.")
        else:
            messages.success(request, f"Case {case.case_id} registered successfully without FIR upload.")
        return redirect("general:view_cases")

    return render(request, "general/case_form.html", {"form": form, "title": "Register Case"})


@portal_required(C.PORTAL_GENERAL)
def view_cases(request):
    q = request.GET.get("q", "").strip()
    queryset = CaseRecord.objects.all()
    if q:
        queryset = queryset.filter(
            Q(case_id__icontains=q)
            | Q(title__icontains=q)
            | Q(case_type__icontains=q)
            | Q(investigating_agency__icontains=q)
            | Q(police_station__icontains=q)
        )
    cases = _visible_cases(request.user, C.ACTION_CASE_VIEW, queryset)
    cases.sort(key=lambda case: case.updated_at, reverse=True)
    return render(request, "general/case_list.html", {"cases": cases, "query": q})


# ---------------------------------------------------------------------------
# Protected file delivery
# ---------------------------------------------------------------------------
# Media files are never served by URL alone: ``MEDIA_URL`` is not a capability.
# Every byte goes through an authorized view so that "unauthorized download"
# is a real DENY rather than an unguessable-URL hope.
@portal_required(C.PORTAL_GENERAL)
def download_fir(request, case_id: str):
    return _serve_case_file(request, case_id, evidence_pk=None)


@portal_required(C.PORTAL_GENERAL)
def download_evidence(request, case_id: str, pk: int):
    return _serve_case_file(request, case_id, evidence_pk=pk)


def _serve_case_file(request, case_id: str, evidence_pk: int | None):
    case = get_object_or_404(CaseRecord, case_id=case_id)
    if not authorization_service.can_access_case(request.user, case, C.ACTION_CASE_DOWNLOAD):
        return _denied(request, case, C.ACTION_CASE_DOWNLOAD)

    if evidence_pk is None:
        field = case.fir_document
        filename = f"{case.case_id}-FIR"
        resource_id = f"{case.case_id}:fir"
    else:
        evidence = get_object_or_404(CaseEvidenceFile, pk=evidence_pk, case=case)
        field = evidence.file
        filename = evidence.file.name.rsplit("/", 1)[-1]
        resource_id = f"{case.case_id}:evidence:{evidence.pk}"

    if not field:
        raise Http404("No such file.")

    audit_service.record_event(
        C.EVENT_CASE_DOCUMENT_DOWNLOAD,
        officer=request.user,
        actor=request.user,
        portal=C.PORTAL_GENERAL,
        resource_type="case_document",
        resource_id=resource_id,
        action=C.ACTION_CASE_DOWNLOAD,
        result=C.RESULT_ALLOW,
        request=request,
    )
    return FileResponse(field.open("rb"), as_attachment=True, filename=filename)


# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------
def build_nav(caps: dict):
    """Capability-driven navigation for the general portal.

    Only entries with a real destination are offered. Placeholders for
    unbuilt features are deliberately absent — a link that goes nowhere is
    worse than no link, and each target still re-checks authorization.
    """
    permissions = set(caps.get("permissions", []))
    items = []

    def add(name, url_name, icon, required):
        if required in permissions:
            items.append({"name": name, "url": reverse(url_name), "icon": icon})

    add("Register Case", "general:register_case", "case", C.PERM_CASE_CREATE)
    add("View Cases", "general:view_cases", "folder", C.PERM_CASE_VIEW)
    items.append({"name": "My Account", "url": reverse("account_profile"), "icon": "account"})
    return items
