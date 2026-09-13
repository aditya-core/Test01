"""General Officer portal shell with operational case workflow."""
from __future__ import annotations

from django.contrib import messages
from django.db.models import Q
from django.shortcuts import redirect, render

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.decorators import portal_required
from general.forms import CaseRegistrationForm
from general.models import CaseEvidenceFile, CaseRecord


@portal_required(C.PORTAL_GENERAL)
def dashboard(request):
    caps = authorization_service.portal_capabilities(request.user, C.PORTAL_GENERAL)
    nav = build_nav(caps)
    recent_cases = CaseRecord.objects.filter(created_by=request.user).order_by("-updated_at")[:5]
    return render(
        request,
        "general/dashboard.html",
        {"caps": caps, "nav": nav, "recent_cases": recent_cases},
    )


@portal_required(C.PORTAL_GENERAL)
def register_case(request):
    form = CaseRegistrationForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        case = form.save(commit=False)
        case.created_by = request.user
        case.fir_document = request.FILES.get("fir_document") or case.fir_document
        case.save()

        for evidence in request.FILES.getlist("evidence_files"):
            CaseEvidenceFile.objects.create(case=case, file=evidence)

        if case.fir_document:
            messages.success(request, f"Case {case.case_id} registered successfully.")
        else:
            messages.success(request, f"Case {case.case_id} registered successfully without FIR upload.")
        return redirect("general:view_cases")

    return render(request, "general/case_form.html", {"form": form, "title": "Register Case"})


@portal_required(C.PORTAL_GENERAL)
def view_cases(request):
    q = request.GET.get("q", "").strip()
    queryset = CaseRecord.objects.filter(created_by=request.user)
    if q:
        queryset = queryset.filter(
            Q(case_id__icontains=q)
            | Q(title__icontains=q)
            | Q(case_type__icontains=q)
            | Q(investigating_agency__icontains=q)
            | Q(police_station__icontains=q)
        )
    cases = queryset.order_by("-updated_at")
    return render(request, "general/case_list.html", {"cases": cases, "query": q})


def build_nav(caps: dict):
    """Capability-driven navigation for the general portal."""
    permissions = set(caps.get("permissions", []))
    items = []

    def add(name, url, icon, required=None):
        if required is None or required in permissions:
            items.append({"name": name, "url": url, "icon": icon})

    items.append({"name": "Register Case", "url": "/general/cases/register/", "icon": "case"})
    items.append({"name": "View Cases", "url": "/general/cases/", "icon": "folder"})
    add("My Tasks", "#", "task", "task.view")
    add("Assigned Documents", "#", "doc", "document.view")
    add("Upload Document", "#", "upload", "document.upload")
    add("Reviews", "#", "review", "case.review")
    add("Assignments", "#", "assign", "case.assign")
    add("District Overview", "#", "overview", "district.report")
    add("Approvals", "#", "approve", "case.approve")
    add("Reports", "#", "report", "report.view")
    add("Notifications", "#", "bell", "notification.view")
    items.append({"name": "My Account", "url": "/account/", "icon": "account"})
    return items
