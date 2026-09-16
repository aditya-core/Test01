"""Read-only cross-portal case oversight for authorized administrators."""
from __future__ import annotations

from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import get_object_or_404, render

from accounts import constants as C
from accounts.decorators import permission_required, portal_required
from audit.models import AuditEvent
from general.models import AccessGrant, CaseRecord

PORTAL = C.PORTAL_IT_ADMIN


@portal_required(PORTAL)
@permission_required(C.PERM_CASE_AUDIT_VIEW)
def case_oversight_list(request):
    """Browse every case without granting operational case permissions."""
    query = request.GET.get("q", "").strip()
    cases = CaseRecord.objects.select_related(
        "created_by", "classification", "organization", "unit"
    ).prefetch_related("assignments__officer")
    if query:
        cases = cases.filter(
            Q(case_id__icontains=query)
            | Q(title__icontains=query)
            | Q(case_type__icontains=query)
            | Q(police_station__icontains=query)
            | Q(investigating_agency__icontains=query)
            | Q(created_by__officer_id__icontains=query)
        )
    page = Paginator(cases.order_by("-updated_at"), 25).get_page(request.GET.get("page"))
    return render(request, "it_admin/case_oversight_list.html", {
        "page": page,
        "cases": page.object_list,
        "query": query,
    })


@portal_required(PORTAL)
@permission_required(C.PERM_CASE_AUDIT_VIEW)
def case_oversight_detail(request, case_id: str):
    """Show case metadata, assignments, grants, and related audit activity."""
    case = get_object_or_404(
        CaseRecord.objects.select_related(
            "created_by", "classification", "organization", "unit"
        ).prefetch_related("assignments__officer"),
        case_id=case_id,
    )
    activity = AuditEvent.objects.filter(
        Q(resource_id=case.case_id)
        | Q(context__case_id=case.case_id)
    ).select_related("officer", "actor").order_by("-occurred_at")[:300]
    grants = AccessGrant.objects.filter(
        resource_type=C.RESOURCE_CASE, resource_id=case.case_id
    ).select_related("grantor", "recipient_officer", "recipient_department", "recipient_unit")
    return render(request, "it_admin/case_oversight_detail.html", {
        "case": case,
        "activity": activity,
        "grants": grants,
        "assignments": case.assignments.select_related("officer").all(),
    })


__all__ = ["case_oversight_list", "case_oversight_detail"]