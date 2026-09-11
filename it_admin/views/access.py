"""Access explainability, temporary capabilities and access reviews."""
from __future__ import annotations

from django.contrib import messages
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST, require_http_methods

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.decorators import any_permission_required, permission_required, portal_required, reauth_required
from accounts.models import Officer, Permission, TemporaryCapability

from ..exceptions import AdminActionError
from ..forms import AccessReviewDecisionForm, ReasonForm, TemporaryCapabilityForm
from ..models import AccessReview
from ..services import access_review_service, temporary_access_service
from ._common import PORTAL, actor_can, officer_queryset

__all__ = [
    "officer_access_explanation", "temporary_access_list", "temporary_access_create", "temporary_access_revoke",
    "access_review_list", "access_review_detail", "access_review_raise", "access_review_decide",
]


# --------------------------------------------------------------------------- WHY?
@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_VIEW)
def officer_access_explanation(request, pk):
    officer = get_object_or_404(officer_queryset(), pk=pk)
    codename = request.GET.get("capability", "").strip()
    explanations = authorization_service.explain_all(officer)
    single = authorization_service.explain_permission(officer, codename) if codename else None
    # Show operational codenames the role carries only as an opaque count —
    # never enumerate or explain them here.
    operational = [p for p in authorization_service.get_role_permissions(officer) if not C.is_admin_capability(p)]
    return render(request, "it_admin/officer_access.html", {
        "officer": officer, "explanations": explanations, "single": single, "codename": codename,
        "operational_count": len(operational),
        "all_admin_capabilities": sorted(c for c in Permission.objects.values_list("codename", flat=True) if C.is_admin_capability(c)),
    })


# --------------------------------------------------------------------------- temporary access
@portal_required(PORTAL)
@any_permission_required(C.PERM_ACCESS_GRANT_TEMPORARY, C.PERM_ACCESS_REVIEW)
def temporary_access_list(request):
    qs = TemporaryCapability.objects.select_related("officer", "permission", "granted_by")
    show_all = request.GET.get("all") == "1"
    now = timezone.now()
    if not show_all:
        qs = qs.filter(status=C.TEMP_ACCESS_ACTIVE, expires_at__gt=now)
    page = Paginator(qs, 25).get_page(request.GET.get("page"))
    return render(request, "it_admin/temporary_access_list.html", {
        "page": page, "show_all": show_all, "can_grant": actor_can(request, C.PERM_ACCESS_GRANT_TEMPORARY),
    })


@portal_required(PORTAL)
@permission_required(C.PERM_ACCESS_GRANT_TEMPORARY)
@reauth_required
@require_http_methods(["GET", "POST"])
def temporary_access_create(request):
    initial = {}
    if request.GET.get("officer"):
        initial["officer"] = request.GET["officer"]
    form = TemporaryCapabilityForm(request.POST or None, initial=initial, actor=request.user)
    if request.method == "POST" and form.is_valid():
        d = form.cleaned_data
        try:
            temporary_access_service.grant(
                d["officer"], d["permission"], reason=d["reason"], starts_at=d["starts_at"],
                expires_at=d["expires_at"], actor=request.user, request=request,
            )
        except AdminActionError as exc:
            form.add_error(None, str(exc))
        else:
            messages.success(request, f"Temporary capability {d['permission'].codename} granted to {d['officer'].officer_id} until {timezone.localtime(d['expires_at']):%d %b %Y %H:%M}.")
            return redirect("it_admin:temporary_access_list")
    return render(request, "it_admin/temporary_access_form.html", {"form": form})


@portal_required(PORTAL)
@permission_required(C.PERM_ACCESS_GRANT_TEMPORARY)
@require_POST
def temporary_access_revoke(request, pk):
    grant = get_object_or_404(TemporaryCapability.objects.select_related("officer", "permission"), pk=pk)
    form = ReasonForm(request.POST)
    if not form.is_valid():
        messages.error(request, "A reason is required to revoke a temporary capability.")
    else:
        temporary_access_service.revoke(grant, request.user, reason=form.cleaned_data["reason"], request=request)
        messages.success(request, "Temporary capability revoked.")
    from .security import _redirect_next

    return _redirect_next(request, "it_admin:temporary_access_list")


# --------------------------------------------------------------------------- access reviews
@portal_required(PORTAL)
@permission_required(C.PERM_ACCESS_REVIEW)
def access_review_list(request):
    pending = AccessReview.objects.filter(status=AccessReview.STATUS_PENDING).select_related("officer", "created_by")
    completed = AccessReview.objects.filter(status=AccessReview.STATUS_COMPLETED).select_related("officer", "reviewed_by")[:25]
    due = access_review_service.officers_due()
    return render(request, "it_admin/access_review_list.html", {
        "pending": pending, "completed": completed, "due": due,
        "interval_days": access_review_service.REVIEW_INTERVAL_DAYS,
    })


@portal_required(PORTAL)
@permission_required(C.PERM_ACCESS_REVIEW)
@require_POST
def access_review_raise(request, pk):
    officer = get_object_or_404(Officer, pk=pk)
    review = access_review_service.ensure_pending(
        officer, trigger=request.POST.get("trigger", "Periodic access review")[:120],
        created_by=request.user, request=request,
    )
    messages.success(request, f"Access review opened for {officer.officer_id}.")
    return redirect("it_admin:access_review_detail", pk=review.pk)


@portal_required(PORTAL)
@permission_required(C.PERM_ACCESS_REVIEW)
def access_review_detail(request, pk):
    review = get_object_or_404(AccessReview.objects.select_related("officer", "created_by", "reviewed_by"), pk=pk)
    officer = review.officer
    return render(request, "it_admin/access_review_detail.html", {
        "review": review, "officer": officer, "form": AccessReviewDecisionForm(),
        "explanations": authorization_service.explain_all(officer),
        "current": access_review_service.admin_capability_snapshot(officer),
        "temporary": TemporaryCapability.objects.filter(officer=officer).select_related("permission")[:10],
        "is_self": officer.pk == request.user.pk,
    })


@portal_required(PORTAL)
@permission_required(C.PERM_ACCESS_REVIEW)
@reauth_required
@require_POST
def access_review_decide(request, pk):
    review = get_object_or_404(AccessReview.objects.select_related("officer"), pk=pk)
    form = AccessReviewDecisionForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Choose KEEP, MODIFY or REVOKE.")
        return redirect("it_admin:access_review_detail", pk=review.pk)
    try:
        access_review_service.decide(review, decision=form.cleaned_data["decision"],
                                     note=form.cleaned_data["note"], reviewer=request.user, request=request)
    except AdminActionError as exc:
        messages.error(request, str(exc))
        return redirect("it_admin:access_review_detail", pk=review.pk)
    decision = form.cleaned_data["decision"]
    if decision == AccessReview.DECISION_MODIFY:
        messages.success(request, "Review recorded as MODIFY — adjust the officer's authorization attributes now.")
        return redirect("it_admin:officer_authorization", pk=review.officer_id) \
            if actor_can(request, C.PERM_OFFICER_AUTHORIZATION) else redirect("it_admin:officer_detail", pk=review.officer_id)
    messages.success(request, f"Access review completed: {decision}.")
    return redirect("it_admin:access_review_list")
