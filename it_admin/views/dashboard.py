"""Dashboard — database-driven statistics + recent administrative activity."""
from __future__ import annotations

from django.shortcuts import render
from django.utils import timezone

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.decorators import portal_required
from accounts.models import Officer, OfficerSession, TemporaryCapability
from audit.models import AuditEvent, SecurityEvent

from ..models import AccessReview, ApprovalRequest

__all__ = ["dashboard"]


@portal_required(C.PORTAL_IT_ADMIN)
def dashboard(request):
    user = request.user
    caps = authorization_service.portal_capabilities(user, C.PORTAL_IT_ADMIN)
    perms = set(caps["permissions"])
    context = {"caps": caps, "stats": [], "recent": [], "quick_actions": []}

    if C.PERM_OFFICER_VIEW in perms:
        total = Officer.objects.count()
        active = Officer.objects.filter(account_status=C.ACCOUNT_STATUS_ACTIVE).count()
        blocked = Officer.objects.filter(account_status__in=[C.ACCOUNT_STATUS_SUSPENDED, C.ACCOUNT_STATUS_LOCKED]).count()
        invited = Officer.objects.filter(account_status__in=[C.ACCOUNT_STATUS_INVITED, C.ACCOUNT_STATUS_PENDING]).count()
        context["stats"] += [
            {"label": "Total officers", "value": total, "url": "it_admin:officer_list"},
            {"label": "Active", "value": active, "url": "it_admin:officer_list", "query": "status=ACTIVE"},
            {"label": "Suspended / locked", "value": blocked, "url": "it_admin:account_security", "tone": "danger" if blocked else ""},
            {"label": "Awaiting activation", "value": invited, "url": "it_admin:officer_list", "query": "status=INVITED"},
        ]
        # Officer-level admin capabilities are the only place the older
        # "officer_count / active_count" template variables were used; keep
        # them for backwards compatibility with any external template.
        context["officer_count"] = total
        context["active_count"] = active

    if C.PERM_ACCESS_REVIEW in perms:
        pending_reviews = AccessReview.objects.filter(status=AccessReview.STATUS_PENDING).count()
        context["stats"].append({"label": "Pending reviews", "value": pending_reviews, "url": "it_admin:access_review_list",
                                 "tone": "warn" if pending_reviews else ""})
    if C.PERM_APPROVAL_REVIEW in perms:
        pending_approvals = ApprovalRequest.objects.filter(status=ApprovalRequest.STATUS_PENDING).count()
        context["stats"].append({"label": "Pending approvals", "value": pending_approvals, "url": "it_admin:approval_list",
                                 "tone": "warn" if pending_approvals else ""})
    if C.PERM_SESSION_VIEW in perms:
        context["stats"].append({"label": "Open sessions", "value": OfficerSession.objects.filter(ended_at__isnull=True).count(),
                                 "url": "it_admin:device_session_overview"})
    if C.PERM_ACCESS_GRANT_TEMPORARY in perms or C.PERM_ACCESS_REVIEW in perms:
        now = timezone.now()
        context["stats"].append({"label": "Temporary grants live", "value": TemporaryCapability.objects.filter(
            status=C.TEMP_ACCESS_ACTIVE, starts_at__lte=now, expires_at__gt=now).count(),
            "url": "it_admin:temporary_access_list"})
    if C.PERM_SECURITY_VIEW_EVENTS in perms:
        alerts = SecurityEvent.objects.filter(severity__in=[C.SEVERITY_ALERT, C.SEVERITY_CRITICAL]).count()
        context["open_alerts"] = alerts
        context["stats"].append({"label": "Security alerts", "value": alerts, "url": "it_admin:security_dashboard",
                                 "tone": "danger" if alerts else ""})

    if C.PERM_AUDIT_VIEW in perms or C.PERM_OFFICER_VIEW in perms:
        context["recent"] = (
            AuditEvent.objects.filter(event_type__in=C.ADMIN_TIMELINE_EVENT_TYPES)
            .select_related("officer", "actor")
            .order_by("-occurred_at")[:12]
        )

    quick = []
    if C.PERM_OFFICER_CREATE in perms:
        quick.append(("Provision Officer", "it_admin:officer_create", "primary"))
    if C.PERM_OFFICER_VIEW in perms:
        quick.append(("Manage Officers", "it_admin:officer_list", "ghost"))
    if C.PERM_ACCESS_REVIEW in perms:
        quick.append(("Access Reviews", "it_admin:access_review_list", "ghost"))
    if C.PERM_APPROVAL_REVIEW in perms:
        quick.append(("Approval Center", "it_admin:approval_list", "ghost"))
    if C.PERM_AUDIT_VIEW in perms:
        quick.append(("Audit Log", "it_admin:audit_dashboard", "ghost"))
    context["quick_actions"] = quick
    context["admin_capabilities"] = [p for p in caps["permissions"] if C.is_admin_capability(p)]
    return render(request, "it_admin/dashboard.html", context)
