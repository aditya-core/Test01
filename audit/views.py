"""Authorized audit & security interface (shared across portals)."""
from __future__ import annotations

from django.shortcuts import render

from accounts import constants as C
from accounts.decorators import permission_required
from .models import AuditEvent, SecurityEvent


@permission_required(C.PERM_AUDIT_VIEW)
def audit_list(request):
    events = AuditEvent.objects.select_related("officer").order_by("-occurred_at")[:200]
    return render(request, "audit/list.html", {"events": events})


@permission_required(C.PERM_SECURITY_VIEW_EVENTS)
def security_list(request):
    events = SecurityEvent.objects.select_related("officer").order_by("-occurred_at")[:200]
    return render(request, "audit/security_list.html", {"events": events})
