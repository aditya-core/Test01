"""General Officer portal shell.

The dashboard is generated from the authorization engine — no giant page with
JavaScript-hidden buttons. Each nav target re-checks authorization server-side.
"""
from __future__ import annotations

from django.shortcuts import render

from accounts.authorization import authorization_service
from accounts.decorators import portal_required
from accounts import constants as C


@portal_required(C.PORTAL_GENERAL)
def dashboard(request):
    caps = authorization_service.portal_capabilities(request.user, C.PORTAL_GENERAL)
    nav = build_nav(caps)
    return render(
        request,
        "general/dashboard.html",
        {"caps": caps, "nav": nav},
    )


def build_nav(caps: dict):
    """Capability-driven navigation for the general portal."""
    permissions = set(caps.get("permissions", []))
    items = []

    def add(name, url, icon, required=None):
        if required is None or required in permissions:
            items.append({"name": name, "url": url, "icon": icon})

    add("My Cases", "#", "case", "case.view")
    add("My Tasks", "#", "task", "task.view")
    add("Assigned Documents", "#", "doc", "document.view")
    add("Upload Document", "#", "upload", "document.upload")
    add("Reviews", "#", "review", "case.review")
    add("Assignments", "#", "assign", "case.assign")
    add("District Overview", "#", "overview", "district.report")
    add("Approvals", "#", "approve", "case.approve")
    add("Reports", "#", "report", "report.view")
    add("Notifications", "#", "bell", "notification.view")

    # Without case/document permissions yet, every officer can still manage
    # their own account.
    items.append({"name": "My Account", "url": "/account/", "icon": "account"})
    return items
