"""Template context helpers.

These only expose *display* facts about the authenticated user. They are never
an authorization boundary.
"""
from __future__ import annotations

from . import constants as C
from .authorization import authorization_service


def portal_context(request):
    """Expose the active portal and available portals for navigation."""
    user = request.user
    ctx = {
        "active_portal": request.session.get(C.SESSION_PORTAL_KEY, ""),
    }
    if user.is_authenticated:
        ctx["authorized_portals"] = authorization_service.list_authorized_portals(user)
    return ctx
