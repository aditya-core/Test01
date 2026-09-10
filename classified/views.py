"""Classified portal shell.

Entry requires authenticated identity + explicit classified portal access +
the required clearance. Isolated at the authorization level from general
workflows.
"""
from __future__ import annotations

from django.shortcuts import render

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.decorators import portal_required


@portal_required(C.PORTAL_CLASSIFIED)
def dashboard(request):
    caps = authorization_service.portal_capabilities(request.user, C.PORTAL_CLASSIFIED)
    return render(request, "classified/dashboard.html", {"caps": caps})
