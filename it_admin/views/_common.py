"""Shared helpers for IT / Admin views."""
from __future__ import annotations

from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from accounts import constants as C
from accounts.authorization import authorization_service

PORTAL = C.PORTAL_IT_ADMIN


def activation_link(request, officer) -> str:
    uidb64 = urlsafe_base64_encode(force_bytes(officer.pk))
    token = default_token_generator.make_token(officer)
    return request.build_absolute_uri(
        reverse("accounts:activate", kwargs={"uidb64": uidb64, "token": token})
    )


def actor_can(request, permission: str) -> bool:
    return authorization_service.has_permission(request.user, permission)


def officer_queryset():
    from accounts.models import Officer

    return Officer.objects.select_related("role", "clearance", "unit", "unit__organization", "department", "designation", "supervisor")
