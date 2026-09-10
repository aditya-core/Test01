"""Authentication backend.

Verifies *identity only* (WHO ARE YOU?). Authorization — portals, roles,
clearance, scope — is evaluated separately by the AuthorizationService after
authentication succeeds. A successful login proves identity, nothing more.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.hashers import check_password

from . import constants as C

Officer = get_user_model()


class OfficerBackend(BaseBackend):
    """Authenticate against the central ``Officer`` model by officer_id.

    Failure results are deliberately indistinguishable (same return shape) so
    callers can emit a single generic message — no user enumeration.
    """

    def authenticate(self, request, officer_id=None, password=None, **kwargs):
        username = kwargs.get("username") or officer_id
        if not username or not password:
            return None

        try:
            officer = Officer.objects.get(officer_id__iexact=username.strip())
        except Officer.DoesNotExist:
            # Constant-ish time against a dummy hash to reduce timing signal.
            check_password(password, "invalid$pbkdf2_sha256$390000$dummy$dummy")
            return None

        if not check_password(password, officer.password):
            return None

        return officer

    def get_user(self, user_id):
        try:
            return Officer.objects.get(pk=user_id)
        except Officer.DoesNotExist:
            return None

    def has_perm(self, user_obj, perm, obj=None):
        """Delegate permission checks to the central authorization service."""
        if not user_obj.is_active:
            return False
        from .authorization import authorization_service

        if obj is not None:
            return False  # object-level decisions go through authorize()
        return authorization_service.has_permission(user_obj, perm)
