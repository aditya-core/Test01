"""Class-based-view mixins mirroring the function decorators."""
from __future__ import annotations

from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied

from .authorization import authorization_service


class PortalRequiredMixin:
    """CBV equivalent of ``@portal_required``."""

    portal_key = None

    def dispatch(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return self.handle_no_permission()
        if not authorization_service.can_access_portal(user, self.portal_key):
            from audit.services import audit_service

            audit_service.record_denied(
                officer=user,
                action="portal_entry",
                resource_type="portal",
                resource_id=self.portal_key,
                portal=self.portal_key,
                reason="Portal authorization failed",
                request=request,
            )
            raise PermissionDenied("You are not authorized to access this portal.")
        return super().dispatch(request, *args, **kwargs)


class PermissionRequiredMixin:
    """CBV equivalent of ``@permission_required``."""

    permission = None

    def dispatch(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return self.handle_no_permission()
        if not authorization_service.has_permission(user, self.permission):
            from audit.services import audit_service

            audit_service.record_denied(
                officer=user,
                action=self.permission,
                resource_type="permission",
                resource_id=self.permission,
                reason="Permission denied",
                request=request,
            )
            raise PermissionDenied("You do not have permission to perform this action.")
        return super().dispatch(request, *args, **kwargs)


class ActiveOfficerRequiredMixin(LoginRequiredMixin):
    """Require a logged-in officer whose account is ACTIVE."""

    def dispatch(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return self.handle_no_permission()
        if not authorization_service._is_active_identity(user):
            from django.contrib.auth import logout

            logout(request)
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)
