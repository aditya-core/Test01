"""Server-side enforcement decorators.

The UI only *reflects* permissions; these decorators are the real boundary.
Every protected view re-checks authorization regardless of what the browser
sent.
"""
from __future__ import annotations

from functools import wraps

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.urls import reverse

from .authorization import authorization_service
from .services import session_service

LOGIN_URL_NAME = "accounts:login"


def portal_required(portal_key: str):
    """Require authentication AND explicit authorization for a portal.

    Not logged in ⇒ redirect to login for that portal.
    Logged in but unauthorized ⇒ 403 + audited denial.
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            user = request.user
            if not user.is_authenticated:
                return HttpResponseRedirect(
                    reverse(LOGIN_URL_NAME, kwargs={"portal_key": portal_key})
                )

            if authorization_service.can_access_portal(user, portal_key):
                return view_func(request, *args, **kwargs)

            from audit.services import audit_service

            audit_service.record_denied(
                officer=user,
                action="portal_entry",
                resource_type="portal",
                resource_id=portal_key,
                portal=portal_key,
                reason="Portal authorization failed",
                request=request,
            )
            raise PermissionDenied("You are not authorized to access this portal.")

        return _wrapped

    return decorator


def permission_required(permission: str):
    """Require a specific RBAC permission."""

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            user = request.user
            if not user.is_authenticated:
                return HttpResponseRedirect(reverse(LOGIN_URL_NAME, kwargs={"portal_key": "general"}))

            if authorization_service.has_permission(user, permission):
                return view_func(request, *args, **kwargs)

            from audit.services import audit_service

            audit_service.record_denied(
                officer=user,
                action=permission,
                resource_type="permission",
                resource_id=permission,
                reason="Permission denied",
                request=request,
            )
            raise PermissionDenied("You do not have permission to perform this action.")

        return _wrapped

    return decorator


def any_permission_required(*permissions: str):
    """Require at least one of several RBAC permissions.

    Used for pages that aggregate several capabilities (e.g. an account
    security page showing suspend *or* reactivate). Each individual action
    endpoint still checks its own specific permission.
    """

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            user = request.user
            if not user.is_authenticated:
                return HttpResponseRedirect(reverse(LOGIN_URL_NAME, kwargs={"portal_key": "general"}))

            held = authorization_service.get_user_permissions(user)
            if any(p in held for p in permissions):
                return view_func(request, *args, **kwargs)

            from audit.services import audit_service

            audit_service.record_denied(
                officer=user,
                action=" | ".join(permissions),
                resource_type="permission",
                resource_id=permissions[0] if permissions else "",
                reason="Permission denied",
                request=request,
            )
            raise PermissionDenied("You do not have permission to perform this action.")

        return _wrapped

    return decorator


def reauth_required(view_func):
    """Require a recent second-factor verification before a sensitive action."""

    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseRedirect(reverse(LOGIN_URL_NAME, kwargs={"portal_key": "general"}))
        if session_service.requires_reauth(request):
            request.session["reauth_next"] = request.path
            return HttpResponseRedirect(reverse("accounts:reauth"))
        return view_func(request, *args, **kwargs)

    return _wrapped


def audit_event(event_type: str, **extra):
    """Record an audit event on successful view execution (side-effect only)."""

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            response = view_func(request, *args, **kwargs)
            from audit.services import audit_service

            audit_service.record_event(
                event_type,
                officer=request.user if request.user.is_authenticated else None,
                actor=request.user if request.user.is_authenticated else None,
                result="SUCCESS",
                request=request,
                **extra,
            )
            return response

        return _wrapped

    return decorator


def non_field_error_message(request, message: str):
    """Attach a generic message for the next rendered page (used by auth views)."""
    messages.error(request, message)
