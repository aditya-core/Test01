"""Session & account-state enforcement middleware.

Runs after authentication so ``request.user`` is resolved, and enforces:

  * account-state invalidation (disabled/suspended/locked accounts lose their
    sessions immediately),
  * inactivity timeout,
  * absolute session lifetime.

Expired/terminated sessions are flushed server-side and audited.
"""
from __future__ import annotations

from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone

from audit.services import audit_service

from . import constants as C
from .devices import device_session_service


class SessionSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            now = timezone.now()

            # 1. Account state: a disabled/suspended/deactivated/locked account
            #    loses its session immediately.
            if not user.is_active or getattr(user, "account_status", None) != C.ACCOUNT_STATUS_ACTIVE:
                audit_service.record_event(
                    C.EVENT_SESSION_EXPIRED,
                    officer=user,
                    result="DENY",
                    reason=f"Account state {getattr(user, 'account_status', 'unknown')}",
                    request=request,
                )
                device_session_service.close_current(request, C.SESSION_END_ACCOUNT_STATE)
                logout(request)
                request.session.flush()
                return HttpResponseRedirect(reverse("portal_selection"))

            # 2. Absolute session lifetime.
            created = request.session.get(C.SESSION_LOGIN_AT)
            if created:
                try:
                    started = timezone.datetime.fromisoformat(created)
                    max_age = int(getattr(settings, "ACCOUNTS_SESSION_MAX_AGE_MINUTES", 480)) * 60
                    if (now - started).total_seconds() > max_age:
                        audit_service.record_event(
                            C.EVENT_SESSION_EXPIRED,
                            officer=user,
                            result="DENY",
                            reason="Session maximum age exceeded",
                            request=request,
                        )
                        device_session_service.close_current(request, C.SESSION_END_EXPIRED)
                        logout(request)
                        request.session.flush()
                        return HttpResponseRedirect(reverse("portal_selection"))
                except (ValueError, TypeError):
                    pass

            # 3. Inactivity timeout.
            last = request.session.get("last_activity")
            if last:
                try:
                    last_active = timezone.datetime.fromisoformat(last)
                    inactivity = int(getattr(settings, "ACCOUNTS_SESSION_INACTIVITY_MINUTES", 30)) * 60
                    if (now - last_active).total_seconds() > inactivity:
                        audit_service.record_event(
                            C.EVENT_SESSION_EXPIRED,
                            officer=user,
                            result="DENY",
                            reason="Session inactivity timeout",
                            request=request,
                        )
                        device_session_service.close_current(request, C.SESSION_END_EXPIRED)
                        logout(request)
                        request.session.flush()
                        return HttpResponseRedirect(reverse("portal_selection"))
                except (ValueError, TypeError):
                    pass

            # Track last activity for the next request.
            request.session["last_activity"] = now.isoformat()
            device_session_service.touch(request)

        return self.get_response(request)
