"""Lightweight device & session registry.

Design constraints (deliberate):

* **No fingerprinting.** A device is identified by a random token stored in
  an HttpOnly cookie; only its SHA-256 is persisted. Losing the cookie simply
  means the browser registers as a new device on the next sign-in.
* Browser / OS are parsed from the User-Agent header with a small, forgiving
  matcher — good enough for an administrator to recognise "Chrome on
  Windows", never used for authorization.
* The Django session remains the source of truth for authentication. The
  ``OfficerSession`` registry mirrors it (by hashed key) so that admins can
  see and terminate sessions; termination deletes the real Django session.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from typing import Optional

from django.conf import settings
from django.contrib.sessions.models import Session
from django.utils import timezone

from . import constants as C
from .models import OfficerSession, RegisteredDevice

DEVICE_COOKIE_NAME = "sdms_device"
DEVICE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- UA parsing
_BROWSERS = (
    ("Edg/", "Microsoft Edge"),
    ("OPR/", "Opera"),
    ("Firefox/", "Firefox"),
    ("Chrome/", "Chrome"),
    ("Safari/", "Safari"),
    ("MSIE", "Internet Explorer"),
    ("Trident/", "Internet Explorer"),
)
_OSES = (
    (re.compile(r"Windows NT 10"), "Windows 10/11"),
    (re.compile(r"Windows NT 6\.3"), "Windows 8.1"),
    (re.compile(r"Windows NT 6\.1"), "Windows 7"),
    (re.compile(r"Windows"), "Windows"),
    (re.compile(r"Android"), "Android"),
    (re.compile(r"iPhone|iPad|iPod"), "iOS"),
    (re.compile(r"Mac OS X"), "macOS"),
    (re.compile(r"CrOS"), "ChromeOS"),
    (re.compile(r"Linux"), "Linux"),
)


def parse_user_agent(user_agent: str) -> tuple[str, str]:
    """Return ``(browser, operating_system)`` labels for display only."""
    ua = user_agent or ""
    browser = "Unknown browser"
    for needle, label in _BROWSERS:
        if needle in ua:
            browser = label
            break
    os_label = "Unknown OS"
    for pattern, label in _OSES:
        if pattern.search(ua):
            os_label = label
            break
    if not ua:
        return browser, os_label
    return browser, os_label


def _client_ip(request) -> Optional[str]:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class DeviceSessionService:
    """Registers devices/sessions on login and keeps the registry honest."""

    # -- Registration -------------------------------------------------------
    def register_login(self, request, officer, portal_key: str) -> tuple[RegisteredDevice, OfficerSession, Optional[str]]:
        """Bind the freshly-authenticated session to a device.

        Returns ``(device, session_row, new_cookie_token_or_None)``. The
        caller sets the cookie on the response when a token is returned.
        """
        ua = (request.META.get("HTTP_USER_AGENT") or "")[:300]
        browser, os_label = parse_user_agent(ua)
        ip = _client_ip(request)

        device = None
        new_token = None
        token = request.COOKIES.get(DEVICE_COOKIE_NAME)
        if token:
            device = RegisteredDevice.objects.filter(
                device_key_hash=hash_token(token), officer=officer, status=C.DEVICE_STATUS_ACTIVE
            ).first()
        if device is None:
            # Unknown, revoked or someone else's cookie ⇒ issue a fresh token.
            # A revoked device therefore never silently re-activates.
            new_token = secrets.token_urlsafe(32)
            device = RegisteredDevice.objects.create(
                officer=officer,
                device_key_hash=hash_token(new_token),
                browser=browser,
                operating_system=os_label,
                user_agent=ua,
                last_ip=ip,
            )
            from audit.services import audit_service

            audit_service.record_event(
                C.EVENT_DEVICE_REGISTERED,
                officer=officer,
                actor=officer,
                portal=portal_key,
                resource_type="device",
                resource_id=str(device.pk),
                result=C.RESULT_SUCCESS,
                context={"browser": browser, "os": os_label},
                request=request,
            )
        else:
            RegisteredDevice.objects.filter(pk=device.pk).update(
                last_seen=timezone.now(), last_ip=ip, user_agent=ua, browser=browser, operating_system=os_label
            )

        session_row = OfficerSession.objects.create(
            officer=officer,
            session_key_hash=hash_token(request.session.session_key or ""),
            device=device,
            portal=portal_key,
            ip_address=ip,
            browser=browser,
            operating_system=os_label,
        )
        request.session["officer_session_id"] = session_row.pk
        return device, session_row, new_token

    def set_device_cookie(self, response, token: str):
        response.set_cookie(
            DEVICE_COOKIE_NAME,
            token,
            max_age=DEVICE_COOKIE_MAX_AGE,
            httponly=True,
            secure=bool(getattr(settings, "SESSION_COOKIE_SECURE", False)),
            samesite="Lax",
        )

    # -- Activity / closure ----------------------------------------------------
    def touch(self, request):
        """Cheap last-activity update; called from middleware."""
        row_id = request.session.get("officer_session_id")
        if not row_id:
            return
        OfficerSession.objects.filter(pk=row_id, ended_at__isnull=True).update(last_activity=timezone.now())

    def close_current(self, request, reason: str = C.SESSION_END_LOGOUT):
        row_id = request.session.get("officer_session_id")
        if not row_id:
            key = request.session.session_key
            if key:
                OfficerSession.objects.filter(session_key_hash=hash_token(key), ended_at__isnull=True).update(
                    ended_at=timezone.now(), end_reason=reason
                )
            return
        OfficerSession.objects.filter(pk=row_id, ended_at__isnull=True).update(
            ended_at=timezone.now(), end_reason=reason
        )

    def is_session_alive(self, session_row: OfficerSession) -> bool:
        """True when the underlying Django session still exists."""
        if session_row.ended_at is not None:
            return False
        for session in Session.objects.filter(expire_date__gt=timezone.now()).iterator():
            if hash_token(session.session_key) == session_row.session_key_hash:
                return True
        return False

    def reconcile(self, officer):
        """Close registry rows whose Django session has already vanished
        (expired, flushed) so the admin view never shows ghosts."""
        open_rows = list(OfficerSession.objects.filter(officer=officer, ended_at__isnull=True))
        if not open_rows:
            return 0
        live_hashes = {
            hash_token(s.session_key)
            for s in Session.objects.filter(expire_date__gt=timezone.now()).iterator()
        }
        closed = 0
        for row in open_rows:
            if row.session_key_hash not in live_hashes:
                row.ended_at = timezone.now()
                row.end_reason = C.SESSION_END_EXPIRED
                row.save(update_fields=["ended_at", "end_reason"])
                closed += 1
        return closed

    # -- Administrative actions ---------------------------------------------------
    def terminate_session(self, session_row: OfficerSession, actor, reason: str = "", request=None) -> bool:
        """Delete the real Django session and close the registry row."""
        deleted = False
        for session in Session.objects.all().iterator():
            if hash_token(session.session_key) == session_row.session_key_hash:
                session.delete()
                deleted = True
                break
        if session_row.ended_at is None:
            session_row.ended_at = timezone.now()
            session_row.end_reason = C.SESSION_END_TERMINATED
            session_row.ended_by = actor
            session_row.save(update_fields=["ended_at", "end_reason", "ended_by"])

        from audit.services import audit_service

        audit_service.record_admin_action(
            C.EVENT_SESSION_TERMINATED,
            actor=actor,
            target=session_row.officer,
            reason=reason,
            context={"session": session_row.pk, "server_session_deleted": deleted},
            request=request,
        )
        return deleted

    def terminate_all(self, officer, actor, reason: str = "", request=None) -> int:
        removed = officer.revoke_all_sessions(end_reason=C.SESSION_END_TERMINATED, actor=actor)
        from audit.services import audit_service

        audit_service.record_admin_action(
            C.EVENT_SESSION_TERMINATED,
            actor=actor,
            target=officer,
            action="terminate_all_sessions",
            reason=reason,
            context={"sessions_removed": removed},
            request=request,
        )
        return removed

    def revoke_device(self, device: RegisteredDevice, actor, reason: str = "", request=None) -> int:
        """Revoke a device and terminate every session bound to it."""
        if device.status == C.DEVICE_STATUS_REVOKED:
            return 0
        device.status = C.DEVICE_STATUS_REVOKED
        device.revoked_at = timezone.now()
        device.revoked_by = actor
        device.revoke_reason = reason[:255]
        device.save(update_fields=["status", "revoked_at", "revoked_by", "revoke_reason"])

        ended = 0
        for row in device.sessions.filter(ended_at__isnull=True):
            for session in Session.objects.all().iterator():
                if hash_token(session.session_key) == row.session_key_hash:
                    session.delete()
                    break
            row.ended_at = timezone.now()
            row.end_reason = C.SESSION_END_DEVICE_REVOKED
            row.ended_by = actor
            row.save(update_fields=["ended_at", "end_reason", "ended_by"])
            ended += 1

        from audit.services import audit_service

        audit_service.record_admin_action(
            C.EVENT_DEVICE_REVOKED,
            actor=actor,
            target=device.officer,
            reason=reason,
            context={"device": device.pk, "browser": device.browser, "os": device.operating_system, "sessions_ended": ended},
            request=request,
        )
        return ended


device_session_service = DeviceSessionService()
