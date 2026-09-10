"""Audit recording service — the single write-path into the audit trail."""
from __future__ import annotations

import hashlib
from typing import Any, Optional

from django.http import HttpRequest

from accounts import constants as C
from .models import AuditEvent, SecurityEvent


def _hash_session_key(session_key: Optional[str]) -> str:
    if not session_key:
        return ""
    return hashlib.sha256(session_key.encode()).hexdigest()


def _request_meta(request: Optional[HttpRequest]) -> dict:
    """Extract non-sensitive contextual metadata from a request."""
    meta = {"ip_address": None, "user_agent": "", "session_id": ""}
    if request is None:
        return meta

    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        meta["ip_address"] = xff.split(",")[0].strip()
    else:
        meta["ip_address"] = request.META.get("REMOTE_ADDR")

    meta["user_agent"] = (request.META.get("HTTP_USER_AGENT") or "")[:300]
    session = getattr(request, "session", None)
    meta["session_id"] = _hash_session_key(getattr(session, "session_key", None))
    return meta


class AuditService:
    """Append-only audit writer.

    Deliberately offers no update/delete methods — the trail is immutable.
    """

    # -- Audit events --------------------------------------------------------
    def record_event(
        self,
        event_type: str,
        *,
        officer=None,
        actor=None,
        officer_id_snapshot: str = "",
        portal: str = "",
        resource_type: str = "",
        resource_id: str = "",
        action: str = "",
        result: str = "",
        reason: str = "",
        context: Optional[dict] = None,
        request: Optional[HttpRequest] = None,
    ) -> AuditEvent:
        meta = _request_meta(request)
        snapshot = officer_id_snapshot or (officer.officer_id if officer is not None else "")

        event = AuditEvent.objects.create(
            event_type=event_type,
            officer=officer,
            officer_id_snapshot=snapshot,
            actor=actor,
            portal=portal,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            result=result,
            reason=reason[:255],
            ip_address=meta["ip_address"],
            user_agent=meta["user_agent"],
            session_id=meta["session_id"],
            context=context or {},
        )
        return event

    # -- Security events ------------------------------------------------------
    def record_security_event(
        self,
        event_type: str,
        severity: str = C.SEVERITY_INFO,
        *,
        officer=None,
        details: Optional[dict] = None,
        request: Optional[HttpRequest] = None,
    ) -> SecurityEvent:
        meta = _request_meta(request)
        event = SecurityEvent.objects.create(
            event_type=event_type,
            severity=severity,
            officer=officer,
            source_ip=meta["ip_address"],
            user_agent=meta["user_agent"],
            details=details or {},
        )
        return event

    # -- Convenience helpers --------------------------------------------------
    def record_denied(
        self,
        *,
        officer,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        portal: str = "",
        reason: str = "",
        request: Optional[HttpRequest] = None,
    ) -> AuditEvent:
        """Standardized access-denied event (spec §28)."""
        return self.record_event(
            C.EVENT_ACCESS_DENIED,
            officer=officer,
            actor=officer,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            portal=portal,
            result=C.RESULT_DENY,
            reason=reason,
            request=request,
        )


audit_service = AuditService()
