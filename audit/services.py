"""Audit recording service — the single write-path into the audit trail."""
from __future__ import annotations

import hashlib
from typing import Any, Optional

from django.db import transaction
from django.http import HttpRequest

from accounts import constants as C

from .hashing import GENESIS_HASH, compute_event_hash, event_hash_fields
from .models import AuditChainHead, AuditEvent, SecurityEvent


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


def _jsonable(value: Any) -> Any:
    """Coerce model instances / dates into JSON-friendly primitives."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "pk") and hasattr(value, "_meta"):
        # Model instance → human label (never a secret).
        for attr in ("officer_id", "codename", "code", "name", "key"):
            label = getattr(value, attr, None)
            if label:
                return str(label)
        return str(value)
    return str(value)


class AuditService:
    """Append-only audit writer.

    Deliberately offers no update/delete methods — the trail is immutable.
    Every event is linked into the tamper-evident hash chain.
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
        previous_state: Optional[dict] = None,
        new_state: Optional[dict] = None,
        request: Optional[HttpRequest] = None,
    ) -> AuditEvent:
        meta = _request_meta(request)
        snapshot = officer_id_snapshot or (officer.officer_id if officer is not None else "")

        # The chain head row is locked for the duration of the insert so that
        # sequence numbers are strictly serial. This runs inside whatever
        # outer transaction the caller opened (atomic is re-entrant), so an
        # administrative change and its audit row commit — or roll back —
        # together.
        with transaction.atomic():
            head, _ = AuditChainHead.objects.select_for_update().get_or_create(singleton=True)
            sequence = head.last_sequence + 1
            previous_hash = head.last_hash or GENESIS_HASH

            event = AuditEvent(
                event_type=event_type,
                officer=officer,
                officer_id_snapshot=snapshot,
                actor=actor,
                portal=portal,
                resource_type=resource_type,
                resource_id=str(resource_id)[:64] if resource_id else "",
                action=action,
                result=result,
                reason=(reason or "")[:255],
                ip_address=meta["ip_address"],
                user_agent=meta["user_agent"],
                session_id=meta["session_id"],
                context=_jsonable(context or {}),
                previous_state=_jsonable(previous_state or {}),
                new_state=_jsonable(new_state or {}),
                sequence=sequence,
                previous_hash=previous_hash,
            )
            # ``occurred_at`` is auto_now_add; it is only known after the first
            # save, so the hash is computed and written in a second, guarded
            # save of the same row inside the same transaction.
            event.save()
            event.current_hash = compute_event_hash(previous_hash, event_hash_fields(event))
            event.save(update_fields=["current_hash"], _chain_write=True)

            head.last_sequence = sequence
            head.last_hash = event.current_hash
            head.save(update_fields=["last_sequence", "last_hash", "updated_at"])
        return event

    def record_admin_action(
        self,
        event_type: str,
        *,
        actor,
        target=None,
        target_type: str = "",
        target_id: str = "",
        action: str = "",
        reason: str = "",
        previous_state: Optional[dict] = None,
        new_state: Optional[dict] = None,
        result: str = C.RESULT_SUCCESS,
        context: Optional[dict] = None,
        request: Optional[HttpRequest] = None,
    ) -> AuditEvent:
        """Convenience wrapper for IT-administration events.

        ``target`` may be an Officer (recorded as the event's ``officer``) or
        any other registry object (recorded as resource_type/resource_id).
        """
        officer = None
        if target is not None and hasattr(target, "officer_id") and hasattr(target, "account_status"):
            officer = target
            target_type = target_type or "officer"
            target_id = target_id or target.officer_id
        elif target is not None:
            target_type = target_type or target._meta.model_name
            target_id = target_id or str(getattr(target, "code", None) or getattr(target, "pk", ""))
        return self.record_event(
            event_type,
            officer=officer,
            actor=actor,
            portal=C.PORTAL_IT_ADMIN,
            resource_type=target_type,
            resource_id=target_id,
            action=action or event_type.lower(),
            result=result,
            reason=reason,
            context=context,
            previous_state=previous_state,
            new_state=new_state,
            request=request,
        )

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
            details=_jsonable(details or {}),
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

    # -- Chain verification -----------------------------------------------------
    def verify_chain(self, limit: Optional[int] = None) -> dict:
        """Walk the chain in sequence order and recompute every hash.

        Returns a summary dict: ``{"ok": bool, "checked": n, "first_break":
        sequence-or-None, "unchained": count-of-legacy-rows}``. Rows written
        before the chain existed (``sequence`` NULL) are reported but not
        treated as failures.
        """
        qs = AuditEvent.objects.filter(sequence__isnull=False).order_by("sequence")
        if limit:
            qs = qs[:limit]
        expected_prev = GENESIS_HASH
        expected_seq = None
        checked = 0
        first_break = None
        for event in qs.iterator():
            if expected_seq is not None and event.sequence != expected_seq:
                first_break = event.sequence
                break
            if event.previous_hash != expected_prev:
                first_break = event.sequence
                break
            recomputed = compute_event_hash(event.previous_hash, event_hash_fields(event))
            if recomputed != event.current_hash:
                first_break = event.sequence
                break
            expected_prev = event.current_hash
            expected_seq = event.sequence + 1
            checked += 1
        unchained = AuditEvent.objects.filter(sequence__isnull=True).count()
        return {
            "ok": first_break is None,
            "checked": checked,
            "first_break": first_break,
            "unchained": unchained,
        }


audit_service = AuditService()
