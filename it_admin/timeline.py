"""Officer 360° administrative timeline.

Merges identity / security / administrative records into one chronological
view. Sources are the *existing* audit trail plus the posting-history,
device, session and review registries — nothing is duplicated into a new
table. Investigation / case data is never consulted.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from accounts import constants as C
from audit.models import AuditEvent

from .models import AccessReview, ApprovalRequest

EVENT_LABELS = {
    C.EVENT_ACCOUNT_CREATED: "Officer created",
    C.EVENT_ACCOUNT_ACTIVATED: "Account activated",
    C.EVENT_ACCOUNT_REACTIVATED: "Account reactivated",
    C.EVENT_ACCOUNT_SUSPENDED: "Account suspended",
    C.EVENT_ACCOUNT_DISABLED: "Account disabled",
    C.EVENT_ACCOUNT_DEACTIVATED: "Account deactivated",
    C.EVENT_ACCOUNT_LOCKED: "Account locked",
    C.EVENT_ACCOUNT_EMERGENCY_LOCKED: "Emergency lock applied",
    C.EVENT_ACCOUNT_UNLOCKED: "Account unlocked",
    C.EVENT_ACCOUNT_STATUS_CHANGED: "Account status changed",
    C.EVENT_PASSWORD_RESET: "Password reset by administrator",
    C.EVENT_PASSWORD_CHANGED: "Password changed",
    C.EVENT_SECRET_CODE_RESET: "Security code reset",
    C.EVENT_SECRET_CODE_CHANGED: "Security code set",
    C.EVENT_MFA_CHANGED: "MFA updated",
    C.EVENT_ROLE_CHANGED: "Role changed",
    C.EVENT_CLEARANCE_CHANGED: "Clearance changed",
    C.EVENT_UNIT_CHANGED: "Unit changed",
    C.EVENT_PORTAL_GRANTED: "Portal access granted",
    C.EVENT_PORTAL_REVOKED: "Portal access revoked",
    C.EVENT_OFFICER_UPDATED: "Identity details updated",
    C.EVENT_DESIGNATION_CHANGED: "Designation changed",
    C.EVENT_DEPARTMENT_CHANGED: "Department changed",
    C.EVENT_TRANSFER_COMPLETED: "Transfer completed",
    C.EVENT_DEVICE_REGISTERED: "Device registered",
    C.EVENT_DEVICE_REVOKED: "Device revoked",
    C.EVENT_SESSION_TERMINATED: "Session terminated",
    C.EVENT_TEMPORARY_ACCESS_GRANTED: "Temporary capability granted",
    C.EVENT_TEMPORARY_ACCESS_REVOKED: "Temporary capability revoked",
    C.EVENT_ACCESS_REVIEW_CREATED: "Access review raised",
    C.EVENT_ACCESS_REVIEW_DECIDED: "Access review decided",
    C.EVENT_ADMIN_ROLE_CHANGED: "Administrative role changed",
    C.EVENT_APPROVAL_REQUESTED: "Approval requested",
    C.EVENT_APPROVAL_GRANTED: "Approval granted",
    C.EVENT_APPROVAL_REJECTED: "Approval rejected",
    C.EVENT_APPROVAL_CANCELLED: "Approval cancelled",
    C.EVENT_BULK_OPERATION: "Bulk operation",
}

TONE = {
    "danger": {C.EVENT_ACCOUNT_SUSPENDED, C.EVENT_ACCOUNT_DISABLED, C.EVENT_ACCOUNT_DEACTIVATED,
               C.EVENT_ACCOUNT_LOCKED, C.EVENT_ACCOUNT_EMERGENCY_LOCKED, C.EVENT_DEVICE_REVOKED,
               C.EVENT_SESSION_TERMINATED, C.EVENT_PORTAL_REVOKED, C.EVENT_TEMPORARY_ACCESS_REVOKED,
               C.EVENT_APPROVAL_REJECTED},
    "success": {C.EVENT_ACCOUNT_CREATED, C.EVENT_ACCOUNT_ACTIVATED, C.EVENT_ACCOUNT_REACTIVATED,
                C.EVENT_ACCOUNT_UNLOCKED, C.EVENT_TRANSFER_COMPLETED, C.EVENT_APPROVAL_GRANTED,
                C.EVENT_PORTAL_GRANTED, C.EVENT_TEMPORARY_ACCESS_GRANTED},
}


@dataclass
class TimelineEntry:
    time: datetime
    actor: str
    event: str
    detail: str
    result: str
    tone: str = "info"
    source: str = "audit"
    previous_state: Optional[dict] = None
    new_state: Optional[dict] = None
    event_type: str = ""


def _fmt_state(d: Optional[dict]) -> str:
    if not d:
        return ""
    return ", ".join(f"{k}: {v if v not in (None, '') else '—'}" for k, v in d.items())


def _detail_for(event: AuditEvent) -> str:
    parts = []
    if event.previous_state or event.new_state:
        before, after = _fmt_state(event.previous_state), _fmt_state(event.new_state)
        if before and after:
            parts.append(f"{before} → {after}")
        elif after:
            parts.append(after)
        elif before:
            parts.append(f"was {before}")
    elif event.context:
        ctx = event.context
        if "from" in ctx or "to" in ctx:
            parts.append(f"{ctx.get('from') or '—'} → {ctx.get('to') or '—'}")
        elif ctx:
            parts.append(_fmt_state(ctx))
    if event.reason:
        parts.append(f"Reason: {event.reason}")
    if event.portal and event.event_type in (C.EVENT_PORTAL_GRANTED, C.EVENT_PORTAL_REVOKED):
        parts.insert(0, f"Portal {event.portal}")
    return " · ".join(parts)


def build_timeline(officer, limit: int = 300) -> list[TimelineEntry]:
    entries: list[TimelineEntry] = []

    audit_qs = (
        AuditEvent.objects.filter(officer=officer, event_type__in=C.ADMIN_TIMELINE_EVENT_TYPES)
        .select_related("actor").order_by("-occurred_at")[:limit]
    )
    for e in audit_qs:
        tone = "info"
        for name, types in TONE.items():
            if e.event_type in types:
                tone = name
        entries.append(TimelineEntry(
            time=e.occurred_at,
            actor=e.actor.officer_id if e.actor else (e.officer_id_snapshot or "system"),
            event=EVENT_LABELS.get(e.event_type, e.event_type.replace("_", " ").capitalize()),
            detail=_detail_for(e),
            result=e.result or "—",
            tone=tone,
            previous_state=e.previous_state or None,
            new_state=e.new_state or None,
            event_type=e.event_type,
        ))

    # Reviews and approvals that target this officer but were audited with a
    # non-officer resource (e.g. role changes requested about them).
    for req in ApprovalRequest.objects.filter(target_type="officer", target_id=officer.officer_id).select_related("requested_by", "decided_by"):
        entries.append(TimelineEntry(
            time=req.requested_at, actor=req.requested_by.officer_id,
            event=f"Approval requested: {req.get_action_display()}",
            detail=f"{req.summary} · Reason: {req.reason}", result=req.status, tone="info", source="approval",
        ))
    for rev in AccessReview.objects.filter(officer=officer).select_related("created_by", "reviewed_by"):
        entries.append(TimelineEntry(
            time=rev.created_at, actor=rev.created_by.officer_id if rev.created_by else "system",
            event="Access review raised", detail=rev.trigger, result=rev.status, tone="info", source="review",
        ))

    # De-duplicate identical (time, event) pairs coming from two sources and
    # sort newest first.
    seen, unique = set(), []
    for entry in entries:
        key = (entry.time.replace(microsecond=0), entry.event, entry.source)
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    unique.sort(key=lambda x: x.time, reverse=True)
    return unique
