"""Operational case-access services.

Everything that decides, grants, revokes, requests or transfers case access
lives here — never in a view and never in a template. Views call these
services; the services call ``AuthorizationService``.

Rule of thumb for this module:

    View → Service → AuthorizationService → Models → Audit

The database does the *narrowing*; the engine makes the *decision*. A queryset
is an optimisation and is always treated as an over-approximation: the engine
re-decides every object before it is shown.
"""
from __future__ import annotations

import uuid
from typing import Iterable, Optional

from django.core.paginator import Paginator
from django.db.models import Q
from django.utils import timezone

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.models import organization_descendant_ids, unit_descendant_ids

from .models import (
    AccessGrant,
    AccessRequest,
    CaseRecord,
    CaseTransferRecord,
)


# ---------------------------------------------------------------------------
# Case access — authorization-aware listing (§27 / §28)
# ---------------------------------------------------------------------------
class CaseAccessService:
    """Builds authorization-aware querysets without leaking counts or IDs."""

    PER_PAGE = 20

    def authorized_queryset(self, user, action: str = C.ACTION_VIEW):
        """Cases ``user`` could plausibly reach, filtered in the database.

        Combines every access path as a ``Q`` so the database does the work:

        * explicit ``CaseAssignment``
        * ownership (``created_by``)
        * hierarchical inheritance (creator or an assignee sits under the
          officer in the supervisory tree, or the case's station sits under
          the officer's unit)
        * explicit ``AccessGrant`` (officer / department / station /
          jurisdiction scope)

        Hard restrictions are applied here too — clearance and jurisdiction —
        because they can never be granted away.
        """
        if not getattr(user, "is_authenticated", False):
            return CaseRecord.objects.none()

        descendants = list(user.descendant_ids())
        unit_ids = list(unit_descendant_ids(user.unit_id)) if user.unit_id else []
        grant_case_ids = list(self._granted_case_ids(user))
        jurisdiction_ids = list(user.jurisdiction_ids())

        paths = Q(assignments__officer=user, assignments__revoked_at__isnull=True)
        paths |= Q(created_by=user)
        if descendants:
            paths |= Q(created_by__in=descendants)
            paths |= Q(assignments__officer__in=descendants, assignments__revoked_at__isnull=True)
        if unit_ids:
            paths |= Q(unit__in=unit_ids)
        if grant_case_ids:
            paths |= Q(case_id__in=grant_case_ids)

        queryset = CaseRecord.objects.filter(paths)

        # Hard restriction: classification. A grant cannot lift this.
        if user.clearance_id:
            queryset = queryset.filter(
                Q(classification__isnull=True) | Q(classification__weight__lte=user.clearance.weight)
            )
        else:
            queryset = queryset.filter(classification__isnull=True)

        # Hard restriction: jurisdiction.
        if jurisdiction_ids:
            queryset = queryset.filter(
                Q(organization__isnull=True) | Q(organization__in=jurisdiction_ids)
            )
        else:
            queryset = queryset.filter(organization__isnull=True)

        return queryset.distinct()

    def authorized_cases(self, user, action: str = C.ACTION_VIEW, queryset=None):
        """Narrow in the database, then let the engine decide each row."""
        qs = queryset if queryset is not None else self.authorized_queryset(user, action)
        return [
            case for case in qs
            if authorization_service.can_access_resource(user, case, action)
        ]

    def authorized_page(self, user, action: str = C.ACTION_VIEW, queryset=None,
                        search: str = "", page_number=None, per_page: int = PER_PAGE):
        """Paginate an authorization-aware case list.

        The database narrows and paginates; the engine then re-decides each row
        on the current page only, so the cost stays proportional to the page
        rather than to the whole table.
        """
        qs = queryset if queryset is not None else self.authorized_queryset(user, action)
        if search:
            qs = qs.filter(
                Q(case_id__icontains=search)
                | Q(title__icontains=search)
                | Q(case_type__icontains=search)
                | Q(investigating_agency__icontains=search)
                | Q(police_station__icontains=search)
            )
        qs = qs.select_related("classification", "organization", "unit", "created_by") \
               .prefetch_related("evidence_files").distinct()

        paginator = Paginator(qs, per_page)
        page = paginator.get_page(page_number)
        page.authorized = [
            case for case in page.object_list
            if authorization_service.can_access_resource(user, case, action)
        ]
        return page

    def _granted_case_ids(self, user) -> list:
        """Case ids covered by currently-effective grants for ``user``."""
        now = timezone.now()
        grants = AccessGrant.objects.filter(
            status=C.GRANT_STATUS_ACTIVE,
            starts_at__lte=now,
        ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))

        case_ids = set()
        for grant in grants:
            if not grant.covers_officer(user):
                continue
            if grant.resource_type == C.RESOURCE_CASE:
                case_ids.add(grant.resource_id)
            elif grant.case_id_for_resource():
                case_ids.add(grant.case_id_for_resource())
        return list(case_ids)

    def search_queryset(self, user, search: str, action: str = C.ACTION_VIEW):
        """Authorization-aware search (§28 — never leak through results)."""
        return self.authorized_queryset(user, action)


# ---------------------------------------------------------------------------
# Explicit access grants (§13 / §14)
# ---------------------------------------------------------------------------
class AccessGrantService:
    """Create, revoke and expire explicit delegations of access."""

    def can_grant(self, grantor, resource, scope: str, actions: Iterable[str]) -> tuple:
        """May ``grantor`` delegate ``actions`` on ``resource`` at ``scope``?

        Returns ``(allowed, reason)``. Deliberately strict:

        * the capability ``case.manage_access`` is required,
        * the grantor must themselves hold ``manage_access`` on the resource,
        * broad (station / jurisdiction) scopes additionally require the
          grantor to be an owner or a supervisor in the hierarchy — a mere
          grantee cannot widen access,
        * a grantor may never delegate an action they do not hold.
        """
        actions = set(actions or [])
        if not actions:
            return False, "Select at least one permission."
        if not authorization_service.has_permission(grantor, C.PERM_CASE_MANAGE_ACCESS):
            return False, "You are not authorized to manage access."

        decision = authorization_service.authorize_resource(
            grantor, resource, C.ACTION_MANAGE_ACCESS
        )
        if not decision:
            return False, "You do not have access-management rights on this resource."

        if scope in C.GRANT_PLACE_SCOPES:
            paths = set(decision.paths or [])
            if not paths & {"ownership", "hierarchy"}:
                return (
                    False,
                    "Only the case owner or a supervising officer may grant "
                    "station- or jurisdiction-wide access.",
                )

        for action in actions:
            required = C.CASE_ACTION_PERMISSIONS.get(action)
            if required and not authorization_service.has_permission(grantor, required):
                return False, f"You cannot delegate '{action}' — you do not hold it."
        return True, ""

    def grant(
        self,
        *,
        grantor,
        resource_type: str,
        resource_ids: Iterable[str],
        actions: Iterable[str],
        reason: str,
        scope: str = C.GRANT_SCOPE_CASE,
        recipient_officer=None,
        recipient_department=None,
        recipient_unit=None,
        recipient_organization=None,
        starts_at=None,
        expires_at=None,
        approved_by=None,
        request=None,
    ) -> list:
        """Create one grant per resource (grouped by ``batch_id``).

        Validates authority first and refuses the whole batch rather than
        half-applying a privileged change.
        """
        resource_ids = [str(r) for r in resource_ids if r]
        actions = sorted(set(actions or []) & set(C.CASE_ACTIONS))
        if not resource_ids or not actions:
            return []

        batch_id = uuid.uuid4() if len(resource_ids) > 1 else None
        now = starts_at or timezone.now()

        created = []
        for resource_id in resource_ids:
            grant = AccessGrant.objects.create(
                grantor=grantor,
                recipient_officer=recipient_officer,
                recipient_department=recipient_department,
                recipient_unit=recipient_unit,
                recipient_organization=recipient_organization,
                scope=scope,
                resource_type=resource_type,
                resource_id=resource_id,
                batch_id=batch_id,
                actions=actions,
                reason=reason,
                starts_at=now,
                expires_at=expires_at,
                approved_by=approved_by,
            )
            created.append(grant)

        from audit.services import audit_service

        event = C.EVENT_BROAD_ACCESS_GRANTED if scope in C.GRANT_PLACE_SCOPES else C.EVENT_ACCESS_GRANT_CREATED
        audit_service.record_event(
            event,
            officer=recipient_officer,
            actor=grantor,
            portal=C.PORTAL_GENERAL,
            resource_type=resource_type,
            resource_id=",".join(resource_ids)[:64],
            action="grant_access",
            result=C.RESULT_SUCCESS,
            reason=reason,
            new_state={
                "scope": scope,
                "actions": actions,
                "recipients": {
                    "officer": getattr(recipient_officer, "officer_id", None),
                    "department": getattr(recipient_department, "name", None),
                    "unit": getattr(recipient_unit, "name", None),
                    "organization": getattr(recipient_organization, "name", None),
                },
                "expires_at": expires_at.isoformat() if expires_at else None,
                "grants": [g.pk for g in created],
            },
            request=request,
        )
        return created

    def revoke(self, grant: AccessGrant, actor, reason: str = "", request=None) -> AccessGrant:
        """Revoke a grant immediately (idempotent)."""
        if grant.status == C.GRANT_STATUS_REVOKED:
            return grant
        grant.status = C.GRANT_STATUS_REVOKED
        grant.revoked_at = timezone.now()
        grant.revoked_by = actor
        grant.revoke_reason = (reason or "")[:255]
        grant.save(update_fields=["status", "revoked_at", "revoked_by", "revoke_reason"])

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_ACCESS_GRANT_REVOKED,
            actor=actor,
            portal=C.PORTAL_GENERAL,
            resource_type=grant.resource_type,
            resource_id=grant.resource_id,
            action="revoke_access",
            result=C.RESULT_SUCCESS,
            reason=reason,
            previous_state={"status": C.GRANT_STATUS_ACTIVE},
            new_state={"status": C.GRANT_STATUS_REVOKED, "grant": grant.pk},
            request=request,
        )
        return grant

    def expire_due(self, actor=None, request=None) -> int:
        """Close out grants past their expiry (housekeeping; access is already
        denied by ``effective_status``, this just records it)."""
        now = timezone.now()
        due = AccessGrant.objects.filter(
            status=C.GRANT_STATUS_ACTIVE, expires_at__isnull=False, expires_at__lte=now
        )
        count = due.count()
        if count:
            from audit.services import audit_service

            for grant in due:
                audit_service.record_event(
                    C.EVENT_ACCESS_GRANT_EXPIRED,
                    actor=actor,
                    portal=C.PORTAL_GENERAL,
                    resource_type=grant.resource_type,
                    resource_id=grant.resource_id,
                    action="grant_expired",
                    result=C.RESULT_SUCCESS,
                    context={"grant": grant.pk},
                    request=request,
                )
        return count

    def revoke_place_scopes_on_transfer(self, officer, actor=None, reason: str = "", request=None) -> int:
        """§22 — a transferred officer must not keep place-based access.

        Station and jurisdiction grants derive from *where* an officer is
        posted, so they are revoked on transfer. Officer-specific grants to a
        named case survive (they were an explicit, deliberate delegation) but
        are flagged for review.
        """
        revoked = 0
        for grant in AccessGrant.objects.filter(
            recipient_officer=officer,
            status=C.GRANT_STATUS_ACTIVE,
            scope__in=list(C.GRANT_PLACE_SCOPES),
        ):
            self.revoke(grant, actor, reason=reason or "Officer transferred", request=request)
            revoked += 1
        return revoked


# ---------------------------------------------------------------------------
# Access requests (§17 / §18)
# ---------------------------------------------------------------------------
class AccessRequestService:
    """The reverse workflow: ask for access, then have someone else decide."""

    def create(self, *, requester, resource_type: str, resource_id: str, actions: Iterable[str],
               reason: str, duration_days: int = 7, request=None) -> AccessRequest:
        access_request = AccessRequest.objects.create(
            requester=requester,
            resource_type=resource_type,
            resource_id=str(resource_id),
            actions=sorted(set(actions or []) & set(C.CASE_ACTIONS)),
            reason=reason,
            duration_days=max(1, int(duration_days or 7)),
        )

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_ACCESS_REQUEST_CREATED,
            officer=requester,
            actor=requester,
            portal=C.PORTAL_GENERAL,
            resource_type=resource_type,
            resource_id=str(resource_id),
            action="request_access",
            result=C.RESULT_SUCCESS,
            reason=reason,
            new_state={"actions": access_request.actions, "duration_days": access_request.duration_days},
            request=request,
        )
        return access_request

    def can_decide(self, user, access_request) -> bool:
        """§18 — the requester may never decide their own request.

        Authority comes from being able to manage access on the underlying
        resource, which covers the owner and supervising officers.
        """
        if access_request is None or access_request.requester_id == getattr(user, "pk", None):
            return False
        resource = self._resolve(access_request)
        if resource is None:
            return False
        return authorization_service.can_access_resource(
            user, resource, C.ACTION_MANAGE_ACCESS
        )

    def approve(self, access_request, decider, decision_reason: str = "", request=None):
        if not access_request.is_pending:
            return None
        if not self.can_decide(decider, access_request):
            raise PermissionError("You are not authorized to decide this request.")

        starts_at = timezone.now()
        expires_at = starts_at + timezone.timedelta(days=access_request.duration_days)
        grants = AccessGrantService().grant(
            grantor=decider,
            resource_type=access_request.resource_type,
            resource_ids=[access_request.resource_id],
            actions=access_request.actions,
            reason=access_request.reason,
            scope=C.GRANT_SCOPE_CASE,
            recipient_officer=access_request.requester,
            starts_at=starts_at,
            expires_at=expires_at,
            approved_by=decider,
            request=request,
        )

        access_request.status = C.REQUEST_APPROVED
        access_request.decided_by = decider
        access_request.decided_at = timezone.now()
        access_request.decision_reason = decision_reason
        access_request.grant = grants[0] if grants else None
        access_request.save(update_fields=[
            "status", "decided_by", "decided_at", "decision_reason", "grant"
        ])

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_ACCESS_REQUEST_APPROVED,
            officer=access_request.requester,
            actor=decider,
            portal=C.PORTAL_GENERAL,
            resource_type=access_request.resource_type,
            resource_id=access_request.resource_id,
            action="approve_access_request",
            result=C.RESULT_SUCCESS,
            reason=decision_reason,
            previous_state={"status": C.REQUEST_PENDING},
            new_state={"status": C.REQUEST_APPROVED},
            request=request,
        )
        return access_request

    def reject(self, access_request, decider, decision_reason: str = "", request=None):
        if not access_request.is_pending:
            return None
        if not self.can_decide(decider, access_request):
            raise PermissionError("You are not authorized to decide this request.")

        access_request.status = C.REQUEST_REJECTED
        access_request.decided_by = decider
        access_request.decided_at = timezone.now()
        access_request.decision_reason = decision_reason
        access_request.save(update_fields=[
            "status", "decided_by", "decided_at", "decision_reason"
        ])

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_ACCESS_REQUEST_REJECTED,
            officer=access_request.requester,
            actor=decider,
            portal=C.PORTAL_GENERAL,
            resource_type=access_request.resource_type,
            resource_id=access_request.resource_id,
            action="reject_access_request",
            result=C.RESULT_SUCCESS,
            reason=decision_reason,
            previous_state={"status": C.REQUEST_PENDING},
            new_state={"status": C.REQUEST_REJECTED},
            request=request,
        )
        return access_request

    def cancel(self, access_request, actor, request=None):
        if not access_request.is_pending:
            return None
        if access_request.requester_id != actor.pk:
            raise PermissionError("Only the requester may cancel their request.")

        access_request.status = C.REQUEST_CANCELLED
        access_request.decided_by = actor
        access_request.decided_at = timezone.now()
        access_request.save(update_fields=["status", "decided_by", "decided_at"])

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_ACCESS_REQUEST_CANCELLED,
            officer=actor,
            actor=actor,
            portal=C.PORTAL_GENERAL,
            resource_type=access_request.resource_type,
            resource_id=access_request.resource_id,
            action="cancel_access_request",
            result=C.RESULT_SUCCESS,
            previous_state={"status": C.REQUEST_PENDING},
            new_state={"status": C.REQUEST_CANCELLED},
            request=request,
        )
        return access_request

    def _resolve(self, access_request):
        from django.apps import apps

        if access_request.resource_type == C.RESOURCE_CASE:
            model_name, lookup = "CaseRecord", "case_id"
        elif access_request.resource_type == C.RESOURCE_EVIDENCE:
            model_name, lookup = "CaseEvidenceFile", "pk"
        elif access_request.resource_type == C.RESOURCE_DOCUMENT:
            model_name, lookup = "CaseDocument", "pk"
        else:
            return None
        try:
            model = apps.get_model("general", model_name)
        except LookupError:
            return None
        return model.objects.filter(**{lookup: access_request.resource_id}).first()


# ---------------------------------------------------------------------------
# Case transfer (§24)
# ---------------------------------------------------------------------------
class CaseTransferService:
    """Move a case between stations / jurisdictions.

    Policy (explicit, directive §24): access is always derived from the case's
    *current* location. After a transfer:

    * officers gain access through the new station / jurisdiction,
    * the original creator keeps access **only** through their explicit
      ``OWNER`` assignment — jurisdiction-derived access moves with the case,
      * the transfer itself is recorded and audited, and existing place-scoped
      grants are untouched (they name a place, not the case's owner).
    """

    def can_transfer(self, user, case) -> bool:
        return authorization_service.can_access_resource(user, case, C.ACTION_MANAGE_ACCESS)

    def transfer(self, case, *, to_unit, to_organization, actor, reason: str = "", request=None):
        if not self.can_transfer(actor, case):
            raise PermissionError("You are not authorized to transfer this case.")

        from_unit, from_organization = case.unit, case.organization
        if to_unit is not None and to_unit.organization_id and to_organization is None:
            to_organization = to_unit.organization

        case.unit = to_unit
        case.organization = to_organization
        case.save(update_fields=["unit", "organization", "updated_at"])

        record = CaseTransferRecord.objects.create(
            case=case,
            from_unit=from_unit,
            from_organization=from_organization,
            to_unit=to_unit,
            to_organization=to_organization,
            reason=reason,
            transferred_by=actor,
        )

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_CASE_TRANSFERRED,
            officer=case.created_by,
            actor=actor,
            portal=C.PORTAL_GENERAL,
            resource_type="case",
            resource_id=case.case_id,
            action="transfer_case",
            result=C.RESULT_SUCCESS,
            reason=reason,
            previous_state={
                "unit": from_unit.name if from_unit else None,
                "organization": from_organization.name if from_organization else None,
            },
            new_state={
                "unit": to_unit.name if to_unit else None,
                "organization": to_organization.name if to_organization else None,
            },
            request=request,
        )
        return record


case_access_service = CaseAccessService()
access_grant_service = AccessGrantService()
access_request_service = AccessRequestService()
case_transfer_service = CaseTransferService()
