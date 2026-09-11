"""Identity-administration services for the IT / Admin portal.

Everything here changes *identity / service / account* state only. None of
these functions grant or revoke operational authorization (case, evidence,
document access) — that belongs to the separate authorization domain and is,
at most, *flagged for review* from here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Optional

from django.db import transaction
from django.utils import timezone

from accounts import constants as C
from accounts.authorization import authorization_service
from accounts.models import (
    Department,
    Designation,
    Officer,
    OrganizationUnit,
    Permission,
    PostingHistory,
    TemporaryCapability,
)
from audit.services import audit_service

from .exceptions import AdminActionError
from .models import AccessReview, ApprovalRequest


# --------------------------------------------------------------------------- helpers
def _label(obj) -> Optional[str]:
    return None if obj is None else str(getattr(obj, "name", obj))


def officer_service_snapshot(officer: Officer) -> dict:
    return {
        "department": _label(officer.department),
        "unit": _label(officer.unit),
        "designation": _label(officer.designation),
    }


def officer_identity_snapshot(officer: Officer) -> dict:
    return {
        "full_name": officer.full_name,
        "employee_id": officer.employee_id,
        "email": officer.email,
        "phone": officer.phone,
        "supervisor": officer.supervisor.officer_id if officer.supervisor else None,
        "joining_date": officer.joining_date,
    }


# --------------------------------------------------------------------------- officer edits
class OfficerAdminService:
    IDENTITY_FIELDS = ("full_name", "employee_id", "email", "phone", "supervisor", "joining_date")

    def update_identity(self, officer: Officer, data: dict, actor: Officer, reason: str = "", request=None) -> list:
        """Apply identity edits and audit the delta. Returns changed field names."""
        before = officer_identity_snapshot(officer)
        changed = []
        for name in self.IDENTITY_FIELDS:
            if name not in data:
                continue
            new = data[name]
            if name == "employee_id" and new:
                new = new.strip().upper()
            if getattr(officer, name) != new:
                setattr(officer, name, new)
                changed.append(name)
        if not changed:
            return []
        with transaction.atomic():
            officer.save()
            after = officer_identity_snapshot(officer)
            audit_service.record_admin_action(
                C.EVENT_OFFICER_UPDATED,
                actor=actor,
                target=officer,
                action="update_identity",
                reason=reason,
                previous_state={k: before[k] for k in changed},
                new_state={k: after[k] for k in changed},
                request=request,
            )
        return changed

    def change_designation(self, officer: Officer, designation: Optional[Designation], actor: Officer,
                           reason: str = "", effective_date: Optional[date] = None, request=None) -> bool:
        old = officer.designation
        if (old.pk if old else None) == (designation.pk if designation else None):
            return False
        if designation is not None and not designation.is_active:
            raise AdminActionError("Selected designation is not available.")
        with transaction.atomic():
            officer.designation = designation
            officer.rank = designation.name if designation else ""
            officer.save(update_fields=["designation", "rank", "updated_at"])
            PostingHistory.objects.create(
                officer=officer,
                kind=C.POSTING_DESIGNATION,
                from_department=officer.department,
                to_department=officer.department,
                from_unit=officer.unit,
                to_unit=officer.unit,
                from_designation=old,
                to_designation=designation,
                effective_date=effective_date or timezone.localdate(),
                reason=reason,
                recorded_by=actor,
            )
            audit_service.record_admin_action(
                C.EVENT_DESIGNATION_CHANGED,
                actor=actor,
                target=officer,
                reason=reason,
                previous_state={"designation": _label(old)},
                new_state={"designation": _label(designation)},
                request=request,
            )
        return True


officer_admin_service = OfficerAdminService()


# --------------------------------------------------------------------------- transfers
@dataclass
class TransferPlan:
    officer: Officer
    to_department: Optional[Department]
    to_unit: Optional[OrganizationUnit]
    to_designation: Optional[Designation]
    effective_date: date
    reason: str
    changes: list = field(default_factory=list)
    authorization_review_required: bool = False

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)


class TransferService:
    """Controlled transfer / posting workflow (Feature #5)."""

    def plan(self, officer: Officer, *, to_department, to_unit, to_designation, effective_date, reason) -> TransferPlan:
        plan = TransferPlan(officer, to_department, to_unit, to_designation, effective_date, reason)
        pairs = (
            ("Department", officer.department, to_department),
            ("Unit", officer.unit, to_unit),
            ("Designation", officer.designation, to_designation),
        )
        for label, old, new in pairs:
            if (old.pk if old else None) != (new.pk if new else None):
                plan.changes.append({"field": label, "from": _label(old) or "—", "to": _label(new) or "—"})
        # A unit move changes organizational scope, which the authorization
        # engine uses. We only *flag* it; nothing operational is changed here.
        if (officer.unit_id or None) != (to_unit.pk if to_unit else None):
            plan.authorization_review_required = True
        return plan

    def validate(self, plan: TransferPlan):
        if plan.to_department is not None and not plan.to_department.is_active:
            raise AdminActionError("Selected department is not available.")
        if plan.to_unit is not None and not plan.to_unit.is_active:
            raise AdminActionError("Selected unit is not available.")
        if plan.to_designation is not None and not plan.to_designation.is_active:
            raise AdminActionError("Selected designation is not available.")
        if plan.to_unit is not None and plan.to_department is not None and plan.to_unit.department_id \
                and plan.to_unit.department_id != plan.to_department.pk:
            raise AdminActionError("Selected unit does not belong to the selected department.")
        if not plan.has_changes:
            raise AdminActionError("No changes to apply — the new posting matches the current one.")

    def apply(self, plan: TransferPlan, actor: Officer, request=None) -> PostingHistory:
        self.validate(plan)
        officer = plan.officer
        before = officer_service_snapshot(officer)
        with transaction.atomic():
            history = PostingHistory.objects.create(
                officer=officer,
                kind=C.POSTING_TRANSFER,
                from_department=officer.department,
                from_unit=officer.unit,
                from_designation=officer.designation,
                to_department=plan.to_department,
                to_unit=plan.to_unit,
                to_designation=plan.to_designation,
                effective_date=plan.effective_date,
                reason=plan.reason,
                authorization_review_required=plan.authorization_review_required,
                recorded_by=actor,
            )
            officer.department = plan.to_department
            officer.unit = plan.to_unit
            officer.designation = plan.to_designation
            officer.rank = plan.to_designation.name if plan.to_designation else ""
            officer.save(update_fields=["department", "unit", "designation", "rank", "updated_at"])

            audit_service.record_admin_action(
                C.EVENT_TRANSFER_COMPLETED,
                actor=actor,
                target=officer,
                reason=plan.reason,
                previous_state=before,
                new_state=officer_service_snapshot(officer),
                context={
                    "effective_date": plan.effective_date,
                    "posting_history": history.pk,
                    "authorization_review_required": plan.authorization_review_required,
                },
                request=request,
            )
            if plan.authorization_review_required:
                # Do not touch role / clearance / portal grants here. Raise a
                # review so an authorized reviewer decides in the proper domain.
                access_review_service.ensure_pending(
                    officer, trigger="Transfer changed organizational unit", created_by=actor, request=request,
                )
        return history


transfer_service = TransferService()


# --------------------------------------------------------------------------- registries
class RegistryService:
    """Designation / Department / Unit CRUD with safety rails."""

    # -- designations -------------------------------------------------------
    def save_designation(self, designation: Designation, actor: Officer, request=None, created: bool = False) -> Designation:
        before = None
        if not created and designation.pk:
            before = Designation.objects.filter(pk=designation.pk).values("code", "name", "rank_level", "description", "is_active").first()
        with transaction.atomic():
            designation.full_clean()
            designation.save()
            audit_service.record_admin_action(
                C.EVENT_DESIGNATION_REGISTRY_CHANGED,
                actor=actor,
                target=designation,
                action="create" if created else "update",
                previous_state=before or {},
                new_state={"code": designation.code, "name": designation.name, "rank_level": designation.rank_level,
                           "description": designation.description, "is_active": designation.is_active},
                request=request,
            )
        return designation

    def set_designation_active(self, designation: Designation, active: bool, actor: Officer, request=None):
        if designation.is_active == active:
            return designation
        if not active and designation.officers.exists():
            # Deactivating is allowed (blocks new assignments) — deletion is not.
            pass
        with transaction.atomic():
            designation.is_active = active
            designation.save(update_fields=["is_active", "updated_at"])
            audit_service.record_admin_action(
                C.EVENT_DESIGNATION_REGISTRY_CHANGED,
                actor=actor, target=designation,
                action="activate" if active else "deactivate",
                previous_state={"is_active": not active}, new_state={"is_active": active},
                request=request,
            )
        return designation

    def delete_designation(self, designation: Designation, actor: Officer, request=None):
        if designation.officers.exists() or PostingHistory.objects.filter(
            models_q_designation(designation)
        ).exists():
            raise AdminActionError("This designation is currently assigned and cannot be removed.")
        with transaction.atomic():
            snapshot = {"code": designation.code, "name": designation.name}
            designation.delete()
            audit_service.record_admin_action(
                C.EVENT_DESIGNATION_REGISTRY_CHANGED, actor=actor, target_type="designation",
                target_id=snapshot["code"], action="delete", previous_state=snapshot, request=request,
            )

    # -- departments ----------------------------------------------------------
    def save_department(self, department: Department, actor: Officer, request=None, created: bool = False) -> Department:
        before = None
        if not created and department.pk:
            before = Department.objects.filter(pk=department.pk).values("code", "name", "description", "is_active").first()
        with transaction.atomic():
            department.full_clean()
            department.save()
            audit_service.record_admin_action(
                C.EVENT_DEPARTMENT_REGISTRY_CHANGED,
                actor=actor, target=department,
                action="create" if created else "update",
                previous_state=before or {},
                new_state={"code": department.code, "name": department.name,
                           "description": department.description, "is_active": department.is_active},
                request=request,
            )
        return department

    def set_department_active(self, department: Department, active: bool, actor: Officer, request=None):
        if department.is_active == active:
            return department
        with transaction.atomic():
            department.is_active = active
            department.save(update_fields=["is_active", "updated_at"])
            audit_service.record_admin_action(
                C.EVENT_DEPARTMENT_REGISTRY_CHANGED, actor=actor, target=department,
                action="activate" if active else "deactivate",
                previous_state={"is_active": not active}, new_state={"is_active": active},
                request=request,
            )
        return department

    # -- units --------------------------------------------------------------------
    def save_unit(self, unit: OrganizationUnit, actor: Officer, request=None, created: bool = False) -> OrganizationUnit:
        before = None
        if not created and unit.pk:
            old = OrganizationUnit.objects.select_related("department", "organization").get(pk=unit.pk)
            before = {"name": old.name, "kind": old.kind, "department": _label(old.department),
                      "organization": old.organization.name, "is_active": old.is_active}
        with transaction.atomic():
            unit.full_clean()
            unit.save()
            audit_service.record_admin_action(
                C.EVENT_UNIT_REGISTRY_CHANGED,
                actor=actor, target=unit, target_id=str(unit.pk),
                action="create" if created else "update",
                previous_state=before or {},
                new_state={"name": unit.name, "kind": unit.kind, "department": _label(unit.department),
                           "organization": unit.organization.name, "is_active": unit.is_active},
                request=request,
            )
        return unit

    def set_unit_active(self, unit: OrganizationUnit, active: bool, actor: Officer, request=None):
        if unit.is_active == active:
            return unit
        with transaction.atomic():
            unit.is_active = active
            unit.save(update_fields=["is_active"])
            audit_service.record_admin_action(
                C.EVENT_UNIT_REGISTRY_CHANGED, actor=actor, target=unit, target_id=str(unit.pk),
                action="activate" if active else "deactivate",
                previous_state={"is_active": not active}, new_state={"is_active": active},
                request=request,
            )
        return unit


def models_q_designation(designation):
    from django.db.models import Q

    return Q(from_designation=designation) | Q(to_designation=designation)


registry_service = RegistryService()


# --------------------------------------------------------------------------- temporary access
class TemporaryAccessService:
    def grant(self, officer: Officer, permission: Permission, *, reason: str, starts_at, expires_at,
              actor: Officer, request=None) -> TemporaryCapability:
        # Only administrative capabilities can be granted temporarily. This is
        # enforced here *and* ignored by the authorization engine, so a stray
        # row can never confer operational access.
        if not C.is_admin_capability(permission.codename):
            raise AdminActionError("Only administrative capabilities can be granted temporarily. "
                                   "Operational authorization is managed separately.")
        if expires_at <= starts_at:
            raise AdminActionError("Expiry must be after the start.")
        if expires_at <= timezone.now():
            raise AdminActionError("Expiry must be in the future.")
        if actor.pk == officer.pk:
            raise AdminActionError("You cannot grant a temporary capability to yourself.")
        with transaction.atomic():
            grant = TemporaryCapability.objects.create(
                officer=officer, permission=permission, reason=reason,
                starts_at=starts_at, expires_at=expires_at, granted_by=actor,
            )
            audit_service.record_admin_action(
                C.EVENT_TEMPORARY_ACCESS_GRANTED, actor=actor, target=officer, reason=reason,
                new_state={"capability": permission.codename, "starts_at": starts_at, "expires_at": expires_at},
                context={"grant": grant.pk}, request=request,
            )
        return grant

    def revoke(self, grant: TemporaryCapability, actor: Officer, reason: str, request=None) -> TemporaryCapability:
        if grant.status == C.TEMP_ACCESS_REVOKED:
            return grant
        with transaction.atomic():
            grant.status = C.TEMP_ACCESS_REVOKED
            grant.revoked_at = timezone.now()
            grant.revoked_by = actor
            grant.revoke_reason = reason[:255]
            grant.save(update_fields=["status", "revoked_at", "revoked_by", "revoke_reason"])
            audit_service.record_admin_action(
                C.EVENT_TEMPORARY_ACCESS_REVOKED, actor=actor, target=grant.officer, reason=reason,
                previous_state={"capability": grant.permission.codename, "status": C.TEMP_ACCESS_ACTIVE},
                new_state={"capability": grant.permission.codename, "status": C.TEMP_ACCESS_REVOKED},
                context={"grant": grant.pk}, request=request,
            )
        return grant


temporary_access_service = TemporaryAccessService()


# --------------------------------------------------------------------------- access reviews
class AccessReviewService:
    REVIEW_INTERVAL_DAYS = 90

    def admin_capability_snapshot(self, officer: Officer) -> dict:
        return {
            "role": officer.role.name if officer.role else None,
            "capabilities": sorted(p for p in authorization_service.get_user_permissions(officer) if C.is_admin_capability(p)),
            "portals": authorization_service.list_authorized_portals(officer),
        }

    def ensure_pending(self, officer: Officer, *, trigger: str, created_by: Optional[Officer], due_at=None, request=None) -> AccessReview:
        existing = AccessReview.objects.filter(officer=officer, status=AccessReview.STATUS_PENDING).first()
        if existing:
            return existing
        with transaction.atomic():
            review = AccessReview.objects.create(
                officer=officer, trigger=trigger[:120], due_at=due_at or timezone.now(),
                snapshot=self.admin_capability_snapshot(officer), created_by=created_by,
            )
            audit_service.record_admin_action(
                C.EVENT_ACCESS_REVIEW_CREATED, actor=created_by, target=officer, reason=trigger,
                context={"review": review.pk}, request=request,
            )
        return review

    def officers_due(self):
        """Officers holding admin capabilities whose last completed review is
        older than the interval (or who were never reviewed)."""
        cutoff = timezone.now() - timezone.timedelta(days=self.REVIEW_INTERVAL_DAYS)
        admin_codenames = [p.codename for p in Permission.objects.all() if C.is_admin_capability(p.codename)]
        holders = (
            Officer.objects.filter(role__permissions__codename__in=admin_codenames)
            .exclude(account_status__in=(C.ACCOUNT_STATUS_DEACTIVATED, C.ACCOUNT_STATUS_DISABLED))
            .select_related("role").distinct()
        )
        pending = set(AccessReview.objects.filter(status=AccessReview.STATUS_PENDING).values_list("officer_id", flat=True))
        due = []
        for officer in holders:
            if officer.pk in pending:
                continue
            last = AccessReview.objects.filter(officer=officer, status=AccessReview.STATUS_COMPLETED).order_by("-reviewed_at").first()
            if last is None or (last.reviewed_at and last.reviewed_at < cutoff):
                officer.last_review_at = last.reviewed_at if last else None
                due.append(officer)
        return due

    def decide(self, review: AccessReview, *, decision: str, note: str, reviewer: Officer, request=None) -> AccessReview:
        if review.status != AccessReview.STATUS_PENDING:
            raise AdminActionError("This review has already been completed.")
        if reviewer.pk == review.officer_id:
            raise AdminActionError("You cannot review your own access.")
        if decision not in dict(AccessReview.DECISION_CHOICES):
            raise AdminActionError("Unknown decision.")
        with transaction.atomic():
            review.decision = decision
            review.decision_note = note[:255]
            review.reviewed_by = reviewer
            review.reviewed_at = timezone.now()
            review.status = AccessReview.STATUS_COMPLETED
            review.save()

            officer = review.officer
            if decision == AccessReview.DECISION_REVOKE:
                # REVOKE means: strip *administrative* capabilities. We do that
                # by ending temporary grants and detaching the admin role. The
                # officer's identity, history and operational attributes stay.
                for grant in TemporaryCapability.objects.filter(officer=officer, status=C.TEMP_ACCESS_ACTIVE):
                    temporary_access_service.revoke(grant, reviewer, reason=f"Access review {review.pk}: revoked", request=request)
                if officer.role and any(C.is_admin_capability(p) for p in officer.role.permissions.values_list("codename", flat=True)):
                    from accounts.services import account_service

                    account_service.assign_role(officer, None, reviewer, reason=f"Access review {review.pk}: revoked", request=request)
            audit_service.record_admin_action(
                C.EVENT_ACCESS_REVIEW_DECIDED, actor=reviewer, target=officer, reason=note,
                new_state={"decision": decision}, context={"review": review.pk}, request=request,
            )
        return review


access_review_service = AccessReviewService()


# --------------------------------------------------------------------------- four-eyes approvals
class ApprovalService:
    """Dual-control for sensitive administrative operations."""

    def request(self, *, action: str, target_type: str, target_id: str, target_label: str, payload: dict,
                summary: str, reason: str, requested_by: Officer, request=None) -> ApprovalRequest:
        if action not in dict(ApprovalRequest.ACTION_CHOICES):
            raise AdminActionError("Unknown approval action.")
        duplicate = ApprovalRequest.objects.filter(
            action=action, target_type=target_type, target_id=str(target_id), status=ApprovalRequest.STATUS_PENDING,
        ).first()
        if duplicate:
            raise AdminActionError("An identical request is already pending approval.")
        with transaction.atomic():
            req = ApprovalRequest.objects.create(
                action=action, target_type=target_type, target_id=str(target_id), target_label=target_label[:160],
                payload=payload, summary=summary[:255], reason=reason, requested_by=requested_by,
            )
            audit_service.record_admin_action(
                C.EVENT_APPROVAL_REQUESTED, actor=requested_by, target_type=target_type, target_id=str(target_id),
                reason=reason, new_state={"action": action, "summary": summary, "status": req.status},
                context={"approval": req.pk}, request=request,
            )
        return req

    def approve(self, req: ApprovalRequest, approver: Officer, decision_reason: str, request=None) -> ApprovalRequest:
        if not req.is_pending:
            raise AdminActionError("This request has already been decided.")
        # Four-eyes rule: the requester can never approve their own request,
        # regardless of role or superuser flag.
        if req.requested_by_id == approver.pk:
            raise AdminActionError("You cannot approve your own request.")
        from .approvals import execute

        with transaction.atomic():
            req.decided_by = approver
            req.decided_at = timezone.now()
            req.decision_reason = decision_reason[:255]
            try:
                req.result = execute(req, approver, request=request)[:255]
                req.status = ApprovalRequest.STATUS_APPROVED
            except AdminActionError as exc:
                req.result = str(exc)[:255]
                req.status = ApprovalRequest.STATUS_FAILED
            req.save()
            audit_service.record_admin_action(
                C.EVENT_APPROVAL_GRANTED, actor=approver, target_type=req.target_type, target_id=req.target_id,
                reason=decision_reason, previous_state={"status": ApprovalRequest.STATUS_PENDING},
                new_state={"status": req.status, "result": req.result},
                result=C.RESULT_SUCCESS if req.status == ApprovalRequest.STATUS_APPROVED else C.RESULT_FAILURE,
                context={"approval": req.pk, "requested_by": req.requested_by.officer_id}, request=request,
            )
        return req

    def reject(self, req: ApprovalRequest, approver: Officer, decision_reason: str, request=None) -> ApprovalRequest:
        if not req.is_pending:
            raise AdminActionError("This request has already been decided.")
        if req.requested_by_id == approver.pk:
            raise AdminActionError("Use “cancel” to withdraw your own request.")
        with transaction.atomic():
            req.status = ApprovalRequest.STATUS_REJECTED
            req.decided_by = approver
            req.decided_at = timezone.now()
            req.decision_reason = decision_reason[:255]
            req.result = "Rejected — no change executed."
            req.save()
            audit_service.record_admin_action(
                C.EVENT_APPROVAL_REJECTED, actor=approver, target_type=req.target_type, target_id=req.target_id,
                reason=decision_reason, previous_state={"status": ApprovalRequest.STATUS_PENDING},
                new_state={"status": req.status}, context={"approval": req.pk}, request=request,
            )
        return req

    def cancel(self, req: ApprovalRequest, actor: Officer, request=None) -> ApprovalRequest:
        if not req.is_pending:
            raise AdminActionError("This request has already been decided.")
        if req.requested_by_id != actor.pk:
            raise AdminActionError("Only the requester can cancel a pending request.")
        with transaction.atomic():
            req.status = ApprovalRequest.STATUS_CANCELLED
            req.decided_by = actor
            req.decided_at = timezone.now()
            req.result = "Cancelled by requester."
            req.save()
            audit_service.record_admin_action(
                C.EVENT_APPROVAL_CANCELLED, actor=actor, target_type=req.target_type, target_id=req.target_id,
                previous_state={"status": ApprovalRequest.STATUS_PENDING}, new_state={"status": req.status},
                context={"approval": req.pk}, request=request,
            )
        return req


approval_service = ApprovalService()
