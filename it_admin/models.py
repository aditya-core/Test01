"""IT / Admin portal models — administrative governance records.

These models govern *how the IT administration itself is controlled*:
four-eyes approval of sensitive administrative changes and periodic access
reviews. They live here (not in ``accounts``) because they are workflow
records of the admin portal, not identity attributes.

They never reference case / evidence / document data.
"""
from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils import timezone


class ApprovalRequest(models.Model):
    """A sensitive administrative change awaiting a second administrator.

    Flow: requested (PENDING) → approved/rejected by a *different* officer
    holding ``approval.review`` → on approval the stored payload is executed
    by ``it_admin.approvals.execute`` and the outcome is recorded.
    """

    ACTION_ADMIN_ROLE_CHANGE = "ADMIN_ROLE_CHANGE"
    ACTION_ROLE_CAPABILITIES = "ROLE_CAPABILITY_CHANGE"
    ACTION_PRIVILEGED_DEACTIVATE = "PRIVILEGED_ACCOUNT_DEACTIVATE"
    ACTION_CHOICES = (
        (ACTION_ADMIN_ROLE_CHANGE, "Change an administrator's role"),
        (ACTION_ROLE_CAPABILITIES, "Change capabilities of an administrative role"),
        (ACTION_PRIVILEGED_DEACTIVATE, "Deactivate a privileged account"),
    )

    STATUS_PENDING = "PENDING"
    STATUS_APPROVED = "APPROVED"
    STATUS_REJECTED = "REJECTED"
    STATUS_CANCELLED = "CANCELLED"
    STATUS_FAILED = "FAILED"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending approval"),
        (STATUS_APPROVED, "Approved & executed"),
        (STATUS_REJECTED, "Rejected"),
        (STATUS_CANCELLED, "Cancelled by requester"),
        (STATUS_FAILED, "Approved but execution failed"),
    )

    action = models.CharField(max_length=40, choices=ACTION_CHOICES)
    target_type = models.CharField(max_length=32)
    target_id = models.CharField(max_length=64)
    target_label = models.CharField(max_length=160, blank=True, default="")
    payload = models.JSONField(default=dict, blank=True, help_text="Parameters needed to execute the change.")
    summary = models.CharField(max_length=255, blank=True, default="")

    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="approval_requests_made"
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    reason = models.CharField(max_length=255)

    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="approval_requests_decided",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_reason = models.CharField(max_length=255, blank=True, default="")
    result = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        ordering = ["-requested_at"]

    def __str__(self) -> str:
        return f"{self.get_action_display()} → {self.target_label or self.target_id} [{self.status}]"

    @property
    def is_pending(self) -> bool:
        return self.status == self.STATUS_PENDING


class AccessReview(models.Model):
    """A periodic attestation that an officer's *administrative* access is
    still appropriate. Decisions: KEEP / MODIFY / REVOKE.

    Reviews concern admin capabilities only. Operational authorization is
    reviewed by the operational domain, not here.
    """

    STATUS_PENDING = "PENDING"
    STATUS_COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (STATUS_PENDING, "Pending review"),
        (STATUS_COMPLETED, "Completed"),
    )

    DECISION_KEEP = "KEEP"
    DECISION_MODIFY = "MODIFY"
    DECISION_REVOKE = "REVOKE"
    DECISION_CHOICES = (
        (DECISION_KEEP, "Keep access"),
        (DECISION_MODIFY, "Modify access"),
        (DECISION_REVOKE, "Revoke access"),
    )

    officer = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="access_reviews"
    )
    due_at = models.DateTimeField(default=timezone.now)
    trigger = models.CharField(max_length=120, blank=True, default="", help_text="Why the review was raised.")
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    snapshot = models.JSONField(default=dict, blank=True, help_text="Admin capabilities at the time of review.")

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    decision = models.CharField(max_length=8, choices=DECISION_CHOICES, blank=True, default="")
    decision_note = models.CharField(max_length=255, blank=True, default="")
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="access_reviews_done"
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["status", "due_at"]

    def __str__(self) -> str:
        return f"Access review {self.officer.officer_id} [{self.status}]"

    @property
    def is_overdue(self) -> bool:
        return self.status == self.STATUS_PENDING and self.due_at < timezone.now()
