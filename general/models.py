"""General portal case and evidence models.

Case access is an *operational* authorization decision and is always evaluated
by the central ``AuthorizationService`` — never by filtering in a view. This
module only supplies the data the engine needs:

* ``CaseRecord.security_requirement`` — the resource protocol: the clearance,
  jurisdiction and case identity a requester must satisfy.
* ``CaseAssignment`` — the explicit grant that puts an officer on a case.
"""
from __future__ import annotations

import os
from uuid import uuid4

from django.conf import settings
from django.db import models
from django.utils import timezone

from accounts import constants as C
from accounts.authorization import ResourceRequirement


def case_storage_path(instance, filename):
    """Store uploads under ``cases/<case id>/``.

    ``CaseRecord`` carries ``case_id`` directly; ``CaseEvidenceFile`` reaches it
    through its ``case`` FK. Resolving both keeps FIRs in their own case folder
    instead of a shared "UNASSIGNED" bucket.
    """
    base, ext = os.path.splitext(filename)
    safe_base = base.replace(" ", "_")
    unique_name = f"{safe_base}-{uuid4().hex}{ext}"
    case_id = (
        getattr(instance, "case_id", None)
        or getattr(getattr(instance, "case", None), "case_id", None)
        or "UNASSIGNED"
    )
    return os.path.join("cases", str(case_id), unique_name)


def _generate_case_id() -> str:
    date_prefix = timezone.localdate().strftime("%Y%m%d")
    seq = 1
    while True:
        candidate = f"CASE-{date_prefix}-{seq:04d}"
        if not CaseRecord.objects.filter(case_id=candidate).exists():
            return candidate
        seq += 1


class CaseRecord(models.Model):
    STATUS_OPEN = "Open"
    STATUS_IN_PROGRESS = "In Progress"
    STATUS_PENDING = "Pending"
    STATUS_CLOSED = "Closed"
    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_IN_PROGRESS, "In Progress"),
        (STATUS_PENDING, "Pending"),
        (STATUS_CLOSED, "Closed"),
    ]

    case_id = models.CharField(max_length=32, unique=True, editable=False)
    title = models.CharField(max_length=200)
    case_type = models.CharField(max_length=80)
    police_station = models.CharField(max_length=150, blank=True)
    investigating_agency = models.CharField(max_length=150, blank=True)
    incident_date = models.DateField()
    location = models.CharField(max_length=200, blank=True)
    summary = models.TextField(blank=True)
    complainant_name = models.CharField(max_length=160, blank=True)
    complainant_contact = models.CharField(max_length=50, blank=True)
    status = models.CharField(max_length=24, choices=STATUS_CHOICES, default=STATUS_OPEN)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="cases")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    fir_document = models.FileField(upload_to=case_storage_path, blank=True, null=True)

    # --- Security attributes (consumed by the authorization engine) ---------
    # ``classification`` is the sensitivity band of the case: a requester needs
    # at least this clearance. ``organization`` is the jurisdiction: a
    # requester must be posted inside it.
    classification = models.ForeignKey(
        "accounts.ClearanceLevel",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="cases",
        help_text="Sensitivity of this case; access requires at least this clearance.",
    )
    organization = models.ForeignKey(
        "accounts.Organization",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="cases",
        help_text="Jurisdiction (district / state) the case belongs to.",
    )

    class Meta:
        ordering = ["-updated_at", "-created_at"]

    def save(self, *args, **kwargs):
        if not self.case_id:
            self.case_id = _generate_case_id()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.case_id} - {self.title}"

    @property
    def recent_activity(self):
        return self.updated_at or self.created_at

    @property
    def security_requirement(self) -> ResourceRequirement:
        """What this case demands of a requester (the resource protocol).

        These values describe the *resource* and are therefore static. The
        per-officer action ceiling is resolved separately from the officer's
        ``CaseAssignment`` row, so the engine can combine
        "may anyone do this at all?" with "may *this* officer do it?".
        """
        return ResourceRequirement(
            classification_code=self.classification.code if self.classification_id else None,
            organization_id=self.organization_id,
            case_id=self.case_id,
            allowed_actions=C.CASE_ACTIONS,
        )

    def officers_with_access(self):
        """Active assignments on this case (ordered by grant time)."""
        return self.assignments.filter(revoked_at__isnull=True).select_related("officer")



class CaseEvidenceFile(models.Model):
    case = models.ForeignKey(CaseRecord, on_delete=models.CASCADE, related_name="evidence_files")
    file = models.FileField(upload_to=case_storage_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["uploaded_at"]

    def __str__(self) -> str:
        return f"{self.case.case_id} - {self.file.name}"


class CaseAssignment(models.Model):
    """An explicit grant putting an officer on a case.

    Case authorization is deny-by-default: being an authenticated officer — or
    even the officer who registered the case — is not itself authorization.
    Registration creates an ``OWNER`` assignment so the registering officer is
    authorized through the normal path rather than by a special case in a view.

    This is OPERATIONAL authorization. IT administration never creates or
    revokes these rows (``is_admin_capability`` excludes ``case.*``), and the
    IT portal reports operational access as "managed separately".
    """

    case = models.ForeignKey(CaseRecord, on_delete=models.CASCADE, related_name="assignments")
    officer = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="case_assignments"
    )
    role = models.CharField(
        max_length=16, choices=C.ASSIGNMENT_ROLE_CHOICES, default=C.ASSIGNMENT_INVESTIGATOR
    )
    reason = models.CharField(max_length=255, blank=True, default="")

    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    granted_at = models.DateTimeField(auto_now_add=True)

    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    revoke_reason = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        ordering = ["-granted_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["case", "officer"],
                condition=models.Q(revoked_at__isnull=True),
                name="uniq_active_case_assignment",
            ),
        ]
        indexes = [models.Index(fields=["officer", "revoked_at"])]

    def __str__(self) -> str:
        return f"{self.officer.officer_id} → {self.case.case_id} ({self.role})"

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    @property
    def allowed_actions(self) -> frozenset:
        """The action ceiling this role confers (empty once revoked)."""
        if not self.is_active:
            return frozenset()
        return C.ASSIGNMENT_ROLE_ACTIONS.get(self.role, frozenset())
