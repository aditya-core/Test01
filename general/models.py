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
from django.db import IntegrityError, models, transaction
from django.utils import timezone

from accounts import constants as C
from accounts.authorization import ResourceRequirement
from accounts.models import organization_descendant_ids


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


#: Guard against an unbounded retry loop if something is systematically wrong
#: with the counter.
CASE_ID_MAX_ATTEMPTS = 50


def _next_case_id() -> str:
    """Return the next free ``CASE-YYYYMMDD-NNNN`` number read from the DB.

    Always recomputed from live rows, so a caller that just lost a race gets a
    genuinely new number rather than retrying the one that was taken.
    """
    date_prefix = timezone.localdate().strftime("%Y%m%d")
    prefix = f"CASE-{date_prefix}-"
    highest = (
        CaseRecord.objects.filter(case_id__startswith=prefix)
        .aggregate(models.Max("case_id"))
        .get("case_id__max")
    )
    seq = 1
    if highest:
        try:
            seq = int(highest.rsplit("-", 1)[-1]) + 1
        except (TypeError, ValueError, IndexError):
            seq = 1
    candidate = f"{prefix}{seq:04d}"
    while CaseRecord.objects.filter(case_id=candidate).exists():
        seq += 1
        candidate = f"{prefix}{seq:04d}"
    return candidate


def _generate_case_id() -> str:
    return _next_case_id()


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
    unit = models.ForeignKey(
        "accounts.OrganizationUnit",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="cases",
        help_text="Station / unit that owns this case (hierarchical access root).",
    )

    class Meta:
        ordering = ["-updated_at", "-created_at"]

    def save(self, *args, **kwargs):
        """Persist the case, allocating an identifier first when it is new.

        ``case_id`` is UNIQUE, so the database — not this method — is the
        final arbiter of the number. Two concurrent registrations that compute
        the same candidate collide on INSERT; the loser rolls back to the
        savepoint, takes the next free number and retries, so identifiers are
        never duplicated and never silently reused.
        """
        if self.case_id:
            return super().save(*args, **kwargs)
        self.case_id = _generate_case_id()
        for _ in range(CASE_ID_MAX_ATTEMPTS):
            try:
                with transaction.atomic():
                    return super().save(*args, **kwargs)
            except IntegrityError:
                taken = CaseRecord.objects.filter(case_id=self.case_id)
                if self.pk is not None:
                    taken = taken.exclude(pk=self.pk)
                if not taken.exists():
                    raise  # a different constraint failed -- do not mask it.
                self.case_id = _next_case_id()
        raise IntegrityError("Could not allocate a unique case id.")

    def __str__(self) -> str:
        return f"{self.case_id} - {self.title}"

    @property
    def recent_activity(self):
        return self.updated_at or self.created_at

    @property
    def security_requirement(self) -> ResourceRequirement:
        """What this case demands of a requester (the resource protocol).

        These values describe the *resource* and are therefore static. The
        per-officer facts (assignment, hierarchy, grants, capability) are
        resolved separately by the engine, so it can combine "may anyone do
        this at all?" with "may *this* officer do it?".
        """
        return ResourceRequirement(
            resource_type=C.RESOURCE_CASE,
            resource_id=self.case_id,
            classification_code=self.classification.code if self.classification_id else None,
            organization_id=self.organization_id,
            unit_id=self.unit_id,
            case_id=self.case_id,
            allowed_actions=C.CASE_ACTIONS,
        )

    @property
    def fir_requirement(self) -> ResourceRequirement:
        """The FIR treated as its own protected resource (see directive §20).

        File access is decided independently: having a case open does not imply
        being allowed to download its FIR.
        """
        return ResourceRequirement(
            resource_type=C.RESOURCE_FIR,
            resource_id=self.case_id,
            classification_code=self.classification.code if self.classification_id else None,
            organization_id=self.organization_id,
            unit_id=self.unit_id,
            case_id=self.case_id,
            allowed_actions=C.FILE_ACTIONS,
        )

    @property
    def fir_resource(self) -> "CaseFir":
        """The FIR exposed as a first-class protected resource."""
        return CaseFir(self)

    def officers_with_access(self):
        """Active assignments on this case (ordered by grant time)."""
        return self.assignments.filter(revoked_at__isnull=True).select_related("officer")


class CaseFir:
    """The case's FIR, addressed as its own resource.

    The FIR is a field on ``CaseRecord`` rather than a row, so this tiny
    adapter lets the authorization engine treat it like any other file
    resource instead of special-casing it in views.
    """

    def __init__(self, case):
        self.case = case

    @property
    def security_requirement(self) -> ResourceRequirement:
        return self.case.fir_requirement

    def __str__(self) -> str:
        return f"{self.case.case_id} — FIR"



class CaseEvidenceFile(models.Model):
    case = models.ForeignKey(CaseRecord, on_delete=models.CASCADE, related_name="evidence_files")
    file = models.FileField(upload_to=case_storage_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        ordering = ["uploaded_at"]

    def __str__(self) -> str:
        return f"{self.case.case_id} - {self.file.name}"

    @property
    def security_requirement(self) -> ResourceRequirement:
        """Evidence is authorized independently of the case (directive §20)."""
        case = self.case
        return ResourceRequirement(
            resource_type=C.RESOURCE_EVIDENCE,
            resource_id=str(self.pk),
            classification_code=case.classification.code if case.classification_id else None,
            organization_id=case.organization_id,
            unit_id=case.unit_id,
            case_id=case.case_id,
            allowed_actions=C.FILE_ACTIONS,
        )


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


class CaseDocument(models.Model):
    """A general document attached to a case (reports, statements, ...).

    Separate from evidence: a document is case paperwork, evidence is
    exhibit material. Both are protected resources decided by the engine.
    """

    case = models.ForeignKey(CaseRecord, on_delete=models.CASCADE, related_name="documents")
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to=case_storage_path)
    classification = models.ForeignKey(
        "accounts.ClearanceLevel",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="documents",
        help_text="Defaults to the case classification when left empty.",
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["uploaded_at"]

    def __str__(self) -> str:
        return f"{self.case.case_id} - {self.title}"

    @property
    def effective_classification(self):
        return self.classification or self.case.classification

    @property
    def security_requirement(self) -> ResourceRequirement:
        return ResourceRequirement(
            resource_type=C.RESOURCE_DOCUMENT,
            resource_id=str(self.pk),
            classification_code=(
                self.effective_classification.code if self.effective_classification_id else None
            ),
            organization_id=self.case.organization_id,
            unit_id=self.case.unit_id,
            case_id=self.case.case_id,
            allowed_actions=C.FILE_ACTIONS,
        )


class AccessGrant(models.Model):
    """An explicit delegation of access to a protected resource.

    This is the "someone decided this officer may see this" record. It is an
    *additional* authorization path, never an override: a grant can never
    defeat an inactive account, insufficient clearance, a security block or
    a missing capability (see directive §12).

    A grant targets exactly one resource, except for the place-based scopes
    (STATION / JURISDICTION) which cover every permitted resource in that
    place. ``batch_id`` groups the rows created by one "selected cases" action.
    """

    grantor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="access_grants_made"
    )

    # Exactly one recipient dimension is normally set.
    recipient_officer = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE,
        related_name="access_grants",
    )
    recipient_department = models.ForeignKey(
        "accounts.Department", null=True, blank=True, on_delete=models.CASCADE,
        related_name="access_grants",
    )
    recipient_unit = models.ForeignKey(
        "accounts.OrganizationUnit", null=True, blank=True, on_delete=models.CASCADE,
        related_name="access_grants",
    )
    recipient_organization = models.ForeignKey(
        "accounts.Organization", null=True, blank=True, on_delete=models.CASCADE,
        related_name="access_grants",
    )

    scope = models.CharField(max_length=16, choices=C.GRANT_SCOPE_CHOICES, default=C.GRANT_SCOPE_CASE)
    resource_type = models.CharField(max_length=16, choices=C.RESOURCE_TYPE_CHOICES, default=C.RESOURCE_CASE)
    resource_id = models.CharField(max_length=64, blank=True, default="")
    batch_id = models.UUIDField(null=True, blank=True, db_index=True)

    actions = models.JSONField(default=list, help_text="Actions this grant confers.")
    reason = models.CharField(max_length=255)

    starts_at = models.DateTimeField()
    expires_at = models.DateTimeField(null=True, blank=True)

    status = models.CharField(
        max_length=12, choices=C.GRANT_STATUS_CHOICES, default=C.GRANT_STATUS_ACTIVE, db_index=True
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="access_grants_approved",
    )

    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    revoke_reason = models.CharField(max_length=255, blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["resource_type", "resource_id", "status"]),
            models.Index(fields=["recipient_officer", "status"]),
            models.Index(fields=["status", "expires_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.recipient_label} → {self.resource_type}:{self.resource_id} [{self.effective_status}]"

    def clean(self):
        super().clean()
        from django.core.exceptions import ValidationError

        if not any([
            self.recipient_officer_id, self.recipient_department_id,
            self.recipient_unit_id, self.recipient_organization_id,
        ]):
            raise ValidationError("A grant must name at least one recipient.")
        if self.expires_at and self.starts_at and self.expires_at <= self.starts_at:
            raise ValidationError({"expires_at": "Expiry must be after the start."})

    @property
    def recipient_label(self) -> str:
        for attr in ("recipient_officer", "recipient_department", "recipient_unit", "recipient_organization"):
            target = getattr(self, attr, None)
            if target is not None:
                return getattr(target, "officer_id", None) or str(target)
        return "—"

    @property
    def is_expired(self) -> bool:
        return bool(self.expires_at and timezone.now() >= self.expires_at)

    @property
    def is_revoked(self) -> bool:
        return self.status == C.GRANT_STATUS_REVOKED

    @property
    def effective_status(self) -> str:
        if self.is_revoked:
            return "REVOKED"
        if self.is_expired:
            return "EXPIRED"
        if timezone.now() < self.starts_at:
            return "SCHEDULED"
        return "ACTIVE"

    @property
    def is_currently_active(self) -> bool:
        return self.effective_status == "ACTIVE"

    def actions_for_officer(self, officer) -> frozenset:
        """Actions this grant confers on ``officer`` right now (empty if not)."""
        if not self.is_currently_active or not self.covers_officer(officer):
            return frozenset()
        return frozenset(a for a in (self.actions or []) if a in C.CASE_ACTIONS)

    def case_id_for_resource(self) -> str:
        """The parent case id for file resources (empty for a case itself).

        Lets a grant written against a case cover its files without requiring a
        separate grant per file.
        """
        if self.resource_type == C.RESOURCE_CASE:
            return self.resource_id
        if self.resource_type == C.RESOURCE_FIR:
            return self.resource_id
        from django.apps import apps

        model_name = {
            C.RESOURCE_EVIDENCE: "CaseEvidenceFile",
            C.RESOURCE_DOCUMENT: "CaseDocument",
        }.get(self.resource_type)
        if not model_name:
            return ""
        try:
            model = apps.get_model("general", model_name)
        except LookupError:
            return ""
        obj = model.objects.filter(pk=self.resource_id).select_related("case").first()
        return obj.case.case_id if obj is not None else ""

    def covers_officer(self, officer) -> bool:
        """Does this grant's recipient dimension include ``officer``?"""
        if officer is None:
            return False
        if self.recipient_officer_id:
            return self.recipient_officer_id == officer.pk
        if self.recipient_department_id:
            return self.recipient_department_id == officer.department_id
        if self.recipient_unit_id:
            return self.recipient_unit_id == officer.unit_id
        if self.recipient_organization_id:
            jurisdiction = officer.jurisdiction
            if jurisdiction is None:
                return False
            return jurisdiction.pk in organization_descendant_ids(self.recipient_organization_id)
        return False


class AccessRequest(models.Model):
    """The reverse workflow: an officer asks for access they do not have.

    Requests are never auto-approved. A request is decided by a *different*
    officer who has authority over the resource (directive §18).
    """

    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="access_requests_made"
    )
    resource_type = models.CharField(max_length=16, choices=C.RESOURCE_TYPE_CHOICES, default=C.RESOURCE_CASE)
    resource_id = models.CharField(max_length=64)
    actions = models.JSONField(default=list)
    reason = models.CharField(max_length=255)
    duration_days = models.PositiveSmallIntegerField(default=7)

    status = models.CharField(
        max_length=12, choices=C.REQUEST_STATUS_CHOICES, default=C.REQUEST_PENDING, db_index=True
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="access_requests_decided",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_reason = models.CharField(max_length=255, blank=True, default="")
    grant = models.ForeignKey(AccessGrant, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["resource_type", "resource_id", "status"])]

    def __str__(self) -> str:
        return f"{self.requester.officer_id} → {self.resource_type}:{self.resource_id} [{self.status}]"

    @property
    def is_pending(self) -> bool:
        return self.status == C.REQUEST_PENDING


class CaseTransferRecord(models.Model):
    """Append-only history of a case moving between stations / jurisdictions.

    Access is always computed from the case's *current* location, so a transfer
    immediately changes who can reach it (directive §22 / §24).
    """

    case = models.ForeignKey(CaseRecord, on_delete=models.CASCADE, related_name="transfers")
    from_unit = models.ForeignKey(
        "accounts.OrganizationUnit", null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    from_organization = models.ForeignKey(
        "accounts.Organization", null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    to_unit = models.ForeignKey(
        "accounts.OrganizationUnit", null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    to_organization = models.ForeignKey(
        "accounts.Organization", null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    reason = models.CharField(max_length=255, blank=True, default="")
    transferred_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    transferred_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-transferred_at"]

    def __str__(self) -> str:
        return f"{self.case.case_id} transferred {self.transferred_at:%Y-%m-%d}"
