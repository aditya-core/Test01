"""Central identity models.

``Officer`` is the custom Django User model (``AUTH_USER_MODEL``). One real
officer has exactly one identity; the portals they may enter are determined by
authorization attributes (role, clearance, scope, portal grants) — never by
separate per-portal user tables.
"""
from __future__ import annotations

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from . import constants as C
from .managers import OfficerManager


# ---------------------------------------------------------------------------
# Organizational hierarchy (data-driven: National → State → District → Unit)
# ---------------------------------------------------------------------------
class Organization(models.Model):
    """A level of the administrative hierarchy.

    MVP seeds a single DISTRICT; the model already supports National/State
    parents so multi-district and national rollout need no migration.
    """

    name = models.CharField(max_length=120, unique=True)
    kind = models.CharField(max_length=16, choices=C.ORG_KIND_CHOICES)
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="children",
        help_text="Parent level (State → District → ...).",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["kind", "name"]
        verbose_name_plural = "organizations"

    def __str__(self) -> str:
        return f"{self.name} ({self.kind})"

    def scope_chain(self):
        """Return [self, parent, ...] up the hierarchy for scope comparisons."""
        chain, node = [], self
        while node is not None:
            chain.append(node)
            node = node.parent
        return chain


class OrganizationUnit(models.Model):
    """An operational unit that officers belong to (Investigation, Cyber, ...)."""

    name = models.CharField(max_length=120)
    kind = models.CharField(max_length=24, choices=C.UNIT_KIND_CHOICES, default=C.UNIT_KIND_HQ)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.PROTECT,
        related_name="units",
        help_text="The district/state/national organization this unit belongs to.",
    )
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="children",
        help_text="Optional parent unit for nested units.",
    )
    department = models.ForeignKey(
        "Department",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="units",
        help_text="Functional department this unit belongs to (Department → Unit → Officer).",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["organization__name", "name"]
        constraints = [
            models.UniqueConstraint(fields=["organization", "name"], name="uniq_unit_org_name"),
        ]

    def __str__(self) -> str:
        return f"{self.name} — {self.organization.name}"

    def scope_chain(self):
        """Return the unit plus its organization chain for scope comparisons."""
        chain = [self]
        chain.extend(self.organization.scope_chain())
        node = self.parent
        while node is not None:
            chain.append(node)
            node = node.parent
        return chain


# ---------------------------------------------------------------------------
# Department registry (functional grouping: Cyber Crime, CID, Administration…)
# ---------------------------------------------------------------------------
class Department(models.Model):
    """A functional department. Units belong to departments; officers are
    posted to a department + unit.

    Purely an *identity / service* attribute — it carries no authorization
    weight. Operational scope is still decided by ``OrganizationUnit`` /
    ``Organization`` in the authorization engine.
    """

    code = models.CharField(max_length=24, unique=True, help_text="Short code, e.g. CYBER.")
    name = models.CharField(max_length=120, unique=True)
    description = models.CharField(max_length=255, blank=True, default="")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def clean(self):
        super().clean()
        if self.code:
            self.code = self.code.strip().upper()

    @property
    def officer_count(self) -> int:
        return self.officers.count()


# ---------------------------------------------------------------------------
# Designation registry (rank / post — descriptive, NOT authorization)
# ---------------------------------------------------------------------------
class Designation(models.Model):
    """A designation such as Constable, Sub-Inspector, Inspector.

    ``rank_level`` is a display/ordering value only. A designation never
    grants a capability: authorization comes from ``Role`` + clearance + scope.
    """

    code = models.CharField(max_length=24, unique=True, help_text="Short code, e.g. SI.")
    name = models.CharField(max_length=120, unique=True)
    rank_level = models.PositiveSmallIntegerField(
        default=0, help_text="Ordering only (higher = more senior). Carries NO authorization weight."
    )
    description = models.CharField(max_length=255, blank=True, default="")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-rank_level", "name"]

    def __str__(self) -> str:
        return self.name

    def clean(self):
        super().clean()
        if self.code:
            self.code = self.code.strip().upper()

    @property
    def officer_count(self) -> int:
        return self.officers.count()


# ---------------------------------------------------------------------------
# Clearance (independent of rank)
# ---------------------------------------------------------------------------
class ClearanceLevel(models.Model):
    """A sensitivity band. Configurable — never hard-coded as policy."""

    code = models.CharField(max_length=8, unique=True)
    label = models.CharField(max_length=60)
    weight = models.PositiveSmallIntegerField(
        unique=True,
        help_text="Ordering value; higher weight = more sensitive.",
    )
    description = models.CharField(max_length=255, blank=True)
    is_classified = models.BooleanField(
        default=False,
        help_text="Whether this level belongs to the classified band.",
    )

    class Meta:
        ordering = ["weight"]

    def __str__(self) -> str:
        return f"{self.code} — {self.label}"


# ---------------------------------------------------------------------------
# Portal
# ---------------------------------------------------------------------------
class Portal(models.Model):
    """An entry surface. Access is an explicit grant (default deny)."""

    key = models.CharField(max_length=16, unique=True, choices=C.PORTAL_CHOICES)
    name = models.CharField(max_length=60)
    description = models.CharField(max_length=255, blank=True)
    is_restricted = models.BooleanField(
        default=False,
        help_text="Restricted portals require additional clearance checks.",
    )
    min_clearance = models.ForeignKey(
        ClearanceLevel,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        help_text="If set, entry requires at least this clearance.",
    )

    def __str__(self) -> str:
        return self.name


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------
class Permission(models.Model):
    """A capability codename evaluated by the authorization engine."""

    codename = models.CharField(max_length=64, unique=True)
    description = models.CharField(max_length=255, blank=True)

    def __str__(self) -> str:
        return self.codename


class Role(models.Model):
    """A broad capability set. Rank is *not* a role (see ``Officer.rank``)."""

    name = models.CharField(max_length=64, unique=True)
    description = models.CharField(max_length=255, blank=True)
    rank_weight = models.PositiveSmallIntegerField(
        default=0,
        help_text="Display ordering only. Carries NO authorization weight.",
    )
    is_system_role = models.BooleanField(default=False)
    permissions = models.ManyToManyField(Permission, blank=True, related_name="roles")
    allowed_portals = models.ManyToManyField(Portal, blank=True, related_name="roles")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["rank_weight", "name"]

    def __str__(self) -> str:
        return self.name


# ---------------------------------------------------------------------------
# The custom User
# ---------------------------------------------------------------------------
class Officer(AbstractBaseUser, PermissionsMixin):
    """One identity per real officer.

    ``rank`` and ``department`` are descriptive only — they carry **no**
    authorization weight. Role, clearance, unit and portal grants do.
    """

    officer_id = models.CharField(
        max_length=32,
        unique=True,
        help_text="Unique officer identifier (e.g. OFF-052).",
    )
    employee_id = models.CharField(
        max_length=32,
        blank=True,
        default="",
        help_text="HR / payroll employee number (optional, unique when present).",
    )
    full_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=32, blank=True, default="")

    account_status = models.CharField(
        max_length=16,
        choices=C.ACCOUNT_STATUS_CHOICES,
        default=C.ACCOUNT_STATUS_PENDING,
    )

    # Descriptive service attributes (NOT authorization).
    # ``rank`` is a denormalised label kept in sync with ``designation`` so
    # that legacy readers (sidebar, capability bundle) keep working.
    rank = models.CharField(max_length=64, blank=True, default="")
    designation = models.ForeignKey(
        Designation,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="officers",
    )
    department = models.ForeignKey(
        Department,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="officers",
    )
    legacy_department = models.CharField(
        max_length=120,
        blank=True,
        default="",
        editable=False,
        help_text="Free-text department label recorded before the department registry existed.",
    )
    supervisor = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="supervisees",
    )
    joining_date = models.DateField(null=True, blank=True)

    # Authorization attributes.
    role = models.ForeignKey(
        Role,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="officers",
    )
    clearance = models.ForeignKey(
        ClearanceLevel,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="officers",
    )
    unit = models.ForeignKey(
        OrganizationUnit,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="officers",
    )

    # Second-factor state.
    mfa_enabled = models.BooleanField(default=False)
    secret_code_configured = models.BooleanField(default=False)

    # Login protection.
    failed_login_attempts = models.PositiveSmallIntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    locked_until = models.DateTimeField(null=True, blank=True)

    # Django fields we rely on.
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "officer_id"
    REQUIRED_FIELDS = ["email", "full_name"]

    objects = OfficerManager()

    class Meta:
        ordering = ["officer_id"]
        verbose_name = "officer"
        verbose_name_plural = "officers"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(officer_id__regex=r"^[A-Z0-9][A-Z0-9\-]*$"),
                name="officer_id_uppercase",
            ),
            models.UniqueConstraint(
                fields=["employee_id"],
                condition=~models.Q(employee_id=""),
                name="uniq_officer_employee_id",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.officer_id} — {self.full_name}"

    def clean(self):
        super().clean()
        if self.officer_id:
            self.officer_id = self.officer_id.strip().upper()
        if self.employee_id:
            self.employee_id = self.employee_id.strip().upper()

    def save(self, *args, **kwargs):
        # Keep the legacy ``rank`` label aligned with the designation registry.
        if self.designation_id and self.designation:
            self.rank = self.designation.name
        super().save(*args, **kwargs)

    # -- Django auth plumbing ----------------------------------------------
    def get_full_name(self) -> str:
        return self.full_name

    def get_short_name(self) -> str:
        return self.officer_id

    # -- Domain helpers ------------------------------------------------------
    @property
    def is_active_account(self) -> bool:
        return (
            self.is_active
            and self.account_status == C.ACCOUNT_STATUS_ACTIVE
        )

    @property
    def is_locked_out(self) -> bool:
        return bool(self.locked_until and self.locked_until > timezone.now())

    @property
    def clearance_weight(self) -> int:
        return self.clearance.weight if self.clearance else 0

    def has_portal_access(self, portal_key: str) -> bool:
        return self.portal_accesses.filter(
            portal__key=portal_key, revoked_at__isnull=True
        ).exists()

    @property
    def is_blocked(self) -> bool:
        return self.account_status in C.BLOCKING_STATUSES

    def revoke_all_sessions(self, end_reason: str = C.SESSION_END_ACCOUNT_STATE, actor=None):
        """Invalidate every session this officer holds (used on lock/disable).

        Also closes the officer's session-registry rows so the device/session
        views reflect reality. Returns the number of server sessions removed.
        """
        from django.contrib.sessions.models import Session
        from django.contrib.auth import SESSION_KEY, BACKEND_SESSION_KEY

        uid = str(self.pk)
        removed = 0
        for session in Session.objects.all().iterator():
            data = session.get_decoded()
            if data.get(SESSION_KEY) == uid or data.get(BACKEND_SESSION_KEY) == uid:
                session.delete()
                removed += 1

        OfficerSession.objects.filter(officer=self, ended_at__isnull=True).update(
            ended_at=timezone.now(), end_reason=end_reason, ended_by=actor
        )
        return removed


# ---------------------------------------------------------------------------
# Portal access grants (explicit ⇒ default deny)
# ---------------------------------------------------------------------------
class PortalAccess(models.Model):
    officer = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="portal_accesses"
    )
    portal = models.ForeignKey(Portal, on_delete=models.PROTECT, related_name="accesses")
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    reason = models.CharField(max_length=255, blank=True, default="")
    granted_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["officer", "portal"], name="uniq_officer_portal"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.officer.officer_id} → {self.portal.key}"


# ---------------------------------------------------------------------------
# Authentication factors
# ---------------------------------------------------------------------------
class AuthenticationFactor(models.Model):
    """A second authentication factor.

    MVP stores a *salted HMAC digest* of the secret code (never plaintext).
    The model reserves TOTP / hardware-token types so the factor can be
    migrated to a proper authenticator without schema changes.
    """

    officer = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="factors"
    )
    factor_type = models.CharField(max_length=16, choices=C.FACTOR_TYPE_CHOICES)
    secret_hash = models.CharField(
        max_length=128,
        help_text="Salted HMAC digest of the factor secret. Never plaintext.",
    )
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_verified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["officer", "factor_type"], name="uniq_officer_factor_type"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.officer.officer_id} — {self.factor_type}"

    def verify(self, candidate: str) -> bool:
        """Verify a candidate secret against the stored digest."""
        from .services import SecurityCodeService

        if not candidate:
            return False
        return SecurityCodeService().verify(candidate, self.secret_hash)


# ---------------------------------------------------------------------------
# Posting history — transfers and designation changes are never overwritten
# ---------------------------------------------------------------------------
class PostingHistory(models.Model):
    """Immutable record of where an officer was posted and as what.

    The *current* posting lives on ``Officer`` (department/unit/designation);
    every change appends a row here so the past is never destroyed.
    """

    officer = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="posting_history"
    )
    kind = models.CharField(max_length=24, choices=C.POSTING_KIND_CHOICES, default=C.POSTING_TRANSFER)

    from_department = models.ForeignKey(Department, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    from_unit = models.ForeignKey(OrganizationUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    from_designation = models.ForeignKey(Designation, null=True, blank=True, on_delete=models.PROTECT, related_name="+")

    to_department = models.ForeignKey(Department, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    to_unit = models.ForeignKey(OrganizationUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    to_designation = models.ForeignKey(Designation, null=True, blank=True, on_delete=models.PROTECT, related_name="+")

    effective_date = models.DateField()
    reason = models.CharField(max_length=255, blank=True, default="")
    # Set when the move may affect operational authorization (unit / scope
    # changed). The IT portal only *flags* this — the authorization domain
    # decides what, if anything, changes.
    authorization_review_required = models.BooleanField(default=False)

    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-effective_date", "-recorded_at"]
        verbose_name_plural = "posting histories"

    def __str__(self) -> str:
        return f"{self.officer.officer_id} {self.kind} {self.effective_date}"


# ---------------------------------------------------------------------------
# Device & session registry (lightweight — no invasive fingerprinting)
# ---------------------------------------------------------------------------
class RegisteredDevice(models.Model):
    """A browser/device an officer has signed in from.

    Identified by a random, HttpOnly device cookie (hashed at rest) — not by
    fingerprinting. Revoking a device ends its sessions; the device must
    re-register on the next successful sign-in.
    """

    officer = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="devices"
    )
    device_key_hash = models.CharField(max_length=64, unique=True, help_text="SHA-256 of the device token.")
    label = models.CharField(max_length=120, blank=True, default="")
    browser = models.CharField(max_length=64, blank=True, default="")
    operating_system = models.CharField(max_length=64, blank=True, default="")
    user_agent = models.CharField(max_length=300, blank=True, default="")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=12, choices=C.DEVICE_STATUS_CHOICES, default=C.DEVICE_STATUS_ACTIVE)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    revoke_reason = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        ordering = ["-last_seen"]

    def __str__(self) -> str:
        return f"{self.officer.officer_id} — {self.browser or 'Unknown'} / {self.operating_system or 'Unknown'}"

    @property
    def is_active(self) -> bool:
        return self.status == C.DEVICE_STATUS_ACTIVE


class OfficerSession(models.Model):
    """Registry row for an authenticated session (the server-side session
    itself is Django's; only a hash of its key is stored here)."""

    officer = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sessions"
    )
    session_key_hash = models.CharField(max_length=64, db_index=True)
    device = models.ForeignKey(
        RegisteredDevice, null=True, blank=True, on_delete=models.SET_NULL, related_name="sessions"
    )
    portal = models.CharField(max_length=16, blank=True, default="")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    browser = models.CharField(max_length=64, blank=True, default="")
    operating_system = models.CharField(max_length=64, blank=True, default="")
    started_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    end_reason = models.CharField(max_length=24, choices=C.SESSION_END_CHOICES, blank=True, default="")
    ended_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    class Meta:
        ordering = ["-started_at"]
        indexes = [models.Index(fields=["officer", "ended_at"])]

    def __str__(self) -> str:
        return f"{self.officer.officer_id} session {self.started_at:%Y-%m-%d %H:%M}"

    @property
    def is_open(self) -> bool:
        return self.ended_at is None


# ---------------------------------------------------------------------------
# Temporary administrative capability (time-boxed, admin domain only)
# ---------------------------------------------------------------------------
class TemporaryCapability(models.Model):
    """A time-boxed grant of an *administrative* capability.

    Evaluated by the authorization engine only while ``starts_at <= now <
    expires_at`` and status is ACTIVE. Operational permissions (case.*,
    document.* …) are never grantable here — the engine ignores them.
    """

    officer = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="temporary_capabilities"
    )
    permission = models.ForeignKey(Permission, on_delete=models.PROTECT, related_name="temporary_grants")
    reason = models.CharField(max_length=255)
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    starts_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=12, choices=C.TEMP_ACCESS_STATUS_CHOICES, default=C.TEMP_ACCESS_ACTIVE)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    revoke_reason = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name_plural = "temporary capabilities"

    def __str__(self) -> str:
        return f"{self.officer.officer_id} +{self.permission.codename} until {self.expires_at:%Y-%m-%d %H:%M}"

    def clean(self):
        super().clean()
        if self.starts_at and self.expires_at and self.expires_at <= self.starts_at:
            raise ValidationError({"expires_at": "Expiry must be after the start."})

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    @property
    def is_currently_active(self) -> bool:
        now = timezone.now()
        return self.status == C.TEMP_ACCESS_ACTIVE and self.starts_at <= now < self.expires_at

    @property
    def effective_status(self) -> str:
        if self.status == C.TEMP_ACCESS_REVOKED:
            return "REVOKED"
        if self.is_expired:
            return "EXPIRED"
        if timezone.now() < self.starts_at:
            return "SCHEDULED"
        return "ACTIVE"
