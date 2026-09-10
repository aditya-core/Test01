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
    full_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=32, blank=True, default="")

    account_status = models.CharField(
        max_length=16,
        choices=C.ACCOUNT_STATUS_CHOICES,
        default=C.ACCOUNT_STATUS_PENDING,
    )

    # Descriptive attributes (NOT authorization).
    rank = models.CharField(max_length=64, blank=True, default="")
    department = models.CharField(max_length=120, blank=True, default="")

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
                check=models.Q(officer_id__regex=r"^[A-Z0-9][A-Z0-9\-]*$"),
                name="officer_id_uppercase",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.officer_id} — {self.full_name}"

    def clean(self):
        super().clean()
        if self.officer_id:
            self.officer_id = self.officer_id.strip().upper()

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

    def revoke_all_sessions(self):
        """Invalidate every session this officer holds (used on lock/disable)."""
        from django.contrib.sessions.models import Session
        from django.contrib.auth import SESSION_KEY, BACKEND_SESSION_KEY

        uid = str(self.pk)
        for session in Session.objects.all().iterator():
            data = session.get_decoded()
            if data.get(SESSION_KEY) == uid or data.get(BACKEND_SESSION_KEY) == uid:
                session.delete()


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
