"""Central Authorization Engine.

This is the single place where access decisions are made. Portal apps,
dashboards, and (future) case/document modules call into this module instead
of scattering permission logic through templates or JavaScript.

Design rules:
  * Deny by default — any unresolved condition ⇒ DENY.
  * Fail closed — exceptions and missing attributes ⇒ DENY.
  * Complete mediation — every sensitive request goes through here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import constants as C


class AuthorizationDenied(Exception):
    """Raised when an authorization decision is DENY (with a safe reason)."""

    def __init__(self, reason: str = "You are not authorized to access this resource."):
        self.reason = reason
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Value objects for future domain resources (cases / documents).
# These are deliberately plain: the authorization engine works against a
# resource *protocol* so that future apps plug in without coupling.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ResourceRequirement:
    """The security attributes a resource demands of its requester.

    ``allowed_actions=None`` means actions are not further restricted (other
    conditions still apply). An explicit (possibly empty) frozenset restricts
    the permitted actions to exactly that set — an empty set allows nothing.
    """

    classification_code: Optional[str] = None   # e.g. "L4"
    organization_id: Optional[int] = None       # required organization
    unit_id: Optional[int] = None               # required unit
    case_id: Optional[str] = None               # required case assignment
    required_permission: Optional[str] = None   # e.g. "case.view"
    allowed_actions: Optional[frozenset] = None


class AuthorizationService:
    """Single entry-point for every allow/deny decision."""

    # ------------------------------------------------------------------ #
    # Portal authorization
    # ------------------------------------------------------------------ #
    def can_access_portal(self, user, portal_key: str) -> bool:
        """Portal entry requires: ACTIVE + explicit portal grant (+ clearance
        when the portal is restricted)."""
        if not self._is_active_identity(user):
            return False

        portal = self._get_portal(portal_key)
        if portal is None:
            return False

        if not user.has_portal_access(portal_key):
            # Role defaults may also carry portal entry.
            if not self._role_allows_portal(user, portal_key):
                return False

        if portal.is_restricted:
            if portal.min_clearance and not self.has_clearance(user, portal.min_clearance.code):
                return False
        return True

    # ------------------------------------------------------------------ #
    # Clearance
    # ------------------------------------------------------------------ #
    def has_clearance(self, user, level_code: str) -> bool:
        if not user or not user.clearance:
            return False
        try:
            required = self._get_clearance(level_code)
        except Exception:
            return False
        if required is None:
            return False
        return user.clearance.weight >= required.weight

    # ------------------------------------------------------------------ #
    # RBAC permissions
    # ------------------------------------------------------------------ #
    def get_role_permissions(self, user) -> set:
        """Capabilities carried by the officer's role (plus umbrella
        implications), ignoring temporary grants."""
        if not self._is_active_identity(user):
            return set()
        role = getattr(user, "role", None)
        if role is None:
            return set()
        perms = set(role.permissions.values_list("codename", flat=True))
        return self._expand_implications(perms)

    def get_temporary_permissions(self, user) -> set:
        """Currently-effective time-boxed *administrative* capabilities.

        Only admin-domain codenames are honoured: a temporary grant can never
        confer operational (case/document/...) authorization, even if such a
        row were inserted directly into the database.
        """
        if not self._is_active_identity(user):
            return set()
        from django.utils import timezone

        from .models import TemporaryCapability

        now = timezone.now()
        codenames = TemporaryCapability.objects.filter(
            officer=user,
            status=C.TEMP_ACCESS_ACTIVE,
            starts_at__lte=now,
            expires_at__gt=now,
        ).values_list("permission__codename", flat=True)
        return {c for c in codenames if C.is_admin_capability(c)}

    def get_user_permissions(self, user) -> set:
        if not self._is_active_identity(user):
            return set()
        return self.get_role_permissions(user) | self.get_temporary_permissions(user)

    def has_permission(self, user, permission: str) -> bool:
        return permission in self.get_user_permissions(user)

    def explain_permission(self, user, permission: str) -> dict:
        """Explain WHY an officer does / does not hold a capability.

        Returns ``{"what", "granted", "why", "source", "status", "expires_at"}``.
        Operational capabilities are deliberately *not* explained beyond
        "managed separately" — this portal must not reason about case access.
        """
        result = {
            "what": permission,
            "granted": False,
            "why": "Not granted.",
            "source": None,
            "status": "INACTIVE",
            "expires_at": None,
        }
        if not C.is_admin_capability(permission):
            result.update(
                why="Operational authorization is managed separately.",
                source="operational-domain",
                status="N/A",
            )
            return result
        if not self._is_active_identity(user):
            result.update(why=f"Account is {getattr(user, 'account_status', 'inactive')}; no capability is active.", status="INACTIVE")
            return result

        role = getattr(user, "role", None)
        if role is not None:
            direct = set(role.permissions.values_list("codename", flat=True))
            if permission in direct:
                result.update(
                    granted=True,
                    why=f"Granted through the {role.name} role.",
                    source=f"role:{role.name}",
                    status="ACTIVE",
                )
                return result
            for umbrella, implied in C.CAPABILITY_IMPLICATIONS.items():
                if umbrella in direct and permission in implied:
                    result.update(
                        granted=True,
                        why=f"Implied by {umbrella} carried by the {role.name} role.",
                        source=f"role:{role.name}→{umbrella}",
                        status="ACTIVE",
                    )
                    return result

        from django.utils import timezone

        from .models import TemporaryCapability

        now = timezone.now()
        grant = (
            TemporaryCapability.objects.filter(
                officer=user, permission__codename=permission, status=C.TEMP_ACCESS_ACTIVE,
                starts_at__lte=now, expires_at__gt=now,
            )
            .select_related("granted_by")
            .order_by("-expires_at")
            .first()
        )
        if grant is not None:
            granted_by = grant.granted_by.officer_id if grant.granted_by else "unknown"
            result.update(
                granted=True,
                why=f"Temporary capability granted by {granted_by}: {grant.reason}",
                source=f"temporary:{grant.pk}",
                status="TEMPORARY",
                expires_at=grant.expires_at,
            )
            return result

        # Not granted — say whether an expired/revoked grant explains a recent loss.
        latest = (
            TemporaryCapability.objects.filter(officer=user, permission__codename=permission)
            .order_by("-expires_at")
            .first()
        )
        if latest is not None:
            result.update(
                why=f"Previous temporary grant is {latest.effective_status.lower()}.",
                source=f"temporary:{latest.pk}",
                status=latest.effective_status,
                expires_at=latest.expires_at,
            )
        elif role is None:
            result.update(why="No role assigned.")
        else:
            result.update(why=f"The {role.name} role does not carry this capability.", source=f"role:{role.name}")
        return result

    def explain_all(self, user) -> list:
        """Explain every admin capability the officer currently holds."""
        return [self.explain_permission(user, p) for p in sorted(self.get_user_permissions(user)) if C.is_admin_capability(p)]

    @staticmethod
    def _expand_implications(perms: set) -> set:
        expanded = set(perms)
        for umbrella, implied in C.CAPABILITY_IMPLICATIONS.items():
            if umbrella in perms:
                expanded |= implied
        return expanded

    def can(self, user, permission: str) -> bool:
        return self.has_permission(user, permission)

    # ------------------------------------------------------------------ #
    # Portal capability bundle — drives dashboards
    # ------------------------------------------------------------------ #
    def portal_capabilities(self, user, portal_key: str) -> dict:
        """Return the set of capabilities the dashboard may *show*. The UI is
        decoration: every target view re-checks authorization server-side."""
        if not self.can_access_portal(user, portal_key):
            return {
                "portal": portal_key,
                "permissions": [],
                "clearance": None,
                "role": None,
            }

        return {
            "portal": portal_key,
            "permissions": sorted(self.get_user_permissions(user)),
            "clearance": user.clearance.code if user.clearance else None,
            "role": user.role.name if user.role else None,
            "rank": getattr(user, "rank", ""),
            "unit": user.unit.name if user.unit else None,
            "organization": user.unit.organization.name if user.unit else None,
            "portals": self.list_authorized_portals(user),
        }

    def list_authorized_portals(self, user) -> List[str]:
        if not self._is_active_identity(user):
            return []
        keys = list(
            user.portal_accesses.filter(revoked_at__isnull=True)
            .values_list("portal__key", flat=True)
        )
        # Include role defaults not already explicitly granted.
        if user.role:
            for key in user.role.allowed_portals.values_list("key", flat=True):
                if key not in keys:
                    keys.append(key)
        return sorted(keys)

    # ------------------------------------------------------------------ #
    # Generic / resource-level decisions
    # ------------------------------------------------------------------ #
    def authorize(
        self,
        user,
        action: str,
        resource=None,
        requirement: Optional[ResourceRequirement] = None,
        portal: str = "",
    ) -> bool:
        """The full decision function:

            active + role + clearance + scope + case + resource + action.

        Returns True only when every applicable condition is satisfied.
        """
        if not self._is_active_identity(user):
            return False

        # Action must be explicitly named.
        if not action:
            return False

        requirement = requirement or getattr(resource, "security_requirement", None)
        if requirement is None:
            # No policy known for this resource ⇒ fail closed.
            return False

        # A requirement with no conditions at all encodes "no policy" ⇒ deny.
        if not any([
            requirement.classification_code,
            requirement.organization_id is not None,
            requirement.unit_id is not None,
            requirement.case_id,
            requirement.required_permission,
            requirement.allowed_actions is not None,
        ]):
            return False

        # 1. Classification / clearance.
        if requirement.classification_code and not self.has_clearance(
            user, requirement.classification_code
        ):
            return False

        # 2. Organizational scope.
        if requirement.organization_id is not None:
            if not self._in_organization(user, requirement.organization_id):
                return False
        if requirement.unit_id is not None:
            if not self._in_unit(user, requirement.unit_id):
                return False

        # 3. Case assignment (future — evaluated via the resource protocol).
        if requirement.case_id is not None:
            if not self._assigned_to_case(user, requirement.case_id):
                return False

        # 4. Role/permission requirement.
        if requirement.required_permission and not self.has_permission(
            user, requirement.required_permission
        ):
            return False

        # 5. Action permission.
        if requirement.allowed_actions is not None and action not in requirement.allowed_actions:
            return False

        return True

    def can_access(self, user, resource, action: str = "view", portal: str = "") -> bool:
        return self.authorize(user, action=action, resource=resource, portal=portal)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _is_active_identity(self, user) -> bool:
        if user is None or not user.is_authenticated:
            return False
        if not user.is_active:
            return False
        if getattr(user, "account_status", None) != C.ACCOUNT_STATUS_ACTIVE:
            return False
        return True

    def _get_portal(self, portal_key: str):
        from .models import Portal

        try:
            return Portal.objects.get(key=portal_key)
        except Portal.DoesNotExist:
            return None

    def _get_clearance(self, code: str):
        from .models import ClearanceLevel

        try:
            return ClearanceLevel.objects.get(code=code)
        except ClearanceLevel.DoesNotExist:
            return None

    def _role_allows_portal(self, user, portal_key: str) -> bool:
        role = getattr(user, "role", None)
        if role is None:
            return False
        return role.allowed_portals.filter(key=portal_key).exists()

    def _in_organization(self, user, organization_id) -> bool:
        if user.unit is None:
            return False
        return user.unit.organization_id == organization_id

    def _in_unit(self, user, unit_id) -> bool:
        if user.unit is None:
            return False
        return user.unit_id == unit_id

    def _assigned_to_case(self, user, case_id: str) -> bool:
        """Case authorization hook. The future cases app will expose
        ``user.is_assigned_to_case(case_id)``; until then, fail closed."""
        resolver = getattr(user, "is_assigned_to_case", None)
        if callable(resolver):
            return resolver(case_id)
        return False


authorization_service = AuthorizationService()
