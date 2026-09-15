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

    resource_type: Optional[str] = None         # "case" | "fir" | "evidence" | "document"
    resource_id: Optional[str] = None           # id of the protected resource
    classification_code: Optional[str] = None   # e.g. "L4"
    organization_id: Optional[int] = None       # required organization
    unit_id: Optional[int] = None               # required unit
    case_id: Optional[str] = None               # parent case (for file resources)
    required_permission: Optional[str] = None   # e.g. "case.view"
    allowed_actions: Optional[frozenset] = None


class ActionSet(set):
    """A set of granted actions that also records which path granted each.

    Keeps the "why" attached to the decision so the UI can explain access
    instead of guessing (directive §15 / §21).
    """

    def __init__(self):
        super().__init__()
        self.paths: set = set()

    def add(self, action, path: str):  # type: ignore[override]
        super().add(action)
        if path:
            self.paths.add(path)


class AccessDecision:
    """The result of one authorization decision."""

    def __init__(self, allowed: bool, action: str = "", reason: str = "", stage: str = ""):
        self.allowed = allowed
        self.action = action
        self.reason = reason
        self.stage = stage
        self.paths: list = []
        self.available_actions: list = []
        self.resource_type = ""
        self.resource_id = ""

    def __bool__(self) -> bool:
        return self.allowed

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<AccessDecision {'ALLOW' if self.allowed else 'DENY'} "
            f"{self.action} stage={self.stage or '-'} paths={self.paths}>"
        )


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
    # Resource authorization (operational domain)
    #
    # ONE central decision process, in a fixed order. Hard security
    # restrictions are evaluated first and can never be overridden by an
    # explicit grant (directive §12).
    # ------------------------------------------------------------------ #
    def authorize_resource(self, user, resource, action: str, portal: str = ""):
        """The single decision function for cases, FIRs, evidence and documents.

        Returns an :class:`AccessDecision` (truthy when allowed) carrying the
        reason and the path that granted access, so callers can audit and the
        UI can explain itself.
        """
        decision = AccessDecision(allowed=False, action=action)

        # -- Steps 1-2: identity and account state (hard restriction) --------
        if not self._is_active_identity(user):
            decision.reason = "Identity is not active."
            decision.stage = "identity"
            return decision

        # -- Step 3: portal authority ---------------------------------------
        if portal and not self.can_access_portal(user, portal):
            decision.reason = "Portal access denied."
            decision.stage = "portal"
            return decision

        requirement = self._requirement_of(resource)
        if requirement is None:
            decision.reason = "Resource declares no security policy."
            decision.stage = "policy"
            return decision
        if not action:
            decision.reason = "No action requested."
            decision.stage = "action"
            return decision

        decision.resource_type = requirement.resource_type or ""
        decision.resource_id = requirement.resource_id or ""

        # -- Step 13 / hard restriction: clearance vs classification ---------
        if not self._clearance_satisfied(user, requirement):
            decision.reason = "Insufficient clearance for this classification."
            decision.stage = "clearance"
            return decision

        # -- Step 6: organizational / jurisdictional scope --------------------
        if not self._in_scope(user, requirement):
            decision.reason = "Resource is outside the officer's jurisdiction."
            decision.stage = "scope"
            return decision

        # -- Steps 7-12: the access paths ------------------------------------
        actions = self._granted_actions(user, requirement)
        decision.available_actions = sorted(actions)
        decision.paths = sorted(actions.paths)

        if not actions:
            decision.reason = "No ownership, hierarchy, assignment or grant applies."
            decision.stage = "access_path"
            return decision

        # -- Action permission: the capability the action requires -----------
        needed = C.CASE_ACTION_PERMISSIONS.get(action)
        if needed and not self.has_permission(user, needed):
            decision.reason = f"Role does not carry {needed}."
            decision.stage = "capability"
            return decision

        # -- Action permission: does the winning path allow this action? -----
        if action not in actions:
            allowed = sorted(actions)
            decision.reason = (
                f"Access path permits {', '.join(allowed)} but not '{action}'."
                if allowed else "Access path permits no actions."
            )
            decision.stage = "action_permission"
            return decision

        if requirement.allowed_actions is not None and action not in requirement.allowed_actions:
            decision.reason = "Action is not valid for this resource type."
            decision.stage = "action_permission"
            return decision

        decision.allowed = True
        decision.reason = f"Allowed via {', '.join(sorted(actions.paths))}." if actions.paths else "Allowed."
        decision.stage = "allow"
        return decision

    def can_access_resource(self, user, resource, action: str, portal: str = "") -> bool:
        """Boolean convenience wrapper around :meth:`authorize_resource`."""
        return bool(self.authorize_resource(user, resource, action, portal=portal))

    def case_actions(self, user, case) -> frozenset:
        """The action ceiling ``user`` has on ``case`` (fail closed)."""
        if case is None or not self._is_active_identity(user):
            return frozenset()
        return frozenset(self._granted_actions(user, self._requirement_of(case)))

    def can_access_case(self, user, case, action: str = C.ACTION_VIEW) -> bool:
        """Case authorization — delegates to the central decision process."""
        return self.can_access_resource(user, case, action)

    def explain_resource_access(self, user, resource, action: str, portal: str = "") -> dict:
        """Human-readable WHY for the grant / access UI (directive §15)."""
        decision = self.authorize_resource(user, resource, action, portal=portal)
        return {
            "action": action,
            "allowed": decision.allowed,
            "stage": decision.stage,
            "reason": decision.reason,
            "paths": decision.paths,
            "available_actions": decision.available_actions,
        }

    # -- Decision internals ------------------------------------------------
    def _requirement_of(self, resource):
        requirement = getattr(resource, "security_requirement", None)
        return requirement if isinstance(requirement, ResourceRequirement) else None

    def _clearance_satisfied(self, user, requirement) -> bool:
        if not requirement.classification_code:
            return True
        return self.has_clearance(user, requirement.classification_code)

    def _in_scope(self, user, requirement) -> bool:
        """Jurisdictional containment (step 6).

        An officer reaches resources inside their own jurisdiction tree. A
        resource with no recorded jurisdiction is treated as unrestricted by
        scope — every other layer still applies.
        """
        if requirement.organization_id is None and requirement.unit_id is None:
            return True
        if requirement.organization_id is not None:
            jurisdiction_ids = set(user.jurisdiction_ids())
            if not jurisdiction_ids:
                return False
            if requirement.organization_id not in jurisdiction_ids:
                return False
        return True

    def _resolve_case(self, requirement):
        """Load the parent case for a file resource (fail closed)."""
        from django.apps import apps

        if not requirement.case_id:
            return None
        try:
            model = apps.get_model("general", "CaseRecord")
        except LookupError:
            return None
        return model.objects.filter(case_id=requirement.case_id).first()

    def _granted_actions(self, user, requirement) -> "ActionSet":
        """Union every access path's allowed actions for this resource.

        Order reflects the documented precedence (directive §12): ownership,
        hierarchical inheritance, assignment, then explicit grants. A grant is
        an additional path — it can only ever *add* actions, never restore
        something a hard restriction removed.
        """
        granted = ActionSet()
        case = self._resolve_case(requirement)
        ceiling = requirement.allowed_actions

        def add(actions: frozenset, path: str):
            for action in actions:
                if ceiling is None or action in ceiling:
                    granted.add(action, path)

        # Step 7 — ownership.
        if case is not None and case.created_by_id == user.pk:
            add(C.ASSIGNMENT_ROLE_ACTIONS[C.ASSIGNMENT_OWNER], "ownership")

        # Step 8 — hierarchical inheritance (real relationships, not rank).
        if case is not None and self._hierarchy_reaches(user, case):
            add(C.ASSIGNMENT_ROLE_ACTIONS[C.ASSIGNMENT_SUPERVISOR], "hierarchy")

        # Step 9 — case assignment.
        if case is not None:
            add(self.case_assignment_actions(user, case), "assignment")

        # Steps 10-12 — explicit access grants (officer / department / station
        # / jurisdiction), honouring start, expiry and revocation.
        add(self._grant_actions(user, requirement), "grant")

        return granted

    def case_assignment_actions(self, user, case) -> frozenset:
        """Actions from the officer's active CaseAssignment rows."""
        model = self._case_assignment_model()
        if model is None or case is None:
            return frozenset()
        actions: set = set()
        for assignment in model.objects.filter(case=case, officer=user, revoked_at__isnull=True):
            actions |= assignment.allowed_actions
        return frozenset(actions)

    def _hierarchy_reaches(self, user, case) -> bool:
        """Does the supervisory / unit tree put ``case`` under ``user``?

        Uses the real reporting relationship only. Rank, designation and
        seniority are deliberately not consulted (directive §7): a constable
        supervising a case reaches it, and a senior officer outside the tree
        does not.
        """
        if case is None:
            return False
        descendants = set(user.descendant_ids())

        if case.created_by_id and case.created_by_id in descendants:
            return True

        model = self._case_assignment_model()
        if model is not None:
            assignee_ids = set(
                model.objects.filter(case=case, revoked_at__isnull=True)
                .values_list("officer_id", flat=True)
            )
            if assignee_ids & descendants:
                return True

        # Unit tree: the officer's unit is an ancestor of the case's station.
        if case.unit_id and user.unit_id:
            from accounts.models import unit_descendant_ids

            if case.unit_id in set(unit_descendant_ids(user.unit_id)):
                return True
        return False

    def _grant_actions(self, user, requirement) -> frozenset:
        """Actions conferred by currently-effective AccessGrant rows."""
        model = self._access_grant_model()
        if model is None:
            return frozenset()
        from django.db.models import Q
        from django.utils import timezone

        now = timezone.now()
        resource_ids = [i for i in (requirement.resource_id, requirement.case_id) if i]
        if not resource_ids:
            return frozenset()

        candidates = model.objects.filter(
            status=C.GRANT_STATUS_ACTIVE,
            resource_id__in=resource_ids,
            starts_at__lte=now,
        ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))

        actions: set = set()
        for grant in candidates:
            actions |= grant.actions_for_officer(user)
        return frozenset(actions)

    @staticmethod
    def _case_assignment_model():
        from django.apps import apps

        try:
            return apps.get_model("general", "CaseAssignment")
        except LookupError:
            return None

    @staticmethod
    def _access_grant_model():
        from django.apps import apps

        try:
            return apps.get_model("general", "AccessGrant")
        except LookupError:
            return None

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
