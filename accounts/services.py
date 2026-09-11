"""Central service layer for identity, authentication and provisioning.

The audit service is imported lazily inside methods so the dependency remains
one-directional and the module stays import-safe.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Iterable, Optional

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from . import constants as C
from .models import (
    AuthenticationFactor,
    Department,
    Designation,
    Officer,
    OrganizationUnit,
    Portal,
    PortalAccess,
    PostingHistory,
    Role,
    ClearanceLevel,
)


# ---------------------------------------------------------------------------
# Officer ID generation (configurable, section 6)
# ---------------------------------------------------------------------------
class OfficerIDService:
    """Generates unique, configurable officer identifiers.

    The ID is an *identity* identifier only. It encodes no rank, clearance or
    permission. Its format is configurable via settings.
    """

    def generate(self) -> str:
        prefix = getattr(settings, "ACCOUNTS_OFFICER_ID_PREFIX", "OFF-")
        width = int(getattr(settings, "ACCOUNTS_OFFICER_ID_WIDTH", 3))
        for _ in range(100):  # bounded retry for collisions
            candidate = f"{prefix}{secrets.randbelow(10 ** width):0{width}d}"
            if not Officer.objects.filter(officer_id=candidate).exists():
                return candidate
        raise RuntimeError("Unable to generate a unique officer ID.")


# ---------------------------------------------------------------------------
# Secret code / second factor (section 10)
# ---------------------------------------------------------------------------
class SecurityCodeService:
    """Second factor management.

    Secret codes are stored as a salted HMAC-SHA256 digest, never in plaintext
    and never logged. ``AuthenticationFactor`` reserves TOTP / hardware-token
    types so the factor can be migrated to a proper authenticator later.
    """

    @property
    def _pepper(self) -> str:
        return getattr(settings, "ACCOUNTS_SECRET_CODE_PEPPER", "")

    def hash_secret(self, secret: str) -> str:
        salt = secrets.token_hex(16)
        digest = hmac.new(
            self._pepper.encode(), (salt + secret).encode(), hashlib.sha256
        ).hexdigest()
        return f"hmac${salt}${digest}"

    def verify(self, secret: str, stored_hash: str) -> bool:
        try:
            algo, salt, digest = stored_hash.split("$")
            if algo != "hmac":
                return False
        except (ValueError, AttributeError):
            return False
        expected = hmac.new(
            self._pepper.encode(), (salt + secret).encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(digest, expected)

    def set_secret_code(self, officer: Officer, code: str, actor=None):
        """Provision or replace the officer's secret-code factor."""
        factor, _ = AuthenticationFactor.objects.get_or_create(
            officer=officer,
            factor_type=C.FACTOR_SECRET_CODE,
            defaults={"secret_hash": self.hash_secret(code)},
        )
        factor.secret_hash = self.hash_secret(code)
        factor.enabled = True
        factor.save(update_fields=["secret_hash", "enabled"])

        officer.mfa_enabled = True
        officer.secret_code_configured = True
        officer.save(update_fields=["mfa_enabled", "secret_code_configured", "updated_at"])

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_SECRET_CODE_CHANGED if actor is None else C.EVENT_SECRET_CODE_RESET,
            officer=officer,
            actor=actor or officer,
            result=C.RESULT_SUCCESS,
        )
        return factor

    def clear(self, officer: Officer, actor=None):
        AuthenticationFactor.objects.filter(
            officer=officer, factor_type=C.FACTOR_SECRET_CODE
        ).delete()
        officer.mfa_enabled = False
        officer.secret_code_configured = False
        officer.save(update_fields=["mfa_enabled", "secret_code_configured", "updated_at"])

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_SECRET_CODE_RESET,
            officer=officer,
            actor=actor or officer,
            result=C.RESULT_SUCCESS,
        )

    def get_factor(self, officer: Officer) -> Optional[AuthenticationFactor]:
        return AuthenticationFactor.objects.filter(
            officer=officer, factor_type=C.FACTOR_SECRET_CODE, enabled=True
        ).first()

    def verify_for(self, officer: Officer, candidate: str) -> bool:
        factor = self.get_factor(officer)
        if factor is None or not factor.enabled:
            return False
        ok = factor.verify(candidate)
        if ok:
            AuthenticationFactor.objects.filter(pk=factor.pk).update(
                last_verified_at=timezone.now()
            )
        return ok

    def is_enrolled(self, officer: Officer) -> bool:
        return officer.mfa_enabled and officer.secret_code_configured


# ---------------------------------------------------------------------------
# Login protection (section 12)
# ---------------------------------------------------------------------------
class LoginProtectionService:
    """Brute-force protection: failed-attempt tracking, temporary lockout,
    rate limiting and escalating cooldown."""

    def is_blocked(self, officer: Optional[Officer]) -> bool:
        if officer is None:
            return False
        return officer.is_locked_out

    def lockout_seconds_remaining(self, officer: Optional[Officer]) -> int:
        if officer is None or not officer.locked_until:
            return 0
        return max(0, int((officer.locked_until - timezone.now()).total_seconds()))

    def record_failure(self, officer: Optional[Officer], request=None) -> bool:
        """Record a failed attempt; return True if this failure locked the account."""
        from audit.services import audit_service

        if officer is None:
            return False

        officer.failed_login_attempts += 1
        officer.last_failed_login = timezone.now()
        max_attempts = int(getattr(settings, "ACCOUNTS_MAX_FAILED_ATTEMPTS", 5))
        locked = officer.failed_login_attempts >= max_attempts
        if locked:
            minutes = int(getattr(settings, "ACCOUNTS_LOCKOUT_MINUTES", 15))
            officer.locked_until = timezone.now() + timezone.timedelta(minutes=minutes)
            officer.account_status = C.ACCOUNT_STATUS_LOCKED
            officer.is_active = False
        officer.save()

        audit_service.record_event(
            C.EVENT_LOGIN_FAILURE,
            officer=officer,
            result=C.RESULT_FAILURE,
            context={"attempts": officer.failed_login_attempts},
            request=request,
        )
        audit_service.record_security_event(
            C.EVENT_LOGIN_FAILURE,
            severity=C.SEVERITY_WARNING,
            officer=officer,
            details={"attempts": officer.failed_login_attempts},
            request=request,
        )

        if locked:
            audit_service.record_event(
                C.EVENT_ACCOUNT_LOCKED,
                officer=officer,
                result=C.RESULT_DENY,
                context={"attempts": officer.failed_login_attempts},
                request=request,
            )
            audit_service.record_security_event(
                C.EVENT_ACCOUNT_LOCKED,
                severity=C.SEVERITY_ALERT,
                officer=officer,
                details={"attempts": officer.failed_login_attempts},
                request=request,
            )
            officer.revoke_all_sessions()
        return locked

    def clear_failures(self, officer: Optional[Officer]):
        if officer is None:
            return
        Officer.objects.filter(pk=officer.pk).update(
            failed_login_attempts=0, last_failed_login=None
        )

    def cooldown_seconds(self, officer: Optional[Officer]) -> int:
        """Escalating cooldown after recent failures (never reveal why)."""
        if officer is None or not officer.last_failed_login:
            return 0
        base = int(getattr(settings, "ACCOUNTS_COOLDOWN_SECONDS", 3))
        attempts = min(officer.failed_login_attempts, 10)
        return base * attempts

    # -- Rate limiting (per identifier + IP) ----------------------------------
    def rate_limit_allowed(self, request, identifier: str) -> bool:
        window = int(getattr(settings, "ACCOUNTS_RATE_LIMIT_WINDOW_SECONDS", 300))
        max_attempts = int(getattr(settings, "ACCOUNTS_RATE_LIMIT_MAX_ATTEMPTS", 20))
        ip = request.META.get("REMOTE_ADDR", "unknown")
        key = f"login-rl:{identifier}:{ip}"
        try:
            count = cache.get(key, 0)
        except Exception:
            return True  # fail open only if the cache layer itself is broken
        if count >= max_attempts:
            return False
        try:
            if count == 0:
                cache.set(key, 1, window)
            else:
                cache.incr(key)
        except Exception:
            pass
        return True


# ---------------------------------------------------------------------------
# Account state management (section 11)
# ---------------------------------------------------------------------------
class AccountService:
    """Central IT state transitions. Every change is audited and (for blocking
    transitions) invalidates the officer's active sessions."""

    # Transitions an administrator may request from the IT portal. LOCKED is
    # reached through ``emergency_lock`` / login protection, never directly.
    ADMIN_TRANSITIONS = {
        "suspend": (C.ACCOUNT_STATUS_SUSPENDED, {C.ACCOUNT_STATUS_ACTIVE, C.ACCOUNT_STATUS_LOCKED}),
        "reactivate": (C.ACCOUNT_STATUS_ACTIVE, C.BLOCKING_STATUSES | {C.ACCOUNT_STATUS_INVITED, C.ACCOUNT_STATUS_PENDING}),
        "deactivate": (C.ACCOUNT_STATUS_DEACTIVATED, {
            C.ACCOUNT_STATUS_ACTIVE, C.ACCOUNT_STATUS_SUSPENDED, C.ACCOUNT_STATUS_LOCKED,
            C.ACCOUNT_STATUS_DISABLED, C.ACCOUNT_STATUS_INVITED, C.ACCOUNT_STATUS_PENDING,
        }),
    }

    def can_transition(self, officer: Officer, action: str) -> bool:
        spec = self.ADMIN_TRANSITIONS.get(action)
        if spec is None:
            return False
        _target, allowed_from = spec
        return officer.account_status in allowed_from

    def set_status(self, officer: Officer, status: str, actor: Officer, reason: str = "", request=None):
        old = officer.account_status
        if old == status:
            return officer

        # The state change and its audit record commit together; a failure
        # while writing the audit row rolls the state change back.
        with transaction.atomic():
            officer.account_status = status
            officer.is_active = status == C.ACCOUNT_STATUS_ACTIVE
            if status != C.ACCOUNT_STATUS_ACTIVE:
                officer.locked_until = None
                officer.failed_login_attempts = 0
            else:
                # Reactivation clears any residual lockout so the officer can
                # actually sign in again.
                officer.locked_until = None
                officer.failed_login_attempts = 0
            officer.save()

            from audit.services import audit_service

            event_map = {
                C.ACCOUNT_STATUS_ACTIVE: C.EVENT_ACCOUNT_ACTIVATED,
                C.ACCOUNT_STATUS_SUSPENDED: C.EVENT_ACCOUNT_SUSPENDED,
                C.ACCOUNT_STATUS_DISABLED: C.EVENT_ACCOUNT_DISABLED,
                C.ACCOUNT_STATUS_DEACTIVATED: C.EVENT_ACCOUNT_DEACTIVATED,
                C.ACCOUNT_STATUS_LOCKED: C.EVENT_ACCOUNT_LOCKED,
            }
            event_type = event_map.get(status, C.EVENT_ACCOUNT_STATUS_CHANGED)
            if status == C.ACCOUNT_STATUS_ACTIVE and old in C.BLOCKING_STATUSES:
                event_type = C.EVENT_ACCOUNT_REACTIVATED
            audit_service.record_event(
                event_type,
                officer=officer,
                actor=actor,
                portal=C.PORTAL_IT_ADMIN if actor is not None and actor.pk != officer.pk else "",
                resource_type="officer",
                resource_id=officer.officer_id,
                action=event_type.lower(),
                result=C.RESULT_SUCCESS,
                reason=reason,
                context={"from": old, "to": status},
                previous_state={"account_status": old},
                new_state={"account_status": status},
                request=request,
            )
            audit_service.record_security_event(
                event_type,
                severity=C.SEVERITY_WARNING,
                officer=officer,
                details={"from": old, "to": status, "actor": actor.officer_id if actor else None},
                request=request,
            )

        if status in C.BLOCKING_STATUSES or old in C.BLOCKING_STATUSES:
            # Do not revoke operational authorization here. IT administration
            # controls identity state; investigation authorization is handled
            # by the separate authorization domain.
            officer.revoke_all_sessions(end_reason=C.SESSION_END_ACCOUNT_STATE, actor=actor)
        return officer

    # Convenience transitions.
    def activate(self, officer, actor=None, reason="activated", request=None):
        return self.set_status(officer, C.ACCOUNT_STATUS_ACTIVE, actor, reason, request=request)

    def suspend(self, officer, actor, reason="suspended by Central IT", request=None):
        return self.set_status(officer, C.ACCOUNT_STATUS_SUSPENDED, actor, reason, request=request)

    def disable(self, officer, actor, reason="disabled by Central IT", request=None):
        return self.set_status(officer, C.ACCOUNT_STATUS_DISABLED, actor, reason, request=request)

    def deactivate(self, officer, actor, reason="deactivated by Central IT", request=None):
        return self.set_status(officer, C.ACCOUNT_STATUS_DEACTIVATED, actor, reason, request=request)

    def reactivate(self, officer, actor, reason="reactivated by Central IT", request=None):
        return self.set_status(officer, C.ACCOUNT_STATUS_ACTIVE, actor, reason, request=request)

    def lock(self, officer: Officer, actor: Officer, minutes: Optional[int] = None, reason: str = "", request=None):
        minutes = minutes or int(getattr(settings, "ACCOUNTS_LOCKOUT_MINUTES", 15))
        old = officer.account_status
        with transaction.atomic():
            officer.locked_until = timezone.now() + timezone.timedelta(minutes=minutes)
            officer.account_status = C.ACCOUNT_STATUS_LOCKED
            officer.is_active = False
            officer.save()

            from audit.services import audit_service

            audit_service.record_event(
                C.EVENT_ACCOUNT_LOCKED, officer=officer, actor=actor,
                portal=C.PORTAL_IT_ADMIN, resource_type="officer", resource_id=officer.officer_id,
                action="lock", result=C.RESULT_SUCCESS, reason=reason,
                previous_state={"account_status": old},
                new_state={"account_status": C.ACCOUNT_STATUS_LOCKED, "locked_until": officer.locked_until},
                request=request,
            )
            audit_service.record_security_event(
                C.EVENT_ACCOUNT_LOCKED, severity=C.SEVERITY_ALERT, officer=officer,
                details={"actor": actor.officer_id}, request=request,
            )
        officer.revoke_all_sessions(end_reason=C.SESSION_END_ACCOUNT_STATE, actor=actor)
        return officer

    def emergency_lock(self, officer: Officer, actor: Officer, reason: str, request=None):
        """Immediate, indefinite lock: blocks authentication, kills every
        session and revokes every registered device. Reversible only through
        an explicit administrator reactivation (no auto-expiry)."""
        from .devices import device_session_service
        from .models import RegisteredDevice

        old = officer.account_status
        with transaction.atomic():
            officer.locked_until = None  # indefinite — status alone blocks login
            officer.account_status = C.ACCOUNT_STATUS_LOCKED
            officer.is_active = False
            officer.save()

            from audit.services import audit_service

            audit_service.record_event(
                C.EVENT_ACCOUNT_EMERGENCY_LOCKED, officer=officer, actor=actor,
                portal=C.PORTAL_IT_ADMIN, resource_type="officer", resource_id=officer.officer_id,
                action="emergency_lock", result=C.RESULT_SUCCESS, reason=reason,
                previous_state={"account_status": old},
                new_state={"account_status": C.ACCOUNT_STATUS_LOCKED},
                request=request,
            )
            audit_service.record_security_event(
                C.EVENT_ACCOUNT_EMERGENCY_LOCKED, severity=C.SEVERITY_CRITICAL, officer=officer,
                details={"actor": actor.officer_id, "reason": reason}, request=request,
            )
        officer.revoke_all_sessions(end_reason=C.SESSION_END_ACCOUNT_STATE, actor=actor)
        for device in RegisteredDevice.objects.filter(officer=officer, status=C.DEVICE_STATUS_ACTIVE):
            device_session_service.revoke_device(device, actor, reason=f"Emergency lock: {reason}"[:255], request=request)
        return officer

    def unlock(self, officer: Officer, actor: Officer, reason: str = "", request=None):
        old = officer.account_status
        with transaction.atomic():
            officer.locked_until = None
            officer.failed_login_attempts = 0
            if officer.account_status == C.ACCOUNT_STATUS_LOCKED:
                officer.account_status = C.ACCOUNT_STATUS_ACTIVE
                officer.is_active = True
            officer.save()

            from audit.services import audit_service

            audit_service.record_event(
                C.EVENT_ACCOUNT_UNLOCKED, officer=officer, actor=actor,
                portal=C.PORTAL_IT_ADMIN, resource_type="officer", resource_id=officer.officer_id,
                action="unlock", result=C.RESULT_SUCCESS, reason=reason,
                previous_state={"account_status": old},
                new_state={"account_status": officer.account_status},
                request=request,
            )
            audit_service.record_security_event(
                C.EVENT_ACCOUNT_UNLOCKED, severity=C.SEVERITY_INFO, officer=officer,
                details={"actor": actor.officer_id}, request=request,
            )
        return officer

    def assign_role(self, officer: Officer, role: Optional[Role], actor: Officer, reason: str = "", request=None):
        old = officer.role
        if (old.pk if old else None) == (role.pk if role else None):
            return officer
        officer.role = role
        officer.save(update_fields=["role", "updated_at"])

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_ROLE_CHANGED, officer=officer, actor=actor, result=C.RESULT_SUCCESS,
            portal=C.PORTAL_IT_ADMIN, resource_type="officer", resource_id=officer.officer_id,
            action="assign_role", reason=reason,
            context={"from": old.name if old else None, "to": role.name if role else None},
            previous_state={"role": old.name if old else None},
            new_state={"role": role.name if role else None},
            request=request,
        )
        return officer

    def assign_clearance(self, officer: Officer, clearance: Optional[ClearanceLevel], actor: Officer, reason: str = "", request=None):
        old = officer.clearance
        if (old.pk if old else None) == (clearance.pk if clearance else None):
            return officer
        officer.clearance = clearance
        officer.save(update_fields=["clearance", "updated_at"])

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_CLEARANCE_CHANGED, officer=officer, actor=actor, result=C.RESULT_SUCCESS,
            portal=C.PORTAL_IT_ADMIN, resource_type="officer", resource_id=officer.officer_id,
            action="assign_clearance", reason=reason,
            context={"from": old.code if old else None, "to": clearance.code if clearance else None},
            previous_state={"clearance": old.code if old else None},
            new_state={"clearance": clearance.code if clearance else None},
            request=request,
        )
        return officer

    def assign_unit(self, officer: Officer, unit: Optional[OrganizationUnit], actor: Officer, reason: str = "", request=None):
        old = officer.unit
        if (old.pk if old else None) == (unit.pk if unit else None):
            return officer
        officer.unit = unit
        officer.save(update_fields=["unit", "updated_at"])

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_UNIT_CHANGED, officer=officer, actor=actor, result=C.RESULT_SUCCESS,
            portal=C.PORTAL_IT_ADMIN, resource_type="officer", resource_id=officer.officer_id,
            action="assign_unit", reason=reason,
            context={"from": old.name if old else None, "to": unit.name if unit else None},
            previous_state={"unit": old.name if old else None},
            new_state={"unit": unit.name if unit else None},
            request=request,
        )
        return officer


# ---------------------------------------------------------------------------
# Provisioning (section 7) — Central IT is the root identity authority
# ---------------------------------------------------------------------------
class ProvisioningService:
    """All account creation and credential operations flow through here.

    Senior officers have no path here — only ``officer.manage`` holders
    (Central IT) may provision. This is also where the no-impersonation rule
    is anchored: provisioning changes a *target* officer, never the actor.
    """

    def provision_officer(
        self,
        *,
        actor: Officer,
        officer_id: str,
        email: str,
        full_name: str,
        initial_password: str,
        role: Optional[Role],
        clearance: Optional[ClearanceLevel],
        unit: Optional[OrganizationUnit],
        rank: str = "",
        department=None,
        designation: Optional[Designation] = None,
        employee_id: str = "",
        supervisor: Optional[Officer] = None,
        joining_date=None,
        phone: str = "",
        portals: Iterable[Portal] = (),
        initial_secret_code: str = "",
        reason: str = "",
        request=None,
    ) -> Officer:
        # ``department`` accepts a Department instance (new) or a legacy
        # free-text label (older callers/tests) which is preserved verbatim.
        legacy_department = ""
        if isinstance(department, str):
            legacy_department, department = department, None

        with transaction.atomic():
            officer = Officer.objects.create_officer(
                officer_id=officer_id,
                email=email,
                password=initial_password,
                full_name=full_name,
                role=role,
                clearance=clearance,
                unit=unit,
                rank=rank or (designation.name if designation else ""),
                designation=designation,
                department=department,
                legacy_department=legacy_department,
                employee_id=(employee_id or "").strip().upper(),
                supervisor=supervisor,
                joining_date=joining_date,
                phone=phone,
                account_status=C.ACCOUNT_STATUS_INVITED,
                is_active=False,
            )

            if initial_secret_code:
                SecurityCodeService().set_secret_code(officer, initial_secret_code, actor=actor)

            granted = []
            for portal in portals:
                self.grant_portal(officer, portal, actor, reason="provisioned by Central IT")
                granted.append(portal.key)

            # Initial posting is history too — a later transfer must be able
            # to show where the officer started.
            if department or unit or designation:
                PostingHistory.objects.create(
                    officer=officer,
                    kind=C.POSTING_INITIAL,
                    to_department=department,
                    to_unit=unit,
                    to_designation=designation,
                    effective_date=joining_date or timezone.localdate(),
                    reason=reason or "Initial posting at provisioning",
                    recorded_by=actor,
                )

            from audit.services import audit_service

            audit_service.record_event(
                C.EVENT_ACCOUNT_CREATED,
                officer=officer,
                actor=actor,
                portal=C.PORTAL_IT_ADMIN,
                resource_type="officer",
                resource_id=officer.officer_id,
                action="provision",
                result=C.RESULT_SUCCESS,
                reason=reason,
                context={"portals": granted, "role": role.name if role else None},
                new_state={
                    "full_name": full_name,
                    "email": email,
                    "department": department.name if department else legacy_department or None,
                    "unit": unit.name if unit else None,
                    "designation": designation.name if designation else rank or None,
                    "account_status": C.ACCOUNT_STATUS_INVITED,
                },
                request=request,
            )
        return officer

    def generate_officer_id(self) -> str:
        return OfficerIDService().generate()

    def reset_password(self, officer: Officer, actor: Officer, new_password: str):
        officer.set_password(new_password)
        officer.failed_login_attempts = 0
        officer.locked_until = None
        officer.save()

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_PASSWORD_RESET, officer=officer, actor=actor, result=C.RESULT_SUCCESS,
            portal=C.PORTAL_IT_ADMIN, resource_type="officer", resource_id=officer.officer_id,
            action="reset_password",
        )
        officer.revoke_all_sessions(end_reason=C.SESSION_END_CREDENTIAL_RESET, actor=actor)
        return officer

    def reset_secret_code(self, officer: Officer, actor: Officer, new_code: str):
        SecurityCodeService().set_secret_code(officer, new_code, actor=actor)
        officer.revoke_all_sessions(end_reason=C.SESSION_END_CREDENTIAL_RESET, actor=actor)
        return officer

    def grant_portal(self, officer: Officer, portal: Portal, actor: Officer, reason: str = ""):
        access, created = PortalAccess.objects.get_or_create(
            officer=officer, portal=portal,
            defaults={"granted_by": actor, "reason": reason},
        )
        if not created and access.revoked_at:
            access.revoked_at = None
            access.granted_by = actor
            access.reason = reason
            access.save()

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_PORTAL_GRANTED,
            officer=officer, actor=actor, portal=portal.key,
            result=C.RESULT_SUCCESS, reason=reason,
        )
        return access

    def revoke_portal(self, officer: Officer, portal: Portal, actor: Officer, reason: str = ""):
        access = PortalAccess.objects.filter(officer=officer, portal=portal).first()
        if access:
            access.revoked_at = timezone.now()
            access.save(update_fields=["revoked_at"])

        from audit.services import audit_service

        audit_service.record_event(
            C.EVENT_PORTAL_REVOKED,
            officer=officer, actor=actor, portal=portal.key,
            result=C.RESULT_SUCCESS, reason=reason,
        )
        return access


# ---------------------------------------------------------------------------
# Session security (section 13)
# ---------------------------------------------------------------------------
class SessionService:
    """Establishes and polices authenticated sessions."""

    def establish(self, request, officer: Officer, portal_key: str):
        """Configure the freshly-authenticated session (rotation happens in
        ``django.contrib.auth.login``)."""
        now = timezone.now()
        request.session[C.SESSION_PORTAL_KEY] = portal_key
        request.session[C.SESSION_LOGIN_AT] = now.isoformat()
        request.session[C.SESSION_MFA_VERIFIED_AT] = now.isoformat()
        request.session[C.SESSION_REAUTH_AT] = now.isoformat()

    def mark_mfa_verified(self, request):
        request.session[C.SESSION_MFA_VERIFIED_AT] = timezone.now().isoformat()

    def mark_reauth(self, request):
        request.session[C.SESSION_REAUTH_AT] = timezone.now().isoformat()

    def mfa_verified_at(self, request):
        raw = request.session.get(C.SESSION_MFA_VERIFIED_AT)
        if not raw:
            return None
        try:
            return timezone.datetime.fromisoformat(raw)
        except (ValueError, TypeError):
            return None

    def reauth_at(self, request):
        raw = request.session.get(C.SESSION_REAUTH_AT)
        if not raw:
            return None
        try:
            return timezone.datetime.fromisoformat(raw)
        except (ValueError, TypeError):
            return None

    def requires_reauth(self, request) -> bool:
        """True when the officer must re-verify their second factor for a
        sensitive operation (inactivity or re-auth interval exceeded)."""
        last = self.reauth_at(request)
        if last is None:
            return True
        interval = int(getattr(settings, "ACCOUNTS_REAUTH_INTERVAL_SECONDS", 600))
        return (timezone.now() - last).total_seconds() > interval

    def expire_session(self, request):
        request.session.flush()

    def session_age_seconds(self, request) -> int:
        raw = request.session.get(C.SESSION_LOGIN_AT)
        if not raw:
            return 0
        try:
            started = timezone.datetime.fromisoformat(raw)
        except (ValueError, TypeError):
            return 0
        return int((timezone.now() - started).total_seconds())


# Singleton instances.
officer_id_service = OfficerIDService()
security_code_service = SecurityCodeService()
login_protection_service = LoginProtectionService()
account_service = AccountService()
provisioning_service = ProvisioningService()
session_service = SessionService()
