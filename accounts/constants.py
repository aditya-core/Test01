"""Central constants for the identity and authorization layer.

Everything here is *configurable data* — values are referenced by name and
stored in the database (roles, clearances, portals, permissions). The string
constants below are the keys/identifiers used across the codebase; their
meaning is defined by seed data, not by hard-coded policy.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Account states (section 11 of the spec)
# ---------------------------------------------------------------------------
ACCOUNT_STATUS_PENDING = "PENDING"
ACCOUNT_STATUS_INVITED = "INVITED"
ACCOUNT_STATUS_ACTIVE = "ACTIVE"
ACCOUNT_STATUS_SUSPENDED = "SUSPENDED"
ACCOUNT_STATUS_LOCKED = "LOCKED"
ACCOUNT_STATUS_DISABLED = "DISABLED"
ACCOUNT_STATUS_DEACTIVATED = "DEACTIVATED"

ACCOUNT_STATUS_CHOICES = (
    (ACCOUNT_STATUS_PENDING, "Pending"),
    (ACCOUNT_STATUS_INVITED, "Invited"),
    (ACCOUNT_STATUS_ACTIVE, "Active"),
    (ACCOUNT_STATUS_SUSPENDED, "Suspended"),
    (ACCOUNT_STATUS_LOCKED, "Locked"),
    (ACCOUNT_STATUS_DISABLED, "Disabled"),
    (ACCOUNT_STATUS_DEACTIVATED, "Deactivated"),
)

# Statuses in which authentication is allowed at all.
AUTHENTICABLE_STATUSES = {ACCOUNT_STATUS_ACTIVE}

# Statuses that block a user from authenticating but are reversible.
BLOCKING_STATUSES = {
    ACCOUNT_STATUS_SUSPENDED,
    ACCOUNT_STATUS_LOCKED,
    ACCOUNT_STATUS_DISABLED,
    ACCOUNT_STATUS_DEACTIVATED,
}

# ---------------------------------------------------------------------------
# Portal keys (section 3)
# ---------------------------------------------------------------------------
PORTAL_CLASSIFIED = "classified"
PORTAL_IT_ADMIN = "it_admin"
PORTAL_GENERAL = "general"

PORTAL_CHOICES = (
    (PORTAL_CLASSIFIED, "Classified"),
    (PORTAL_IT_ADMIN, "IT / Admin"),
    (PORTAL_GENERAL, "General"),
)

# Portal → login URL name + required login "kind" label (UI only).
PORTAL_LOGIN_URLS = {
    PORTAL_CLASSIFIED: "accounts:login",
    PORTAL_IT_ADMIN: "accounts:login",
    PORTAL_GENERAL: "accounts:login",
}

# ---------------------------------------------------------------------------
# RBAC permission codenames
# ---------------------------------------------------------------------------
PERM_OFFICER_MANAGE = "officer.manage"
PERM_OFFICER_VIEW = "officer.view"
PERM_SECURITY_VIEW_EVENTS = "security.view_events"
PERM_SECURITY_MANAGE_SETTINGS = "security.manage_settings"
PERM_AUDIT_VIEW = "audit.view"
PERM_ACCOUNT_MANAGE_SECURITY = "account.manage_security"

# ---------------------------------------------------------------------------
# Authentication factor types
# ---------------------------------------------------------------------------
FACTOR_SECRET_CODE = "SECRET_CODE"
FACTOR_TOTP = "TOTP"                      # reserved for future migration
FACTOR_HARDWARE_TOKEN = "HARDWARE_TOKEN"  # reserved for future migration

FACTOR_TYPE_CHOICES = (
    (FACTOR_SECRET_CODE, "Secret code"),
    (FACTOR_TOTP, "TOTP authenticator"),
    (FACTOR_HARDWARE_TOKEN, "Hardware token"),
)

# ---------------------------------------------------------------------------
# Organization / unit kinds
# ---------------------------------------------------------------------------
ORG_NATIONAL = "NATIONAL"
ORG_STATE = "STATE"
ORG_DISTRICT = "DISTRICT"

ORG_KIND_CHOICES = (
    (ORG_NATIONAL, "National"),
    (ORG_STATE, "State"),
    (ORG_DISTRICT, "District"),
)

UNIT_KIND_HQ = "HQ"
UNIT_KIND_INVESTIGATION = "INVESTIGATION"
UNIT_KIND_CYBER = "CYBER"
UNIT_KIND_FORENSIC = "FORENSIC"
UNIT_KIND_ADMIN = "ADMINISTRATION"

UNIT_KIND_CHOICES = (
    (UNIT_KIND_HQ, "Headquarters"),
    (UNIT_KIND_INVESTIGATION, "Investigation Unit"),
    (UNIT_KIND_CYBER, "Cyber Unit"),
    (UNIT_KIND_FORENSIC, "Forensic Unit"),
    (UNIT_KIND_ADMIN, "Administration Unit"),
)

# ---------------------------------------------------------------------------
# Audit event types
# ---------------------------------------------------------------------------
EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILURE = "LOGIN_FAILURE"
EVENT_LOGIN_BLOCKED = "LOGIN_BLOCKED"
EVENT_ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
EVENT_ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
EVENT_ACCOUNT_CREATED = "ACCOUNT_CREATED"
EVENT_ACCOUNT_ACTIVATED = "ACCOUNT_ACTIVATED"
EVENT_ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
EVENT_ACCOUNT_SUSPENDED = "ACCOUNT_SUSPENDED"
EVENT_ACCOUNT_DEACTIVATED = "ACCOUNT_DEACTIVATED"
EVENT_ACCOUNT_STATUS_CHANGED = "ACCOUNT_STATUS_CHANGED"
EVENT_PASSWORD_CHANGED = "PASSWORD_CHANGED"
EVENT_PASSWORD_RESET = "PASSWORD_RESET"
EVENT_MFA_CHANGED = "MFA_CHANGED"
EVENT_SECRET_CODE_CHANGED = "SECRET_CODE_CHANGED"
EVENT_SECRET_CODE_RESET = "SECRET_CODE_RESET"
EVENT_ROLE_CHANGED = "ROLE_CHANGED"
EVENT_CLEARANCE_CHANGED = "CLEARANCE_CHANGED"
EVENT_UNIT_CHANGED = "UNIT_CHANGED"
EVENT_PORTAL_GRANTED = "PORTAL_GRANTED"
EVENT_PORTAL_REVOKED = "PORTAL_REVOKED"
EVENT_PORTAL_ACCESS = "PORTAL_ACCESS"
EVENT_PORTAL_ACCESS_DENIED = "PORTAL_ACCESS_DENIED"
EVENT_ACCESS_GRANTED = "ACCESS_GRANTED"
EVENT_ACCESS_DENIED = "ACCESS_DENIED"
EVENT_LOGOUT = "LOGOUT"
EVENT_SESSION_EXPIRED = "SESSION_EXPIRED"
EVENT_REAUTH_SUCCESS = "REAUTH_SUCCESS"
EVENT_REAUTH_FAILURE = "REAUTH_FAILURE"
EVENT_IMPERSONATION_REJECTED = "IMPERSONATION_REJECTED"
EVENT_BREAK_GLASS_REQUEST = "BREAK_GLASS_REQUEST"  # reserved for future use

# ---------------------------------------------------------------------------
# Audit / security result values
# ---------------------------------------------------------------------------
RESULT_ALLOW = "ALLOW"
RESULT_DENY = "DENY"
RESULT_SUCCESS = "SUCCESS"
RESULT_FAILURE = "FAILURE"

# ---------------------------------------------------------------------------
# Security event severity
# ---------------------------------------------------------------------------
SEVERITY_INFO = "INFO"
SEVERITY_WARNING = "WARNING"
SEVERITY_ALERT = "ALERT"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_CHOICES = (
    (SEVERITY_INFO, "Info"),
    (SEVERITY_WARNING, "Warning"),
    (SEVERITY_ALERT, "Alert"),
    (SEVERITY_CRITICAL, "Critical"),
)

# ---------------------------------------------------------------------------
# Session keys
# ---------------------------------------------------------------------------
SESSION_PORTAL_KEY = "portal"
SESSION_MFA_VERIFIED_AT = "mfa_verified_at"
SESSION_REAUTH_AT = "reauth_at"
SESSION_LOGIN_AT = "session_created_at"
