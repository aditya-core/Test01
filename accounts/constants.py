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
# Legacy umbrella capability kept for backward compatibility. It *implies* the
# granular officer.* capabilities below (see ``CAPABILITY_IMPLICATIONS``).
PERM_OFFICER_MANAGE = "officer.manage"
PERM_OFFICER_VIEW = "officer.view"
PERM_SECURITY_VIEW_EVENTS = "security.view_events"
PERM_SECURITY_MANAGE_SETTINGS = "security.manage_settings"
PERM_AUDIT_VIEW = "audit.view"
PERM_ACCOUNT_MANAGE_SECURITY = "account.manage_security"

# Granular identity-administration capabilities (IT / Admin portal).
PERM_OFFICER_CREATE = "officer.create"
PERM_OFFICER_UPDATE = "officer.update"
PERM_OFFICER_SUSPEND = "officer.suspend"
PERM_OFFICER_REACTIVATE = "officer.reactivate"
PERM_OFFICER_TRANSFER = "officer.transfer"
PERM_OFFICER_AUTHORIZATION = "officer.authorization"
PERM_OFFICER_BULK_IMPORT = "officer.bulk_import"
PERM_DESIGNATION_VIEW = "designation.view"
PERM_DESIGNATION_MANAGE = "designation.manage"
PERM_DEPARTMENT_VIEW = "department.view"
PERM_DEPARTMENT_MANAGE = "department.manage"
PERM_DEVICE_VIEW = "device.view"
PERM_DEVICE_REVOKE = "device.revoke"
PERM_SESSION_VIEW = "session.view"
PERM_SESSION_TERMINATE = "session.terminate"
PERM_ADMIN_ROLE_MANAGE = "admin.role.manage"
PERM_APPROVAL_REVIEW = "approval.review"
PERM_ACCESS_REVIEW = "access.review"
PERM_ACCESS_GRANT_TEMPORARY = "access.grant_temporary"

# Descriptions used by seed data / data migrations (data, not policy).
ADMIN_CAPABILITY_DESCRIPTIONS = {
    PERM_OFFICER_VIEW: "View the officer directory and profiles.",
    PERM_OFFICER_MANAGE: "Legacy umbrella: implies the granular officer.* capabilities.",
    PERM_OFFICER_CREATE: "Provision new officer identities.",
    PERM_OFFICER_UPDATE: "Edit officer identity and service information.",
    PERM_OFFICER_SUSPEND: "Suspend, lock, disable or deactivate officer accounts.",
    PERM_OFFICER_REACTIVATE: "Reactivate or unlock officer accounts.",
    PERM_OFFICER_TRANSFER: "Transfer officers between departments / units.",
    PERM_OFFICER_AUTHORIZATION: "Assign role, clearance and portal entry to officers.",
    PERM_OFFICER_BULK_IMPORT: "Run bulk officer operations (CSV import, bulk updates).",
    PERM_DESIGNATION_VIEW: "View the designation registry.",
    PERM_DESIGNATION_MANAGE: "Create, edit and deactivate designations.",
    PERM_DEPARTMENT_VIEW: "View departments and units.",
    PERM_DEPARTMENT_MANAGE: "Create, edit and deactivate departments and units.",
    PERM_DEVICE_VIEW: "View registered devices.",
    PERM_DEVICE_REVOKE: "Revoke registered devices.",
    PERM_SESSION_VIEW: "View active sessions.",
    PERM_SESSION_TERMINATE: "Terminate sessions.",
    PERM_SECURITY_VIEW_EVENTS: "View security events (failed logins, lockouts, denials).",
    PERM_SECURITY_MANAGE_SETTINGS: "Manage system-level security settings.",
    PERM_AUDIT_VIEW: "View the tamper-evident audit trail.",
    PERM_ACCOUNT_MANAGE_SECURITY: "Issue / reset credentials and MFA for officers.",
    PERM_ADMIN_ROLE_MANAGE: "Manage administrative roles and their capabilities (four-eyes).",
    PERM_APPROVAL_REVIEW: "Approve or reject pending administrative requests.",
    PERM_ACCESS_REVIEW: "Perform periodic access reviews.",
    PERM_ACCESS_GRANT_TEMPORARY: "Grant time-boxed administrative capabilities.",
}

# Capability prefixes that belong to the IT / identity administration domain.
# Anything else (case.*, document.*, report.* ...) is OPERATIONAL authorization
# and is never granted, revoked or explained as an admin capability here.
ADMIN_CAPABILITY_PREFIXES = (
    "officer.", "designation.", "department.", "device.", "session.",
    "security.", "audit.", "account.", "admin.", "approval.", "access.",
)


def is_admin_capability(codename: str) -> bool:
    return bool(codename) and codename.startswith(ADMIN_CAPABILITY_PREFIXES)


# Umbrella → implied capabilities. Kept deliberately tiny: it exists only so
# that roles created before the granular capabilities existed keep working.
CAPABILITY_IMPLICATIONS = {
    PERM_OFFICER_MANAGE: frozenset({
        PERM_OFFICER_VIEW, PERM_OFFICER_CREATE, PERM_OFFICER_UPDATE,
        PERM_OFFICER_SUSPEND, PERM_OFFICER_REACTIVATE, PERM_OFFICER_TRANSFER,
        PERM_OFFICER_AUTHORIZATION,
    }),
}

# Reference capability set for seeded IT administration roles (data).
IDENTITY_ADMIN_CAPABILITIES = (
    PERM_OFFICER_VIEW, PERM_OFFICER_CREATE, PERM_OFFICER_UPDATE,
    PERM_OFFICER_TRANSFER, PERM_OFFICER_SUSPEND, PERM_OFFICER_REACTIVATE,
    PERM_DESIGNATION_VIEW, PERM_DESIGNATION_MANAGE,
    PERM_DEPARTMENT_VIEW, PERM_DEPARTMENT_MANAGE,
)
SYSTEM_ADMIN_CAPABILITIES = IDENTITY_ADMIN_CAPABILITIES + (
    PERM_OFFICER_MANAGE, PERM_OFFICER_AUTHORIZATION, PERM_OFFICER_BULK_IMPORT,
    PERM_ACCOUNT_MANAGE_SECURITY, PERM_DEVICE_VIEW, PERM_DEVICE_REVOKE,
    PERM_SESSION_VIEW, PERM_SESSION_TERMINATE, PERM_AUDIT_VIEW,
    PERM_ADMIN_ROLE_MANAGE, PERM_APPROVAL_REVIEW, PERM_ACCESS_REVIEW,
    PERM_ACCESS_GRANT_TEMPORARY,
)
SECURITY_ADMIN_CAPABILITIES = (
    PERM_OFFICER_VIEW, PERM_SECURITY_VIEW_EVENTS, PERM_SECURITY_MANAGE_SETTINGS,
    PERM_AUDIT_VIEW, PERM_DEVICE_VIEW, PERM_DEVICE_REVOKE, PERM_SESSION_VIEW,
    PERM_SESSION_TERMINATE, PERM_OFFICER_SUSPEND, PERM_OFFICER_REACTIVATE,
    PERM_APPROVAL_REVIEW, PERM_ACCESS_REVIEW,
)
AUDITOR_CAPABILITIES = (
    PERM_OFFICER_VIEW, PERM_AUDIT_VIEW, PERM_SECURITY_VIEW_EVENTS,
    PERM_DEVICE_VIEW, PERM_SESSION_VIEW, PERM_DESIGNATION_VIEW, PERM_DEPARTMENT_VIEW,
)

# ---------------------------------------------------------------------------
# Operational (case / document / evidence) authorization
# ---------------------------------------------------------------------------
# Operational authorization is *evaluated* by the central engine but granted by
# the operational domain — never by IT administration. ``is_admin_capability``
# deliberately excludes the ``case.`` prefix so the IT portal can neither grant
# nor explain these.

# --- Resource types ---------------------------------------------------------
RESOURCE_CASE = "case"
RESOURCE_DOCUMENT = "document"
RESOURCE_FIR = "fir"
RESOURCE_EVIDENCE = "evidence"

RESOURCE_TYPE_CHOICES = (
    (RESOURCE_CASE, "Case"),
    (RESOURCE_DOCUMENT, "Document"),
    (RESOURCE_FIR, "FIR"),
    (RESOURCE_EVIDENCE, "Evidence"),
)

# --- Actions ----------------------------------------------------------------
# Access is never a boolean: every request names an action.
ACTION_VIEW = "view"
ACTION_DOWNLOAD = "download"
ACTION_UPLOAD = "upload"
ACTION_EDIT = "edit"
ACTION_SHARE = "share"
ACTION_COMMENT = "comment"
ACTION_APPROVE = "approve"
ACTION_MANAGE_ACCESS = "manage_access"
ACTION_ASSIGN = "assign"

CASE_ACTIONS = frozenset({
    ACTION_VIEW,
    ACTION_DOWNLOAD,
    ACTION_UPLOAD,
    ACTION_EDIT,
    ACTION_SHARE,
    ACTION_COMMENT,
    ACTION_APPROVE,
    ACTION_MANAGE_ACCESS,
    ACTION_ASSIGN,
})

# What a *file* resource (FIR / evidence / document) can be asked for.
FILE_ACTIONS = frozenset({ACTION_VIEW, ACTION_DOWNLOAD, ACTION_SHARE})

ACTION_LABELS = {
    ACTION_VIEW: "View",
    ACTION_DOWNLOAD: "Download",
    ACTION_UPLOAD: "Upload",
    ACTION_EDIT: "Edit",
    ACTION_SHARE: "Share",
    ACTION_COMMENT: "Comment",
    ACTION_APPROVE: "Approve",
    ACTION_MANAGE_ACCESS: "Manage access",
    ACTION_ASSIGN: "Assign officers",
}

# --- Capabilities ------------------------------------------------------------
PERM_CASE_VIEW = "case.view"
PERM_CASE_CREATE = "case.create"
PERM_CASE_EDIT = "case.edit"
PERM_CASE_ASSIGN = "case.assign"
PERM_CASE_UPLOAD = "case.upload"
PERM_CASE_DOWNLOAD = "case.download"
PERM_CASE_SHARE = "case.share"
PERM_CASE_COMMENT = "case.comment"
PERM_CASE_APPROVE = "case.approve"
PERM_CASE_MANAGE_ACCESS = "case.manage_access"

# Action -> capability an officer must hold to perform it. An officer can only
# exercise actions their role carries; a grant can never invent a capability.
CASE_ACTION_PERMISSIONS = {
    ACTION_VIEW: PERM_CASE_VIEW,
    ACTION_DOWNLOAD: PERM_CASE_DOWNLOAD,
    ACTION_UPLOAD: PERM_CASE_UPLOAD,
    ACTION_EDIT: PERM_CASE_EDIT,
    ACTION_SHARE: PERM_CASE_SHARE,
    ACTION_COMMENT: PERM_CASE_COMMENT,
    ACTION_APPROVE: PERM_CASE_APPROVE,
    ACTION_MANAGE_ACCESS: PERM_CASE_MANAGE_ACCESS,
    ACTION_ASSIGN: PERM_CASE_ASSIGN,
}

# --- Case assignment roles ------------------------------------------------------
ASSIGNMENT_OWNER = "OWNER"
ASSIGNMENT_INVESTIGATOR = "INVESTIGATOR"
ASSIGNMENT_SUPERVISOR = "SUPERVISOR"
ASSIGNMENT_VIEWER = "VIEWER"

ASSIGNMENT_ROLE_CHOICES = (
    (ASSIGNMENT_OWNER, "Case owner (full control)"),
    (ASSIGNMENT_INVESTIGATOR, "Investigating officer"),
    (ASSIGNMENT_SUPERVISOR, "Supervising officer (oversight)"),
    (ASSIGNMENT_VIEWER, "Viewer (read-only)"),
)

ASSIGNMENT_ROLE_ACTIONS = {
    ASSIGNMENT_OWNER: frozenset(CASE_ACTIONS),
    ASSIGNMENT_INVESTIGATOR: frozenset({
        ACTION_VIEW, ACTION_DOWNLOAD, ACTION_UPLOAD, ACTION_EDIT, ACTION_COMMENT,
    }),
    # A supervising officer inherits oversight *and* the ability to manage who
    # else may see the case — that is the point of hierarchical authority — but
    # not the owner's power to assign or edit the investigation itself.
    ASSIGNMENT_SUPERVISOR: frozenset({
        ACTION_VIEW, ACTION_DOWNLOAD, ACTION_COMMENT, ACTION_APPROVE,
        ACTION_MANAGE_ACCESS, ACTION_SHARE,
    }),
    ASSIGNMENT_VIEWER: frozenset({ACTION_VIEW}),
}

# --- Access grant scopes --------------------------------------------------------
GRANT_SCOPE_CASE = "CASE"
GRANT_SCOPE_SELECTED = "SELECTED"
GRANT_SCOPE_STATION = "STATION"
GRANT_SCOPE_JURISDICTION = "JURISDICTION"

GRANT_SCOPE_CHOICES = (
    (GRANT_SCOPE_CASE, "This case"),
    (GRANT_SCOPE_SELECTED, "Selected cases"),
    (GRANT_SCOPE_STATION, "Station / unit"),
    (GRANT_SCOPE_JURISDICTION, "Jurisdiction"),
)

# Scopes that derive access from a *place* rather than from a named resource.
# These are re-evaluated when an officer is transferred.
GRANT_PLACE_SCOPES = frozenset({GRANT_SCOPE_STATION, GRANT_SCOPE_JURISDICTION})

GRANT_STATUS_ACTIVE = "ACTIVE"
GRANT_STATUS_REVOKED = "REVOKED"
GRANT_STATUS_CHOICES = (
    (GRANT_STATUS_ACTIVE, "Active"),
    (GRANT_STATUS_REVOKED, "Revoked"),
)

# --- Access requests ------------------------------------------------------------
REQUEST_PENDING = "PENDING"
REQUEST_APPROVED = "APPROVED"
REQUEST_REJECTED = "REJECTED"
REQUEST_CANCELLED = "CANCELLED"
REQUEST_STATUS_CHOICES = (
    (REQUEST_PENDING, "Pending"),
    (REQUEST_APPROVED, "Approved"),
    (REQUEST_REJECTED, "Rejected"),
    (REQUEST_CANCELLED, "Cancelled"),
)

# --- Seed data ---------------------------------------------------------------------
OPERATIONAL_CAPABILITY_DESCRIPTIONS = {
    PERM_CASE_VIEW: "View authorized investigation cases.",
    PERM_CASE_CREATE: "Register new investigation cases.",
    PERM_CASE_EDIT: "Edit authorized investigation cases.",
    PERM_CASE_ASSIGN: "Assign officers to authorized cases.",
    PERM_CASE_UPLOAD: "Upload evidence and documents into authorized cases.",
    PERM_CASE_DOWNLOAD: "Download FIR, evidence and documents from authorized cases.",
    PERM_CASE_SHARE: "Share authorized case material with other officers.",
    PERM_CASE_COMMENT: "Comment on authorized cases.",
    PERM_CASE_APPROVE: "Approve actions on authorized cases.",
    PERM_CASE_MANAGE_ACCESS: "Grant, revoke and decide access to authorized cases.",
}

# Operational capabilities granted to each seeded operational role (data, not
# policy). IT-administration roles are deliberately absent: administering
# accounts never grants investigation access (see docs/07 separation of duties).
ROLE_OPERATIONAL_CAPABILITIES = {
    "FIELD_OFFICER": (
        PERM_CASE_VIEW, PERM_CASE_CREATE, PERM_CASE_UPLOAD, PERM_CASE_DOWNLOAD,
        PERM_CASE_COMMENT,
    ),
    "INVESTIGATING_OFFICER": (
        PERM_CASE_VIEW, PERM_CASE_CREATE, PERM_CASE_EDIT, PERM_CASE_UPLOAD,
        PERM_CASE_DOWNLOAD, PERM_CASE_COMMENT, PERM_CASE_MANAGE_ACCESS,
    ),
    "FORENSIC_OFFICER": (
        PERM_CASE_VIEW, PERM_CASE_UPLOAD, PERM_CASE_DOWNLOAD, PERM_CASE_COMMENT,
    ),
    "INSPECTOR": (
        PERM_CASE_VIEW, PERM_CASE_CREATE, PERM_CASE_EDIT, PERM_CASE_ASSIGN,
        PERM_CASE_UPLOAD, PERM_CASE_DOWNLOAD, PERM_CASE_SHARE, PERM_CASE_COMMENT,
        PERM_CASE_APPROVE, PERM_CASE_MANAGE_ACCESS,
    ),
    "SENIOR_OFFICER": (
        PERM_CASE_VIEW, PERM_CASE_ASSIGN, PERM_CASE_DOWNLOAD, PERM_CASE_SHARE,
        PERM_CASE_COMMENT, PERM_CASE_APPROVE, PERM_CASE_MANAGE_ACCESS,
    ),
    "COMMISSIONER": (
        PERM_CASE_VIEW, PERM_CASE_ASSIGN, PERM_CASE_DOWNLOAD, PERM_CASE_SHARE,
        PERM_CASE_COMMENT, PERM_CASE_APPROVE, PERM_CASE_MANAGE_ACCESS,
    ),
}

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
UNIT_KIND_STATION = "POLICE_STATION"

UNIT_KIND_CHOICES = (
    (UNIT_KIND_HQ, "Headquarters"),
    (UNIT_KIND_INVESTIGATION, "Investigation Unit"),
    (UNIT_KIND_CYBER, "Cyber Unit"),
    (UNIT_KIND_FORENSIC, "Forensic Unit"),
    (UNIT_KIND_ADMIN, "Administration Unit"),
    (UNIT_KIND_STATION, "Police Station"),
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

# Identity-administration events (IT / Admin portal).
EVENT_OFFICER_CREATED = EVENT_ACCOUNT_CREATED  # same lifecycle event
EVENT_OFFICER_UPDATED = "OFFICER_UPDATED"
EVENT_CREDENTIALS_ISSUED = "CREDENTIALS_ISSUED"
EVENT_DESIGNATION_CHANGED = "DESIGNATION_CHANGED"
EVENT_DEPARTMENT_CHANGED = "DEPARTMENT_CHANGED"
EVENT_TRANSFER_COMPLETED = "TRANSFER_COMPLETED"
EVENT_ACCOUNT_REACTIVATED = "ACCOUNT_REACTIVATED"
EVENT_ACCOUNT_EMERGENCY_LOCKED = "ACCOUNT_EMERGENCY_LOCKED"
EVENT_DEVICE_REGISTERED = "DEVICE_REGISTERED"
EVENT_DEVICE_REVOKED = "DEVICE_REVOKED"
EVENT_SESSION_TERMINATED = "SESSION_TERMINATED"
EVENT_DESIGNATION_REGISTRY_CHANGED = "DESIGNATION_REGISTRY_CHANGED"
EVENT_DEPARTMENT_REGISTRY_CHANGED = "DEPARTMENT_REGISTRY_CHANGED"
EVENT_UNIT_REGISTRY_CHANGED = "UNIT_REGISTRY_CHANGED"
EVENT_TEMPORARY_ACCESS_GRANTED = "TEMPORARY_ACCESS_GRANTED"
EVENT_TEMPORARY_ACCESS_REVOKED = "TEMPORARY_ACCESS_REVOKED"
EVENT_ACCESS_REVIEW_CREATED = "ACCESS_REVIEW_CREATED"
EVENT_ACCESS_REVIEW_DECIDED = "ACCESS_REVIEW_DECIDED"
EVENT_ADMIN_ROLE_CHANGED = "ADMIN_ROLE_CHANGED"
EVENT_APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
EVENT_APPROVAL_GRANTED = "APPROVAL_GRANTED"
EVENT_APPROVAL_REJECTED = "APPROVAL_REJECTED"
EVENT_APPROVAL_CANCELLED = "APPROVAL_CANCELLED"
EVENT_BULK_OPERATION = "BULK_OPERATION"
EVENT_AUDIT_CHAIN_VERIFIED = "AUDIT_CHAIN_VERIFIED"

# Operational (case) authorization events.
EVENT_CASE_REGISTERED = "CASE_REGISTERED"
EVENT_CASE_VIEWED = "CASE_VIEWED"
EVENT_CASE_TRANSFERRED = "CASE_TRANSFERRED"
EVENT_CASE_ACCESS_DENIED = "CASE_ACCESS_DENIED"
EVENT_CASE_DOCUMENT_DOWNLOAD = "CASE_DOCUMENT_DOWNLOAD"
EVENT_FILE_VIEW = "FILE_VIEW"
EVENT_FILE_DOWNLOAD = "FILE_DOWNLOAD"
EVENT_FILE_ACCESS_DENIED = "FILE_ACCESS_DENIED"

# Explicit access delegation (AccessGrant / AccessRequest).
EVENT_ACCESS_GRANT_CREATED = "ACCESS_GRANT_CREATED"
EVENT_ACCESS_GRANT_REVOKED = "ACCESS_GRANT_REVOKED"
EVENT_ACCESS_GRANT_EXPIRED = "ACCESS_GRANT_EXPIRED"
EVENT_BROAD_ACCESS_GRANTED = "BROAD_ACCESS_GRANTED"
EVENT_ACCESS_REQUEST_CREATED = "ACCESS_REQUEST_CREATED"
EVENT_ACCESS_REQUEST_APPROVED = "ACCESS_REQUEST_APPROVED"
EVENT_ACCESS_REQUEST_REJECTED = "ACCESS_REQUEST_REJECTED"
EVENT_ACCESS_REQUEST_CANCELLED = "ACCESS_REQUEST_CANCELLED"

# Event types that make up an officer's administrative timeline / the
# dashboard's "recent administrative activity". Login noise is excluded.
ADMIN_TIMELINE_EVENT_TYPES = (
    EVENT_ACCOUNT_CREATED, EVENT_ACCOUNT_ACTIVATED, EVENT_ACCOUNT_SUSPENDED,
    EVENT_ACCOUNT_DISABLED, EVENT_ACCOUNT_DEACTIVATED, EVENT_ACCOUNT_LOCKED,
    EVENT_ACCOUNT_UNLOCKED, EVENT_ACCOUNT_STATUS_CHANGED, EVENT_ACCOUNT_REACTIVATED,
    EVENT_ACCOUNT_EMERGENCY_LOCKED, EVENT_PASSWORD_RESET, EVENT_SECRET_CODE_RESET,
    EVENT_CREDENTIALS_ISSUED, EVENT_ROLE_CHANGED, EVENT_CLEARANCE_CHANGED,
    EVENT_UNIT_CHANGED, EVENT_PORTAL_GRANTED, EVENT_PORTAL_REVOKED,
    EVENT_OFFICER_UPDATED, EVENT_DESIGNATION_CHANGED, EVENT_DEPARTMENT_CHANGED,
    EVENT_TRANSFER_COMPLETED, EVENT_DEVICE_REGISTERED, EVENT_DEVICE_REVOKED,
    EVENT_SESSION_TERMINATED, EVENT_TEMPORARY_ACCESS_GRANTED,
    EVENT_TEMPORARY_ACCESS_REVOKED, EVENT_ACCESS_REVIEW_CREATED,
    EVENT_ACCESS_REVIEW_DECIDED, EVENT_ADMIN_ROLE_CHANGED, EVENT_APPROVAL_REQUESTED,
    EVENT_APPROVAL_GRANTED, EVENT_APPROVAL_REJECTED, EVENT_APPROVAL_CANCELLED,
    EVENT_BULK_OPERATION, EVENT_MFA_CHANGED,
)

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
# Device / session registry
# ---------------------------------------------------------------------------
DEVICE_STATUS_ACTIVE = "ACTIVE"
DEVICE_STATUS_REVOKED = "REVOKED"
DEVICE_STATUS_CHOICES = (
    (DEVICE_STATUS_ACTIVE, "Active"),
    (DEVICE_STATUS_REVOKED, "Revoked"),
)

SESSION_END_LOGOUT = "LOGOUT"
SESSION_END_EXPIRED = "EXPIRED"
SESSION_END_TERMINATED = "TERMINATED"
SESSION_END_ACCOUNT_STATE = "ACCOUNT_STATE"
SESSION_END_CREDENTIAL_RESET = "CREDENTIAL_RESET"
SESSION_END_DEVICE_REVOKED = "DEVICE_REVOKED"
SESSION_END_CHOICES = (
    (SESSION_END_LOGOUT, "Signed out"),
    (SESSION_END_EXPIRED, "Expired"),
    (SESSION_END_TERMINATED, "Terminated by administrator"),
    (SESSION_END_ACCOUNT_STATE, "Account state change"),
    (SESSION_END_CREDENTIAL_RESET, "Credential reset"),
    (SESSION_END_DEVICE_REVOKED, "Device revoked"),
)

# ---------------------------------------------------------------------------
# Temporary administrative access
# ---------------------------------------------------------------------------
TEMP_ACCESS_ACTIVE = "ACTIVE"
TEMP_ACCESS_REVOKED = "REVOKED"
TEMP_ACCESS_STATUS_CHOICES = (
    (TEMP_ACCESS_ACTIVE, "Active"),
    (TEMP_ACCESS_REVOKED, "Revoked"),
)

# ---------------------------------------------------------------------------
# Posting history kinds
# ---------------------------------------------------------------------------
POSTING_INITIAL = "INITIAL"
POSTING_TRANSFER = "TRANSFER"
POSTING_DESIGNATION = "DESIGNATION_CHANGE"
POSTING_KIND_CHOICES = (
    (POSTING_INITIAL, "Initial posting"),
    (POSTING_TRANSFER, "Transfer"),
    (POSTING_DESIGNATION, "Designation change"),
)

# ---------------------------------------------------------------------------
# Session keys
# ---------------------------------------------------------------------------
SESSION_PORTAL_KEY = "portal"
SESSION_MFA_VERIFIED_AT = "mfa_verified_at"
SESSION_REAUTH_AT = "reauth_at"
SESSION_LOGIN_AT = "session_created_at"
