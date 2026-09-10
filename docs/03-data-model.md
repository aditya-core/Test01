# 03 — Database / Entity-Relationship Design

## 1. Entities

### accounts.Officer  (custom User — `AUTH_USER_MODEL = "accounts.Officer"`)
| Field | Type | Notes |
|---|---|---|
| id | PK | |
| officer_id | CharField unique | identity identifier, e.g. `OFF-052`, `DIST-A-INS-052` |
| full_name | CharField | |
| email | EmailField | normalized, unique |
| phone | CharField null | optional |
| password | hash | Django hasher — never plaintext |
| is_active | Boolean | Django field (mirrors ACTIVE state) |
| is_staff | Boolean | Django admin access |
| is_superuser | Boolean | dev-only; production does not rely on it |
| account_status | CharField | PENDING / INVITED / ACTIVE / SUSPENDED / LOCKED / DISABLED / DEACTIVATED |
| rank | CharField | free-text, configurable (NOT a permission) |
| role | FK Role | RBAC role |
| clearance | FK ClearanceLevel | security clearance |
| department | CharField null | optional label |
| unit | FK OrganizationUnit | org placement |
| mfa_enabled | Boolean | second-factor enrolled |
| secret_code_configured | Boolean | hashed secret code present |
| failed_login_attempts | PositiveSmallInteger | |
| last_failed_login | DateTime null | |
| locked_until | DateTime null | temporary lockout window |
| last_login | DateTime | Django field |
| created_at / updated_at | DateTime | |

### accounts.Role
`name` (unique, e.g. `FIELD_OFFICER`), `description`, `rank_weight`
(int, display ordering only — **not** authorization), `permissions` (M2M),
`allowed_portals` (M2M → Portal), `is_system_role`.

### accounts.Permission
`codename` (unique), `description`. Prototype grants: officer.manage,
officer.view, security.view_events, security.manage_settings,
audit.view, account.manage_security, plus portal entry codenames.

### accounts.ClearanceLevel
`code` (unique, e.g. `L1`…`L6`), `label` (General … Special), `weight`
(integer ordering — `L6` > `L1`), `description`. Configurable, not hard-coded.

### accounts.Organization  +  accounts.OrganizationUnit
```
Organization (National → State → District)  [self.parent for levels]
OrganizationUnit  (Unit)  [parent FK for nesting]
```
* `Organization.kind` ∈ NATIONAL / STATE / DISTRICT
* `OrganizationUnit.kind` ∈ HQ / INVESTIGATION / CYBER / FORENSIC / ADMIN …
* Both are **data-driven**; Phase 1 seeds one district + units.
* `OrganizationUnit.organization` ⇒ the district/state/national chain it
  belongs to, giving scope comparisons now and multi-district later.

### accounts.Portal
`key` (unique: `classified`, `it_admin`, `general`), `name`, `description`,
`is_restricted` (classified only). Portal entry is granted via
`PortalAccess` (explicit grant ⇒ default deny).

### accounts.PortalAccess
`officer` × `portal` + `granted_by`, `reason`, `granted_at`, `revoked_at`.
An officer may hold several.

### accounts.AuthenticationFactor
`officer`, `factor_type` (SECRET_CODE / TOTP / HARDWARE_TOKEN — reserved),
`secret_hash` (salted HMAC digest — never plaintext), `enabled`,
`created_at`, `last_verified_at`.

### audit.AuditEvent
`event_id` (UUID), `occurred_at`, `event_type`, `officer` (FK, nullable),
`officer_id_snapshot`, `actor` (FK, nullable), `portal`, `resource_type`,
`resource_id`, `action`, `result` (ALLOW/DENY/…), `ip_address`, `user_agent`,
`session_id` (hashed), `reason`, `context` (JSON). **Never** stores passwords
or secret codes.

### audit.SecurityEvent
`event_id` (UUID), `occurred_at`, `event_type`, `officer` (nullable),
`severity` (INFO/WARNING/ALERT/CRITICAL), `source_ip`, `user_agent`,
`details` (JSON). Aggregates high-value signals: failed logins, lockouts,
denied access, portal-denied attempts.

## 2. Relationships (conceptual)

```
Officer ──┐── Role ──< Permission
          ├── ClearanceLevel
          ├── OrganizationUnit ── Organization
          ├── PortalAccess ── Portal
          ├── AuthenticationFactor
          └── AuditEvent / SecurityEvent

Role ──< Portal  (role defaults for portal entry)
```

## 3. Integrity constraints

* `officer_id` UNIQUE + indexed; `email` UNIQUE.
* `PortalAccess` UNIQUE (officer, portal).
* `AuthenticationFactor` UNIQUE (officer, factor_type).
* `ClearanceLevel.code`, `Role.name`, `Permission.codename`, `Portal.key` UNIQUE.
* FKs protected (PROTECT) so role/clearance/unit data cannot be deleted while
  referenced.
* `CheckConstraint`: officer_id uppercase; account_status in allowed set;
  clearance weight positive.

## 4. Over-normalization policy

Deliberately kept clean but practical: role/clearance/unit are FKs (not raw
strings), portal access is an explicit join table, and the optional `rank`/
`department` remain display/context strings rather than full tables — they
carry **no** authorization weight.
