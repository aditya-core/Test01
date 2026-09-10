# 06 — Portal Access Matrix

## 1. Who may enter which portal (defaults)

| Capability | GENERAL | CLASSIFIED | IT / ADMIN |
|---|---|---|---|
| Authenticate (login) | YES | YES | YES |
| View own profile | YES | YES | YES |
| Change own password | YES | YES | YES |
| Configure own MFA | YES | YES | YES |
| Manage officers (create/activate/suspend/… ) | NO | NO | YES |
| Reset credentials / issue codes | NO | NO | YES |
| Configure MFA for others | NO | NO | YES |
| Manage org structure | NO | NO | YES |
| View security events / failed logins | LIMITED* | LIMITED* | YES |
| View audit logs | LIMITED* | LIMITED* | YES |
| Access classified resources | NO | POLICY (clearance + scope + case) | NO* |
| Access investigation documents | POLICY | POLICY | NO* |

\* **IT administration ≠ investigation-data access.** Administering accounts
never grants read access to case documents.

## 2. Role → portal defaults

| Role | GENERAL | CLASSIFIED | IT / ADMIN |
|---|---|---|---|
| FIELD_OFFICER | YES | — | — |
| INVESTIGATING_OFFICER | YES | — | — |
| FORENSIC_OFFICER | YES | — | — |
| INSPECTOR | YES | — | — |
| SENIOR_OFFICER | YES | policy | — |
| COMMISSIONER | YES | policy | — |
| IT_ADMIN | — | — | YES |
| SECURITY_ADMIN | — | policy | YES |

Policy cells are decided by explicit `PortalAccess` records + clearance, not
by the role alone.

## 3. Configurability

The matrix above is **seed data**, not hard-coded template logic. It is
realized through `Role.allowed_portals`, `PortalAccess` rows and `Portal`
records — all editable by Central IT / via Django admin. Templates render
whatever the authorization engine returns.

## 4. Per-portal capability bundle (what the dashboard shows)

| | FIELD_OFFICER | INSPECTOR | SENIOR_OFFICER | IT_ADMIN |
|---|---|---|---|---|
| My Cases / Tasks | ✓ | ✓ | ✓ | — |
| Upload documents | ✓ | ✓ | — | — |
| Reviews / Assignments | — | ✓ | ✓ | — |
| District overview / analytics | — | — | ✓ | — |
| Approvals | — | ✓ | ✓ | — |
| Officer management | — | — | — | ✓ |
| Security monitoring | — | — | — | ✓ |
| Audit logs | — | — | — | ✓ |
