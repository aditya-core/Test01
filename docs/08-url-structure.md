# 08 — URL Structure

## Shared / authentication

| URL | Purpose |
|---|---|
| `/` | Landing / portal selector |
| `/auth/login/general/` | General officer login |
| `/auth/login/classified/` | Classified login |
| `/auth/login/admin/` | IT / admin login |
| `/auth/logout/` | Logout (POST, CSRF-protected) |
| `/auth/activate/<uidb64>/<token>/` | Secure account activation |
| `/auth/reauth/` | Re-authentication gate (sensitive ops) |
| `/account/` | Own profile + security settings |
| `/account/password/` | Change own password |
| `/account/security/` | Enrol / reset own secret code |
| `/auth/security-code/` | First-run secret-code setup |
| `/general/` | General portal dashboard |
| `/classified/` | Classified portal dashboard |
| `/audit/` | Authorized audit interface (shared) |
| `/security/` | Authorized security functionality |

## General officer portal (`/general/`, namespace `general`)

Protected in this order: authenticated → portal access (`general`) →
capability check → **object-level case authorization**
(`AuthorizationService.authorize_resource`) → action. Files are delivered by an
authorized view, never by media URL.

| URL | Name | Capability | Purpose |
|---|---|---|---|
| `` | `dashboard` | portal access | Overview + recent authorized cases |
| `cases/register/` | `register_case` | `case.create` | Register a case (FIR + evidence); grants the officer `OWNER` |
| `cases/` | `view_cases` | `case.view` **+ access path** | Case register — only cases the officer is authorized to open |
| `cases/<case id>/` | `case_detail` | `case.view` **+ access path** | One case: facts, files, people, `WHY?` |
| `cases/<case id>/access/` | `case_access` | `case.view` | Who can reach this case, and why |
| `cases/<case id>/access/grant/` | `grant_access` | `case.manage_access` | Delegate access (officer / department / station / jurisdiction) |
| `cases/<case id>/access/request/` | `request_access` | `case.view` | Ask for access you do not have |
| `access-requests/` | `access_requests` | `case.manage_access` | Requests awaiting *your* decision |
| `access-requests/<pk>/approve/` | `decide_request` | `case.manage_access` | Approve / reject (never your own request) |
| `grants/<pk>/revoke/` | `revoke_grant` | `case.manage_access` | Revoke a delegation, with a reason |
| `cases/<case id>/transfer/` | `case_transfer` | `case.manage_access` | Move a case to another station / jurisdiction |
| `cases/<case id>/fir/` | `download_fir` | `case.download` **+ access path** | Stream the FIR (audited) |
| `cases/<case id>/evidence/<pk>/` | `download_evidence` | `case.download` **+ access path** | Stream one evidence file (audited) |
| `cases/<case id>/documents/<pk>/` | `download_document` | `case.download` **+ access path** | Stream one case document (audited) |

Case **assignment** is an additional, per-case grant (`CaseAssignment`). It is
not derivable from the URL, from role, or from having created the case —
registration simply creates an `OWNER` row so the registering officer is
authorized through the same path as everyone else.

## IT / Admin portal (`/admin-portal/`, namespace `it_admin`)

Every route is protected in this order: authenticated → portal access
(`it_admin`) → capability check (`permission_required`) → optional
re-authentication (`reauth_required`) → action. All state-changing routes are
POST-only and CSRF-protected.

### Overview

| URL | Name | Capability | Purpose |
|---|---|---|---|
| `/admin-portal/` | `dashboard` | portal access | DB-driven counters, recent administrative activity, quick actions |

### Identity

| URL | Name | Capability | Purpose |
|---|---|---|---|
| `officers/` | `officer_list` | `officer.view` | Officer directory: search, filters, pagination |
| `officers/new/` | `officer_create` | `officer.create` (+ re-auth) | Provisioning wizard (Identity → Service → Account → Review → Create) |
| `officers/<pk>/` | `officer_detail` | `officer.view` | Profile: Identity / Service / Account / Security / Admin history |
| `officers/<pk>/edit/` | `officer_edit` | `officer.update` | Edit identity & service details |
| `officers/<pk>/authorization/` | `officer_authorization` | `officer.authorization` (+ re-auth) | Role / clearance / portals (admin roles go through approval) |
| `officers/<pk>/transfer/` | `officer_transfer` | `officer.transfer` (+ re-auth) | Transfer & posting with change summary; appends `PostingHistory` |
| `officers/<pk>/timeline/` | `officer_timeline` | `officer.view` | 360° timeline (audit + postings + approvals + reviews) |
| `officers/<pk>/access/` | `officer_access` | `officer.view` | “WHY?” access explainability |
| `officers/<pk>/devices/` | `officer_devices_sessions` | `device.view` | Registered devices & sessions of one officer |
| `officers/<pk>/lifecycle/` | `officer_lifecycle` | `officer.suspend` / `officer.reactivate` / `officer.manage` (+ re-auth) | Suspend / reactivate / deactivate with confirmation + reason |
| `officers/<pk>/status/` | `officer_status` | as above | Legacy status endpoint (kept for compatibility, now requires reason) |
| `officers/<pk>/lock/` · `unlock/` | `officer_lock` / `officer_unlock` | `officer.suspend` / `officer.reactivate` (+ re-auth) | Emergency lock (kills sessions, revokes devices) / unlock |
| `officers/<pk>/reset-password/` | `officer_reset_password` | `account.manage_security` (+ re-auth) | Reset password |
| `officers/<pk>/reset-code/` | `officer_reset_code` | `account.manage_security` (+ re-auth) | Reset secret code |
| `officers/<pk>/sessions/terminate-all/` | `session_terminate_all` | `session.terminate` | Terminate all sessions of an officer |
| `officers/<pk>/access-review/raise/` | `access_review_raise` | `access.review` | Open an ad-hoc access review |
| `designations/` (+ `new/`, `<pk>/edit/`, `<pk>/toggle/`, `<pk>/delete/`) | `designation_*` | `designation.view` / `designation.manage` | Designation & rank registry |
| `departments/` (+ `new/`, `<pk>/edit/`, `<pk>/toggle/`) | `department_*` | `department.view` / `department.manage` | Department registry |
| `units/new/`, `units/<pk>/edit/`, `units/<pk>/toggle/` | `unit_*` | `department.manage` | Units inside departments |
| `postings/` | `posting_list` | `officer.view` | Posting history browser |
| `bulk/import/` → `bulk/preview/` → `bulk/commit/` | `bulk_*` | `officer.bulk_import` (+ re-auth) | CSV import: upload → validate → preview → confirm → result |
| `bulk/template.csv` | `bulk_template` | `officer.bulk_import` | Download CSV template |

### Security

| URL | Name | Capability | Purpose |
|---|---|---|---|
| `security/accounts/` | `account_security` | `officer.view` | Account security overview (locked / suspended / MFA state) |
| `security/devices/` | `device_session_overview` | `device.view` | Device & session registry |
| `security/devices/<pk>/revoke/` | `device_revoke` | `device.revoke` | Revoke a device (ends its sessions) |
| `security/sessions/<pk>/terminate/` | `session_terminate` | `session.terminate` | Terminate one session |
| `security/` | `security_dashboard` | `security.view_events` | Security events |
| `security/reviews/` (+ `<pk>/`, `<pk>/decide/`) | `access_review_*` | `access.review` | Access reviews (KEEP / MODIFY / REVOKE) |
| `security/temporary-access/` (+ `new/`, `<pk>/revoke/`) | `temporary_access_*` | `access.grant_temporary` | Time-bound admin capability grants |
| `audit/` | `audit_dashboard` | `audit.view` | Append-only administrative audit log |
| `audit/verify/` | `audit_verify` | `audit.view` | Verify the tamper-evident hash chain |

### Administration

| URL | Name | Capability | Purpose |
|---|---|---|---|
| `roles/` (+ `new/`, `<pk>/`) | `admin_role_*` | `admin.role.manage` | IT admin roles & capability matrix (changes go through approval) |
| `roles/assign/` | `admin_role_assign` | `admin.role.manage` | Request assignment of an admin role to an officer |
| `approvals/` (+ `<pk>/`, `<pk>/decide/`, `<pk>/cancel/`) | `approval_*` | `approval.review` (decide) / requester (cancel) | Four-eyes approval center |

Removed: `officers/<pk>/portals/` (portal assignment now lives on the
authorization page, which is gated by the dedicated `officer.authorization`
capability).
