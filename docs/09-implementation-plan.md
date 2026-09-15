# 09 — Implementation Plan

## Order of work (this milestone)

1. Project scaffold — `django-admin startproject`, app skeletons, requirements.
2. Custom User model (`accounts.Officer`) — **before first migrate**.
3. RBAC + clearance + org + portal + factor models.
4. Constants + managers + backend + services (identity/auth/provisioning).
5. `AuthorizationService` + decorators/mixins + context processors.
6. Audit app (models + service + authorized viewer).
7. Login flow (portal selector + multi-step login + activation + re-auth).
8. Portal shells (`general`, `classified`, `it_admin`).
9. IT provisioning UI (officer CRUD-lite, reset, lock, portals, MFA reset).
10. Account self-service (password, secret-code enrolment/reset).
11. Security middleware/settings + security headers + custom error pages.
12. Templates/CSS/JS (institutional theme).
13. Migrations + seed command + README runbook.
14. Tests (auth, authorization, audit, provisioning, session, CSRF).
15. Live preview verification + git commit.

## Status

The **security core is complete**: identity, authorization, provisioning, the
three portal shells, the tamper-evident audit trail and the full IT /
administration portal (directory, registries, transfers, lifecycle, devices &
sessions, access reviews, temporary access, four-eyes approvals, bulk import).

A **minimal operational case module** also exists in `general` — case
registration with FIR / evidence upload, an authorized case register and
protected file delivery. It was built *on top of* the security core and is
authorized by it: see [`10-case-authorization.md`](10-case-authorization.md).

## Explicit non-goals (still outstanding)

- The remaining operational surface: documents, tasks, reports, notifications,
  review / approval workflows, analytics.
- Case **assignment UI** — `CaseAssignment` rows are created on registration
  and by `general` code; no interface assigns an existing case to another
  officer yet.
- AI / OCR.
- Real TOTP/hardware integration (architecture + factor model reserved).
- Break-glass execution (architecture + audit event types reserved).

## Verification checklist

- [x] `python manage.py check` clean
- [x] `python manage.py makemigrations --check` clean
- [x] `python manage.py test` green (143 tests)
- [x] Live preview loads, portal selector + login work, dashboards render
      per-role capabilities, IT can provision, audit records events.
- [x] Case access and every file download are decided by
      `AuthorizationService`; denials are audited.

## Deployment notes

- `MEDIA_ROOT` **must** stay an absolute path and `MEDIA_URL` a dedicated
  prefix. With the Django defaults, `config.urls` mounts the *working
  directory* at the site root, which publishes `.env`, `db.sqlite3` and the
  whole source tree over HTTP. See `config/settings.py`.
- Uploaded case files are user data: they live under `media/` and are
  git-ignored. Never commit them.
- In production, serve `/media/` with the web server (or an authorized view) —
  never with Django's DEBUG `static()` helper.
