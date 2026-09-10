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

## Explicit non-goals (this milestone)

- Case / document / evidence / report features.
- AI / OCR.
- File storage.
- Real TOTP/hardware integration (architecture + factor model reserved).
- Break-glass execution (architecture + audit event types reserved).

## Verification checklist

- [ ] `python manage.py check` clean
- [ ] `python manage.py makemigrations --check` clean
- [ ] `python manage.py test` green
- [ ] Live preview loads, portal selector + login work, dashboards render
      per-role capabilities, IT can provision, audit records events.
