# 05 — Authorization Flow

## 1. Central engine

One place decides everything: `accounts.authorization.AuthorizationService`.

```python
AuthorizationService.can_access_portal(user, portal)
AuthorizationService.can(user, permission)
AuthorizationService.get_user_permissions(user) -> set[str]
AuthorizationService.portal_capabilities(user, portal) -> dict
AuthorizationService.has_clearance(user, level_code)
AuthorizationService.can_access_case(user, case, action)       # operational (legacy helper)
AuthorizationService.authorize_resource(user, resource, action, portal="")  # THE engine
```

`authorize_resource` is the single entry point used by every portal, case,
file and grant decision. `can_access_case` remains as a thin compatibility
wrapper around it. See [`11-hierarchical-case-access.md`](11-hierarchical-case-access.md).

## 2. Evaluation order

```
1. Is the caller authenticated & the right kind of identity?
2. account_status == ACTIVE?
3. Is the officer's session authenticated to the requested portal?
4. PortalAccess (explicit grant) or role default?
5. (classified only) clearance >= portal required clearance?
6. RBAC: does the role carry the requested permission?
7. Organizational scope: unit/org chain matches the resource/portal scope?
8. Access path: ownership / hierarchy / assignment / explicit grant
9. Resource classification: clearance >= resource?    (case classification)
10. Action permission: allowed for role on resource?  (case actions + path ceiling)
11. Special restrictions (lockout, break-glass)?      [future]

Note that 5–7 are **hard restrictions**: they run before any grant and no
grant can override them. See [`11-hierarchical-case-access.md`](11-hierarchical-case-access.md) §2.
```

**Any failure ⇒ DENY (fail closed) + audit event.**

## 3. Dimensions are independent

* **Rank** is display metadata only — never used in decisions.
* **Role** grants capabilities (RBAC codenames).
* **Clearance** grants sensitivity-band access.
* **Scope** (organization/unit) grants *where*.
* **Case** grants *which investigation*.
* **Resource** grants *which document* (FIR / evidence / document).
* **Action** grants *what operation*.

## 4. Enforcement points (complete mediation)

| Surface | Mechanism |
|---|---|
| Class-based views | `PortalRequiredMixin` |
| Function views | `@portal_required`, `@permission_required`, `@clearance_required`, `@reauth_required` |
| Object-level (case, file, grant) | `authorize_resource()` inside the view, *before* the object is touched |
| Future API | `AuthorizationService` called inside the API layer |
| Dashboards | `portal_capabilities()` drives what is rendered AND each nav target re-checks |
| Admin | Django admin permissions + `OfficerAdmin` guards + audit on mutations |

The UI never *grants* anything — it only reflects the backend result.

## 5. Deny-by-default demonstration (from the test suite)

- Junior officer requesting a senior-only resource ⇒ DENY.
- District A officer requesting District B resource ⇒ DENY.
- Sufficient clearance but wrong case ⇒ DENY.
- Correct case but insufficient action permission ⇒ DENY.
- Unauthorized download / delete ⇒ DENY.
- IT admin reaching investigation data ⇒ DENY (not implemented as data access).

The case module (`general`) proves the same rules at the operational layer —
see [`10-case-authorization.md`](10-case-authorization.md) and
[`11-hierarchical-case-access.md`](11-hierarchical-case-access.md):

- Officer who is **not assigned** to a case ⇒ DENY (even if they created it).
- Assigned officer whose **clearance** is below the case classification ⇒ DENY.
- Assigned officer outside the case **jurisdiction** ⇒ DENY.
- Assigned officer whose role lacks the required `case.*` capability ⇒ DENY.
- `VIEWER` assignment attempting a **download** ⇒ DENY.
- **Revoked** assignment ⇒ DENY.
- Fetching a FIR / evidence **URL** directly without authorization ⇒ DENY (403,
  audited) — media is never served by URL alone.

- A **peer** officer opening another station's case by direct URL ⇒ DENY (403, audited).
- **Seniority without a reporting link** ⇒ DENY (hierarchy is `supervisor`, not rank).
- An **expired** or **revoked** grant ⇒ DENY immediately.
- A grant that would bypass **clearance** or **account state** ⇒ DENY.
- A **station- or jurisdiction-scoped** grant from an officer without hierarchical
  authority over that place ⇒ DENY.
- Requesting access to a case and **approving your own request** ⇒ DENY.
- An **IT administrator** reaching case content ⇒ DENY (separation of duties).
