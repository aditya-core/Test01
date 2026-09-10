# 05 — Authorization Flow

## 1. Central engine

One place decides everything: `accounts.authorization.AuthorizationService`.

```python
AuthorizationService.can_access_portal(user, portal)
AuthorizationService.can(user, permission)
AuthorizationService.get_user_permissions(user) -> set[str]
AuthorizationService.portal_capabilities(user, portal) -> dict
AuthorizationService.has_clearance(user, level_code)
AuthorizationService.can_access_case(user, case)          # interface — future
AuthorizationService.can_access_resource(user, resource, action)  # interface — future
```

## 2. Evaluation order

```
1. Is the caller authenticated & the right kind of identity?
2. account_status == ACTIVE?
3. Is the officer's session authenticated to the requested portal?
4. PortalAccess (explicit grant) or role default?
5. (classified only) clearance >= portal required clearance?
6. RBAC: does the role carry the requested permission?
7. Organizational scope: unit/org chain matches the resource/portal scope?
8. Case authorization: assigned to the case?          [future]
9. Resource classification: clearance >= resource?    [future]
10. Action permission: allowed for role on resource?  [future]
11. Special restrictions (lockout, break-glass)?      [future]
```

**Any failure ⇒ DENY (fail closed) + audit event.**

## 3. Dimensions are independent

* **Rank** is display metadata only — never used in decisions.
* **Role** grants capabilities (RBAC codenames).
* **Clearance** grants sensitivity-band access.
* **Scope** (organization/unit) grants *where*.
* **Case** grants *which investigation* (future).
* **Resource** grants *which document* (future).
* **Action** grants *what operation*.

## 4. Enforcement points (complete mediation)

| Surface | Mechanism |
|---|---|
| Class-based views | `PortalRequiredMixin` |
| Function views | `@portal_required`, `@permission_required`, `@clearance_required`, `@reauth_required` |
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
