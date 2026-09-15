# 10 — Case Authorization (operational domain)

> **Superseded in part.** This document describes the original per-case
> assignment model, which is still in force. The hierarchical layer built on
> top of it — hierarchy, place-scoped grants, requests, transfer and protected
> document delivery — is documented in
> [`11-hierarchical-case-access.md`](11-hierarchical-case-access.md).

## 1. The problem

Authentication and *administrative* authorization were already solved. Cases
are a different domain: they are **operational** authorization — WHO may open
WHICH investigation and WHAT they may do inside it.

Two rules make this distinct:

1. **Authentication ≠ case access.** Being a valid officer says nothing about
   a specific investigation.
2. **IT administration ≠ investigation access.** Administering an officer's
   account must never grant read access to their cases. `case.*` codenames are
   deliberately outside `ADMIN_CAPABILITY_PREFIXES`, so the IT portal cannot
   grant, revoke or even explain them — it reports
   *"Operational authorization is managed separately."*

## 2. The decision

```
can_access_case(user, case, action) =

      ACTIVE IDENTITY
    ∧ clearance(user)      >= case.classification          (sensitivity)
    ∧ jurisdiction(user)   == case.organization            (scope)
    ∧ CASE ASSIGNMENT      (explicit, active, per-case)    (need to know)
    ∧ capability(user)     ⊇ CASE_ACTION_PERMISSIONS[action]
    ∧ action               ∈ user.case_actions_for(case)   (assignment ceiling)

Any failed condition ⇒ DENY + audit event.
```

The five layers are **independent and cumulative**. Assignment is the
cornerstone: it is the explicit, per-case "need to know" grant.

## 3. Data model

| Model | Role |
|---|---|
| `CaseRecord.classification` | FK `ClearanceLevel` — the sensitivity band of the case |
| `CaseRecord.organization` | FK `Organization` — the jurisdiction (district/state) |
| `CaseAssignment` | The grant: `(case, officer, role, granted_by, revoked_at)` |

`CaseAssignment.role` ∈ `OWNER` / `INVESTIGATOR` / `SUPERVISOR` / `VIEWER`.
Each maps to an **action ceiling**:

| Role | Actions |
|---|---|
| `OWNER` | all (`view`, `edit`, `upload_evidence`, `download`, `assign`) |
| `INVESTIGATOR` | `view`, `edit`, `upload_evidence`, `download` |
| `SUPERVISOR` | `view`, `download` |
| `VIEWER` | `view` |

A partial unique index allows only **one active** assignment per
`(case, officer)`; revoking sets `revoked_at` and history is preserved.

### Why registration creates an OWNER row

The registering officer must be able to open the case they just created — but
not by a special case in a view. Registration creates an `OWNER`
`CaseAssignment`, so they are authorized through *exactly the same path* as
everyone else. There is no "or the creator" branch anywhere in the code.

## 4. How the engine stays decoupled

`accounts` is the authority and must not import a portal app. It therefore
reaches operational data through **duck-typed hooks** on `Officer`:

```python
Officer.is_assigned_to_case(case_id)   -> bool      # fail closed
Officer.case_actions_for(case)         -> set       # fail closed
```

Both resolve `general.CaseAssignment` through `apps.get_model(...)`, so:

* there is no import edge from `accounts` → `general`,
* if the cases app is removed, the hooks return empty and every case decision
  denies (fail closed, not a crash).

The case also implements the **resource protocol** the engine already
understood — `CaseRecord.security_requirement` returns a `ResourceRequirement`
(classification, jurisdiction, case id, action ceiling). The engine combines
the static resource demands with the per-officer facts.

## 5. Protected file delivery

A media URL is not a capability. Serving `/media/...` straight from disk means
anyone holding a leaked URL can read an FIR, whatever the authorization engine
decided.

Every byte therefore goes through an authorized view:

```
GET /general/cases/<case id>/fir/              -> download_fir
GET /general/cases/<case id>/evidence/<pk>/    -> download_evidence
GET /general/cases/<case id>/documents/<pk>/   -> download_document
```

Both call `can_access_case(user, case, "download")`, audit the grant
(`CASE_DOCUMENT_DOWNLOAD`) or the denial (`ACCESS_DENIED`), and only then
stream the file with `FileResponse`. The case list template emits these
authorized URLs — it never emits `case.fir_document.url`.

> In production, serve `/media/` with the web server for static assets, but
> keep case files behind an authorized view (or an equivalent
> `X-Accel-Redirect` / signed-URL scheme).

## 6. Auditability

| Event | When |
|---|---|
| `CASE_REGISTERED` | A case is created (records classification + jurisdiction) |
| `CASE_DOCUMENT_DOWNLOAD` | An authorized FIR / evidence download |
| `ACCESS_DENIED` | Any failed case access or download attempt |

Denials are recorded as eagerly as grants, with officer, case id, action and
request context — and land in the same tamper-evident hash chain.

## 7. Deliberate non-goals

* **Case assignment UI: delivered.** `cases/<case id>/access/` (grant, revoke,
  request, decide) is backed by `AccessGrant` / `AccessRequest` and the same
  engine — see [`11`](11-hierarchical-case-access.md) §5–§6.
* **No case-scoped admin.** IT administrators cannot grant case access — by
  design, not by omission.
* **No classification downgrade path.** Changing a case's sensitivity is an
  operational decision and is not yet modelled.
