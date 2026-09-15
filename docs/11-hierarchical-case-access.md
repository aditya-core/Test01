# 11 — Hierarchical Case Access (identity → hierarchy → jurisdiction → role → clearance → assignment → explicit grant)

This document describes the operational authorization layer built in the second
milestone. It answers one question:

> **"May *this* officer perform *this* action on *this* case or document,
> right now?"**

[`10-case-authorization.md`](10-case-authorization.md) remains valid for the
original per-case assignment model. This document describes what was added on
top of it: **hierarchy**, **place-scoped grants**, **explicit temporary
delegation**, **access requests**, **case transfer** and **protected document
delivery**, all decided by the *same* engine.

---

## 1. Design principles

| Principle | Consequence |
|---|---|
| **One central database** | Every case, document and grant lives in the same DB. Separation is achieved by *authorization*, never by physical separation. |
| **One engine** | Every decision — portal, case, file, grant — goes through `AuthorizationService.authorize_resource()`. No view, template or query may invent its own rule. |
| **Deny by default** | A decision is `allowed` only if a rule explicitly allows it. Every failed stage produces a `DENY` with a human-readable reason. |
| **Fail closed** | Unknown resource, missing app, malformed scope, missing clearance ⇒ deny. Never crash-open. |
| **Hard restrictions are absolute** | Account state, portal authentication and clearance are evaluated *before* any grant and can never be overridden by one. |
| **Grants only add** | A grant can widen what an officer may do; it can never lift a clearance, jurisdiction or account-state restriction. |
| **Hierarchy is real, not nominal** | Rank and designation are *display metadata only*. Hierarchy is derived from `Officer.supervisor` and the `OrganizationUnit.parent` tree. |
| **Complete mediation** | Files are streamed by an authorized view. There is no reachable raw media URL for a case file. |
| **Audit everything important** | Grants, denials, downloads, requests and transfers are recorded in the tamper-evident chain. Credentials are never logged. |

---

## 2. The decision pipeline

```python
accounts.authorization.authorize_resource(user, resource, action, portal="")
    -> AccessDecision(allowed, reason, actions, paths, requirements)
```

Stages, in order. The first failure ends the evaluation:

```
1. identity        authenticated? account_status == ACTIVE? not locked out?
2. portal          session authenticated to the portal that owns the surface?
3. policy          account policy / device / re-authentication requirements
4. action          is the action one this resource type understands?
5. clearance       clearance(user) >= resource.classification      (HARD)
6. scope           jurisdiction: user org/unit vs resource org/unit (HARD)
7. access_path     ownership → hierarchy → assignment → grant      (see §4)
8. capability      role carries CASE_ACTION_PERMISSIONS[action]?
9. action_permission  action ∈ the ceiling granted by the winning path
10. allow
```

Stage 5 and 6 precede stage 7 deliberately: an explicit grant to an officer
whose clearance is too low, whose account is suspended, or who sits in another
district **still denies**. This is the single most important invariant of the
design.

`explain_resource_access(user, resource)` returns the same stages as a
structured report, which is what the "WHY?" surfaces render.

---

## 3. Identity and hierarchy (no rank comparison anywhere)

```python
Officer.supervisor          -> the real reporting line
OrganizationUnit.parent     -> station -> district -> state
Officer.descendant_ids()    -> every officer below this one (BFS, cycle-safe)
Officer.unit_descendant_ids(unit_id) -> every unit below this one
Officer.is_supervisor_of(other)      -> bool
Officer.jurisdiction_*               -> organization / unit scope helpers
```

The trees are loaded with a **single query** (`_child_map`) and walked with a
cycle-safe BFS, so a mis-seeded cycle degrades to "no descendants" instead of
hanging the request.

> **Seniority without a reporting link grants nothing.** Two inspectors in
> different stations, or a senior officer who is not in another officer's
> `supervisor` chain, get no access from hierarchy alone. There is exactly one
> mechanism for "I need to see this": an explicit grant or assignment.

---

## 4. Access paths (how an officer "reaches" a case)

`ActionSet.paths` records every path that applies, in precedence order. A path
supplies an **action ceiling**; each individual action must *also* pass the
capability check (stage 8), so no path can exceed what the officer's role
allows.

| Path | Source | Ceiling | Notes |
|---|---|---|---|
| `ownership` | `case.created_by == user` | `ASSIGNMENT_OWNER` (all actions) | Registration also creates an `OWNER` `CaseAssignment`, so the creator is authorized through the ordinary path — there is no "or the creator" branch in the code. |
| `hierarchy` | creator or any *active assignee* is in `user.descendant_ids()`, **or** `case.unit` is inside `unit_descendant_ids(user.unit_id)` | `ASSIGNMENT_SUPERVISOR` | A supervisor may view, download, comment, approve, share and **manage access** — but not edit or reassign the case. |
| `assignment` | active `CaseAssignment(case, officer)` | `allowed_actions` for the assignment role | `OWNER` / `INVESTIGATOR` / `SUPERVISOR` / `VIEWER` (viewer: view only). |
| `grant` | active `AccessGrant` matching the officer | `AccessGrant.actions_for_officer` | Time-bounded, revocable, audited. May be case-, station- or jurisdiction-scoped, or granted to a department. |

**Station-local visibility** falls out of the `hierarchy` path: a case whose
`unit` is a sub-unit of the officer's unit (e.g. an officer posted at a
district sees cases held at its stations) is reachable through the unit tree,
never through a string comparison of station names.

---

## 5. Explicit grants (`AccessGrant`)

An `AccessGrant` is a **delegation**: "officer X (or department D) may perform
actions A on scope S until T, because R said so."

| Field | Meaning |
|---|---|
| `resource_type` / `resource_id` | `case` / `CASE-…`; a case-level grant propagates to its FIR, evidence and documents through `AccessGrant.case_id_for_resource()`. |
| `recipient_officer` | the officer who receives the delegation |
| `recipient_department` | **or** every member of a department (officer-scoped evaluation: department membership is resolved per officer, never as a blanket rule) |
| `recipient_unit` / `recipient_organization` | place scope — *station* or *jurisdiction* |
| `scope` | `CASE` / `SELECTED` / `STATION` / `JURISDICTION` |
| `actions` | subset of the action vocabulary (`view`, `download`, …) |
| `expires_at` | after this instant the grant simply stops applying |
| `status` | `ACTIVE` / `REVOKED`, with `revoked_by`, `revoked_at`, `reason` |
| `granted_by` | who delegated — recorded and audited |

Rules enforced in `general.services.access_grant_service`:

* Only an officer who already holds `manage_access` **on that resource** may
  grant on it (`authorize_resource(..., "manage_access")`).
* **Place-scoped** grants (`STATION`, `JURISDICTION`) additionally require
  **hierarchical authority** over the named place: you may delegate what you
  already supervise, not everything in the database.
* Expiry, revocation and recipient mismatch are evaluated at decision time, so
  a grant that lapses takes effect immediately with no batch job.
* A grant never overrides clearance, jurisdiction, account state or portal
  restrictions (§2).
* Every grant, re-grant and revocation writes an audit event.

---

## 6. Access requests (`AccessRequest`)

The polite counterpart to a grant: an officer who needs a case they cannot see
asks for it instead of being handed a URL.

```
request  ->  (pending)  ->  approve   ->  an AccessGrant is created  + audit
                        ->  reject    ->  denied, reason recorded    + audit
                        ->  cancel    ->  withdrawn by the requester + audit
```

* Only an officer holding `manage_access` on the case may decide a request.
* **A requester may not approve their own request** — the same four-eyes rule
  the admin portal already applies to privileged changes.
* Approving creates a real `AccessGrant` with the requested actions and
  expiry; nothing about the request itself grants access.

---

## 7. Case transfer and officer transfer

### Case transfer (`CaseTransferRecord`)

Moving a case to another station / unit / jurisdiction:

* requires `manage_access` on the case;
* records source and destination unit, organization, actor, reason and time;
* writes `CASE_TRANSFERRED`;
* **access follows the case**: after the move, officers of the destination
  station reach it through the hierarchy path, and officers whose only link was
  the old station no longer do — no separate cleanup step, because the
  decision is recomputed from the current unit tree every time.

### Officer transfer (`it_admin.TransferService`)

Moving an officer between units now triggers
`_revoke_place_scoped_access()`: station- and jurisdiction-scoped grants held
by the transferred officer are revoked and audited, the officer's access is
recomputed from their new posting, and an access review is raised for a human
to confirm. **Explicit officer-to-case grants survive** — they were delegated
to a person, not to a place, and only a human should remove them.

---

## 8. Protected file delivery

A media URL is not a capability. Every byte of every case file is streamed by
an authorized view that re-runs the engine for the **file's own action**:

```
GET /general/cases/<case id>/fir/            -> download_fir
GET /general/cases/<case id>/evidence/<pk>/  -> download_evidence
GET /general/cases/<case id>/documents/<pk>/ -> download_document
```

* The FIR, each evidence file and each document exposes
  `security_requirement` (`resource_type` ∈ `fir` / `evidence` / `document`),
  so a **case-level grant propagates to its files** while a file decision is
  still taken independently of a case decision.
* Authorized downloads are audited (`CASE_DOCUMENT_DOWNLOAD`) **and so are
  denials** (`ACCESS_DENIED`) — a probing officer leaves the same trail whether
  they succeed or not.
* Templates emit only these authorized URLs. `case.fir_document.url` is never
  rendered.

---

## 9. Query-level narrowing (performance, not authorization)

`CaseAccessService.authorized_page(user, page, search, ...)` runs one query
that **over-approximates** what the officer could possibly reach (own cases,
cases in their unit subtree, assigned cases, granted cases) and then re-decides
each returned row through the engine before returning `page.authorized`.

> The SQL is an optimization. **It is never the authorization decision.**
> Removing it would slow the register down; it would not make it less safe.

---

## 10. Separation of duties

| Actor | May | May not |
|---|---|---|
| Officer | see own / assigned / supervised / granted cases | see a peer's case, or elevate their own clearance |
| Station in-charge | everything in their station subtree | other stations' cases without a grant |
| Supervisor | view / download / share / manage access on subordinates' cases | edit or reassign those cases |
| IT administrator | manage identity, devices, transfers | hold or grant `case.*` capabilities (they are outside `ADMIN_CAPABILITY_PREFIXES` by design) |
| Security administrator | reviews, approvals, audit | case content by virtue of that role |

---

## 11. Audited events

| Event | When |
|---|---|
| `CASE_REGISTERED` | case created (classification + jurisdiction recorded) |
| `CASE_VIEWED` | an authorized case detail / dashboard read |
| `CASE_TRANSFERRED` | case moved to another station / jurisdiction |
| `CASE_DOCUMENT_DOWNLOAD` | authorized FIR / evidence / document download |
| `ACCESS_DENIED` / `CASE_ACCESS_DENIED` | any failed case or file decision |
| `ACCESS_REQUEST_CREATED` / `_APPROVED` / `_REJECTED` / `_CANCELLED` | request lifecycle |
| `ACCESS_GRANTED` | grant created / re-granted after expiry |
| `TEMPORARY_ACCESS_GRANTED` / `_REVOKED` | grants that carry an expiry |

All events land in the same append-only, hash-chained log; nothing here logs a
password, secret code or token.

---

## 12. Verification

`general/tests_access.py` (37 tests) encodes the rules above as executable
acceptance criteria, including the negative cases that matter most: peer
denial by direct URL (403), seniority without a reporting link, expired and
revoked grants, grants that cannot bypass clearance or account state,
jurisdiction mismatch, cross-district denial, transfer revoking place scopes,
self-approval refusal, list/search/dashboard leakage, and IT-admin separation
of duties.

Run the whole suite with:

```bash
python3 manage.py test
```
