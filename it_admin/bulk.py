"""Bulk officer operations: CSV import with validate → preview → commit.

The uploaded file is parsed and validated *without* touching the database.
The validated rows are stored in the session (bounded size) so the
administrator sees exactly what will be committed; the commit step re-runs
validation against the live database before writing, because things may
have changed in between.

Nothing here grants operational authorization — imported officers receive
identity + service data and, optionally, a role/portal only if the CSV asks
for one and the importing administrator holds ``officer.authorization``.
"""
from __future__ import annotations

import csv
import io
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone

from accounts import constants as C
from accounts.models import Department, Designation, Officer, OrganizationUnit, Portal, Role
from accounts.services import provisioning_service
from audit.services import audit_service

REQUIRED_COLUMNS = ("full_name", "email")
OPTIONAL_COLUMNS = ("officer_id", "employee_id", "phone", "designation", "department", "unit", "role", "joining_date", "portals")
ALL_COLUMNS = REQUIRED_COLUMNS + OPTIONAL_COLUMNS
MAX_ROWS = 500
OFFICER_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9\-]*$")

CSV_TEMPLATE = (
    "full_name,email,officer_id,employee_id,phone,designation,department,unit,role,joining_date,portals\n"
    "Asha Verma,asha.verma@example.gov,,EMP-2201,+91-9000000001,SI,CYBER,Cyber Unit,,2026-09-01,general\n"
)


@dataclass
class RowResult:
    line: int
    data: dict
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass
class ValidationReport:
    rows: list = field(default_factory=list)
    file_errors: list = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.rows)

    @property
    def valid(self) -> list:
        return [r for r in self.rows if r.ok]

    @property
    def invalid(self) -> list:
        return [r for r in self.rows if not r.ok]

    @property
    def warning_count(self) -> int:
        return sum(len(r.warnings) for r in self.rows)


class BulkImportService:
    def parse(self, raw: bytes) -> ValidationReport:
        report = ValidationReport()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            report.file_errors.append("File must be UTF-8 encoded CSV.")
            return report
        reader = csv.DictReader(io.StringIO(text))
        headers = [h.strip().lower() for h in (reader.fieldnames or [])]
        missing = [c for c in REQUIRED_COLUMNS if c not in headers]
        if missing:
            report.file_errors.append(f"Missing required column(s): {', '.join(missing)}.")
            return report
        unknown = [h for h in headers if h and h not in ALL_COLUMNS]
        if unknown:
            report.file_errors.append(f"Unknown column(s): {', '.join(unknown)}.")
            return report

        rows = []
        for idx, record in enumerate(reader, start=2):  # header is line 1
            if idx - 1 > MAX_ROWS:
                report.file_errors.append(f"Too many rows — at most {MAX_ROWS} rows per import.")
                break
            clean = {k.strip().lower(): (v or "").strip() for k, v in record.items() if k}
            if not any(clean.values()):
                continue  # skip blank lines
            rows.append(RowResult(line=idx, data=clean))
        report.rows = rows
        self.validate(report)
        return report

    # ------------------------------------------------------------------ validation
    def validate(self, report: ValidationReport) -> ValidationReport:
        designations = {d.code.upper(): d for d in Designation.objects.all()}
        designations.update({d.name.upper(): d for d in Designation.objects.all()})
        departments = {d.code.upper(): d for d in Department.objects.all()}
        departments.update({d.name.upper(): d for d in Department.objects.all()})
        units = {u.name.upper(): u for u in OrganizationUnit.objects.select_related("department")}
        roles = {r.name.upper(): r for r in Role.objects.all()}
        portals = {p.key: p for p in Portal.objects.all()}

        seen_ids, seen_emails, seen_emp = set(), set(), set()
        for row in report.rows:
            row.errors, row.warnings = [], []
            d = row.data

            if not d.get("full_name"):
                row.errors.append("Full name is required.")

            email = d.get("email", "").lower()
            d["email"] = email
            if not email:
                row.errors.append("Email is required.")
            else:
                try:
                    validate_email(email)
                except ValidationError:
                    row.errors.append("Invalid email format.")
                if email in seen_emails:
                    row.errors.append("Duplicate email within file.")
                elif Officer.objects.filter(email__iexact=email).exists():
                    row.errors.append("An account with this email already exists.")
                seen_emails.add(email)

            oid = d.get("officer_id", "").upper()
            d["officer_id"] = oid
            if oid:
                if not OFFICER_ID_RE.match(oid):
                    row.errors.append("Invalid Officer ID (use A–Z, 0–9 and hyphens).")
                elif oid in seen_ids:
                    row.errors.append("Duplicate Officer ID within file.")
                elif Officer.objects.filter(officer_id__iexact=oid).exists():
                    row.errors.append("Officer ID already exists.")
                seen_ids.add(oid)
            else:
                row.warnings.append("Officer ID will be auto-generated.")

            emp = d.get("employee_id", "").upper()
            d["employee_id"] = emp
            if emp:
                if emp in seen_emp:
                    row.errors.append("Duplicate Employee ID within file.")
                elif Officer.objects.filter(employee_id__iexact=emp).exists():
                    row.errors.append("Employee ID already exists.")
                seen_emp.add(emp)

            desig = d.get("designation", "")
            if desig:
                obj = designations.get(desig.upper())
                if obj is None:
                    row.errors.append(f"Unknown designation “{desig}”.")
                elif not obj.is_active:
                    row.errors.append(f"Designation “{obj.name}” is inactive.")
                else:
                    d["_designation_pk"] = obj.pk

            dept = d.get("department", "")
            dept_obj = None
            if dept:
                dept_obj = departments.get(dept.upper())
                if dept_obj is None:
                    row.errors.append(f"Unknown department “{dept}”.")
                elif not dept_obj.is_active:
                    row.errors.append(f"Department “{dept_obj.name}” is inactive.")
                else:
                    d["_department_pk"] = dept_obj.pk

            unit = d.get("unit", "")
            if unit:
                unit_obj = units.get(unit.upper())
                if unit_obj is None:
                    row.errors.append(f"Unknown unit “{unit}”.")
                elif not unit_obj.is_active:
                    row.errors.append(f"Unit “{unit_obj.name}” is inactive.")
                else:
                    d["_unit_pk"] = unit_obj.pk
                    if dept_obj and unit_obj.department_id and unit_obj.department_id != dept_obj.pk:
                        row.errors.append("Unit does not belong to the selected department.")

            role = d.get("role", "")
            if role:
                role_obj = roles.get(role.upper())
                if role_obj is None:
                    row.errors.append(f"Unknown role “{role}”.")
                else:
                    d["_role_pk"] = role_obj.pk
                    row.warnings.append("Role assignment requires the officer.authorization capability at commit.")

            jd = d.get("joining_date", "")
            if jd:
                try:
                    datetime.strptime(jd, "%Y-%m-%d")
                except ValueError:
                    row.errors.append("Joining date must be YYYY-MM-DD.")

            portal_keys = [p.strip() for p in d.get("portals", "").split(";") if p.strip()]
            bad = [p for p in portal_keys if p not in portals]
            if bad:
                row.errors.append(f"Unknown portal(s): {', '.join(bad)}.")
            else:
                d["_portal_keys"] = portal_keys
                if portal_keys:
                    row.warnings.append("Portal grants require the officer.authorization capability at commit.")
        return report

    # ------------------------------------------------------------------ session round-trip
    def to_session(self, report: ValidationReport) -> dict:
        return {
            "rows": [{"line": r.line, "data": r.data, "errors": r.errors, "warnings": r.warnings} for r in report.rows],
            "file_errors": report.file_errors,
        }

    def from_session(self, payload: dict) -> ValidationReport:
        report = ValidationReport(file_errors=list(payload.get("file_errors", [])))
        report.rows = [RowResult(line=r["line"], data=dict(r["data"]), errors=list(r["errors"]), warnings=list(r["warnings"]))
                       for r in payload.get("rows", [])]
        return report

    # ------------------------------------------------------------------ session round-trip
    SESSION_KEY = "bulk_import_report"

    def store(self, request, report: ValidationReport) -> None:
        request.session[self.SESSION_KEY] = self.to_session(report)
        request.session.modified = True

    def load(self, request) -> Optional[ValidationReport]:
        payload = request.session.get(self.SESSION_KEY)
        return self.from_session(payload) if payload else None

    def clear(self, request) -> None:
        request.session.pop(self.SESSION_KEY, None)
        request.session.modified = True

    # ------------------------------------------------------------------ commit
    def commit(self, report: ValidationReport, actor: Officer, *, may_authorize: bool, reason: str = "",
               request=None) -> "BulkResult":
        """Create the valid rows. Each row is its own savepoint so one failure
        does not silently discard the rest; invalid/failed rows are reported
        per line. The whole batch is audited as one administrative operation."""
        self.validate(report)  # re-validate against live data
        result = BulkResult()
        batch_ref = timezone.now().strftime("%Y%m%d%H%M%S")
        why = reason.strip() or f"Bulk import by {actor.officer_id}"
        with transaction.atomic():
            for row in report.rows:
                if not row.ok:
                    result.skipped.append(row)
                    continue
                d = row.data
                designation = Designation.objects.filter(pk=d.get("_designation_pk")).first() if d.get("_designation_pk") else None
                department = Department.objects.filter(pk=d.get("_department_pk")).first() if d.get("_department_pk") else None
                unit = OrganizationUnit.objects.filter(pk=d.get("_unit_pk")).first() if d.get("_unit_pk") else None
                role = Role.objects.filter(pk=d.get("_role_pk")).first() if (may_authorize and d.get("_role_pk")) else None
                portal_objs = list(Portal.objects.filter(key__in=d.get("_portal_keys", []))) if may_authorize else []
                joining = datetime.strptime(d["joining_date"], "%Y-%m-%d").date() if d.get("joining_date") else None
                try:
                    with transaction.atomic():
                        officer = provisioning_service.provision_officer(
                            actor=actor,
                            officer_id=d["officer_id"] or provisioning_service.generate_officer_id(),
                            email=d["email"],
                            full_name=d["full_name"],
                            # Provisional password is random and never shown: the
                            # officer must be issued credentials through the normal
                            # reset flow before activation.
                            initial_password=secrets.token_urlsafe(24),
                            role=role,
                            clearance=None,
                            unit=unit,
                            department=department,
                            designation=designation,
                            employee_id=d.get("employee_id", ""),
                            joining_date=joining,
                            phone=d.get("phone", ""),
                            portals=portal_objs,
                            reason=f"{why} (batch {batch_ref}, line {row.line})",
                            request=request,
                        )
                except Exception:  # noqa: BLE001 — surfaced per row, never as a stack trace
                    row.errors.append("Row could not be processed; no account was created for this line.")
                    result.failed.append(row)
                    continue
                result.created.append((row, officer))

            audit_service.record_admin_action(
                C.EVENT_BULK_OPERATION,
                actor=actor,
                target_type="bulk_import",
                target_id=batch_ref,
                action="officer_import",
                reason=why,
                result=C.RESULT_SUCCESS if not result.failed else C.RESULT_FAILURE,
                new_state={
                    "created": [o.officer_id for _, o in result.created],
                    "skipped_lines": [r.line for r in result.skipped],
                    "failed_lines": [r.line for r in result.failed],
                },
                context={"rows": report.total, "created": len(result.created), "skipped": len(result.skipped),
                         "failed": len(result.failed), "authorization_applied": may_authorize},
                request=request,
            )
        result.batch_ref = batch_ref
        return result


@dataclass
class BulkResult:
    created: list = field(default_factory=list)   # (RowResult, Officer)
    skipped: list = field(default_factory=list)   # invalid before commit
    failed: list = field(default_factory=list)    # failed during commit
    batch_ref: str = ""

    @property
    def created_count(self) -> int:
        return len(self.created)

    @property
    def failed_count(self) -> int:
        return len(self.failed) + len(self.skipped)


bulk_import_service = BulkImportService()
