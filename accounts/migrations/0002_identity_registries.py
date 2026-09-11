"""Identity & administration registries.

Non-destructive upgrade:

* ``Officer.department`` (free text) is *renamed* to ``legacy_department`` so
  no existing label is lost, then a new ``department`` FK is added.
* A data step converts existing ``legacy_department`` labels and ``rank``
  labels into ``Department`` / ``Designation`` registry rows and links the
  officers to them.
* New registries: PostingHistory, RegisteredDevice, OfficerSession,
  TemporaryCapability.
"""
from __future__ import annotations

import re

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def _code_from_label(label: str, taken: set) -> str:
    base = re.sub(r"[^A-Z0-9]+", "_", label.strip().upper()).strip("_")[:20] or "DEPT"
    code, n = base, 2
    while code in taken:
        code = f"{base[:17]}_{n}"
        n += 1
    taken.add(code)
    return code


def forwards(apps, schema_editor):
    Officer = apps.get_model("accounts", "Officer")
    Department = apps.get_model("accounts", "Department")
    Designation = apps.get_model("accounts", "Designation")

    # --- legacy department labels → Department registry ------------------
    taken = set(Department.objects.values_list("code", flat=True))
    for label in (
        Officer.objects.exclude(legacy_department="")
        .values_list("legacy_department", flat=True)
        .distinct()
    ):
        label = label.strip()
        if not label:
            continue
        dept = Department.objects.filter(name__iexact=label).first()
        if dept is None:
            dept = Department.objects.create(code=_code_from_label(label, taken), name=label)
        Officer.objects.filter(legacy_department__iexact=label, department__isnull=True).update(department=dept)

    # --- legacy rank labels → Designation registry -----------------------
    taken = set(Designation.objects.values_list("code", flat=True))
    for label in Officer.objects.exclude(rank="").values_list("rank", flat=True).distinct():
        label = label.strip()
        if not label:
            continue
        desig = Designation.objects.filter(name__iexact=label).first()
        if desig is None:
            desig = Designation.objects.create(code=_code_from_label(label, taken), name=label)
        Officer.objects.filter(rank__iexact=label, designation__isnull=True).update(designation=desig)


def backwards(apps, schema_editor):
    # Registry rows are left in place; the FK columns are dropped by the
    # schema operations. Nothing to undo at the data level.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        # ---------------------------------------------------------------- registries
        migrations.CreateModel(
            name="Department",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.CharField(help_text="Short code, e.g. CYBER.", max_length=24, unique=True)),
                ("name", models.CharField(max_length=120, unique=True)),
                ("description", models.CharField(blank=True, default="", max_length=255)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="Designation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.CharField(help_text="Short code, e.g. SI.", max_length=24, unique=True)),
                ("name", models.CharField(max_length=120, unique=True)),
                ("rank_level", models.PositiveSmallIntegerField(default=0, help_text="Ordering only (higher = more senior). Carries NO authorization weight.")),
                ("description", models.CharField(blank=True, default="", max_length=255)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["-rank_level", "name"]},
        ),
        # ---------------------------------------------------------------- unit ↔ department
        migrations.AddField(
            model_name="organizationunit",
            name="department",
            field=models.ForeignKey(blank=True, help_text="Functional department this unit belongs to (Department → Unit → Officer).", null=True, on_delete=django.db.models.deletion.PROTECT, related_name="units", to="accounts.department"),
        ),
        migrations.AddField(
            model_name="organizationunit",
            name="is_active",
            field=models.BooleanField(default=True),
        ),
        # ---------------------------------------------------------------- officer (non-destructive)
        migrations.RenameField(
            model_name="officer",
            old_name="department",
            new_name="legacy_department",
        ),
        migrations.AlterField(
            model_name="officer",
            name="legacy_department",
            field=models.CharField(blank=True, default="", editable=False, help_text="Free-text department label recorded before the department registry existed.", max_length=120),
        ),
        migrations.AddField(
            model_name="officer",
            name="department",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="officers", to="accounts.department"),
        ),
        migrations.AddField(
            model_name="officer",
            name="designation",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="officers", to="accounts.designation"),
        ),
        migrations.AddField(
            model_name="officer",
            name="employee_id",
            field=models.CharField(blank=True, default="", help_text="HR / payroll employee number (optional, unique when present).", max_length=32),
        ),
        migrations.AddField(
            model_name="officer",
            name="joining_date",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="officer",
            name="supervisor",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="supervisees", to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddConstraint(
            model_name="officer",
            constraint=models.UniqueConstraint(condition=models.Q(("employee_id", ""), _negated=True), fields=("employee_id",), name="uniq_officer_employee_id"),
        ),
        # ---------------------------------------------------------------- history / security registries
        migrations.CreateModel(
            name="PostingHistory",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("kind", models.CharField(choices=[("INITIAL", "Initial posting"), ("TRANSFER", "Transfer"), ("DESIGNATION_CHANGE", "Designation change")], default="TRANSFER", max_length=24)),
                ("effective_date", models.DateField()),
                ("reason", models.CharField(blank=True, default="", max_length=255)),
                ("authorization_review_required", models.BooleanField(default=False)),
                ("recorded_at", models.DateTimeField(auto_now_add=True)),
                ("from_department", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="+", to="accounts.department")),
                ("from_designation", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="+", to="accounts.designation")),
                ("from_unit", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="+", to="accounts.organizationunit")),
                ("officer", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="posting_history", to=settings.AUTH_USER_MODEL)),
                ("recorded_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
                ("to_department", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="+", to="accounts.department")),
                ("to_designation", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="+", to="accounts.designation")),
                ("to_unit", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="+", to="accounts.organizationunit")),
            ],
            options={"ordering": ["-effective_date", "-recorded_at"], "verbose_name_plural": "posting histories"},
        ),
        migrations.CreateModel(
            name="RegisteredDevice",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("device_key_hash", models.CharField(help_text="SHA-256 of the device token.", max_length=64, unique=True)),
                ("label", models.CharField(blank=True, default="", max_length=120)),
                ("browser", models.CharField(blank=True, default="", max_length=64)),
                ("operating_system", models.CharField(blank=True, default="", max_length=64)),
                ("user_agent", models.CharField(blank=True, default="", max_length=300)),
                ("first_seen", models.DateTimeField(auto_now_add=True)),
                ("last_seen", models.DateTimeField(auto_now=True)),
                ("last_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("status", models.CharField(choices=[("ACTIVE", "Active"), ("REVOKED", "Revoked")], default="ACTIVE", max_length=12)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revoke_reason", models.CharField(blank=True, default="", max_length=255)),
                ("officer", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="devices", to=settings.AUTH_USER_MODEL)),
                ("revoked_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-last_seen"]},
        ),
        migrations.CreateModel(
            name="OfficerSession",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("session_key_hash", models.CharField(db_index=True, max_length=64)),
                ("portal", models.CharField(blank=True, default="", max_length=16)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("browser", models.CharField(blank=True, default="", max_length=64)),
                ("operating_system", models.CharField(blank=True, default="", max_length=64)),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("last_activity", models.DateTimeField(auto_now_add=True)),
                ("ended_at", models.DateTimeField(blank=True, null=True)),
                ("end_reason", models.CharField(blank=True, choices=[("LOGOUT", "Signed out"), ("EXPIRED", "Expired"), ("TERMINATED", "Terminated by administrator"), ("ACCOUNT_STATE", "Account state change"), ("CREDENTIAL_RESET", "Credential reset"), ("DEVICE_REVOKED", "Device revoked")], default="", max_length=24)),
                ("device", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="sessions", to="accounts.registereddevice")),
                ("ended_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
                ("officer", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="sessions", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-started_at"]},
        ),
        migrations.AddIndex(
            model_name="officersession",
            index=models.Index(fields=["officer", "ended_at"], name="accounts_of_officer_a5b208_idx"),
        ),
        migrations.CreateModel(
            name="TemporaryCapability",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("reason", models.CharField(max_length=255)),
                ("starts_at", models.DateTimeField()),
                ("expires_at", models.DateTimeField()),
                ("status", models.CharField(choices=[("ACTIVE", "Active"), ("REVOKED", "Revoked")], default="ACTIVE", max_length=12)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revoke_reason", models.CharField(blank=True, default="", max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("granted_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
                ("officer", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="temporary_capabilities", to=settings.AUTH_USER_MODEL)),
                ("permission", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="temporary_grants", to="accounts.permission")),
                ("revoked_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-created_at"], "verbose_name_plural": "temporary capabilities"},
        ),
        # ---------------------------------------------------------------- data conversion
        migrations.RunPython(forwards, backwards),
    ]
