"""Forms for the IT / Admin portal.

All validation here is server-side. Forms carry no authorization weight —
every view re-checks the actor's capabilities before acting.
"""
from __future__ import annotations

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone

from accounts import constants as C
from accounts.forms import NEW_SECRET_CODE_HELP, validate_secret_code
from accounts.models import (
    ClearanceLevel,
    Department,
    Designation,
    OrganizationUnit,
    Organization,
    Permission,
    Portal,
    Role,
)

from .models import AccessReview, ApprovalRequest

Officer = get_user_model()

REASON_WIDGET = forms.Textarea(attrs={"rows": 2, "placeholder": "Reason (recorded in the audit trail)"})


class ReasonForm(forms.Form):
    """Confirmation + mandatory reason for sensitive actions."""

    reason = forms.CharField(max_length=255, widget=REASON_WIDGET)

    def clean_reason(self):
        value = self.cleaned_data["reason"].strip()
        if len(value) < 5:
            raise ValidationError("Please provide a meaningful reason (at least 5 characters).")
        return value


class OptionalReasonForm(forms.Form):
    reason = forms.CharField(max_length=255, required=False, widget=REASON_WIDGET)

    def clean_reason(self):
        return (self.cleaned_data.get("reason") or "").strip()


# --------------------------------------------------------------------------- directory filters
class OfficerFilterForm(forms.Form):
    q = forms.CharField(required=False, label="Search",
                        widget=forms.TextInput(attrs={"placeholder": "Officer ID, name, email, employee ID"}))
    status = forms.ChoiceField(required=False, choices=(("", "Any status"),) + C.ACCOUNT_STATUS_CHOICES)
    department = forms.ModelChoiceField(required=False, queryset=Department.objects.all(), empty_label="Any department")
    unit = forms.ModelChoiceField(required=False, queryset=OrganizationUnit.objects.select_related("organization"), empty_label="Any unit")
    designation = forms.ModelChoiceField(required=False, queryset=Designation.objects.all(), empty_label="Any designation")
    mfa = forms.ChoiceField(required=False, choices=(("", "MFA: any"), ("yes", "MFA configured"), ("no", "MFA missing")))

    def apply(self, qs):
        if not self.is_valid():
            return qs
        d = self.cleaned_data
        q = (d.get("q") or "").strip()
        if q:
            from django.db.models import Q

            qs = qs.filter(
                Q(officer_id__icontains=q) | Q(full_name__icontains=q)
                | Q(email__icontains=q) | Q(employee_id__icontains=q)
            )
        if d.get("status"):
            qs = qs.filter(account_status=d["status"])
        if d.get("department"):
            qs = qs.filter(department=d["department"])
        if d.get("unit"):
            qs = qs.filter(unit=d["unit"])
        if d.get("designation"):
            qs = qs.filter(designation=d["designation"])
        if d.get("mfa") == "yes":
            qs = qs.filter(secret_code_configured=True)
        elif d.get("mfa") == "no":
            qs = qs.filter(secret_code_configured=False)
        return qs


# --------------------------------------------------------------------------- provisioning wizard
class ProvisionIdentityForm(forms.Form):
    full_name = forms.CharField(max_length=150)
    officer_id = forms.CharField(max_length=32, required=False, label="Officer ID",
                                 help_text="Leave blank to auto-generate a unique Officer ID.")
    employee_id = forms.CharField(max_length=32, required=False, label="Employee ID")
    email = forms.EmailField(label="Official email")
    phone = forms.CharField(max_length=32, required=False, label="Official phone")

    def clean_officer_id(self):
        value = (self.cleaned_data.get("officer_id") or "").strip().upper()
        if not value:
            return ""
        import re

        if not re.match(r"^[A-Z0-9][A-Z0-9\-]*$", value):
            raise ValidationError("Use letters, digits and hyphens only.")
        if Officer.objects.filter(officer_id__iexact=value).exists():
            raise ValidationError("Officer ID already exists.")
        return value

    def clean_employee_id(self):
        value = (self.cleaned_data.get("employee_id") or "").strip().upper()
        if value and Officer.objects.filter(employee_id__iexact=value).exists():
            raise ValidationError("Employee ID already exists.")
        return value

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if Officer.objects.filter(email__iexact=email).exists():
            raise ValidationError("An account with this email already exists.")
        return email


class ProvisionServiceForm(forms.Form):
    designation = forms.ModelChoiceField(queryset=Designation.objects.none(), required=False)
    department = forms.ModelChoiceField(queryset=Department.objects.none(), required=False)
    unit = forms.ModelChoiceField(queryset=OrganizationUnit.objects.none(), required=False, label="Unit / posting")
    supervisor = forms.ModelChoiceField(queryset=Officer.objects.none(), required=False)
    joining_date = forms.DateField(required=False, widget=forms.DateInput(attrs={"type": "date"}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["designation"].queryset = Designation.objects.filter(is_active=True)
        self.fields["department"].queryset = Department.objects.filter(is_active=True)
        self.fields["unit"].queryset = OrganizationUnit.objects.filter(is_active=True).select_related("organization", "department")
        self.fields["supervisor"].queryset = Officer.objects.filter(account_status=C.ACCOUNT_STATUS_ACTIVE).order_by("officer_id")

    def clean(self):
        cleaned = super().clean()
        unit, dept = cleaned.get("unit"), cleaned.get("department")
        if unit and dept and unit.department_id and unit.department_id != dept.pk:
            raise ValidationError("Selected unit does not belong to the selected department.")
        return cleaned


class ProvisionAccountForm(forms.Form):
    """Account step. Role/clearance/portals are *authorization* attributes and
    are only shown to administrators holding ``officer.authorization``."""

    initial_password = forms.CharField(
        label="Provisional password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text="Shown once after creation. The officer replaces it during activation.",
    )
    initial_secret_code = forms.CharField(
        label="Initial security code",
        required=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "off"}),
        help_text=NEW_SECRET_CODE_HELP,
        validators=[validate_secret_code],
    )
    role = forms.ModelChoiceField(queryset=Role.objects.all(), required=False)
    clearance = forms.ModelChoiceField(queryset=ClearanceLevel.objects.all(), required=False)
    portals = forms.ModelMultipleChoiceField(queryset=Portal.objects.all(), required=False,
                                             widget=forms.CheckboxSelectMultiple)
    reason = forms.CharField(max_length=255, required=False, label="Provisioning reason", widget=REASON_WIDGET)

    def __init__(self, *args, may_authorize: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.may_authorize = may_authorize
        if not may_authorize:
            # Do not even render authorization fields for admins who cannot
            # grant them; the view also discards any posted values.
            for name in ("role", "clearance", "portals"):
                self.fields.pop(name)

    def clean_initial_password(self):
        value = self.cleaned_data["initial_password"]
        validate_password(value)
        return value


# --------------------------------------------------------------------------- officer edit
class OfficerIdentityForm(forms.ModelForm):
    class Meta:
        model = Officer
        fields = ["full_name", "employee_id", "email", "phone", "supervisor", "joining_date"]
        widgets = {"joining_date": forms.DateInput(attrs={"type": "date"})}

    # Designation is deliberately *not* a Meta field: changing it goes through
    # ``officer_admin_service.change_designation`` so posting history is kept.
    designation = forms.ModelChoiceField(queryset=Designation.objects.none(), required=False)
    reason = forms.CharField(max_length=255, required=False, widget=REASON_WIDGET)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["supervisor"].queryset = Officer.objects.filter(
            account_status=C.ACCOUNT_STATUS_ACTIVE
        ).exclude(pk=self.instance.pk).order_by("officer_id")
        self.fields["supervisor"].label_from_instance = lambda o: f"{o.officer_id} — {o.full_name}"
        self.fields["designation"].queryset = (
            Designation.objects.filter(is_active=True) | Designation.objects.filter(pk=self.instance.designation_id)
        ).distinct()
        if not self.is_bound:
            self.fields["designation"].initial = self.instance.designation_id

    def clean_employee_id(self):
        value = (self.cleaned_data.get("employee_id") or "").strip().upper()
        if value and Officer.objects.filter(employee_id__iexact=value).exclude(pk=self.instance.pk).exists():
            raise ValidationError("Employee ID already exists.")
        return value

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if Officer.objects.filter(email__iexact=email).exclude(pk=self.instance.pk).exists():
            raise ValidationError("An account with this email already exists.")
        return email


class OfficerAuthorizationForm(forms.Form):
    """Role / clearance / portal grants — *authorization attributes*.

    These remain in the IT portal because the existing architecture assigns
    them at provisioning time, but they are gated by a dedicated capability
    (``officer.authorization``) rather than by plain officer editing.
    """

    role = forms.ModelChoiceField(queryset=Role.objects.all(), required=False)
    clearance = forms.ModelChoiceField(queryset=ClearanceLevel.objects.all(), required=False)
    portals = forms.ModelMultipleChoiceField(queryset=Portal.objects.all(), required=False,
                                             widget=forms.CheckboxSelectMultiple)
    reason = forms.CharField(max_length=255, widget=REASON_WIDGET)

    def __init__(self, *args, officer=None, **kwargs):
        super().__init__(*args, **kwargs)
        if officer is not None and not self.is_bound:
            self.fields["role"].initial = officer.role_id
            self.fields["clearance"].initial = officer.clearance_id
            self.fields["portals"].initial = list(
                officer.portal_accesses.filter(revoked_at__isnull=True).values_list("portal_id", flat=True)
            )


# --------------------------------------------------------------------------- transfers
class TransferForm(forms.Form):
    to_department = forms.ModelChoiceField(queryset=Department.objects.none(), required=False, label="New department")
    to_unit = forms.ModelChoiceField(queryset=OrganizationUnit.objects.none(), required=False, label="New unit")
    to_designation = forms.ModelChoiceField(queryset=Designation.objects.none(), required=False, label="New designation")
    effective_date = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))
    reason = forms.CharField(max_length=255, widget=REASON_WIDGET)

    def __init__(self, *args, officer=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["to_department"].queryset = Department.objects.filter(is_active=True)
        self.fields["to_unit"].queryset = OrganizationUnit.objects.filter(is_active=True).select_related("organization", "department")
        self.fields["to_designation"].queryset = Designation.objects.filter(is_active=True)
        if officer is not None and not self.is_bound:
            self.fields["to_department"].initial = officer.department_id
            self.fields["to_unit"].initial = officer.unit_id
            self.fields["to_designation"].initial = officer.designation_id
            self.fields["effective_date"].initial = timezone.localdate()

    def clean_reason(self):
        value = self.cleaned_data["reason"].strip()
        if len(value) < 5:
            raise ValidationError("Please provide a meaningful reason (at least 5 characters).")
        return value


# --------------------------------------------------------------------------- registries
class DesignationForm(forms.ModelForm):
    class Meta:
        model = Designation
        fields = ["code", "name", "rank_level", "description"]

    def clean_code(self):
        return self.cleaned_data["code"].strip().upper()


class DepartmentForm(forms.ModelForm):
    class Meta:
        model = Department
        fields = ["code", "name", "description"]

    def clean_code(self):
        return self.cleaned_data["code"].strip().upper()


class UnitForm(forms.ModelForm):
    class Meta:
        model = OrganizationUnit
        fields = ["name", "kind", "organization", "department", "parent"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["organization"].queryset = Organization.objects.all()
        self.fields["department"].queryset = Department.objects.filter(is_active=True)
        self.fields["department"].required = True
        parents = OrganizationUnit.objects.select_related("organization")
        if self.instance.pk:
            parents = parents.exclude(pk=self.instance.pk)
        self.fields["parent"].queryset = parents


# --------------------------------------------------------------------------- lifecycle
class LifecycleActionForm(ReasonForm):
    ACTIONS = (("suspend", "Suspend"), ("reactivate", "Reactivate"), ("deactivate", "Deactivate"),
               ("emergency_lock", "Emergency lock"), ("unlock", "Unlock"))
    action = forms.ChoiceField(choices=ACTIONS)


# --------------------------------------------------------------------------- temporary access
class TemporaryCapabilityForm(forms.Form):
    officer = forms.ModelChoiceField(queryset=Officer.objects.none())
    permission = forms.ModelChoiceField(queryset=Permission.objects.none(), label="Capability")
    starts_at = forms.DateTimeField(widget=forms.DateTimeInput(attrs={"type": "datetime-local"}))
    expires_at = forms.DateTimeField(widget=forms.DateTimeInput(attrs={"type": "datetime-local"}))
    reason = forms.CharField(max_length=255, widget=REASON_WIDGET)

    def __init__(self, *args, actor=None, **kwargs):
        super().__init__(*args, **kwargs)
        qs = Officer.objects.filter(account_status=C.ACCOUNT_STATUS_ACTIVE).order_by("officer_id")
        if actor is not None:
            qs = qs.exclude(pk=actor.pk)
        self.fields["officer"].queryset = qs
        # Only administrative capabilities are offered — never case/document.
        admin_perms = [p.pk for p in Permission.objects.all() if C.is_admin_capability(p.codename)]
        self.fields["permission"].queryset = Permission.objects.filter(pk__in=admin_perms).order_by("codename")
        if not self.is_bound:
            now = timezone.localtime().replace(second=0, microsecond=0)
            self.fields["starts_at"].initial = now.strftime("%Y-%m-%dT%H:%M")
            self.fields["expires_at"].initial = (now + timezone.timedelta(days=3)).strftime("%Y-%m-%dT%H:%M")

    def clean(self):
        cleaned = super().clean()
        s, e = cleaned.get("starts_at"), cleaned.get("expires_at")
        if s and e and e <= s:
            raise ValidationError("Expiry must be after the start.")
        if e and e <= timezone.now():
            raise ValidationError("Expiry must be in the future.")
        return cleaned


class AccessReviewDecisionForm(forms.Form):
    decision = forms.ChoiceField(choices=AccessReview.DECISION_CHOICES, widget=forms.RadioSelect)
    note = forms.CharField(max_length=255, required=False, widget=REASON_WIDGET)


# --------------------------------------------------------------------------- admin roles / approvals
class AdminRoleForm(forms.ModelForm):
    reason = forms.CharField(max_length=255, widget=REASON_WIDGET)

    class Meta:
        model = Role
        fields = ["name", "description", "rank_weight"]

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        qs = Role.objects.filter(name__iexact=name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise ValidationError("A role with this name already exists.")
        return name


class RoleCapabilitiesRequestForm(forms.Form):
    capabilities = forms.ModelMultipleChoiceField(queryset=Permission.objects.none(), required=False,
                                                  widget=forms.CheckboxSelectMultiple)
    reason = forms.CharField(max_length=255, widget=REASON_WIDGET)

    def __init__(self, *args, role=None, **kwargs):
        super().__init__(*args, **kwargs)
        admin_perms = [p.pk for p in Permission.objects.all() if C.is_admin_capability(p.codename)]
        self.fields["capabilities"].queryset = Permission.objects.filter(pk__in=admin_perms).order_by("codename")
        if role is not None and not self.is_bound:
            self.fields["capabilities"].initial = [
                p.pk for p in role.permissions.all() if C.is_admin_capability(p.codename)
            ]


class AdminRoleAssignRequestForm(forms.Form):
    officer = forms.ModelChoiceField(queryset=Officer.objects.none())
    role = forms.ModelChoiceField(queryset=Role.objects.all(), required=False, empty_label="— no role —")
    reason = forms.CharField(max_length=255, widget=REASON_WIDGET)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["officer"].queryset = Officer.objects.exclude(
            account_status__in=(C.ACCOUNT_STATUS_DEACTIVATED, C.ACCOUNT_STATUS_DISABLED)
        ).order_by("officer_id")
        self.fields["officer"].label_from_instance = lambda o: f"{o.officer_id} — {o.full_name}"


class ApprovalDecisionForm(forms.Form):
    decision = forms.ChoiceField(choices=(("approve", "Approve"), ("reject", "Reject")))
    decision_reason = forms.CharField(max_length=255, widget=REASON_WIDGET)


class BulkUploadForm(forms.Form):
    file = forms.FileField(label="CSV file", help_text="UTF-8 CSV, at most 500 rows. Download the template for the expected columns.")
    reason = forms.CharField(max_length=255, label="Import reason", widget=REASON_WIDGET,
                             help_text="Recorded on every account created by this batch.")

    def clean_file(self):
        f = self.cleaned_data["file"]
        if f.size > 1024 * 1024:
            raise ValidationError("File is too large (1 MB limit).")
        if not f.name.lower().endswith(".csv"):
            raise ValidationError("Please upload a .csv file.")
        return f
