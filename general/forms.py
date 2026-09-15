from django import forms

from accounts import constants as C
from accounts.models import ClearanceLevel
from .models import CaseRecord


class CaseRegistrationForm(forms.ModelForm):
    """Case registration.

    The officer chooses the case's sensitivity (``classification``); the
    jurisdiction (``organization``) is derived from their own posting in the
    view and is deliberately not a form field — an officer must not be able to
    file a case into someone else's district.
    """

    fir_document = forms.FileField(required=False)

    class Meta:
        model = CaseRecord
        fields = [
            "title",
            "case_type",
            "police_station",
            "investigating_agency",
            "incident_date",
            "location",
            "summary",
            "complainant_name",
            "complainant_contact",
            "status",
            "classification",
            "fir_document",
        ]
        widgets = {
            "summary": forms.Textarea(attrs={"rows": 4}),
            "incident_date": forms.DateInput(attrs={"type": "date"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["title"].widget.attrs.update({"placeholder": "Case title"})
        self.fields["case_type"].widget.attrs.update({"placeholder": "e.g. Theft, Fraud, Assault"})
        self.fields["police_station"].widget.attrs.update({"placeholder": "Police station / jurisdiction"})
        self.fields["investigating_agency"].widget.attrs.update({"placeholder": "CID / Crime Branch / Local police"})
        self.fields["location"].widget.attrs.update({"placeholder": "Incident location"})
        self.fields["complainant_name"].widget.attrs.update({"placeholder": "Complainant name"})
        self.fields["complainant_contact"].widget.attrs.update({"placeholder": "Phone or contact number"})

        # Classification is required and defaults to the lowest band: a case's
        # sensitivity must always be explicit, because it drives who may open it.
        self.fields["classification"].required = True
        self.fields["classification"].empty_label = None
        self.fields["classification"].queryset = ClearanceLevel.objects.all()
        if not self.initial.get("classification"):
            lowest = ClearanceLevel.objects.order_by("weight").first()
            if lowest is not None:
                self.initial["classification"] = lowest.pk

    def save(self, commit=True):
        case = super().save(commit=False)
        case.fir_document = self.cleaned_data.get("fir_document") or self.files.get("fir_document")
        if commit:
            case.save()
        return case


# ---------------------------------------------------------------------------
# Access delegation (directive §15) — deliberately simple for normal users.
# ---------------------------------------------------------------------------
class AccessGrantForm(forms.Form):
    """Grant access to a case.

    Only the options the grantor is actually authorized to use are offered;
    the service re-checks every choice server-side (§15 / §30).
    """

    recipient_officer = forms.ModelChoiceField(
        queryset=None, required=False, label="Officer",
        help_text="Search by officer ID or name.",
    )
    recipient_department = forms.ModelChoiceField(
        queryset=None, required=False, label="Department",
    )
    scope = forms.ChoiceField(choices=C.GRANT_SCOPE_CHOICES, initial=C.GRANT_SCOPE_CASE)
    actions = forms.MultipleChoiceField(
        choices=[], widget=forms.CheckboxSelectMultiple, label="Permissions",
    )
    duration_days = forms.IntegerField(
        min_value=1, max_value=365, initial=7, label="Duration (days)",
    )
    reason = forms.CharField(
        max_length=255, widget=forms.Textarea(attrs={"rows": 3}),
        label="Reason", help_text="Recorded in the audit trail.",
    )

    def __init__(self, *args, grantor=None, grantable_actions=None, **kwargs):
        self.grantor = grantor
        super().__init__(*args, **kwargs)

        from accounts.models import Department, Officer

        self.fields["recipient_officer"].queryset = (
            Officer.objects.filter(is_active=True)
            .exclude(pk=grantor.pk if grantor else None)
            .select_related("designation", "unit")
            .order_by("officer_id")
        )
        self.fields["recipient_department"].queryset = Department.objects.filter(is_active=True)

        grantable = list(grantable_actions or [])
        self.fields["actions"].choices = [
            (a, C.ACTION_LABELS.get(a, a)) for a in grantable
        ]
        if not grantable:
            self.fields["actions"].required = False

    def clean(self):
        cleaned = super().clean()
        officer = cleaned.get("recipient_officer")
        department = cleaned.get("recipient_department")
        if not officer and not department:
            raise forms.ValidationError("Choose an officer or a department.")
        if officer and department:
            raise forms.ValidationError("Choose either an officer or a department, not both.")
        if not cleaned.get("actions"):
            raise forms.ValidationError("Select at least one permission.")
        return cleaned

    def recipient_kwargs(self) -> dict:
        return {
            "recipient_officer": self.cleaned_data.get("recipient_officer"),
            "recipient_department": self.cleaned_data.get("recipient_department"),
        }


class AccessRequestForm(forms.Form):
    """Ask for access you do not currently have (directive §17)."""

    actions = forms.MultipleChoiceField(
        choices=[], widget=forms.CheckboxSelectMultiple, label="Requested permissions",
    )
    duration_days = forms.IntegerField(min_value=1, max_value=90, initial=7, label="Duration (days)")
    reason = forms.CharField(
        max_length=255, widget=forms.Textarea(attrs={"rows": 3}), label="Reason",
    )

    def __init__(self, *args, requestable_actions=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["actions"].choices = [
            (a, C.ACTION_LABELS.get(a, a)) for a in (requestable_actions or [])
        ]

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("actions"):
            raise forms.ValidationError("Select at least one permission.")
        return cleaned


class CaseTransferForm(forms.Form):
    """Move a case to another station / jurisdiction (directive §24)."""

    to_unit = forms.ModelChoiceField(queryset=None, required=False, label="Station / unit")
    to_organization = forms.ModelChoiceField(queryset=None, required=False, label="Jurisdiction")
    reason = forms.CharField(max_length=255, widget=forms.Textarea(attrs={"rows": 3}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from accounts.models import Organization, OrganizationUnit

        self.fields["to_unit"].queryset = OrganizationUnit.objects.filter(
            is_active=True
        ).select_related("organization").order_by("organization__name", "name")
        self.fields["to_organization"].queryset = Organization.objects.all()

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("to_unit") and not cleaned.get("to_organization"):
            raise forms.ValidationError("Choose a destination station or jurisdiction.")
        return cleaned
