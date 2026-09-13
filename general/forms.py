from django import forms

from .models import CaseRecord


class CaseRegistrationForm(forms.ModelForm):
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

    def save(self, commit=True):
        case = super().save(commit=False)
        case.fir_document = self.cleaned_data.get("fir_document") or self.files.get("fir_document")
        if commit:
            case.save()
        return case
