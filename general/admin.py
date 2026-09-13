from django.contrib import admin

from .models import CaseEvidenceFile, CaseRecord


@admin.register(CaseRecord)
class CaseRecordAdmin(admin.ModelAdmin):
    list_display = ("case_id", "title", "status", "created_by", "incident_date", "created_at")
    list_filter = ("status", "created_by", "investigating_agency")
    search_fields = ("case_id", "title", "complainant_name", "investigating_agency", "police_station")
    readonly_fields = ("case_id", "created_at", "updated_at")


@admin.register(CaseEvidenceFile)
class CaseEvidenceFileAdmin(admin.ModelAdmin):
    list_display = ("case", "file", "uploaded_at")
    search_fields = ("case__case_id", "file")
    readonly_fields = ("uploaded_at",)