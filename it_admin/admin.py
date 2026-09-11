"""Django admin registration (development / emergency surface only).

Decisions on approval requests and access reviews must go through the IT
portal so the four-eyes and self-review rules are enforced; the admin is
therefore read-only for these models.
"""
from django.contrib import admin

from .models import AccessReview, ApprovalRequest


class _ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(ApprovalRequest)
class ApprovalRequestAdmin(_ReadOnlyAdmin):
    list_display = ("pk", "action", "target_type", "target_id", "requested_by", "requested_at", "status", "decided_by", "decided_at")
    list_filter = ("action", "status")
    search_fields = ("target_id", "target_label", "requested_by__officer_id")


@admin.register(AccessReview)
class AccessReviewAdmin(_ReadOnlyAdmin):
    list_display = ("pk", "officer", "trigger", "status", "due_at", "decision", "reviewed_by", "reviewed_at")
    list_filter = ("status", "decision")
    search_fields = ("officer__officer_id",)
