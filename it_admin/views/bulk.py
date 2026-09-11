"""Bulk officer import: upload → validate → preview → confirm → process → result."""
from __future__ import annotations

from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST, require_http_methods

from accounts import constants as C
from accounts.decorators import permission_required, portal_required, reauth_required

from ..bulk import CSV_TEMPLATE, MAX_ROWS, bulk_import_service
from ..forms import BulkUploadForm
from ._common import PORTAL, actor_can

__all__ = ["bulk_import", "bulk_preview", "bulk_commit", "bulk_template"]

REASON_KEY = "bulk_import_reason"


@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_BULK_IMPORT)
@reauth_required
@require_http_methods(["GET", "POST"])
def bulk_import(request):
    form = BulkUploadForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        report = bulk_import_service.parse(form.cleaned_data["file"].read())
        if report.file_errors:
            for err in report.file_errors:
                form.add_error("file", err)
        elif report.total == 0:
            form.add_error("file", "The file contains no data rows.")
        else:
            bulk_import_service.store(request, report)
            request.session[REASON_KEY] = form.cleaned_data["reason"]
            return redirect("it_admin:bulk_preview")
    return render(request, "it_admin/bulk_import.html", {
        "form": form, "max_rows": MAX_ROWS,
        "may_authorize": actor_can(request, C.PERM_OFFICER_AUTHORIZATION),
    })


@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_BULK_IMPORT)
def bulk_preview(request):
    report = bulk_import_service.load(request)
    if report is None:
        messages.info(request, "Upload a CSV file first.")
        return redirect("it_admin:bulk_import")
    # Re-validate on every preview so the administrator sees the live state.
    bulk_import_service.validate(report)
    return render(request, "it_admin/bulk_preview.html", {
        "report": report, "result": None, "reason": request.session.get(REASON_KEY, ""),
        "may_authorize": actor_can(request, C.PERM_OFFICER_AUTHORIZATION),
    })


@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_BULK_IMPORT)
@reauth_required
@require_POST
def bulk_commit(request):
    report = bulk_import_service.load(request)
    if report is None:
        messages.info(request, "Upload a CSV file first.")
        return redirect("it_admin:bulk_import")
    if request.POST.get("action") == "discard":
        bulk_import_service.clear(request)
        request.session.pop(REASON_KEY, None)
        messages.info(request, "Import discarded. No officers were created.")
        return redirect("it_admin:bulk_import")
    if request.POST.get("confirm") != "1":
        messages.error(request, "Confirm the import to proceed.")
        return redirect("it_admin:bulk_preview")
    may_authorize = actor_can(request, C.PERM_OFFICER_AUTHORIZATION)
    result = bulk_import_service.commit(
        report, request.user, may_authorize=may_authorize,
        reason=request.session.get(REASON_KEY, ""), request=request,
    )
    if not result.created and not result.failed and not result.skipped:
        messages.error(request, "There were no rows to import.")
        return redirect("it_admin:bulk_preview")
    bulk_import_service.clear(request)
    request.session.pop(REASON_KEY, None)
    if result.failed or result.skipped:
        messages.warning(request, f"Import finished: {result.created_count} created, {result.failed_count} not processed.")
    else:
        messages.success(request, "Import finished: officer identities created successfully. Operational authorization is managed separately.")
    return render(request, "it_admin/bulk_preview.html", {
        "report": report, "result": result, "may_authorize": may_authorize,
    })


@portal_required(PORTAL)
@permission_required(C.PERM_OFFICER_BULK_IMPORT)
def bulk_template(request):
    response = HttpResponse(CSV_TEMPLATE, content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="officer_import_template.csv"'
    return response
