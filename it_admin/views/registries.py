"""Designation, Department and Unit registries."""
from __future__ import annotations

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST, require_http_methods

from accounts import constants as C
from accounts.decorators import permission_required, portal_required
from accounts.models import Department, Designation, OrganizationUnit

from ..exceptions import AdminActionError
from ..forms import DepartmentForm, DesignationForm, UnitForm
from ..services import registry_service
from ._common import PORTAL, actor_can

__all__ = [
    "designation_list", "designation_create", "designation_edit", "designation_toggle", "designation_delete",
    "department_list", "department_create", "department_edit", "department_toggle",
    "unit_create", "unit_edit", "unit_toggle",
]


# --------------------------------------------------------------------------- designations
@portal_required(PORTAL)
@permission_required(C.PERM_DESIGNATION_VIEW)
def designation_list(request):
    qs = Designation.objects.annotate(assigned=Count("officers"))
    show_inactive = request.GET.get("inactive") == "1"
    if not show_inactive:
        qs = qs.filter(is_active=True)
    return render(request, "it_admin/designation_list.html", {
        "designations": qs, "show_inactive": show_inactive,
        "can_manage": actor_can(request, C.PERM_DESIGNATION_MANAGE),
    })


@portal_required(PORTAL)
@permission_required(C.PERM_DESIGNATION_MANAGE)
@require_http_methods(["GET", "POST"])
def designation_create(request):
    form = DesignationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            registry_service.save_designation(form.save(commit=False), request.user, request=request, created=True)
        except ValidationError as exc:
            form.add_error(None, exc)
        else:
            messages.success(request, "Designation created.")
            return redirect("it_admin:designation_list")
    return render(request, "it_admin/registry_form.html", {"form": form, "kind": "Designation", "creating": True,
                                                           "back": "it_admin:designation_list"})


@portal_required(PORTAL)
@permission_required(C.PERM_DESIGNATION_MANAGE)
@require_http_methods(["GET", "POST"])
def designation_edit(request, pk):
    designation = get_object_or_404(Designation, pk=pk)
    form = DesignationForm(request.POST or None, instance=designation)
    if request.method == "POST" and form.is_valid():
        try:
            registry_service.save_designation(form.save(commit=False), request.user, request=request)
        except ValidationError as exc:
            form.add_error(None, exc)
        else:
            # Keep the denormalised rank label of assigned officers in sync.
            designation.officers.exclude(rank=designation.name).update(rank=designation.name)
            messages.success(request, "Designation updated.")
            return redirect("it_admin:designation_list")
    officers = designation.officers.select_related("department", "unit").order_by("officer_id")
    return render(request, "it_admin/registry_form.html", {"form": form, "kind": "Designation", "creating": False,
                                                           "obj": designation, "officers": officers,
                                                           "back": "it_admin:designation_list"})


@portal_required(PORTAL)
@permission_required(C.PERM_DESIGNATION_MANAGE)
@require_POST
def designation_toggle(request, pk):
    designation = get_object_or_404(Designation, pk=pk)
    registry_service.set_designation_active(designation, not designation.is_active, request.user, request=request)
    messages.success(request, f"Designation {'activated' if designation.is_active else 'deactivated'}.")
    return redirect("it_admin:designation_list")


@portal_required(PORTAL)
@permission_required(C.PERM_DESIGNATION_MANAGE)
@require_POST
def designation_delete(request, pk):
    designation = get_object_or_404(Designation, pk=pk)
    try:
        registry_service.delete_designation(designation, request.user, request=request)
    except AdminActionError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "Designation removed.")
    return redirect("it_admin:designation_list")


# --------------------------------------------------------------------------- departments & units
@portal_required(PORTAL)
@permission_required(C.PERM_DEPARTMENT_VIEW)
def department_list(request):
    show_inactive = request.GET.get("inactive") == "1"
    depts = Department.objects.annotate(officer_total=Count("officers", distinct=True))
    if not show_inactive:
        depts = depts.filter(is_active=True)
    units = OrganizationUnit.objects.select_related("organization", "department").annotate(officer_total=Count("officers"))
    unassigned_units = units.filter(department__isnull=True)
    if not show_inactive:
        unassigned_units = unassigned_units.filter(is_active=True)
    dept_units = {}
    for u in units:
        if u.department_id and (show_inactive or u.is_active):
            dept_units.setdefault(u.department_id, []).append(u)
    return render(request, "it_admin/department_list.html", {
        "departments": depts, "dept_units": dept_units, "unassigned_units": unassigned_units,
        "show_inactive": show_inactive, "can_manage": actor_can(request, C.PERM_DEPARTMENT_MANAGE),
    })


@portal_required(PORTAL)
@permission_required(C.PERM_DEPARTMENT_MANAGE)
@require_http_methods(["GET", "POST"])
def department_create(request):
    form = DepartmentForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            registry_service.save_department(form.save(commit=False), request.user, request=request, created=True)
        except ValidationError as exc:
            form.add_error(None, exc)
        else:
            messages.success(request, "Department created.")
            return redirect("it_admin:department_list")
    return render(request, "it_admin/registry_form.html", {"form": form, "kind": "Department", "creating": True,
                                                           "back": "it_admin:department_list"})


@portal_required(PORTAL)
@permission_required(C.PERM_DEPARTMENT_MANAGE)
@require_http_methods(["GET", "POST"])
def department_edit(request, pk):
    department = get_object_or_404(Department, pk=pk)
    form = DepartmentForm(request.POST or None, instance=department)
    if request.method == "POST" and form.is_valid():
        try:
            registry_service.save_department(form.save(commit=False), request.user, request=request)
        except ValidationError as exc:
            form.add_error(None, exc)
        else:
            messages.success(request, "Department updated.")
            return redirect("it_admin:department_list")
    officers = department.officers.select_related("designation", "unit").order_by("officer_id")
    return render(request, "it_admin/registry_form.html", {"form": form, "kind": "Department", "creating": False,
                                                           "obj": department, "officers": officers,
                                                           "units": department.units.all(),
                                                           "back": "it_admin:department_list"})


@portal_required(PORTAL)
@permission_required(C.PERM_DEPARTMENT_MANAGE)
@require_POST
def department_toggle(request, pk):
    department = get_object_or_404(Department, pk=pk)
    registry_service.set_department_active(department, not department.is_active, request.user, request=request)
    messages.success(request, f"Department {'activated' if department.is_active else 'deactivated'}.")
    return redirect("it_admin:department_list")


@portal_required(PORTAL)
@permission_required(C.PERM_DEPARTMENT_MANAGE)
@require_http_methods(["GET", "POST"])
def unit_create(request):
    initial = {}
    if request.GET.get("department"):
        initial["department"] = request.GET["department"]
    form = UnitForm(request.POST or None, initial=initial)
    if request.method == "POST" and form.is_valid():
        try:
            registry_service.save_unit(form.save(commit=False), request.user, request=request, created=True)
        except ValidationError as exc:
            form.add_error(None, exc)
        else:
            messages.success(request, "Unit created.")
            return redirect("it_admin:department_list")
    return render(request, "it_admin/registry_form.html", {"form": form, "kind": "Unit", "creating": True,
                                                           "back": "it_admin:department_list"})


@portal_required(PORTAL)
@permission_required(C.PERM_DEPARTMENT_MANAGE)
@require_http_methods(["GET", "POST"])
def unit_edit(request, pk):
    unit = get_object_or_404(OrganizationUnit.objects.select_related("organization", "department"), pk=pk)
    form = UnitForm(request.POST or None, instance=unit)
    if request.method == "POST" and form.is_valid():
        try:
            registry_service.save_unit(form.save(commit=False), request.user, request=request)
        except ValidationError as exc:
            form.add_error(None, exc)
        else:
            messages.success(request, "Unit updated.")
            return redirect("it_admin:department_list")
    officers = unit.officers.select_related("designation", "department").order_by("officer_id")
    return render(request, "it_admin/registry_form.html", {"form": form, "kind": "Unit", "creating": False,
                                                           "obj": unit, "officers": officers,
                                                           "back": "it_admin:department_list"})


@portal_required(PORTAL)
@permission_required(C.PERM_DEPARTMENT_MANAGE)
@require_POST
def unit_toggle(request, pk):
    unit = get_object_or_404(OrganizationUnit, pk=pk)
    registry_service.set_unit_active(unit, not unit.is_active, request.user, request=request)
    messages.success(request, f"Unit {'activated' if unit.is_active else 'deactivated'}.")
    return redirect("it_admin:department_list")
