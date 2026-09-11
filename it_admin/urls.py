from django.urls import path

from . import views

app_name = "it_admin"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),

    # ---- Identity: officers
    path("officers/", views.officer_list, name="officer_list"),
    path("officers/new/", views.officer_create, name="officer_create"),
    path("officers/<int:pk>/", views.officer_detail, name="officer_detail"),
    path("officers/<int:pk>/edit/", views.officer_edit, name="officer_edit"),
    path("officers/<int:pk>/authorization/", views.officer_authorization, name="officer_authorization"),
    path("officers/<int:pk>/transfer/", views.officer_transfer, name="officer_transfer"),
    path("officers/<int:pk>/timeline/", views.officer_timeline, name="officer_timeline"),
    path("officers/<int:pk>/access/", views.officer_access_explanation, name="officer_access"),
    path("officers/<int:pk>/devices/", views.officer_devices_sessions, name="officer_devices_sessions"),
    path("officers/<int:pk>/lifecycle/", views.officer_lifecycle, name="officer_lifecycle"),
    path("officers/<int:pk>/status/", views.officer_status, name="officer_status"),
    path("officers/<int:pk>/lock/", views.officer_lock, name="officer_lock"),
    path("officers/<int:pk>/unlock/", views.officer_unlock, name="officer_unlock"),
    path("officers/<int:pk>/reset-password/", views.officer_reset_password, name="officer_reset_password"),
    path("officers/<int:pk>/reset-code/", views.officer_reset_code, name="officer_reset_code"),
    path("officers/<int:pk>/sessions/terminate-all/", views.session_terminate_all, name="session_terminate_all"),
    path("officers/<int:pk>/access-review/raise/", views.access_review_raise, name="access_review_raise"),

    # ---- Identity: registries
    path("designations/", views.designation_list, name="designation_list"),
    path("designations/new/", views.designation_create, name="designation_create"),
    path("designations/<int:pk>/edit/", views.designation_edit, name="designation_edit"),
    path("designations/<int:pk>/toggle/", views.designation_toggle, name="designation_toggle"),
    path("designations/<int:pk>/delete/", views.designation_delete, name="designation_delete"),
    path("departments/", views.department_list, name="department_list"),
    path("departments/new/", views.department_create, name="department_create"),
    path("departments/<int:pk>/edit/", views.department_edit, name="department_edit"),
    path("departments/<int:pk>/toggle/", views.department_toggle, name="department_toggle"),
    path("units/new/", views.unit_create, name="unit_create"),
    path("units/<int:pk>/edit/", views.unit_edit, name="unit_edit"),
    path("units/<int:pk>/toggle/", views.unit_toggle, name="unit_toggle"),
    path("postings/", views.posting_list, name="posting_list"),

    # ---- Identity: bulk
    path("bulk/import/", views.bulk_import, name="bulk_import"),
    path("bulk/preview/", views.bulk_preview, name="bulk_preview"),
    path("bulk/commit/", views.bulk_commit, name="bulk_commit"),
    path("bulk/template.csv", views.bulk_template, name="bulk_template"),

    # ---- Security
    path("security/accounts/", views.account_security, name="account_security"),
    path("security/devices/", views.device_session_overview, name="device_session_overview"),
    path("security/devices/<int:pk>/revoke/", views.device_revoke, name="device_revoke"),
    path("security/sessions/<int:pk>/terminate/", views.session_terminate, name="session_terminate"),
    path("security/", views.security_dashboard, name="security_dashboard"),
    path("security/reviews/", views.access_review_list, name="access_review_list"),
    path("security/reviews/<int:pk>/", views.access_review_detail, name="access_review_detail"),
    path("security/reviews/<int:pk>/decide/", views.access_review_decide, name="access_review_decide"),
    path("security/temporary-access/", views.temporary_access_list, name="temporary_access_list"),
    path("security/temporary-access/new/", views.temporary_access_create, name="temporary_access_create"),
    path("security/temporary-access/<int:pk>/revoke/", views.temporary_access_revoke, name="temporary_access_revoke"),
    path("audit/", views.audit_dashboard, name="audit_dashboard"),
    path("audit/verify/", views.audit_verify, name="audit_verify"),

    # ---- Administration
    path("roles/", views.admin_role_list, name="admin_role_list"),
    path("roles/new/", views.admin_role_create, name="admin_role_create"),
    path("roles/assign/", views.admin_role_assign, name="admin_role_assign"),
    path("roles/<int:pk>/", views.admin_role_detail, name="admin_role_detail"),
    path("approvals/", views.approval_list, name="approval_list"),
    path("approvals/<int:pk>/", views.approval_detail, name="approval_detail"),
    path("approvals/<int:pk>/decide/", views.approval_decide, name="approval_decide"),
    path("approvals/<int:pk>/cancel/", views.approval_cancel, name="approval_cancel"),
]
