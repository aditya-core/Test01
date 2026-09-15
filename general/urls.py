from django.urls import path

from . import views

app_name = "general"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),

    # Cases
    path("cases/register/", views.register_case, name="register_case"),
    path("cases/", views.view_cases, name="view_cases"),
    path("cases/<str:case_id>/", views.case_detail, name="case_detail"),
    path("cases/<str:case_id>/transfer/", views.case_transfer, name="case_transfer"),

    # Protected file delivery — never a raw media URL.
    path("cases/<str:case_id>/fir/", views.download_fir, name="download_fir"),
    path("cases/<str:case_id>/evidence/<int:pk>/", views.download_evidence, name="download_evidence"),
    path("cases/<str:case_id>/documents/<int:pk>/", views.download_document, name="download_document"),

    # Access management
    path("cases/<str:case_id>/access/", views.case_access, name="case_access"),
    path("cases/<str:case_id>/access/grant/", views.grant_access, name="grant_access"),
    path("cases/<str:case_id>/access/request/", views.request_access, name="request_access"),
    path("grants/<int:pk>/revoke/", views.revoke_grant, name="revoke_grant"),

    # Access requests
    path("access-requests/", views.access_requests, name="access_requests"),
    path("access-requests/<int:pk>/<str:decision>/", views.decide_request, name="decide_request"),
    path("access-requests/<int:pk>/cancel/", views.cancel_request, name="cancel_request"),
]
