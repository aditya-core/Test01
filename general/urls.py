from django.urls import path

from . import views

app_name = "general"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("cases/register/", views.register_case, name="register_case"),
    path("cases/", views.view_cases, name="view_cases"),
    # Protected file delivery — every download is authorized server-side.
    path("cases/<str:case_id>/fir/", views.download_fir, name="download_fir"),
    path("cases/<str:case_id>/evidence/<int:pk>/", views.download_evidence, name="download_evidence"),
]
