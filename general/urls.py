from django.urls import path

from . import views

app_name = "general"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("cases/register/", views.register_case, name="register_case"),
    path("cases/", views.view_cases, name="view_cases"),
]
