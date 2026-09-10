from django.urls import path

from . import views

app_name = "it_admin"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("officers/", views.officer_list, name="officer_list"),
    path("officers/new/", views.officer_create, name="officer_create"),
    path("officers/<int:pk>/", views.officer_detail, name="officer_detail"),
    path("officers/<int:pk>/edit/", views.officer_edit, name="officer_edit"),
    path("officers/<int:pk>/status/", views.officer_status, name="officer_status"),
    path("officers/<int:pk>/lock/", views.officer_lock, name="officer_lock"),
    path("officers/<int:pk>/unlock/", views.officer_unlock, name="officer_unlock"),
    path("officers/<int:pk>/reset-password/", views.officer_reset_password, name="officer_reset_password"),
    path("officers/<int:pk>/reset-code/", views.officer_reset_code, name="officer_reset_code"),
    path("security/", views.security_dashboard, name="security_dashboard"),
    path("audit/", views.audit_dashboard, name="audit_dashboard"),
]
