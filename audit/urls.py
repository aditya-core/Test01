from django.urls import path

from . import views

app_name = "audit"

urlpatterns = [
    path("", views.audit_list, name="list"),
    path("security/", views.security_list, name="security"),
]
