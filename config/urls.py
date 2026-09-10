"""Root URL configuration."""
from django.contrib import admin
from django.urls import include, path

from accounts import views as accounts_views
from audit import views as audit_views


def handler403(request, exception, template_name="errors/403.html"):
    from django.shortcuts import render

    return render(request, template_name, status=403)


def handler404(request, exception, template_name="errors/404.html"):
    from django.shortcuts import render

    return render(request, template_name, status=404)


def handler500(request, template_name="errors/500.html"):
    from django.shortcuts import render

    return render(request, template_name, status=500)


urlpatterns = [
    path("", accounts_views.portal_selection, name="portal_selection"),
    path("auth/", include("accounts.urls")),
    # Account self-service (identity app, non-login routes).
    path("account/", accounts_views.account_profile, name="account_profile"),
    path("account/password/", accounts_views.account_password, name="account_password"),
    path("account/security/", accounts_views.account_security, name="account_security"),
    path("general/", include("general.urls")),
    path("classified/", include("classified.urls")),
    path("admin-portal/", include("it_admin.urls")),
    path("audit/", include("audit.urls")),
    path("security/", audit_views.security_list, name="security_events"),
    path("django-admin/", admin.site.urls),
]
