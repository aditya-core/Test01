"""URLs for the central identity & authentication app (auth routes only).

Account self-service routes (profile / password / security) are mounted at
``/account/`` in the root URLConf.
"""
from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("login/<str:portal_key>/", views.portal_login, name="login"),
    path("logout/", views.portal_logout, name="logout"),
    path("activate/<str:uidb64>/<str:token>/", views.activate_account, name="activate"),
    path("reauth/", views.reauth, name="reauth"),
]
