from django.urls import path

from . import views

app_name = "classified"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
]
