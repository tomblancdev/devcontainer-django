"""URLs module for users app."""

from django.urls import path

from .views import RegisterView, email_activation

urlpatterns = [
    path("activate/<str:token>/", email_activation, name="email_activation"),
    path("register/", RegisterView.as_view(), name="register"),
]
