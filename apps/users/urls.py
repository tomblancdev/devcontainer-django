"""URLs module for users app."""

from django.urls import path

from .views import (
    ActivateAccountView,
    ChangePasswordView,
    LoginView,
    LogoutView,
    RegisterView,
    RequestResetPasswordView,
    ResetPasswordView,
)

urlpatterns = [
    path("activate/", ActivateAccountView.as_view(), name="email_activation"),
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),
    path(
        "request-reset-password/",
        RequestResetPasswordView.as_view(),
        name="request_reset_password",
    ),
    path("reset-password/", ResetPasswordView.as_view(), name="reset_password"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
