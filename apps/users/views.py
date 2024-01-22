"""Views for users app."""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import (
    AuthToken,
    ResetPasswordToken,
    TokenError,
    User,
    UserTokenEmailValidation,
)
from .serializers import (
    ActivateAccountSerializer,
    AuthTokenSerializer,
    PasswordChangeSerializer,
    RegisterSerializer,
    ResetPasswordRequestSerializer,
    ResetPasswordSerializer,
)


def send_mail_activation(
    user: User,
    next_url: str,
) -> None:
    """Send email activation."""
    # create token
    token = UserTokenEmailValidation.objects.create_token(user)
    # create activation link
    activation_link = f"{next_url}?token={token.token}"
    # send email
    user.email_user(
        subject=f"{_('Activate your account')}",
        message=activation_link,
        from_email=settings.DEFAULT_FROM_EMAIL,
        html_message=f"<a href='{activation_link}'>{activation_link}</a>",
    )


def send_mail_reset_password(email: str, next_url: str) -> None:
    """Send email reset password."""
    try:
        reset_password_token = ResetPasswordToken.objects.create_token(email)
    except User.DoesNotExist:
        return
    reset_password_link = f"{next_url}?token={reset_password_token.token}"
    # send email
    reset_password_token.user.email_user(
        subject=f"{_('Reset password')}",
        message=reset_password_link,
        from_email=settings.DEFAULT_FROM_EMAIL,
        html_message=f"<a href='{reset_password_link}'>{reset_password_link}</a>",
    )


class RegisterView(APIView):
    """Register view."""

    permission_classes = (AllowAny,)

    def post(self, request: Request) -> Response:
        """Handle HTTP POST request."""
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if serializer.is_valid():
            user = serializer.save()
            send_mail_activation(user, data.get("next"))
            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED,
            )
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )

    def get(self, request: Request) -> Response:
        """Handle HTTP GET request. Return Form for registration based on serializer."""
        serializer = RegisterSerializer()
        return Response(serializer.data)


class LoginView(ObtainAuthToken):
    serializer_class = AuthTokenSerializer

    permission_classes = (AllowAny,)

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Handle HTTP POST request."""
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class ChangePasswordView(APIView):
    """Change password view."""

    permission_classes = (IsAuthenticated,)

    def post(self, request: Request) -> Response:
        """Handle HTTP POST request."""
        user = request.user
        if not user:
            return Response(
                {"error": _("User not found.")},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        new_password = data.get("new_password")
        if not new_password:
            return Response(
                {"error": _("New password is required.")},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # try to login with old password
        if not user.check_password(data.get("password")):
            return Response(
                {"error": _("Invalid password.")},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.set_password(new_password)
        user.save()
        # invalidate all tokens except current one
        AuthToken.objects.filter(user=user).exclude(key=request.auth.key).delete()
        return Response(
            {"success": _("Password changed successfully.")},
            status=status.HTTP_200_OK,
        )


class ActivateAccountView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request: Request) -> Response:
        """Handle HTTP POST request."""
        serializer = ActivateAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        token = data.get("token")
        try:
            UserTokenEmailValidation.objects.validate_token(token)
        except TokenError as error:
            return Response(
                {"error": str(error)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(
            {"success": _("Account activated successfully.")},
            status=status.HTTP_200_OK,
        )


class RequestResetPasswordView(APIView):
    """Request reset password view."""

    permission_classes = (AllowAny,)

    def post(self, request: Request) -> Response:
        """Handle HTTP POST request."""
        serializer = ResetPasswordRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        email = data.get("email")
        next_url = data.get("next")
        send_mail_reset_password(email, next_url)
        return Response(
            {"success": _("Reset password link sent successfully.")},
            status=status.HTTP_200_OK,
        )


class ResetPasswordView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request: Request) -> Response:
        """Handle HTTP POST request."""
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        token = data.get("token")
        try:
            reset_password_token = ResetPasswordToken.objects.use_token(token)
        except TokenError as error:
            return Response(
                {"error": str(error)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        reset_password_token.user.set_password(data.get("password"))
        reset_password_token.user.save()
        # invalidate all tokens except current one
        AuthToken.objects.filter(user=reset_password_token.user).delete()
        return Response(
            {"success": _("Password reset successfully.")},
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request: Request) -> Response:
        """Handle HTTP POST request."""
        request.auth.delete()
        if request.GET.get("everywhere"):
            AuthToken.objects.filter(user=request.user).delete()
            return Response(
                {"success": _("Logout everywhere successfully.")},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"success": _("Logout successfully.")},
            status=status.HTTP_200_OK,
        )
