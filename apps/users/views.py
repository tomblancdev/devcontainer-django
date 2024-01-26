"""Views for users app."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Self

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .exceptions import InvalidToken
from .models import (
    AuthToken,
    User,
    UserEmailValidationToken,
    UserResetPasswordToken,
)
from .serializers import (
    ActivateAccountSerializer,
    AuthTokenSerializer,
    PasswordChangeSerializer,
    RegisterSerializer,
    ResetPasswordRequestSerializer,
    ResetPasswordSerializer,
    UserSerializer,
)

if TYPE_CHECKING:
    from rest_framework.request import Request


def send_mail_activation(
    user: User,
    next_url: str,
) -> None:
    """Send email activation."""
    # create token
    token = UserEmailValidationToken.objects.create_token_for_user(user)
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
        reset_password_token = UserResetPasswordToken.objects.create_token_for_email(
            email,
        )
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

    def post(self: Self, request: Request) -> Response:
        """Handle HTTP POST request."""
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        user = serializer.save()
        send_mail_activation(user, data.get("next"))
        return Response(
            status=status.HTTP_201_CREATED,
            data={"success": _("User created successfully.")},
        )


class LoginView(ObtainAuthToken):

    """Login view."""

    serializer_class = AuthTokenSerializer

    permission_classes = (AllowAny,)

    def post(
        self: Self,
        request: Request,
        *args: Any,  # noqa: ARG002, ANN401
        **kwargs: Any,  # noqa: ARG002, ANN401
    ) -> Response:
        """Handle HTTP POST request."""
        serializer = self.serializer_class(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class ChangePasswordView(APIView):

    """Change password view."""

    permission_classes = (IsAuthenticated,)

    def post(self: Self, request: Request) -> Response:
        """Handle HTTP POST request."""
        user = request.user
        if not user:
            raise ValidationError(
                {"error": _("User does not exist.")},
            )
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        new_password = data.get("new_password")
        if not user.check_password(data.get("current_password")):
            raise ValidationError(
                {"current_password": [_("Invalid current password.")]},
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

    """Activate account view."""

    permission_classes = (AllowAny,)

    def post(self: Self, request: Request) -> Response:
        """Handle HTTP POST request."""
        serializer = ActivateAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        token = data.get("token")
        try:
            UserEmailValidationToken.objects.validate_token(token)
        except InvalidToken as error:
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

    def post(self: Self, request: Request) -> Response:
        """Handle HTTP POST request."""
        serializer = ResetPasswordRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        email = data.get("email")
        next_url = data.get("next")
        send_mail_reset_password(email, next_url)
        return Response(
            {"success": _("Reset password email sent successfully.")},
            status=status.HTTP_200_OK,
        )


class ResetPasswordView(APIView):

    """Reset password view."""

    permission_classes = (AllowAny,)

    def post(self: Self, request: Request) -> Response:
        """Handle HTTP POST request."""
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        token = data.get("token")
        try:
            reset_password_token = UserResetPasswordToken.objects.use_token(token)
        except InvalidToken as error:
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

    """Logout view."""

    permission_classes = (IsAuthenticated,)

    def post(self: Self, request: Request) -> Response:
        """Handle HTTP POST request."""
        request.auth.delete()
        if request.GET.get("everywhere"):
            AuthToken.objects.filter(user=request.user).delete()
            return Response(
                {"success": _("Logged out everywhere successfully.")},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"success": _("Logged out successfully.")},
            status=status.HTTP_200_OK,
        )


class MyProfileView(APIView):

    """User view."""

    permission_classes = (IsAuthenticated,)

    def get(self: Self, request: Request) -> Response:
        """Handle HTTP GET request."""
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def patch(self: Self, request: Request) -> Response:
        """Handle HTTP PATCH request."""
        serializer = UserSerializer(
            request.user,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def delete(self: Self, request: Request) -> Response:
        """Handle HTTP DELETE request."""
        data = request.data
        password = data.get("password")
        if not request.user.check_password(password):
            raise ValidationError(
                {"password": [_("Invalid password.")]},
            )
        if isinstance(request.user, User):
            recovery_token = request.user.create_recovery_token()
            request.user.email_user(
                subject=f"{_('Account deleted')}",
                message=_(
                    """
                    Your account has been deleted.

                    You can recover it with this unqiue key: {key}.
                    """
                ).format(
                    key=recovery_token.token,
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
            )
            request.user.anonymize()

        else:
            request.user.delete()
        return Response(
            {"success": _("Account deleted successfully.")},
            status=status.HTTP_200_OK,
        )
