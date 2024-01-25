"""Serializers for users app."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from django.contrib.auth import authenticate, password_validation
from rest_framework import serializers

from apps.users.exceptions import (
    InvalidEmailOrPassword,
    PasswordsDoNotMatch,
)

from .models import AuthToken, User
from .validators import (
    validate_email_is_verified,
    validate_mail_login,
    validate_user_does_not_exist,
)


class RegisterSerializer(serializers.ModelSerializer[User]):

    """Serializer for user registration."""

    password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        validators=[password_validation.validate_password],
    )
    password_validation = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )

    next = serializers.URLField(write_only=True)
    email = serializers.EmailField(
        write_only=True, validators=[validate_user_does_not_exist]
    )

    first_name = serializers.CharField(write_only=True)
    last_name = serializers.CharField(write_only=True)
    username = serializers.CharField(write_only=True)

    class Meta:

        """Meta class for user registration serializer."""

        model = User
        fields = (
            "email",
            "password",
            "password_validation",
            "first_name",
            "last_name",
            "username",
            "next",
        )
        extra_kwargs: ClassVar[dict[str, dict[str, bool]]] = {
            "email": {"write_only": True},
            "password": {"write_only": True},
            "first_name": {"write_only": True},
            "last_name": {"write_only": True},
            "username": {"write_only": True},
        }

    def validate_password_validation(
        self: Self,
        value: str,
    ) -> str:
        """Validate that passwords match."""
        password = self.get_initial().get("password")
        if password != value:
            raise PasswordsDoNotMatch

    def create(
        self: Self,
        validated_data: Any,  # noqa: ANN401
    ) -> User:
        """Create user."""
        return User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            username=validated_data["username"],
        )


class UserSerializer(serializers.ModelSerializer[User]):

    """Serializer for user."""

    class Meta:

        """Meta class for user serializer."""

        model = User
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "username",
            "is_active",
            "email_verified",
        )
        extra_kwargs: ClassVar[dict[str, dict[str, bool]]] = {
            "id": {"read_only": True},
            "email": {"read_only": True},
            "is_active": {"read_only": True},
            "email_verified": {"read_only": True},
        }


class AuthTokenSerializer(serializers.ModelSerializer[AuthToken]):

    """Serializer for auth token."""

    email = serializers.EmailField(
        write_only=True,
        validators=[
            validate_mail_login,
        ],
    )
    password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )

    class Meta:

        """Meta class for auth token serializer."""

        model = AuthToken
        fields = ("key", "email", "password", "expires_at")
        extra_kwargs: ClassVar[dict[str, dict[str, bool]]] = {
            "key": {"read_only": True},
        }

    def validate(
        self: Self,
        data: Any,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401
        """Validate that user exists and passwords match."""
        data = super().validate(data)
        user = authenticate(
            email=data["email"],
            password=data["password"],
        )
        if not user:
            raise InvalidEmailOrPassword
        data["user"] = user
        return data

    def create(
        self: Self,
        validated_data: Any,  # noqa: ANN401
    ) -> AuthToken:
        """Create auth token."""
        user = validated_data["user"]
        return AuthToken.objects.create(
            user=user,
            expires_at=validated_data.get("expires_at", None),
        )


class PasswordChangeSerializer(serializers.Serializer):

    """Serializer for password change."""

    current_password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )
    new_password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        validators=[password_validation.validate_password],
    )
    new_password_validation = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )

    def validate_new_password_validation(
        self: Self,
        value: str,
    ) -> str:
        """Validate that passwords match."""
        new_password = self.get_initial().get("new_password")
        if new_password != value:
            raise PasswordsDoNotMatch


class ResetPasswordRequestSerializer(serializers.Serializer):

    """Serializer for reset password token."""

    email = serializers.EmailField(
        write_only=True, validators=[validate_email_is_verified]
    )
    next = serializers.URLField(required=False, write_only=True)


class ResetPasswordSerializer(serializers.Serializer):

    """Serializer for reset password token."""

    token = serializers.CharField(write_only=True)

    password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        validators=[password_validation.validate_password],
    )
    password_validation = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )

    def validate_password_validation(
        self: Self,
        value: str,
    ) -> str:
        """Validate that passwords match."""
        password = self.get_initial().get("password")
        if password != value:
            raise PasswordsDoNotMatch


class ActivateAccountSerializer(serializers.Serializer):

    """Serializer for activate account."""

    token = serializers.CharField(write_only=True)
