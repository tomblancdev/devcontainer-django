"""Serializers for users app."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from django.contrib.auth import authenticate, password_validation
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from .models import AuthToken, User


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
    email = serializers.EmailField(write_only=True)

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

    def validate(
        self: Self,
        data: Any,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401
        """Validate that user does not exist and passwords match."""
        data = super().validate(data)
        if User.objects.filter(email=data["email"]).exists():
            raise serializers.ValidationError({"email": _("User already exists.")})
        if data["password"] != data["password_validation"]:
            raise serializers.ValidationError(
                {"password_validation": _("Passwords must match.")},
            )
        return data

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

    email = serializers.EmailField(write_only=True)
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
        if not user or not user.is_active:
            raise serializers.ValidationError(
                {"error": _("Invalid username or password.")},
            )
        if isinstance(user, User) and not user.email_verified:
            raise serializers.ValidationError({"error": _("Email is not verified.")})
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

    def validate(
        self: Self,
        data: Any,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401
        """Validate that passwords match."""
        data = super().validate(data)
        if data["new_password"] != data["new_password_validation"]:
            raise serializers.ValidationError(
                {"new_password_validation": _("Passwords must match.")},
            )
        return data


class ResetPasswordRequestSerializer(serializers.Serializer):

    """Serializer for reset password token."""

    email = serializers.EmailField(write_only=True)
    next = serializers.URLField(required=False, write_only=True)

    def validate(
        self: Self,
        data: Any,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401
        """Validate that user is validated."""
        data = super().validate(data)
        user = User.objects.filter(email=data["email"]).first()
        if user and not user.email_verified:
            raise serializers.ValidationError({"email": _("Email is not verified.")})
        return data


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

    def validate(
        self: Self,
        data: Any,  # noqa: ANN401
    ) -> Any:  # noqa: ANN401
        """Validate that passwords match."""
        data = super().validate(data)
        if data["password"] != data["password_validation"]:
            raise serializers.ValidationError(
                {"password_validation": _("Passwords must match.")},
            )
        return data


class ActivateAccountSerializer(serializers.Serializer):

    """Serializer for activate account."""

    token = serializers.CharField(write_only=True)
