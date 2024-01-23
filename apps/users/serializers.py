"""Serializers for users app."""

from typing import Any

from django.contrib.auth import authenticate, password_validation
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from .models import AuthToken, User


class RegisterSerializer(serializers.ModelSerializer[User]):
    """Serializer for user registration."""

    password_validation = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )

    next = serializers.URLField(write_only=True)
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
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
        extra_kwargs = {
            "email": {"write_only": True},
            "password": {"write_only": True},
            "first_name": {"write_only": True},
            "last_name": {"write_only": True},
            "username": {"write_only": True},
        }

    def validate(self, data: Any) -> Any:
        """Validate that user does not exist and passwords match."""
        data = super().validate(data)
        if User.objects.filter(email=data["email"]).exists():
            raise serializers.ValidationError(_("User already exists."))
        if data["password"] != data["password_validation"]:
            raise serializers.ValidationError(_("Passwords must match."))
        # check that password is strong enough
        try:
            password_validation.validate_password(data["password"])
        except serializers.ValidationError as error:
            raise serializers.ValidationError({"password": f"{error}"})
        return data

    def create(self, validated_data):
        """Create user."""
        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            username=validated_data["username"],
        )
        return user


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
        extra_kwargs = {
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

    user = UserSerializer(read_only=True)

    class Meta:
        """Meta class for auth token serializer."""

        model = AuthToken
        fields = ("key", "user", "email", "password", "expires_at")
        extra_kwargs = {
            "key": {"read_only": True},
            "user": {"read_only": True},
        }

    def validate(self, data: Any) -> Any:
        """Validate that user exists and passwords match."""
        data = super().validate(data)
        user = authenticate(
            email=data["email"],
            password=data["password"],
        )
        if not user or not user.is_active:
            raise serializers.ValidationError(_("Invalid credentials."))
        if isinstance(user, User) and not user.email_verified:
            raise serializers.ValidationError(_("Email is not verified."))
        data["user"] = user
        return data

    def create(self, validated_data):
        """Create auth token."""
        user = validated_data["user"]
        token = AuthToken.objects.create(
            user=user,
            expires_at=validated_data.get("expires_at", None),
        )
        return token


class PasswordChangeSerializer(serializers.Serializer):
    password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )
    new_password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )
    new_password_validation = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )

    def validate(self, data: Any) -> Any:
        """Validate that passwords match."""
        data = super().validate(data)
        if data["new_password"] != data["new_password_validation"]:
            raise serializers.ValidationError(_("Passwords must match."))
        # check that password is strong enough
        try:
            password_validation.validate_password(data["new_password"])
        except serializers.ValidationError as error:
            raise serializers.ValidationError({"new_password": f"{error}"})
        return data


class ResetPasswordRequestSerializer(serializers.Serializer):
    """Serializer for reset password token."""

    email = serializers.EmailField(write_only=True)
    next = serializers.URLField(required=False, write_only=True)


class ResetPasswordSerializer(serializers.Serializer):
    """Serializer for reset password token."""

    token = serializers.CharField(write_only=True)

    password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )
    password_validation = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )

    def validate(self, data: Any) -> Any:
        """Validate that passwords match."""
        data = super().validate(data)
        if data["password"] != data["password_validation"]:
            raise serializers.ValidationError(_("Passwords must match."))
        # check that password is strong enough
        try:
            password_validation.validate_password(data["password"])
        except serializers.ValidationError as error:
            raise serializers.ValidationError({"password": f"{error}"})
        return data


class ActivateAccountSerializer(serializers.Serializer):
    """Serializer for activate account."""

    token = serializers.CharField(write_only=True)
