"""Serializers for users app."""

from typing import Any

from django.contrib.auth import password_validation
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from .models import User


class RegisterSerializer(serializers.ModelSerializer[User]):
    """Serializer for user registration."""

    password_validation = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )

    next = serializers.URLField(required=False, write_only=True)

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


class LoginSerializer(serializers.Serializer):
    """Serializer for user login."""

    email = serializers.EmailField()
    password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
    )

    def validate(self, data: Any) -> Any:
        """Validate that user exists and password is correct."""
        data = super().validate(data)
        try:
            user = User.objects.get(email=data["email"])
        except User.DoesNotExist:
            raise serializers.ValidationError(_("User does not exist."))
        if not user.check_password(data["password"]):
            raise serializers.ValidationError(_("Password is incorrect."))
        data["user"] = user
        return data
