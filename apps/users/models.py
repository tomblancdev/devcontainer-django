"""Base of user models."""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from datetime import timedelta
from typing import Any, ClassVar, Self, TypedDict, Unpack

from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.core.mail import send_mail
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta


class SendUserEmailOptions(TypedDict, total=False):
    """Type Options for sending an email."""

    subject: str
    message: str
    from_email: str | None
    fail_silently: bool
    auth_user: str | None
    auth_password: str | None
    connection: Any | None
    html_message: str | None


class UserManager(BaseUserManager["User"]):
    """User manager."""

    def create_user(
        self: Self,
        email: str | None = None,
        username: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        password: str | None = None,
    ) -> User:
        """Create and save a user."""
        if not email:
            raise ValueError(_("Users must have an email address."))

        if not username:
            raise ValueError(_("Users must have a username."))

        if not first_name:
            raise ValueError(_("Users must have a first name."))

        if not last_name:
            raise ValueError(_("Users must have a last name."))

        if not password:
            raise ValueError(_("Users must have a password."))

        # check if user already exists
        if self.filter(email=email).exists():
            raise ValueError(_("User already exists."))

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            first_name=first_name,
            last_name=last_name,
        )
        # validate password
        if password is not None:
            password_validation.validate_password(password)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(
        self: Self,
        email: str,
        username: str,
        first_name: str,
        last_name: str,
        password: str,
    ) -> User:
        """Create and save a superuser."""
        user = self.create_user(
            email=self.normalize_email(email),
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password,
        )

        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True

        user.save(using=self._db)

        return user


class User(AbstractBaseUser, PermissionsMixin):
    """Base user model."""

    id = models.BigAutoField(
        verbose_name=_("id"),
        primary_key=True,
        unique=True,
        editable=False,
    )

    email = models.EmailField(
        verbose_name=_("email address"),
        max_length=255,
        unique=True,
    )

    username = models.CharField(
        verbose_name=_("username"),
        max_length=255,
    )

    first_name = models.CharField(
        verbose_name=_("first name"),
        max_length=255,
    )

    last_name = models.CharField(
        verbose_name=_("last name"),
        max_length=255,
    )

    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    date_joined = models.DateTimeField(
        verbose_name=_("date joined"),
        auto_now_add=True,
    )

    token_email_validation: UserTokenEmailValidation
    reset_password_token_set: models.Manager[ResetPasswordToken]
    auth_token_set: models.Manager[AuthToken]

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["username", "first_name", "last_name"]

    objects: ClassVar[UserManager] = UserManager()

    def __str__(self: Self) -> str:
        return f"#{self.id}_{self.username}"

    class Meta(TypedModelMeta):
        """Meta options."""

        abstract = "users" not in settings.INSTALLED_APPS
        verbose_name = _("user")
        verbose_name_plural = _("users")

    @property
    def email_verified(self: Self) -> bool:
        """Return whether the user's email is verified."""
        if self.is_superuser:
            return True
        if not hasattr(self, "token_email_validation"):
            return False

        return self.token_email_validation.is_validated

    def get_short_name(self: Self) -> str:
        """Return the short name for the user."""
        return f"#{self.id}_{self.username}"

    def get_full_name(self: Self) -> str:
        """Return the full name for the user."""
        return f"{self.first_name} {self.last_name}"

    def email_user(
        self: Self,
        **kwargs: Unpack[SendUserEmailOptions],
    ) -> None:
        """Send an email to this user."""
        send_mail(
            recipient_list=[self.email],
            **kwargs,
        )


class TokenError(Exception):
    """Base token error."""


class UserTokenEmailValidationManager(models.Manager["UserTokenEmailValidation"]):
    """User token email validation manager."""

    def create_token(self, user: User) -> UserTokenEmailValidation:
        """Create a token."""
        # check if token for this user exists and is validated
        token_email_validation = self.filter(
            user=user,
        ).first()
        if token_email_validation:
            if token_email_validation.is_validated:
                raise TokenError(_("Token is already validated."))
            return token_email_validation

        # create token
        token_email_validation = self.create(user=user)
        return token_email_validation

    def validate_token(self, token: str) -> User:
        """Validate the token."""
        # check if token exists
        token_email_validation = self.filter(token=token).first()
        if not token_email_validation:
            raise TokenError(_("Token does not exist."))

        # if token is already validated, raise error
        if token_email_validation.is_validated:
            raise TokenError(_("Token is already validated."))

        # validate token
        token_email_validation.validated_at = timezone.now()
        token_email_validation.save()

        return token_email_validation.user

    def unregister_user_with_token(self, token: str) -> None:
        """Unregister the user if the token is not validated."""
        token_email_validation = self.filter(token=token).first()
        if token_email_validation is None:
            raise ValueError(_("Token does not exist."))

        if token_email_validation.is_validated:
            raise ValueError(_("Token is already validated."))

        token_email_validation.user.delete()


class UserTokenEmailValidation(models.Model):
    """User token email validation model."""

    user = models.OneToOneField(
        verbose_name=_("user"),
        to=User,
        on_delete=models.CASCADE,
        related_name="token_email_validation",
    )

    token = models.CharField(
        verbose_name=_("token"),
        max_length=255,
        default=secrets.token_urlsafe,
        unique=True,
    )

    created_at = models.DateTimeField(
        verbose_name=_("created at"),
        auto_now_add=True,
    )

    validated_at = models.DateTimeField(
        verbose_name=_("validated at"),
        null=True,
        blank=True,
    )

    objects: ClassVar[
        UserTokenEmailValidationManager
    ] = UserTokenEmailValidationManager()

    def __str__(self) -> str:
        return f"#{self.user.id}_{self.user.username}_token_email_validation"

    class Meta(TypedModelMeta):
        """Meta options."""

        abstract = "users" not in settings.INSTALLED_APPS

        verbose_name = _("user token email validation")
        verbose_name_plural = _("user token email validations")

    def save(
        self,
        force_insert: bool = False,
        force_update: bool = False,
        using: str | None = None,
        update_fields: Iterable[str] | None = None,
    ) -> None:
        """Save the model."""
        # get previous instance
        previous_instance = UserTokenEmailValidation.objects.filter(
            pk=self.pk,
        ).first()

        if previous_instance and previous_instance.is_validated:
            raise TokenError(_("Cannot save validated token."))
        # if token already exists but is not validated, renew token
        if (
            UserTokenEmailValidation.objects.filter(
                token=self.token,
            )
            .exclude(
                validated_at__isnull=False,
            )
            .exists()
        ):
            self.token = secrets.token_urlsafe()
        return super().save(force_insert, force_update, using, update_fields)

    @property
    def is_validated(self) -> bool:
        """Return whether the token is validated."""
        return self.validated_at is not None


class ResetPasswordTokenManager(models.Manager["ResetPasswordToken"]):
    """Reset password token manager."""

    def create_token(self, email: str) -> ResetPasswordToken:
        """Create a token."""
        # check if user exists
        user = User.objects.filter(email=email).first()
        if not user:
            raise User.DoesNotExist(_("User does not exist."))
        return self.create(user=user)

    def validate_token(self, token: str) -> ResetPasswordToken:
        """Validate the token."""
        # check if token exists
        reset_password_token = self.filter(token=token).first()
        if not reset_password_token:
            raise TokenError(_("Token does not exist."))

        # if token is expired, raise error
        if reset_password_token.is_expired:
            raise TokenError(_("Token is expired."))

        if reset_password_token.is_used:
            raise TokenError(_("Token is already used."))

        return reset_password_token

    def use_token(self, token: str) -> ResetPasswordToken:
        """Use the token."""
        reset_password_token = self.validate_token(token)
        reset_password_token.used_at = timezone.now()
        reset_password_token.save()
        return reset_password_token


class ResetPasswordToken(models.Model):
    user = models.ForeignKey(
        verbose_name=_("user"),
        to=User,
        on_delete=models.CASCADE,
    )

    token = models.CharField(
        verbose_name=_("token"),
        max_length=255,
        default=secrets.token_urlsafe,
        unique=True,
    )

    created_at = models.DateTimeField(
        verbose_name=_("created at"),
        auto_now_add=True,
    )

    expires_at = models.DateTimeField(
        verbose_name=_("expires at"),
        default=timezone.now() + timedelta(minutes=30),  # TODO: make this configurable
    )

    used_at = models.DateTimeField(
        verbose_name=_("used at"),
        null=True,
        blank=True,
    )

    objects: ClassVar[ResetPasswordTokenManager] = ResetPasswordTokenManager()

    def __str__(self) -> str:
        return f"#{self.user.id}_{self.user.username}_reset_password_token"

    class Meta(TypedModelMeta):
        """Meta options."""

        abstract = "users" not in settings.INSTALLED_APPS

        verbose_name = _("reset password token")
        verbose_name_plural = _("reset password tokens")

    @property
    def is_expired(self: Self) -> bool:
        """Return whether the token is expired."""
        return self.expires_at < timezone.now()

    @property
    def is_used(self: Self) -> bool:
        """Return whether the token is used."""
        return self.used_at is not None


def generate_auth_token() -> str:
    """Generate a token."""
    return secrets.token_bytes(32).hex()


class AuthToken(models.Model):
    """Authentification token model."""

    user = models.ForeignKey(
        verbose_name=_("user"),
        to=User,
        on_delete=models.CASCADE,
    )

    key = models.CharField(
        verbose_name=_("token"),
        max_length=255,
        default=generate_auth_token,
        unique=True,
    )

    created_at = models.DateTimeField(
        verbose_name=_("created at"),
        auto_now_add=True,
    )

    expires_at = models.DateTimeField(
        verbose_name=_("expires at"),
        null=True,
        blank=True,
    )

    objects: ClassVar[models.Manager[AuthToken]] = models.Manager()

    def __str__(self) -> str:
        """Return string representation."""
        return f"#{self.user.id}_{self.user.username}_auth_token"

    class Meta(TypedModelMeta):
        """Meta options."""

        abstract = "users" not in settings.INSTALLED_APPS

        verbose_name = _("auth token")
        verbose_name_plural = _("auth tokens")

    @property
    def is_expired(self: Self) -> bool:
        """Return whether the token is expired."""
        if self.expires_at is None:
            return False
        return self.expires_at < timezone.now()
