"""Base of user models."""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import Any, ClassVar, Self, TypedDict, Unpack

from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.contrib.contenttypes.models import ContentType
from django.core.mail import send_mail
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta

from .exceptions import InvalidToken, UserAlreadyExists
from .settings import (
    AUTH_TOKEN_EXPIRATION_TIME,
    EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME,
    RESET_PASSWORD_TOKEN_EXPIRATION_TIME,
)


class UserRelatedModel(models.Model):

    """Base Model for all models related to a user.

    This model adds a foreign key to the user model.
    It handles the anonymization of the user when the user is anonymized.
    """

    user: models.ForeignKey[User] | models.OneToOneField[User] = models.ForeignKey(
        verbose_name=_("user"),
        to=settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

    objects: ClassVar[models.Manager[UserRelatedModel]] = models.Manager()

    class Meta(TypedModelMeta):

        """Meta options."""

        abstract = True

    def anonymize(self: Self) -> None:
        """Anonymize the model in case of anonymization of the user."""
        self.delete()


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

    def create_user(  # noqa: PLR0913
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
            raise UserAlreadyExists

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

    def create_superuser(  # noqa: PLR0913
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

    def anonymize_users(self: Self) -> None:
        """Anonymize all users in the QuerySet."""
        for user in self.all():
            user.anonymize()


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
        blank=True,
        null=True,
    )

    username = models.CharField(
        verbose_name=_("username"),
        max_length=255,
        default="",
    )

    first_name = models.CharField(
        verbose_name=_("first name"),
        max_length=255,
        default="",
    )

    last_name = models.CharField(
        verbose_name=_("last name"),
        max_length=255,
        default="",
    )

    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    date_joined = models.DateTimeField(
        verbose_name=_("date joined"),
        auto_now_add=True,
    )

    token_email_validation: UserEmailValidationToken
    reset_password_token_set: models.Manager[UserResetPasswordToken]
    auth_token_set: models.Manager[AuthToken]
    recovery_token: UserRecoveryToken

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = ["username", "first_name", "last_name"]

    objects: ClassVar[UserManager] = UserManager()

    def __str__(self: Self) -> str:
        """Return string representation."""
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
        return f"{self.username}"

    def get_full_name(self: Self) -> str:
        """Return the full name for the user."""
        return f"{self.first_name} {self.last_name}"

    def email_user(
        self: Self,
        **kwargs: Unpack[SendUserEmailOptions],
    ) -> None:
        """Send an email to this user."""
        if not self.email:
            raise ValueError(_("User does not have an email address."))
        send_mail(
            recipient_list=[self.email],
            **kwargs,
        )

    def create_recovery_token(self: Self) -> UserRecoveryToken:
        """Create a recovery token."""
        return UserRecoveryToken.objects.create_token_for_user(self)

    def anonymize(self: Self) -> None:
        """Anonymize the user."""
        self.username = ""
        self.email = None
        self.first_name = ""
        self.last_name = ""
        self.set_password(None)

        UserRecoveryToken.objects.create_token_for_user(self)

        self.save()

    def anonymize_related_models(self: Self) -> None:
        """Anonymize related models."""
        model_classes = ContentType.objects.all()
        for model_class in model_classes:
            model = model_class.model_class()
            if model is None:
                continue
            if not issubclass(model, UserRelatedModel):
                continue
            instances = model.objects.filter(user=self)
            for instance in instances:
                instance.anonymize()

    def delete_email_validation_token(self: Self) -> None:
        """Delete the email validation token."""
        if hasattr(self, "token_email_validation"):
            self.token_email_validation.delete()

    def delete_reset_password_tokens(self: Self) -> None:
        """Delete the reset password token."""
        if hasattr(self, "reset_password_token_set"):
            self.reset_password_token_set.all().delete()

    def delete_auth_tokens(self: Self) -> None:
        """Delete the auth tokens."""
        if hasattr(self, "auth_token_set"):
            self.auth_token_set.all().delete()


class UserEmailValidationTokenManager(models.Manager["UserEmailValidationToken"]):

    """User token email validation manager."""

    def create_token_for_user(self: Self, user: User) -> UserEmailValidationToken:
        """Create a token."""
        # check if token for this user exists and is validated
        token_email_validation = self.filter(
            user=user,
        ).first()
        if token_email_validation:
            if token_email_validation.is_validated:
                raise InvalidToken(_("Token is already validated."))
            return token_email_validation

        # create token
        return self.create(user=user)

    def validate_token(self: Self, token: str) -> User:
        """Validate the token."""
        # check if token exists
        token_email_validation = self.filter(token=token).first()
        if not token_email_validation:
            raise InvalidToken

        # validate token
        token_email_validation.validate()

        return token_email_validation.user

    def unregister_user_with_token(self: Self, token: str) -> None:
        """Unregister the user if the token is not validated."""
        token_email_validation = self.filter(token=token).first()
        if token_email_validation is None:
            raise InvalidToken

        if token_email_validation.is_validated:
            raise InvalidToken

        token_email_validation.user.delete()

    def regenerate_token_for_user(self: Self, user: User) -> None:
        """Regenerate the token."""
        token_email_validation = self.filter(user=user).first()
        if token_email_validation is None:
            raise InvalidToken
        token_email_validation.regenerate_token()


class UserEmailValidationToken(UserRelatedModel):

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

    expires_at = models.DateTimeField(
        verbose_name=_("expires at"),
        blank=True,
        null=True,
        default=(
            timezone.now() + timedelta(seconds=EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME)
        )
        if EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME is not None
        else None,
    )

    objects: ClassVar[
        UserEmailValidationTokenManager
    ] = UserEmailValidationTokenManager()

    class Meta(TypedModelMeta):

        """Meta options."""

        abstract = "users" not in settings.INSTALLED_APPS

        verbose_name = _("user token email validation")
        verbose_name_plural = _("user token email validations")

    def __str__(self: Self) -> str:
        """Return string representation."""
        return f"#{self.user.id}_{self.user.username}_email_validation_token"

    @property
    def is_validated(self: Self) -> bool:
        """Return whether the token is validated."""
        return self.validated_at is not None

    @property
    def is_expired(self: Self) -> bool:
        """Return whether the token is expired."""
        if self.expires_at is None:
            return False
        return self.expires_at < timezone.now()

    def regenerate_token(self: Self) -> None:
        """Regenerate the token."""
        self.token = secrets.token_urlsafe()
        self.created_at = timezone.now()
        self.validated_at = None

        self.expires_at = (
            (timezone.now() + timedelta(seconds=EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME))
            if EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME is not None
            else None
        )
        self.save()

    def validate(self: Self) -> None:
        """Validate the token."""
        # if token is already validated, raise error
        if self.is_validated:
            raise InvalidToken(_("Token is already validated."))
        # if token is expired, raise error
        if self.is_expired:
            raise InvalidToken(_("Token is expired."))
        self.validated_at = timezone.now()
        self.save()


class UserResetPasswordTokenManager(models.Manager["UserResetPasswordToken"]):

    """Reset password token manager."""

    def create_token_for_email(self: Self, email: str) -> UserResetPasswordToken:
        """Create a token."""
        # check if user exists
        user = User.objects.filter(email=email).first()
        if not user:
            raise User.DoesNotExist(_("User does not exist."))
        return self.create(user=user)

    def use_token(self: Self, token: str) -> UserResetPasswordToken:
        """Use the token."""
        # check if token exists
        reset_password_token = self.filter(token=token).first()
        if not reset_password_token:
            raise InvalidToken
        reset_password_token.use_token()
        return reset_password_token


class UserResetPasswordToken(UserRelatedModel):

    """Reset password token model."""

    user = models.ForeignKey(
        verbose_name=_("user"),
        to=User,
        on_delete=models.CASCADE,
        related_name="reset_password_token_set",
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
        default=(
            timezone.now() + timedelta(seconds=RESET_PASSWORD_TOKEN_EXPIRATION_TIME)
        )
        if RESET_PASSWORD_TOKEN_EXPIRATION_TIME is not None
        else None,
    )

    used_at = models.DateTimeField(
        verbose_name=_("used at"),
        null=True,
        blank=True,
    )

    objects: ClassVar[UserResetPasswordTokenManager] = UserResetPasswordTokenManager()

    class Meta(TypedModelMeta):

        """Meta options."""

        abstract = "users" not in settings.INSTALLED_APPS

        verbose_name = _("reset password token")
        verbose_name_plural = _("reset password tokens")

    def __str__(self: Self) -> str:
        """Return string representation."""
        return f"#{self.user.id}_{self.user.username}_reset_password_token"

    @property
    def is_expired(self: Self) -> bool:
        """Return whether the token is expired."""
        return self.expires_at < timezone.now()

    @property
    def is_used(self: Self) -> bool:
        """Return whether the token is used."""
        return self.used_at is not None

    def use_token(self: Self) -> None:
        """Use the token."""
        if self.is_used:
            raise InvalidToken
        if self.is_expired:
            raise InvalidToken
        self.used_at = timezone.now()
        self.save()


def generate_auth_token() -> str:
    """Generate a token."""
    return secrets.token_bytes(32).hex()


class UserRecoveryTokenManager(models.Manager["UserRecoveryToken"]):

    """User recovery token manager."""

    def create_token_for_user(self: Self, user: User) -> UserRecoveryToken:
        """Create a token."""
        # check if token for this user exists and is validated
        recovery_token = self.filter(
            user=user,
        ).first()
        if recovery_token:
            return recovery_token

        # create token
        return self.create(user=user)


class UserRecoveryToken(UserRelatedModel):

    """User recovery token model."""

    user = models.OneToOneField(
        verbose_name=_("user"),
        to=User,
        on_delete=models.CASCADE,
        related_name="recovery_token",
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

    objects: ClassVar[UserRecoveryTokenManager] = UserRecoveryTokenManager()

    def __str__(self: Self) -> str:
        """Return string representation."""
        return f"#{self.user.id}_{self.token}_recovery_token"

    def anonymize(self: Self) -> None:
        """Do nothing on anonymization."""


class AuthToken(UserRelatedModel):

    """Authentification token model."""

    user = models.ForeignKey(
        verbose_name=_("user"),
        to=User,
        on_delete=models.CASCADE,
        related_name="auth_token_set",
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
        default=(timezone.now() + timedelta(seconds=AUTH_TOKEN_EXPIRATION_TIME))
        if AUTH_TOKEN_EXPIRATION_TIME is not None
        else None,
    )

    objects: ClassVar[models.Manager[AuthToken]] = models.Manager()

    class Meta(TypedModelMeta):

        """Meta options."""

        abstract = "users" not in settings.INSTALLED_APPS

        verbose_name = _("auth token")
        verbose_name_plural = _("auth tokens")

    def __str__(self: Self) -> str:
        """Return string representation."""
        return f"#{self.user.id}_{self.user.username}_auth_token"

    @property
    def is_expired(self: Self) -> bool:
        """Return whether the token is expired."""
        if self.expires_at is None:
            return False
        return self.expires_at < timezone.now()
