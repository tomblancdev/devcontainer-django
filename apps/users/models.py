"""Base of user models."""

from __future__ import annotations

from typing import Any, Generic, Self, TypedDict, TypeVar, Unpack

from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.core.mail import send_mail
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta

T = TypeVar("T", bound="User")


class SendUserEmailOptions(TypedDict, total=False):
    """Options for sending an email."""

    subject: str
    message: str
    from_email: str | None
    fail_silently: bool
    auth_user: str | None
    auth_password: str | None
    connection: Any | None
    html_message: str | None


class UserManager(BaseUserManager, Generic[T]):
    """User manager."""

    model: type[T]

    def create_user(
        self: Self,
        email: str,
        username: str,
        first_name: str,
        last_name: str,
        password: str | None = None,
    ) -> T:
        """Create and save a user."""
        if not email:
            raise ValueError(_("Users must have an email address."))

        if not username:
            raise ValueError(_("Users must have a username."))

        if not first_name:
            raise ValueError(_("Users must have a first name."))

        if not last_name:
            raise ValueError(_("Users must have a last name."))

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            first_name=first_name,
            last_name=last_name,
        )

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
    ) -> T:
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

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["username", "first_name", "last_name"]

    objects = UserManager[Self]()

    def __str__(self: Self) -> str:
        return f"#{self.id}_{self.username}"

    class Meta(TypedModelMeta):
        """Meta options."""

        if "users" not in settings.INSTALLED_APPS:
            abstract = True

        verbose_name = _("user")
        verbose_name_plural = _("users")

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
