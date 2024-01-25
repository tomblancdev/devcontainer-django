"""Exceptions for users app."""
from __future__ import annotations

from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions


class InvalidToken(exceptions.AuthenticationFailed):

    """Invalid token exception."""

    default_detail = _("Invalid token.")
    default_code = "invalid_token"


class UserIsNotActive(exceptions.AuthenticationFailed):

    """Inactive user exception."""

    default_detail = _("User inactive.")
    default_code = "invalid_user"


class EmailNotVerified(exceptions.ValidationError):

    """Email not verified exception."""

    default_detail = _("Email not verified.")
    default_code = "email_not_verified"


class UserAlreadyExists(exceptions.ValidationError):

    """User already exists exception."""

    default_detail = _("User already exists.")
    default_code = "user_already_exists"


class UserDoesNotExist(exceptions.ValidationError):

    """User does not exist exception."""

    default_detail = _("User does not exist.")
    default_code = "user_does_not_exist"


class PasswordsDoNotMatch(exceptions.ValidationError):

    """Passwords do not match exception."""

    default_detail = _("Passwords do not match.")
    default_code = "passwords_do_not_match"


class InvalidEmailOrPassword(exceptions.AuthenticationFailed):

    """Invalid email or password exception."""

    default_detail = _("Invalid email or password.")
    default_code = "invalid_email_or_password"
