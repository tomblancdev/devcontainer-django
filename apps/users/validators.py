"""Validators for users app."""

from __future__ import annotations

from .exceptions import (
    EmailNotVerified,
    InvalidEmailOrPassword,
    InvalidToken,
    UserAlreadyExists,
    UserDoesNotExist,
    UserIsNotActive,
)
from .models import User, UserRecoveryToken


def validate_user_does_not_exist(
    email: str,
) -> None:
    """Validate user does not exist."""
    if User.objects.filter(email=email).exists():
        raise UserAlreadyExists


def validate_user_is_active(
    email: str,
) -> None:
    """Validate user is active."""
    user = User.objects.filter(email=email).first()
    if not user:
        return
    if not user.is_active:
        raise UserIsNotActive


def validate_email_is_verified(
    email: str,
) -> None:
    """Validate email is verified."""
    user = User.objects.filter(email=email).first()
    if not user:
        return
    if not user.email_verified:
        raise EmailNotVerified


def validate_user_exists(
    email: str,
) -> None:
    """Validate user exists."""
    if not User.objects.filter(email=email).exists():
        raise UserDoesNotExist


def validate_mail_login(
    email: str,
) -> None:
    """Validate user exists."""
    try:
        validate_user_exists(email)
        validate_user_is_active(email)
        validate_email_is_verified(email)
    except EmailNotVerified:
        raise
    except UserIsNotActive:
        raise InvalidEmailOrPassword from None
    except UserDoesNotExist:
        raise InvalidEmailOrPassword from None


def validate_recovery_token_exists(
    token: str,
) -> None:
    """Validate recovery token exists."""
    if not UserRecoveryToken.objects.filter(token=token).exists():
        raise InvalidToken
