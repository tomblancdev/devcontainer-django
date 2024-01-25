# ruff : noqa: PT009
"""Test settings for users app."""

from __future__ import annotations

from typing import Self

from django.test import TestCase

from apps.users.tests.test_setup import UsingUser
from users.settings import (
    AUTH_TOKEN_EXPIRATION_TIME,
    EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME,
    RESET_PASSWORD_TOKEN_EXPIRATION_TIME,
)


class TestSettings(TestCase):

    """Test settings for users app."""

    def test_auth_token_expiration_time(self: Self) -> None:
        """Test AUTH_TOKEN_EXPIRATION_TIME."""
        with UsingUser(with_auth_token=True) as user:
            auth_token = user.auth_token_set.first()
            if not auth_token:
                self.fail("Auth token not found.")

            time_delta = (
                auth_token.expires_at.timestamp() - auth_token.created_at.timestamp()
            )

            self.assertAlmostEqual(
                time_delta,
                AUTH_TOKEN_EXPIRATION_TIME,
                delta=100,
            )

    def test_email_token_validation_expiration_time(self: Self) -> None:
        """Test EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME."""
        with UsingUser(with_email_validation_token=True) as user:
            email_token_validation = user.token_email_validation

            time_delta = (
                email_token_validation.expires_at.timestamp()
                - email_token_validation.created_at.timestamp()
            )

            self.assertAlmostEqual(
                time_delta,
                EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME,
                delta=100,
            )

    def test_reset_password_token_expiration_time(self: Self) -> None:
        """Test RESET_PASSWORD_TOKEN_EXPIRATION_TIME."""
        with UsingUser(with_reset_password_token=True) as user:
            reset_password_token = user.reset_password_token_set.first()
            if not reset_password_token:
                self.fail("Reset password token not found.")

            time_delta = (
                reset_password_token.expires_at.timestamp()
                - reset_password_token.created_at.timestamp()
            )

            self.assertAlmostEqual(
                time_delta,
                RESET_PASSWORD_TOKEN_EXPIRATION_TIME,
                delta=100,
            )
