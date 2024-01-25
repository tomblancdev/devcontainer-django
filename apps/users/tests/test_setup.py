"""Setup tests for the users app."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Self

from django.test import TestCase

from users.models import (
    AuthToken,
    User,
    UserEmailValidationToken,
    UserRecoveryToken,
    UserResetPasswordToken,
)

if TYPE_CHECKING:
    from types import TracebackType


class FakeUserInfos:

    """Generate fake user informations."""

    def __init__(self: Self) -> None:
        """Init."""
        self.email = f"{uuid.uuid4()}@test.com"
        self.username = f"{uuid.uuid4()}"
        self.first_name = f"{uuid.uuid4()}"
        self.last_name = f"{uuid.uuid4()}"
        self.password = f"{uuid.uuid4()}"

    def get_different_email(self: Self) -> str:
        """Get a different email."""
        different_email = f"{uuid.uuid4()}@test.com"
        while different_email == self.email:
            different_email = f"{uuid.uuid4()}@test.com"
        return different_email

    def get_different_password(self: Self) -> str:
        """Get a different password."""
        different_password = f"{uuid.uuid4()}"
        while different_password == self.password:
            different_password = f"{uuid.uuid4()}"
        return different_password

    def copy(self: Self) -> FakeUserInfos:
        """Return a copy of the object."""
        copy = FakeUserInfos()
        copy.email = self.email
        copy.username = self.username
        copy.first_name = self.first_name
        copy.last_name = self.last_name
        copy.password = self.password
        return copy


class UsingUser:

    """Create a user for tests."""

    def __init__(  # noqa: PLR0913
        self: Self,
        user_infos: FakeUserInfos | None = None,
        *,
        is_staff: bool = False,
        is_admin: bool = False,
        is_superuser: bool = False,
        email_validated: bool = False,
        with_email_validation_token: bool = False,
        with_reset_password_token: bool = False,
        with_auth_token: bool = False,
        with_recovery_token: bool = False,
    ) -> None:
        """Init."""
        self.user_infos = user_infos or FakeUserInfos()
        self.is_staff = is_staff
        self.is_admin = is_admin
        self.is_superuser = is_superuser
        self.email_validated = email_validated
        self.with_email_validation_token = (
            with_email_validation_token or self.email_validated
        )
        self.with_reset_password_token = with_reset_password_token
        self.with_auth_token = with_auth_token
        self.with_recovery_token = with_recovery_token

    def __enter__(self: Self) -> User:
        """Enter."""
        self.setUp()

        return self.user

    def __exit__(
        self: Self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit."""
        self.user.delete()

    def generate_user(
        self: Self,
    ) -> User:
        """Create a user."""
        user = User.objects.create_user(
            email=self.user_infos.email,
            username=self.user_infos.username,
            first_name=self.user_infos.first_name,
            last_name=self.user_infos.last_name,
            password=self.user_infos.password,
        )
        user.is_staff = self.is_staff
        user.is_superuser = self.is_superuser
        user.is_admin = self.is_admin

        return user

    def setUp(self: Self) -> User:
        """Set up."""
        self.user = self.generate_user()
        if self.with_email_validation_token:
            self.email_token = UserEmailValidationToken.objects.create_token_for_user(
                self.user,
            )
            if self.email_validated:
                self.email_token.validate()
        if self.with_reset_password_token and self.user.email:
            self.reset_password_token = (
                UserResetPasswordToken.objects.create_token_for_email(self.user.email)
            )
        if self.with_auth_token:
            self.auth_token = AuthToken.objects.create(user=self.user)
        if self.with_recovery_token:
            self.recovery_token = UserRecoveryToken.objects.create_token_for_user(
                self.user,
            )

        return self.user


class UserSetupTestCase(TestCase):

    """Test setup for user tests."""
