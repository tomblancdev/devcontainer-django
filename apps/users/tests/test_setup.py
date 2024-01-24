"""Setup tests for the users app."""

from __future__ import annotations

import uuid
from typing import Self

from django.test import TestCase

from users.models import (
    AuthToken,
    User,
    UserEmailValidationToken,
    UserRecoveryToken,
    UserResetPasswordToken,
)


class FakeUserInfos:
    """Generate fake user informations."""

    def __init__(self):
        """Init."""
        self.email = f"{uuid.uuid4()}@test.com"
        self.username = f"{uuid.uuid4()}"
        self.first_name = f"{uuid.uuid4()}"
        self.last_name = f"{uuid.uuid4()}"
        self.password = f"{uuid.uuid4()}"

    def get_different_email(self):
        """Get a different email."""
        different_email = f"{uuid.uuid4()}@test.com"
        while different_email == self.email:
            different_email = f"{uuid.uuid4()}@test.com"
        return different_email

    def get_different_password(self):
        """Get a different password."""
        different_password = f"{uuid.uuid4()}"
        while different_password == self.password:
            different_password = f"{uuid.uuid4()}"
        return different_password

    def copy(self):
        """Return a copy of the object."""
        copy = FakeUserInfos()
        copy.email = self.email
        copy.username = self.username
        copy.first_name = self.first_name
        copy.last_name = self.last_name
        copy.password = self.password
        return copy


class UsingUser(object):
    def __init__(
        self: Self,
        user_infos: FakeUserInfos = FakeUserInfos(),
        is_staff: bool = False,
        is_admin: bool = False,
        is_superuser: bool = False,
        with_email_validation_token: bool = False,
        with_reset_password_token: bool = False,
        with_auth_token: bool = False,
        with_recovery_token: bool = False,
    ) -> None:
        """Init."""
        self.user_infos = user_infos
        self.is_staff = is_staff
        self.is_admin = is_admin
        self.is_superuser = is_superuser
        self.with_email_validation_token = with_email_validation_token
        self.with_reset_password_token = with_reset_password_token
        self.with_auth_token = with_auth_token
        self.with_recovery_token = with_recovery_token

    def __enter__(self: Self) -> User:
        """Enter."""
        self.user = self.generate_user(
            user_infos=self.user_infos,
            is_staff=self.is_staff,
            is_admin=self.is_admin,
            is_superuser=self.is_superuser,
        )
        if self.with_email_validation_token:
            self.email_token = UserEmailValidationToken.objects.create_token_for_user(
                self.user
            )
        if self.with_reset_password_token and self.user.email:
            self.reset_password_token = (
                UserResetPasswordToken.objects.create_token_for_email(self.user.email)
            )
        if self.with_auth_token:
            self.auth_token = AuthToken.objects.create(user=self.user)
        if self.with_recovery_token:
            self.recovery_token = UserRecoveryToken.objects.create_token_for_user(
                self.user
            )

        return self.user

    def __exit__(self: Self, exc_type, exc_value, traceback) -> None:
        """Exit."""
        self.user.delete()

    def generate_user(
        self,
        user_infos: FakeUserInfos = FakeUserInfos(),
        is_staff: bool = False,
        is_admin: bool = False,
        is_superuser: bool = False,
    ) -> User:
        """Create a user."""
        user = User.objects.create_user(
            email=user_infos.email,
            username=user_infos.username,
            first_name=user_infos.first_name,
            last_name=user_infos.last_name,
            password=user_infos.password,
        )
        user.is_staff = is_staff
        user.is_superuser = is_superuser
        user.is_admin = is_admin

        return user


class UserSetupTestCase(TestCase):
    """Test setup for user tests."""
