"""Setup tests for the users app."""

from __future__ import annotations

import uuid

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from users.models import AuthToken, User, UserTokenEmailValidation


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


class TestUserSetup(TestCase):
    """Setup tests for the users app."""

    def setUp(self):
        """Setup for the tests."""
        self.client = APIClient()
        self.user_infos = FakeUserInfos()
        self.verified_user, self.verified_user_token = self.generate_user(
            self.user_infos,
            email_verified=True,
        )
        # create authToken for the verified user
        self.verified_user_auth_token = AuthToken.objects.create(
            user=self.verified_user
        )
        # authentificate the client
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Token {self.verified_user_auth_token.key}"
        )

    def generate_user(
        self,
        user_infos: FakeUserInfos,
        is_staff: bool = False,
        is_admin: bool = False,
        is_superuser: bool = False,
        email_verified: bool = False,
    ) -> tuple[User, UserTokenEmailValidation]:
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
        user_token_email_validation = UserTokenEmailValidation.objects.create_token(
            user
        )
        if email_verified:
            # create mail validation token
            user_token_email_validation.validated_at = timezone.now()
            user_token_email_validation.save()
        return user, user_token_email_validation
