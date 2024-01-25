"""Test Managers for users app."""

from __future__ import annotations

from django.utils import timezone

from users.models import (
    TokenError,
    User,
    UserEmailValidationToken,
    UserResetPasswordToken,
)
from users.tests.test_setup import FakeUserInfos, UserSetupTestCase, UsingUser


class TestUserManager(UserSetupTestCase):
    """Test UserManager."""

    def test_create_user(self) -> None:
        """Test create_user method."""
        user_infos = FakeUserInfos()

        user = User.objects.create_user(
            email=user_infos.email,
            username=user_infos.username,
            first_name=user_infos.first_name,
            last_name=user_infos.last_name,
            password=user_infos.password,
        )

        self.assertEqual(user.email, user_infos.email)
        self.assertEqual(user.username, user_infos.username)
        self.assertEqual(user.first_name, user_infos.first_name)
        self.assertEqual(user.last_name, user_infos.last_name)
        self.assertTrue(user.check_password(user_infos.password))
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_admin)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.email_verified)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_anonymous)

    def test_create_user_with_missing_data(self) -> None:
        """Test create_user method with missing data."""
        user_infos = FakeUserInfos()

        for key in user_infos.__dict__.keys():
            user_info_copy = user_infos.copy()
            delattr(user_info_copy, key)
            with self.assertRaises(ValueError):
                User.objects.create_user(**user_info_copy.__dict__)

    def test_create_user_with_empty_strings_values(self) -> None:
        """Test create_user method with empty strings values."""
        user_infos = FakeUserInfos()

        for key in user_infos.__dict__.keys():
            user_info_copy = user_infos.copy()
            if isinstance(getattr(user_info_copy, key), str):
                setattr(user_info_copy, key, "")
                with self.assertRaises(ValueError):
                    User.objects.create_user(**user_info_copy.__dict__)

    def test_create_user_with_existing_email(self) -> None:
        """Test create_user method with existing email."""
        with UsingUser() as user:
            user_infos = FakeUserInfos()
            if not user.email:
                raise ValueError("user email must be set")
            user_infos.email = user.email
            with self.assertRaises(ValueError):
                User.objects.create_user(**user_infos.__dict__)

    def test_create_user_with_existing_non_unique_values(self) -> None:
        """Test create_user method with existing non unique values."""
        with UsingUser() as user:
            user_infos = FakeUserInfos()
            if not user.username:
                raise ValueError("user username must be set")
            user_infos.username = user.username
            if not user.first_name:
                raise ValueError("user first_name must be set")
            user_infos.first_name = user.first_name
            if not user.last_name:
                raise ValueError("user last_name must be set")
            user_infos.last_name = user.last_name
            new_user = User.objects.create_user(**user_infos.__dict__)
            self.assertEqual(new_user.email, user_infos.email)
            self.assertEqual(new_user.username, user.username)
            self.assertEqual(new_user.first_name, user.first_name)
            self.assertEqual(new_user.last_name, user.last_name)

    def test_create_superuser(self) -> None:
        """Test create_superuser method."""
        user_infos = FakeUserInfos()

        user = User.objects.create_superuser(
            email=user_infos.email,
            username=user_infos.username,
            first_name=user_infos.first_name,
            last_name=user_infos.last_name,
            password=user_infos.password,
        )

        self.assertEqual(user.email, user_infos.email)
        self.assertEqual(user.username, user_infos.username)
        self.assertEqual(user.first_name, user_infos.first_name)
        self.assertEqual(user.last_name, user_infos.last_name)
        self.assertTrue(user.check_password(user_infos.password))
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_admin)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.email_verified)
        self.assertTrue(user.is_active)

    def test_anonymize_users(self) -> None:
        """Test anonymize_users method."""
        with UsingUser() as user:
            User.objects.get(pk=user.pk).anonymize()
            user.refresh_from_db()
            self.assertIsNone(user.username)
            self.assertIsNone(user.first_name)
            self.assertIsNone(user.last_name)
            self.assertIsNone(user.email)
            self.assertFalse(user.email_verified)
            self.assertFalse(hasattr(user, "token_email_validation"))
            self.assertTrue(hasattr(user, "recovery_token"))
            self.assertEqual(user.auth_token_set.count(), 0)
            self.assertEqual(user.reset_password_token_set.count(), 0)


class TestUserEmailValidationTokenManager(UserSetupTestCase):
    """Test UserEmailValidationTokenManager."""

    def test_create_token(self) -> None:
        """Test create_token method."""
        with UsingUser() as user:
            token = UserEmailValidationToken.objects.create_token_for_user(user)
            self.assertEqual(token.user, user)
            self.assertIsNotNone(token.token)
            self.assertIsNotNone(token.created_at)
            self.assertIsNone(token.validated_at)
            self.assertFalse(token.is_expired)
            self.assertFalse(token.is_validated)

    def test_create_token_with_existing_token(self) -> None:
        """Test create_token method with existing token."""
        with UsingUser(with_email_validation_token=True) as user:
            user.token_email_validation.validate()
            with self.assertRaises(TokenError):
                UserEmailValidationToken.objects.create_token_for_user(user)

    def test_validate_token(self) -> None:
        """Test validate_token method."""
        with UsingUser(with_email_validation_token=True) as user:
            token = user.token_email_validation.token
            UserEmailValidationToken.objects.validate_token(token)
            user.refresh_from_db()
            self.assertTrue(user.token_email_validation.is_validated)

    def test_validate_token_with_invalid_token(self) -> None:
        """Test validate_token method with invalid token."""
        with self.assertRaises(TokenError):
            UserEmailValidationToken.objects.validate_token("invalid_token")

    def test_validate_token_with_expired_token(self) -> None:
        """Test validate_token method with expired token."""
        with UsingUser(with_email_validation_token=True) as user:
            user.token_email_validation.expires_at = timezone.now()
            user.token_email_validation.save()
            with self.assertRaises(TokenError):
                UserEmailValidationToken.objects.validate_token(
                    user.token_email_validation.token
                )

    def test_validate_token_with_already_validated_token(self) -> None:
        """Test validate_token method with already validated token."""
        with UsingUser(with_email_validation_token=True) as user:
            user.token_email_validation.validate()
            with self.assertRaises(TokenError):
                UserEmailValidationToken.objects.validate_token(
                    user.token_email_validation.token
                )

    def test_regenerate_token(self) -> None:
        """Test regenerate_token method."""
        with UsingUser(with_email_validation_token=True) as user:
            old_token = user.token_email_validation.token
            old_expires_at = user.token_email_validation.expires_at
            UserEmailValidationToken.objects.regenerate_token_for_user(user)
            user.refresh_from_db()
            self.assertIsNotNone(user.token_email_validation.token)
            self.assertIsNotNone(user.token_email_validation.expires_at)
            self.assertIsNone(user.token_email_validation.validated_at)
            self.assertNotEqual(user.token_email_validation.token, old_token)
            self.assertNotEqual(user.token_email_validation.expires_at, old_expires_at)

    def test_regenerate_unexisting_token(self) -> None:
        """Test regenerate_token method with unexisting token."""
        with UsingUser() as user:
            with self.assertRaises(TokenError):
                UserEmailValidationToken.objects.regenerate_token_for_user(user)


class TestUserResetPasswordTokenManager(UserSetupTestCase):
    """Test UserResetPasswordTokenManager."""

    def test_create_token_for_email(self) -> None:
        """Test create_token method."""
        with UsingUser() as user:
            if not user.email:
                raise ValueError("user email must be set")
            token = UserResetPasswordToken.objects.create_token_for_email(user.email)
            self.assertEqual(token.user, user)
            self.assertIsNotNone(token.token)
            self.assertIsNotNone(token.created_at)
            self.assertIsNone(token.used_at)
            self.assertFalse(token.is_expired)
            self.assertFalse(token.is_used)

    def test_create_token_for_unexisting_user(self) -> None:
        """Test create_token method for unexisting user."""
        with self.assertRaises(User.DoesNotExist):
            UserResetPasswordToken.objects.create_token_for_email("not_user@test.com")

    def test_use_token(self) -> None:
        """Test use_token method."""
        with UsingUser(with_reset_password_token=True) as user:
            token = user.reset_password_token_set.first()
            if not token:
                raise ValueError("token must be set")
            UserResetPasswordToken.objects.use_token(token.token)
            token.refresh_from_db()
            self.assertTrue(token.is_used)

    def test_use_token_with_invalid_token(self) -> None:
        """Test use_token method with invalid token."""
        with self.assertRaises(TokenError):
            UserResetPasswordToken.objects.use_token("invalid_token")

    def test_use_token_with_expired_token(self) -> None:
        """Test use_token method with expired token."""
        with UsingUser(with_reset_password_token=True) as user:
            token = user.reset_password_token_set.first()
            if not token:
                raise ValueError("token must be set")
            token.expires_at = timezone.now()
            token.save()
            with self.assertRaises(TokenError):
                UserResetPasswordToken.objects.use_token(token.token)

    def test_use_token_with_already_used_token(self) -> None:
        """Test use_token method with already used token."""
        with UsingUser(with_reset_password_token=True) as user:
            token = user.reset_password_token_set.first()
            if not token:
                raise ValueError("token must be set")
            token.used_at = timezone.now()
            token.save()
            with self.assertRaises(TokenError):
                UserResetPasswordToken.objects.use_token(token.token)
