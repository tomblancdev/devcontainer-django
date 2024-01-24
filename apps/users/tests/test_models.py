from __future__ import annotations

from typing import Self

from django.core import mail
from django.utils import timezone

from users.models import TokenError
from users.tests.test_setup import UserSetupTestCase, UsingUser


class TestUserModel(UserSetupTestCase):
    """Test user model methods and properties."""

    def test_user_str(self: Self) -> None:
        """Test user string representation."""
        with UsingUser() as user:
            self.assertEqual(str(user), f"#{user.pk}_{user.username}")

    def test_email_verified(self: Self) -> None:
        """Test email_verified property."""
        with UsingUser(with_email_validation_token=True) as user:
            self.assertFalse(user.email_verified)
            user.token_email_validation.validate()
            user.refresh_from_db()
            self.assertTrue(user.email_verified)
        with UsingUser(with_email_validation_token=False) as user:
            self.assertFalse(user.email_verified)
        with UsingUser(is_superuser=True, with_email_validation_token=False) as user:
            self.assertTrue(user.email_verified)

    def test_short_name(self: Self) -> None:
        """Test short_name property."""
        with UsingUser() as user:
            self.assertEqual(user.get_short_name(), user.username)

    def test_full_name(self: Self) -> None:
        """Test full_name property."""
        with UsingUser() as user:
            self.assertEqual(
                user.get_full_name(), f"{user.first_name} {user.last_name}"
            )

    def test_anonymize(self: Self) -> None:
        """Test anonymize method."""
        with UsingUser() as user:
            user.anonymize()
            self.assertEqual(user.username, None)
            self.assertEqual(user.first_name, None)
            self.assertEqual(user.last_name, None)
            self.assertEqual(user.email, None)
            self.assertEqual(user.email_verified, False)
            self.assertFalse(hasattr(user, "token_email_validation"))
            self.assertTrue(hasattr(user, "recovery_token"))
            self.assertEqual(user.auth_token_set.count(), 0)
            self.assertEqual(user.reset_password_token_set.count(), 0)

    def test_email_user(self: Self) -> None:
        """Test email_user method."""
        with UsingUser() as user:
            user.email_user(
                subject="subject",
                message="message",
                from_email="from_email",
            )
            self.assertEqual(len(mail.outbox), 1)
            self.assertEqual(mail.outbox[0].subject, "subject")
            self.assertEqual(mail.outbox[0].body, "message")
            self.assertEqual(mail.outbox[0].from_email, "from_email")
            self.assertEqual(mail.outbox[0].to, [user.email])

    def test_delete_email_validation_token(self: Self) -> None:
        """Test delete_email_validation_token method."""
        with UsingUser(with_email_validation_token=True) as user:
            user.delete_email_validation_token()
            user.refresh_from_db()
            self.assertEqual(user.email_verified, False)
            self.assertFalse(hasattr(user, "token_email_validation"))

    def test_delete_reset_password_tokens(self: Self) -> None:
        """Test delete_reset_password_token method."""
        with UsingUser(with_reset_password_token=True) as user:
            user.delete_reset_password_tokens()
            user.refresh_from_db()
            self.assertEqual(user.reset_password_token_set.count(), 0)

    def test_delete_auth_tokens(self: Self) -> None:
        """Test delete_auth_token method."""
        with UsingUser(with_auth_token=True) as user:
            user.delete_auth_tokens()
            user.refresh_from_db()
            self.assertEqual(user.auth_token_set.count(), 0)


class TestUserEmailValidationToken(UserSetupTestCase):
    """Test user email validation token model methods and properties."""

    def test_email_validation_token_str(self: Self) -> None:
        """Test email_validation_token string representation."""
        with UsingUser(with_email_validation_token=True) as user:
            self.assertEqual(
                str(user.token_email_validation),
                f"#{user.pk}_{user.username}_email_validation_token",
            )

    def test_email_validation_token_is_expired(self: Self) -> None:
        """Test email_validation_token is_expired property."""
        with UsingUser(with_email_validation_token=True) as user:
            self.assertFalse(user.token_email_validation.is_expired)
            user.token_email_validation.expires_at = timezone.now()
            user.token_email_validation.save()
            self.assertTrue(user.token_email_validation.is_expired)

    def test_email_validation_token_is_validated(self: Self) -> None:
        """Test email_validation_token is_validated property."""
        with UsingUser(with_email_validation_token=True) as user:
            self.assertFalse(user.token_email_validation.is_validated)
            user.token_email_validation.validate()
            user.token_email_validation.refresh_from_db()
            self.assertTrue(user.token_email_validation.is_validated)

    def test_regenerate_token(self: Self) -> None:
        """Test regenerate_token method."""
        with UsingUser(with_email_validation_token=True) as user:
            old_token = user.token_email_validation.token
            old_expires_at = user.token_email_validation.expires_at
            user.token_email_validation.regenerate_token()
            self.assertIsNotNone(user.token_email_validation.token)
            self.assertIsNotNone(user.token_email_validation.expires_at)
            self.assertIsNone(user.token_email_validation.validated_at)
            self.assertNotEqual(user.token_email_validation.token, old_token)
            self.assertNotEqual(user.token_email_validation.expires_at, old_expires_at)

    def test_validate(self: Self) -> None:
        """Test validate method."""
        with UsingUser(with_email_validation_token=True) as user:
            user.token_email_validation.validated_at = None
            user.token_email_validation.save()
            user.token_email_validation.refresh_from_db()
            self.assertIsNone(user.token_email_validation.validated_at)
            user.token_email_validation.validate()
            user.token_email_validation.refresh_from_db()
            self.assertTrue(user.email_verified)
            self.assertIsNotNone(user.token_email_validation.validated_at)
        # test with already validated token
        with UsingUser(with_email_validation_token=True) as user:
            user.token_email_validation.validate()
            user.token_email_validation.refresh_from_db()
            self.assertIsNotNone(user.token_email_validation.validated_at)

    def test_validate_validated_token(self: Self) -> None:
        """Test validate method with validated token."""
        with UsingUser(with_email_validation_token=True) as user:
            user.token_email_validation.validate()
            user.token_email_validation.refresh_from_db()
            self.assertIsNotNone(user.token_email_validation.validated_at)
            with self.assertRaises(TokenError):
                user.token_email_validation.validate()

    def test_validate_expired_token(self: Self) -> None:
        """Test validate method with expired token."""
        with UsingUser(with_email_validation_token=True) as user:
            user.token_email_validation.expires_at = timezone.now()
            user.token_email_validation.save()
            user.token_email_validation.refresh_from_db()
            self.assertTrue(user.token_email_validation.is_expired)
            with self.assertRaises(TokenError):
                user.token_email_validation.validate()


class TestUserResetPasswordToken(UserSetupTestCase):
    """Test user reset password token model methods and properties."""

    def test_reset_password_token_str(self: Self) -> None:
        """Test reset_password_token string representation."""
        with UsingUser(with_reset_password_token=True) as user:
            self.assertEqual(
                str(user.reset_password_token_set.first()),
                f"#{user.pk}_{user.username}_reset_password_token",
            )

    def test_reset_password_token_is_expired(self: Self) -> None:
        """Test reset_password_token is_expired property."""
        with UsingUser(with_reset_password_token=True) as user:
            first_reset_password_token = user.reset_password_token_set.first()
            if first_reset_password_token is None:
                raise ValueError("No reset password token found")
            self.assertFalse(first_reset_password_token.is_expired)
            first_reset_password_token.expires_at = timezone.now()
            first_reset_password_token.save()
            self.assertTrue(first_reset_password_token.is_expired)

    def test_reset_passord_token_is_used(self: Self) -> None:
        """Test reset_password_token is_used property."""
        with UsingUser(with_reset_password_token=True) as user:
            first_reset_password_token = user.reset_password_token_set.first()
            if first_reset_password_token is None:
                raise ValueError("No reset password token found")
            self.assertFalse(first_reset_password_token.is_used)
            first_reset_password_token.used_at = timezone.now()
            first_reset_password_token.save()
            self.assertTrue(first_reset_password_token.is_used)

    def test_use_token(self: Self) -> None:
        """Test use_token method."""
        with UsingUser(with_reset_password_token=True) as user:
            first_reset_password_token = user.reset_password_token_set.first()
            if first_reset_password_token is None:
                raise ValueError("No reset password token found")
            self.assertFalse(first_reset_password_token.is_used)
            first_reset_password_token.use_token()
            first_reset_password_token.refresh_from_db()
            self.assertTrue(first_reset_password_token.is_used)

    def test_use_token_already_used(self: Self) -> None:
        """Test use_token method with already used token."""
        with UsingUser(with_reset_password_token=True) as user:
            first_reset_password_token = user.reset_password_token_set.first()
            if first_reset_password_token is None:
                raise ValueError("No reset password token found")
            first_reset_password_token.use_token()
            first_reset_password_token.refresh_from_db()
            self.assertTrue(first_reset_password_token.is_used)
            with self.assertRaises(TokenError):
                first_reset_password_token.use_token()

    def test_use_token_expired(self: Self) -> None:
        """Test use_token method with expired token."""
        with UsingUser(with_reset_password_token=True) as user:
            first_reset_password_token = user.reset_password_token_set.first()
            if first_reset_password_token is None:
                raise ValueError("No reset password token found")
            first_reset_password_token.expires_at = timezone.now()
            first_reset_password_token.save()
            first_reset_password_token.refresh_from_db()
            self.assertTrue(first_reset_password_token.is_expired)
            with self.assertRaises(TokenError):
                first_reset_password_token.use_token()


class TestUserRecoveryToken(UserSetupTestCase):
    """Test user recovery token model methods and properties."""

    def test_recovery_token_str(self: Self) -> None:
        """Test recovery_token string representation."""
        with UsingUser(with_recovery_token=True) as user:
            self.assertEqual(
                str(user.recovery_token),
                f"#{user.pk}_{user.recovery_token.token}_recovery_token",
            )
        with UsingUser() as user:
            user.anonymize()
            self.assertEqual(
                str(user.recovery_token),
                f"#{user.pk}_{user.recovery_token.token}_recovery_token",
            )


class TestAuthToken(UserSetupTestCase):
    """Test auth token model methods and properties."""

    def test_auth_token_str(self: Self) -> None:
        """Test auth_token string representation."""
        with UsingUser(with_auth_token=True) as user:
            self.assertEqual(
                str(user.auth_token_set.first()),
                f"#{user.pk}_{user.username}_auth_token",
            )

    def test_auth_token_is_expired(self: Self) -> None:
        """Test auth_token is_expired property."""
        with UsingUser(with_auth_token=True) as user:
            first_auth_token = user.auth_token_set.first()
            if first_auth_token is None:
                raise ValueError("No auth token found")
            self.assertFalse(first_auth_token.is_expired)
            first_auth_token.expires_at = timezone.now()
            first_auth_token.save()
            self.assertTrue(first_auth_token.is_expired)
