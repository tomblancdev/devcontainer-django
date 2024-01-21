"""Tests for user app."""

from django.test import TestCase

from users.models import User, UserTokenEmailValidation


class UserTestCase(TestCase):
    """Tests for user model."""

    def setUp(self):
        """Set up test case."""
        self.user = User.objects.create_user(
            username="test",
            password="test",
            email="test@example.com",
            first_name="Test",
            last_name="TEST",
        )
        self.user_2 = User.objects.create

    def test_user_creation(self):
        """Test user creation."""
        self.assertEqual(self.user.username, "test")
        self.assertEqual(self.user.email, "test@example.com")
        self.assertEqual(self.user.first_name, "Test")
        self.assertEqual(self.user.last_name, "TEST")
        self.assertTrue(self.user.is_active)
        self.assertFalse(self.user.is_staff)
        self.assertFalse(self.user.is_superuser)
        self.assertEqual(self.user.get_full_name(), "Test TEST")

    def test_user_token_email_validation_creation(self):
        """Test user token email validation creation."""
        token = UserTokenEmailValidation.objects.create(user=self.user)
        self.assertEqual(token.user, self.user)
        self.assertEqual(token.token, self.user.token_email_validation.token)
        self.assertFalse(token.is_validated)
