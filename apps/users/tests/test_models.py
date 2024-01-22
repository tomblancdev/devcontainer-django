from django.utils import timezone

from users.models import TokenError, User, UserTokenEmailValidation
from users.tests.test_setup import FakeUserInfos, TestUserSetup


class TestUserCreation(TestUserSetup):
    def test_create_new_user(self):
        """Test creating a new user."""
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
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.is_admin)
        self.assertTrue(user.is_active)
        self.assertFalse(user.email_verified)
        # create a email validate token
        token = UserTokenEmailValidation.objects.create_token(user)
        self.assertEqual(token.user, user)
        self.assertEqual(user.token_email_validation, token)
        self.assertFalse(token.is_validated)
        self.assertIsNone(token.validated_at)
        self.assertFalse(user.email_verified)
        # validate the token
        token.validated_at = timezone.now()
        token.save()
        self.assertTrue(token.is_validated)
        self.assertIsNotNone(token.validated_at)
        self.assertTrue(user.email_verified)

    def test_create_new_superuser(self):
        """Test creating a new superuser."""
        user = self.verified_user
        user.is_superuser = True
        user.is_staff = True
        user.is_admin = True
        user.save()
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_admin)
        self.assertTrue(user.is_active)
        self.assertTrue(user.email_verified)

    def test_creating_user_without_element(self):
        """Test creating a user without an element."""
        user_infos = FakeUserInfos()
        for key, value in user_infos.__dict__.items():
            new_infos = FakeUserInfos()
            # delete the key
            delattr(new_infos, key)
            with self.assertRaises(ValueError):
                User.objects.create_user(
                    **new_infos.__dict__,
                )

    def test_creating_existing_user(self):
        """Test creating an existing user."""
        user_infos = FakeUserInfos()
        with self.assertRaises(ValueError):
            User.objects.create_user(
                email=self.verified_user.email,
                username=user_infos.username,
                first_name=user_infos.first_name,
                last_name=user_infos.last_name,
                password=user_infos.password,
            )


class TestUserEmailValidation(TestUserSetup):
    def test_email_validation(self):
        """Test email validation."""
        user = self.verified_user
        self.assertTrue(user.email_verified)
        token = self.verified_user_token
        self.assertTrue(token.is_validated)
        self.assertIsNotNone(token.validated_at)
        self.assertEqual(token.user, user)
        self.assertEqual(user.token_email_validation, token)

    def test_reuse_email_validation(self):
        """Test reuse email validation."""
        token = self.verified_user_token
        with self.assertRaises(TokenError):
            UserTokenEmailValidation.objects.validate_token(token.token)

    def test_recreate_email_validation(self):
        """Test recreate email validation."""
        token = self.verified_user_token
        with self.assertRaises(TokenError):
            UserTokenEmailValidation.objects.create_token(token.user)
