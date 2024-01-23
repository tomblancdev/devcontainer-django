"""Test api for users app."""

from django.urls import reverse

from users.models import User

from .test_setup import FakeUserInfos, TestUserSetup


class TestLoginUserWithApi(TestUserSetup):
    """Testing User Login with API."""

    def test_login_user(self):
        """Test connecting a user."""
        response = self.client.post(
            reverse("login"),
            {
                "email": self.verified_user.email,
                "password": self.user_infos.password,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("key", response.data)
        self.assertEqual(response.data["user"]["email"], self.verified_user.email)
        self.assertEqual(response.data["user"]["username"], self.verified_user.username)
        self.assertEqual(
            response.data["user"]["first_name"], self.verified_user.first_name
        )
        self.assertEqual(
            response.data["user"]["last_name"], self.verified_user.last_name
        )
        self.assertEqual(
            response.data["user"]["email_verified"], self.verified_user.email_verified
        )
        self.assertEqual(
            response.data["user"]["is_active"], self.verified_user.is_active
        )

    def test_login_user_with_wrong_password(self):
        """Test connecting a user with a wrong password."""
        response = self.client.post(
            reverse("login"),
            {
                "email": self.verified_user.email,
                "password": "wrong_password",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("non_field_errors", response.data)
        self.assertEqual(
            response.data["non_field_errors"],
            ["Invalid credentials."],
        )

    def test_login_user_with_wrong_email(self):
        """Test connecting a user with a wrong email."""
        response = self.client.post(
            reverse("login"),
            {
                "email": "not_user@example.com",
                "password": self.verified_user.password,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("non_field_errors", response.data)
        self.assertEqual(
            response.data["non_field_errors"],
            ["Invalid credentials."],
        )

    def test_login_user_with_no_email(self):
        """Test connecting a user with no email."""
        response = self.client.post(
            reverse("login"),
            {
                "password": self.verified_user.password,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("email", response.data)
        self.assertEqual(response.data["email"], ["This field is required."])

    def test_login_user_with_no_password(self):
        """Test connecting a user with no password."""
        response = self.client.post(
            reverse("login"),
            {
                "email": self.verified_user.email,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("password", response.data)
        self.assertEqual(response.data["password"], ["This field is required."])

    def test_login_user_with_no_data(self):
        """Test connecting a user with no data."""
        response = self.client.post(
            reverse("login"),
            {},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("email", response.data)
        self.assertEqual(response.data["email"], ["This field is required."])
        self.assertIn("password", response.data)
        self.assertEqual(response.data["password"], ["This field is required."])


class TestRegisterUserWithApi(TestUserSetup):
    """Testing User Register with API."""

    def test_register_user(self):
        """Test registering a user."""
        user_infos = FakeUserInfos()
        response = self.client.post(
            reverse("register"),
            {
                "email": user_infos.email,
                "username": user_infos.username,
                "first_name": user_infos.first_name,
                "last_name": user_infos.last_name,
                "password": user_infos.password,
                "password_validation": user_infos.password,
                "next": "https://example.com",
            },
        )
        self.assertEqual(response.status_code, 201)
        #  get the mail cnfirmation token for this user and validate it
        user = User.objects.get(email=user_infos.email)
        token = user.token_email_validation
        # check that user has no email_verified
        self.assertFalse(user.email_verified)
        # validate token with the API
        response = self.client.post(
            reverse("email_activation"),
            {
                "token": token.token,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("success", response.data)
        self.assertEqual(response.data["success"], "Account activated successfully.")
        # check that the user is now active
        user.refresh_from_db()
        self.assertTrue(user.email_verified)

    def test_register_user_with_wrong_password_validation(self):
        """Test registering a user with a wrong password validation."""
        user_infos = FakeUserInfos()
        response = self.client.post(
            reverse("register"),
            {
                "email": user_infos.email,
                "username": user_infos.username,
                "first_name": user_infos.first_name,
                "last_name": user_infos.last_name,
                "password": user_infos.password,
                "password_validation": "wrong_password",
                "next": "https://example.com",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("non_field_errors", response.data)
        self.assertEqual(
            response.data["non_field_errors"],
            ["Passwords must match."],
        )

    def test_register_existing_user(self):
        """Test registering an existing user."""
        response = self.client.post(
            reverse("register"),
            {
                "email": self.verified_user.email,
                "username": self.user_infos.username,
                "first_name": self.user_infos.first_name,
                "last_name": self.user_infos.last_name,
                "password": self.user_infos.password,
                "password_validation": self.user_infos.password,
                "next": "https://example.com",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("non_field_errors", response.data)
        self.assertEqual(response.data["non_field_errors"], ["User already exists."])
