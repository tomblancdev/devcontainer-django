# ruff: noqa: PT009 PT027
"""Test API for users app."""
from __future__ import annotations

from typing import Self
from uuid import uuid4

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from users.models import AuthToken

from .test_setup import FakeUserInfos, UsingUser


class APISetupTestCase(TestCase):

    """Set up test case for API tests."""

    endpoint: str

    def setUp(self: Self) -> None:
        """Set up test."""
        self.client = APIClient()
        super().setUp()

    def test_get(self: Self) -> None:
        """Test HTTP GET request."""
        if not hasattr(self, "endpoint"):
            return
        response = self.client.get(self.endpoint)
        self.assertEqual(response.status_code, 405)

    def test_post(self: Self) -> None:
        """Test HTTP POST request."""
        if not hasattr(self, "endpoint"):
            return
        response = self.client.post(self.endpoint)
        self.assertEqual(response.status_code, 405)

    def test_put(self: Self) -> None:
        """Test HTTP PUT request."""
        if not hasattr(self, "endpoint"):
            return
        response = self.client.put(self.endpoint)
        self.assertEqual(response.status_code, 405)

    def test_patch(self: Self) -> None:
        """Test HTTP PATCH request."""
        if not hasattr(self, "endpoint"):
            return
        response = self.client.patch(self.endpoint)
        self.assertEqual(response.status_code, 405)

    def test_delete(self: Self) -> None:
        """Test HTTP DELETE request."""
        if not hasattr(self, "endpoint"):
            return
        response = self.client.delete(self.endpoint)
        self.assertEqual(response.status_code, 405)


class TestRegisterView(APISetupTestCase):

    """Test register view."""

    endpoint = reverse("register")

    def test_post(self: Self) -> None:
        """Test HTTP POST request."""
        fake_user_data = FakeUserInfos()
        data = {
            "email": fake_user_data.email,
            "password": fake_user_data.password,
            "password_validation": fake_user_data.password,
            "username": fake_user_data.username,
            "first_name": fake_user_data.first_name,
            "last_name": fake_user_data.last_name,
            "next": "http://localhost:8000",
        }
        response = self.client.post(self.endpoint, data=data)
        self.assertEqual(response.status_code, 201)
        json_response = response.json()
        self.assertEqual(json_response["success"], "User created successfully.")

    def test_post_with_missing_data(self: Self) -> None:
        """Test HTTP POST request with missing data."""
        fake_user_data = FakeUserInfos()
        data = {
            "email": fake_user_data.email,
            "password": fake_user_data.password,
            "password_validation": fake_user_data.password,
            "username": fake_user_data.username,
            "first_name": fake_user_data.first_name,
            "last_name": fake_user_data.last_name,
            "next": "http://localhost:8000",
        }
        for key in data:
            data_copy = data.copy()
            del data_copy[key]
            response = self.client.post(self.endpoint, data=data_copy, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response[key][0], "This field is required.")

    def test_post_with_invalid_email(self: Self) -> None:
        """Test HTTP POST request with invalid email."""
        fake_user_data = FakeUserInfos()
        data = {
            "email": "invalid_email",
            "password": fake_user_data.password,
            "password_validation": fake_user_data.password,
            "username": fake_user_data.username,
            "first_name": fake_user_data.first_name,
            "last_name": fake_user_data.last_name,
            "next": "http://localhost:8000",
        }
        response = self.client.post(self.endpoint, data=data, format="json")
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(json_response["email"][0], "Enter a valid email address.")

    def test_post_with_invalid_password(self: Self) -> None:
        """Test HTTP POST request with invalid password."""
        fake_user_data = FakeUserInfos()
        data = {
            "email": fake_user_data.email,
            "username": fake_user_data.username,
            "first_name": fake_user_data.first_name,
            "last_name": fake_user_data.last_name,
            "next": "http://localhost:8000",
        }

        class WrongPassword:
            password: str
            error_message: str

            def __init__(self: Self, password: str, error_message: str) -> None:
                self.password = password
                self.error_message = error_message

        wrong_passwords: list[WrongPassword] = [
            WrongPassword(
                "sh0RT!",
                "This password is too short. It must contain at least 8 characters.",
            ),
            WrongPassword("123456789", "This password is too common."),
            WrongPassword("abcdefghi", "This password is too common."),
            WrongPassword("ABCDEFGHI", "This password is too common."),
            WrongPassword("abcDEF123", "This password is too common."),
        ]
        for wrong_password in wrong_passwords:
            data["password"] = wrong_password.password
            data["password_validation"] = wrong_password.password
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response["password"][0], wrong_password.error_message)

    def test_post_with_empty_string(self: Self) -> None:
        """Test HTTP POST request with empty string."""
        fake_user_data = FakeUserInfos()
        data = {
            "email": "",
            "password": fake_user_data.password,
            "password_validation": fake_user_data.password,
            "username": fake_user_data.username,
            "first_name": fake_user_data.first_name,
            "last_name": fake_user_data.last_name,
            "next": "http://localhost:8000",
        }
        for key in data:
            data_copy = data.copy()
            data_copy[key] = ""
            response = self.client.post(self.endpoint, data=data_copy, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response[key][0], "This field may not be blank.")

    def test_post_with_existing_user_email(self: Self) -> None:
        """Test registering with existing email."""
        with UsingUser() as user:
            fake_user_data = FakeUserInfos()
            data = {
                "email": user.email,
                "password": fake_user_data.password,
                "password_validation": fake_user_data.password,
                "username": fake_user_data.username,
                "first_name": fake_user_data.first_name,
                "last_name": fake_user_data.last_name,
                "next": "http://localhost:8000",
            }
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response["email"][0], "User already exists.")

    def test_post_with_different_passwords(self: Self) -> None:
        """Test HTTP POST request with different passwords."""
        fake_user_data = FakeUserInfos()
        data = {
            "email": fake_user_data.email,
            "password": fake_user_data.password,
            "password_validation": "different_password",
            "username": fake_user_data.username,
            "first_name": fake_user_data.first_name,
            "last_name": fake_user_data.last_name,
            "next": "http://localhost:8000",
        }
        response = self.client.post(self.endpoint, data=data, format="json")
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(
            json_response["password_validation"][0],
            "Passwords do not match.",
        )


class TestLoginView(APISetupTestCase):

    """Test login view."""

    endpoint = reverse("login")

    def test_post(self: Self) -> None:
        """Test HTTP POST request."""
        with UsingUser(with_email_validation_token=True) as user:
            user.token_email_validation.validate()
            password = uuid4().hex
            user.set_password(password)
            user.save()
            data = {"email": user.email, "password": password}
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 200)
            json_response = response.json()
            self.assertTrue("key" in json_response)
            self.assertTrue("expires_at" in json_response)

    def test_post_user_email_unverrified(self: Self) -> None:
        """Test HTTP POST request with unverified user email."""
        with UsingUser() as user:
            password = uuid4().hex
            user.set_password(password)
            user.save()
            data = {"email": user.email, "password": password}
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response["email"][0], "Email not verified.")

    def test_post_with_invalid_email(self: Self) -> None:
        """Test HTTP POST request with invalid email."""
        with UsingUser() as user:
            password = uuid4().hex
            user.set_password(password)
            user.save()
            data = {"email": "invalid_email", "password": password}
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 401)
            json_response = response.json()
            self.assertEqual(json_response["detail"], "Invalid email or password.")

    def test_post_with_invalid_user_email(self: Self) -> None:
        """Test HTTP POST request with invalid user email."""
        with UsingUser() as user:
            password = uuid4().hex
            user.set_password(password)
            user.save()
            data = {"email": "invalid_email@test.com", "password": password}
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 401)
            json_response = response.json()
            self.assertEqual(json_response["detail"], "Invalid email or password.")

    def test_post_with_invalid_password(self: Self) -> None:
        """Test HTTP POST request with invalid password."""
        with UsingUser(email_validated=True) as user:
            password = uuid4().hex
            user.set_password(password)
            user.save()
            data = {"email": user.email, "password": "invalid_password"}
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 401)
            json_response = response.json()
            self.assertEqual(json_response["detail"], "Invalid email or password.")


class TestChangePasswordView(APISetupTestCase):

    """Test change password view."""

    endpoint = reverse("change_password")

    def setUp(self: Self) -> None:
        """Set up test."""
        super().setUp()
        self.user = UsingUser(email_validated=True, with_auth_token=True).__enter__()
        self.auth_token = self.user.auth_token_set.first()
        if not self.auth_token:
            msg = "No auth token found."
            raise ValueError(msg)
        self.client.defaults["HTTP_AUTHORIZATION"] = f"Token {self.auth_token.key}"

    def test_post(self: Self) -> None:
        """Test HTTP POST request."""
        current_password = uuid4().hex
        new_password = uuid4().hex
        self.user.set_password(current_password)
        self.user.save()
        data = {
            "current_password": current_password,
            "new_password": new_password,
            "new_password_validation": new_password,
        }
        response = self.client.post(self.endpoint, data=data, format="json")
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["success"], "Password changed successfully.")

    def test_post_with_missing_data(self: Self) -> None:
        """Test HTTP POST request with missing data."""
        current_password = uuid4().hex
        new_password = uuid4().hex
        self.user.set_password(current_password)
        self.user.save()
        data = {
            "current_password": current_password,
            "new_password": new_password,
            "new_password_validation": new_password,
        }
        for key in data:
            data_copy = data.copy()
            del data_copy[key]
            response = self.client.post(self.endpoint, data=data_copy, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response[key][0], "This field is required.")

    def test_post_with_invalid_current_password(self: Self) -> None:
        """Test HTTP POST request with invalid current password."""
        current_password = uuid4().hex
        new_password = uuid4().hex
        self.user.set_password(current_password)
        self.user.save()
        data = {
            "current_password": "invalid_password",
            "new_password": new_password,
            "new_password_validation": new_password,
        }
        response = self.client.post(self.endpoint, data=data, format="json")
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(
            json_response["current_password"][0],
            "Invalid current password.",
        )

    def test_post_with_different_passwords(self: Self) -> None:
        """Test HTTP POST request with different passwords."""
        current_password = uuid4().hex
        new_password = uuid4().hex
        self.user.set_password(current_password)
        self.user.save()
        data = {
            "current_password": current_password,
            "new_password": new_password,
            "new_password_validation": "different_password",
        }
        response = self.client.post(self.endpoint, data=data, format="json")
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(
            json_response["new_password_validation"][0],
            "Passwords do not match.",
        )

    def test_post_with_invalid_new_password(self: Self) -> None:
        """Test HTTP POST request with invalid new password."""
        current_password = uuid4().hex
        self.user.set_password(current_password)
        self.user.save()
        data = {
            "current_password": current_password,
            "new_password": "short",
            "new_password_validation": "invalid_password",
        }
        response = self.client.post(self.endpoint, data=data, format="json")
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(
            json_response["new_password"][0],
            "This password is too short. It must contain at least 8 characters.",
        )

    def test_post_for_unauthenticated_user(self: Self) -> None:
        """Test HTTP POST request for unauthenticated user."""
        self.client.defaults["HTTP_AUTHORIZATION"] = ""
        current_password = uuid4().hex
        new_password = uuid4().hex
        self.user.set_password(current_password)
        self.user.save()
        data = {
            "current_password": current_password,
            "new_password": new_password,
            "new_password_validation": new_password,
        }
        response = self.client.post(self.endpoint, data=data, format="json")
        self.assertEqual(response.status_code, 401)


class TestActivateAccountView(APISetupTestCase):

    """Test activate account view."""

    endpoint = reverse("email_activation")

    def test_post(self: Self) -> None:
        """Test HTTP POST request."""
        with UsingUser(with_email_validation_token=True) as user:
            self.assertFalse(user.email_verified)
            user_email_validation_token = user.token_email_validation.token
            data = {"token": user_email_validation_token}
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 200)
            json_response = response.json()
            self.assertEqual(
                json_response["success"],
                "Account activated successfully.",
            )

    def test_post_with_missing_data(self: Self) -> None:
        """Test HTTP POST request with missing data."""
        with UsingUser(with_email_validation_token=True) as user:
            user_email_validation_token = user.token_email_validation.token
            data = {"token": user_email_validation_token}
            for key in data:
                data_copy = data.copy()
                del data_copy[key]
                response = self.client.post(
                    self.endpoint,
                    data=data_copy,
                    format="json",
                )
                self.assertEqual(response.status_code, 400)
                json_response = response.json()
                self.assertEqual(json_response[key][0], "This field is required.")

    def test_post_with_invalid_token(self: Self) -> None:
        """Test HTTP POST request with invalid token."""
        data = {"token": "invalid_token"}
        response = self.client.post(self.endpoint, data=data, format="json")
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(json_response["error"], "Invalid token.")

    def test_post_with_expired_token(self: Self) -> None:
        """Test HTTP POST request with expired token."""
        with UsingUser(with_email_validation_token=True) as user:
            user_email_validation_token = user.token_email_validation.token
            user.token_email_validation.expires_at = timezone.now()
            user.token_email_validation.save()
            data = {"token": user_email_validation_token}
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response["error"], "Token is expired.")

    def test_post_with_already_validated_email(self: Self) -> None:
        """Test HTTP POST request with already validated email."""
        with UsingUser(email_validated=True) as user:
            user_email_validation_token = user.token_email_validation.token
            data = {"token": user_email_validation_token}
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response["error"], "Token is already validated.")


class TestRequestResetPasswordView(APISetupTestCase):

    """Test request reset password view."""

    endpoint = reverse("request_reset_password")

    def test_post(self: Self) -> None:
        """Test HTTP POST request."""
        with UsingUser(email_validated=True) as user:
            data = {"email": user.email}
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 200)
            json_response = response.json()
            self.assertEqual(
                json_response["success"],
                "Reset password email sent successfully.",
            )

    def test_post_with_missing_data(self: Self) -> None:
        """Test HTTP POST request with missing data."""
        with UsingUser(email_validated=True) as user:
            data = {"email": user.email}
            for key in data:
                data_copy = data.copy()
                del data_copy[key]
                response = self.client.post(
                    self.endpoint,
                    data=data_copy,
                    format="json",
                )
                self.assertEqual(response.status_code, 400)
                json_response = response.json()
                self.assertEqual(json_response[key][0], "This field is required.")

    def test_post_with_invalid_email(self: Self) -> None:
        """Test HTTP POST request with invalid email."""
        data = {"email": "invalid_email"}
        response = self.client.post(self.endpoint, data=data, format="json")
        self.assertEqual(response.status_code, 400)
        json_response = response.json()
        self.assertEqual(json_response["email"][0], "Enter a valid email address.")

    def test_post_with_invalid_user_email(self: Self) -> None:
        """Test HTTP POST request with invalid user email."""
        data = {"email": "not_valid@test.com"}
        response = self.client.post(self.endpoint, data=data, format="json")
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["success"],
            "Reset password email sent successfully.",
        )

    def test_post_with_unvalidated_email(self: Self) -> None:
        """Test HTTP POST request with unvalidated email."""
        with UsingUser() as user:
            data = {"email": user.email}
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response["email"][0], "Email not verified.")


class TestResetPasswordView(APISetupTestCase):

    """Test reset password view."""

    endpoint = reverse("reset_password")

    def test_post(self: Self) -> None:
        """Test HTTP POST request."""
        with UsingUser(with_reset_password_token=True, email_validated=True) as user:
            user_reset_password_token = user.reset_password_token_set.first()
            if not user_reset_password_token:
                msg = "No reset password token found."
                raise ValueError(msg)
            new_password = uuid4().hex
            data = {
                "token": user_reset_password_token.token,
                "password": new_password,
                "password_validation": new_password,
            }
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 200)
            json_response = response.json()
            self.assertEqual(json_response["success"], "Password reset successfully.")
            self.assertEqual(user.auth_token_set.count(), 0)
            user_reset_password_token.refresh_from_db()
            self.assertTrue(user_reset_password_token.is_used)

    def test_post_with_missing_data(self: Self) -> None:
        """Test HTTP POST request with missing data."""
        with UsingUser(with_reset_password_token=True, email_validated=True) as user:
            user_reset_password_token = user.reset_password_token_set.first()
            if not user_reset_password_token:
                msg = "No reset password token found."
                raise ValueError(msg)
            new_password = uuid4().hex
            data = {
                "token": user_reset_password_token.token,
                "password": new_password,
                "password_validation": new_password,
            }
            for key in data:
                data_copy = data.copy()
                del data_copy[key]
                response = self.client.post(
                    self.endpoint,
                    data=data_copy,
                    format="json",
                )
                self.assertEqual(response.status_code, 400)
                json_response = response.json()
                self.assertEqual(json_response[key][0], "This field is required.")

    def test_post_with_invalid_token(self: Self) -> None:
        """Test HTTP POST request with invalid token."""
        with UsingUser(with_reset_password_token=True, email_validated=True) as user:
            user_reset_password_token = user.reset_password_token_set.first()
            if not user_reset_password_token:
                msg = "No reset password token found."
                raise ValueError(msg)
            new_password = uuid4().hex
            data = {
                "token": "invalid_token",
                "password": new_password,
                "password_validation": new_password,
            }
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response["error"], "Invalid token.")

    def test_post_with_expired_token(self: Self) -> None:
        """Test HTTP POST request with expired token."""
        with UsingUser(with_reset_password_token=True, email_validated=True) as user:
            user_reset_password_token = user.reset_password_token_set.first()
            if not user_reset_password_token:
                msg = "No reset password token found."
                raise ValueError(msg)
            user_reset_password_token.expires_at = timezone.now()
            user_reset_password_token.save()
            new_password = uuid4().hex
            data = {
                "token": user_reset_password_token.token,
                "password": new_password,
                "password_validation": new_password,
            }
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(json_response["error"], "Invalid token.")

    def test_post_with_different_passwords(self: Self) -> None:
        """Test HTTP POST request with different passwords."""
        with UsingUser(with_reset_password_token=True, email_validated=True) as user:
            user_reset_password_token = user.reset_password_token_set.first()
            if not user_reset_password_token:
                msg = "No reset password token found."
                raise ValueError(msg)
            new_password = uuid4().hex
            data = {
                "token": user_reset_password_token.token,
                "password": new_password,
                "password_validation": "different_password",
            }
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(
                json_response["password_validation"][0],
                "Passwords do not match.",
            )

    def test_post_with_invalid_new_password(self: Self) -> None:
        """Test HTTP POST request with invalid new password."""
        with UsingUser(with_reset_password_token=True, email_validated=True) as user:
            user_reset_password_token = user.reset_password_token_set.first()
            if not user_reset_password_token:
                msg = "No reset password token found."
                raise ValueError(msg)
            data = {
                "token": user_reset_password_token.token,
                "password": "short",
                "password_validation": "invalid_password",
            }
            response = self.client.post(self.endpoint, data=data, format="json")
            self.assertEqual(response.status_code, 400)
            json_response = response.json()
            self.assertEqual(
                json_response["password"][0],
                "This password is too short. It must contain at least 8 characters.",
            )


class TestLogoutView(APISetupTestCase):

    """Test logout view."""

    endpoint = reverse("logout")

    def setUp(self: Self) -> None:
        """Set up test."""
        super().setUp()
        self.user = UsingUser(with_auth_token=True).setUp()
        self.auth_token = self.user.auth_token_set.first()
        if not self.auth_token:
            msg = "No auth token found."
            raise ValueError(msg)
        self.client.defaults["HTTP_AUTHORIZATION"] = f"Token {self.auth_token.key}"

    def test_post(self: Self) -> None:
        """Test HTTP POST request."""
        response = self.client.post(self.endpoint)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response["success"], "Logged out successfully.")
        # assert that token is deleted
        self.assertEqual(self.user.auth_token_set.count(), 0)

    def test_post_for_unauthenticated_user(self: Self) -> None:
        """Test HTTP POST request for unauthenticated user."""
        self.client.defaults["HTTP_AUTHORIZATION"] = ""
        response = self.client.post(self.endpoint)
        self.assertEqual(response.status_code, 401)

    def test_post_delete_everywhere(self: Self) -> None:
        """Test HTTP POST request with delete_everywhere parameter."""
        for _ in range(5):
            AuthToken.objects.create(user=self.user)
        self.assertEqual(self.user.auth_token_set.count(), 6)
        response = self.client.post(f"{self.endpoint}?everywhere=true")
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(
            json_response["success"],
            "Logged out everywhere successfully.",
        )
        # assert that token is deleted
        self.assertEqual(self.user.auth_token_set.count(), 0)
