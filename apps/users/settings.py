"""Settings for users app."""
from __future__ import annotations

from django.conf import settings

# User settings
USERS_SETTINGS = getattr(
    settings,
    "USERS",
    {
        "EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME": 60 * 60 * 24 * 7,
        "RESET_PASSWORD_TOKEN_EXPIRATION_TIME": 60 * 60 * 24 * 7,
        "AUTH_TOKEN_EXPIRATION_TIME": 60 * 60 * 24 * 7,
    },
)

# Email Token Validation Settings
EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME: int = (
    USERS_SETTINGS["EMAIL_TOKEN_VALIDATION_EXPIRATION_TIME"] | 60 * 60 * 24 * 7
)

# Password Reset Token Settings
RESET_PASSWORD_TOKEN_EXPIRATION_TIME: int = (
    USERS_SETTINGS["RESET_PASSWORD_TOKEN_EXPIRATION_TIME"] | 60 * 60 * 24 * 7
)

# Auth Token Settings
AUTH_TOKEN_EXPIRATION_TIME: int = (
    USERS_SETTINGS["AUTH_TOKEN_EXPIRATION_TIME"] | 60 * 60 * 24 * 7
)
