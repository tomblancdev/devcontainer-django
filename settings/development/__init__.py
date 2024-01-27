"""Development settings for the project."""

from settings.settings import BASE_DIR

DEBUG: bool = True

ALLOWED_HOSTS = ["*"]

SECRET_KEY = "django-insecure-fhuiaplmofucl$s3$ivqh+jk&2j7t56@jpy_fq2$g&cck^jo(v"  # noqa: S105

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    },
}

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
