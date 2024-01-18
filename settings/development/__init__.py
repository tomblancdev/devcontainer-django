"""Development settings for the project."""

from settings.settings import BASE_DIR

DEBUG: bool = True

SECRET_KEY = "django-insecure-fhuiaplmofucl$s3$ivqh+jk&2j7t56@jpy_fq2$g&cck^jo(v"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}
