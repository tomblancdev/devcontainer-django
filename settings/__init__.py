"""Settings for the project."""

from __future__ import annotations

import os

from .apps import *  # noqa: F403
from .base import *  # noqa: F403
from .settings import *  # noqa: F403

if os.environ.get("ENVIRONMENT") == "production":
    from .production import *  # noqa: F403

if os.environ.get("ENVIRONMENT") == "development":
    from .development import *  # noqa: F403
