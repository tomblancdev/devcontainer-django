from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import authentication, exceptions

from .models import AuthToken

if TYPE_CHECKING:
    from django.db.models import QuerySet


class AuthTokenAuthentication(authentication.TokenAuthentication):
    """Token authentication class."""

    model: type[AuthToken] = AuthToken

    def get_queryset(self) -> QuerySet[AuthToken]:
        """Get queryset."""
        return self.model.objects.exclude(
            user__is_active=False, expires_at__lte=timezone.now()
        )

    def authenticate_credentials(self, key):
        """Authenticate credentials."""
        try:
            token = self.get_queryset().get(key=key)
        except self.model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_("Invalid Credentials."))
        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_("User inactive or deleted."))
        return (token.user, token)
