"""Views for users app."""

from django.conf import settings
from django.http import HttpRequest, HttpResponsePermanentRedirect, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import TokenError, User, UserTokenEmailValidation
from .serializers import RegisterSerializer


def send_mail_activation(
    user: User,
    next_url: str | None = None,
) -> None:
    """Send email activation."""
    # create token
    token = UserTokenEmailValidation.objects.create_token(user)
    # create activation link
    activation_base_url = reverse("email_activation", args=[token.token])
    activation_link = activation_base_url
    if next_url:
        activation_link = f"{activation_base_url}?next={next_url}"
    # send email
    user.email_user(
        subject=f"{_('Activate your account')}",
        message=activation_link,
        from_email=settings.DEFAULT_FROM_EMAIL,
        html_message=f"<a href='{activation_link}'>{activation_link}</a>",
    )


class RegisterView(APIView):
    """Register view."""

    permission_classes = (AllowAny,)

    def post(self, request: Request) -> Response:
        """Handle HTTP POST request."""
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            send_mail_activation(user, serializer.data.get("next"))
            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED,
            )
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )

    def get(self, request: Request) -> Response:
        """Handle HTTP GET request. Return Form for registration based on serializer."""
        serializer = RegisterSerializer()
        return Response(serializer.data)


def email_activation(
    request: HttpRequest,
    token: str,
) -> HttpResponseRedirect | HttpResponsePermanentRedirect:
    """Handle email activation."""
    # get next parameter from URL
    next_url = request.GET.get("next", "/login")
    try:
        UserTokenEmailValidation.objects.validate_token(token)
    except TokenError as error:
        # redirect to next URL with error message
        return redirect(f"{next_url}?token_error={error}")
    # Validate token.

    return redirect(f"{next_url}?token_success=true")
