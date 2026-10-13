"""User verification and password reset email delivery."""
from urllib.parse import quote

from django.conf import settings
from django.core.mail import send_mail


def send_verification_email(email: str, full_name: str, token: str) -> None:
    link = f"{settings.FRONTEND_BASE_URL}/verify-email#token={quote(token)}"
    send_mail(
        subject="Verify your KeyVaultAI email",
        message=(
            f"Hello {full_name},\n\n"
            f"Verify your email using this link: {link}\n\n"
            "If you did not create this account, you can ignore this message."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )


def send_password_reset_email(email: str, full_name: str, token: str) -> None:
    link = f"{settings.FRONTEND_BASE_URL}/reset-password#token={quote(token)}"
    send_mail(
        subject="Reset your KeyVaultAI password",
        message=(
            f"Hello {full_name},\n\n"
            f"Reset your password using this link: {link}\n\n"
            "If you did not request a reset, you can ignore this message."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )
