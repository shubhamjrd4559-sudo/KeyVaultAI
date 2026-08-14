"""DRF serializers for authentication endpoints.

Responsibility: request data validation and cleaning only.
No business logic. No database access.

write_only=True on password fields ensures they are never echoed back
in serializer output, adding a defence-in-depth layer.
"""
from rest_framework import serializers


class RegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(
        min_length=10,
        max_length=128,
        write_only=True,
        trim_whitespace=False,  # preserve leading/trailing spaces for validation
    )
    full_name = serializers.CharField(min_length=2, max_length=150)

    def validate_email(self, value: str) -> str:
        return value.lower().strip()

    def validate_full_name(self, value: str) -> str:
        return value.strip()


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
    )

    def validate_email(self, value: str) -> str:
        return value.lower().strip()


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class TokenRefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
