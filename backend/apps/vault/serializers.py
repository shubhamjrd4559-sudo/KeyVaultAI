"""DRF serializers for vault credential endpoints.

Responsibilities: request data validation and cleaning ONLY.
No business logic. No encryption. No database access.

Security:
- password field is always write_only=True — never echoed back.
- category is validated against the allowed set.
- search strings are capped at 100 chars (prevents very long regex patterns).
- filter parameters are validated before reaching the repository.
"""
from rest_framework import serializers

from .models import VALID_CATEGORIES, SECURITY_LEVELS

_CATEGORY_CHOICES = sorted(VALID_CATEGORIES)


class CreateCredentialSerializer(serializers.Serializer):
    website_name = serializers.CharField(max_length=200)
    website_url = serializers.URLField(
        required=False, allow_blank=True, default=""
    )
    username = serializers.CharField(
        max_length=200, required=False, allow_blank=True, default=""
    )
    email = serializers.EmailField(
        max_length=254, required=False, allow_blank=True, default=""
    )
    # write_only prevents plaintext password from appearing in any serializer output.
    password = serializers.CharField(
        write_only=True,
        min_length=1,
        max_length=1024,
        trim_whitespace=False,
    )
    category = serializers.ChoiceField(
        choices=_CATEGORY_CHOICES + ["other"],
        required=False,
        default="general",
    )
    notes = serializers.CharField(
        max_length=2000, required=False, allow_blank=True, default=""
    )
    favorite = serializers.BooleanField(required=False, default=False)

    def validate(self, data):
        if not data.get("username") and not data.get("email"):
            raise serializers.ValidationError(
                "At least one of 'username' or 'email' is required."
            )
        return data

    def validate_website_name(self, value: str) -> str:
        return value.strip()


class UpdateCredentialSerializer(serializers.Serializer):
    website_name = serializers.CharField(max_length=200, required=False)
    website_url = serializers.URLField(
        required=False, allow_blank=True
    )
    username = serializers.CharField(
        max_length=200, required=False, allow_blank=True
    )
    email = serializers.EmailField(max_length=254, required=False, allow_blank=True)
    # write_only — new password is never returned in the response.
    password = serializers.CharField(
        write_only=True,
        required=False,
        min_length=1,
        max_length=1024,
        trim_whitespace=False,
    )
    category = serializers.ChoiceField(
        choices=_CATEGORY_CHOICES + ["other"], required=False
    )
    notes = serializers.CharField(
        max_length=2000, required=False, allow_blank=True
    )
    favorite = serializers.BooleanField(required=False)

    def validate_website_name(self, value: str) -> str:
        return value.strip()


class CredentialFilterSerializer(serializers.Serializer):
    """Validates query-string filter parameters for the list endpoint."""

    category = serializers.ChoiceField(
        choices=_CATEGORY_CHOICES + ["other"], required=False
    )
    favorite = serializers.BooleanField(required=False)
    security_level = serializers.ChoiceField(
        choices=list(SECURITY_LEVELS), required=False
    )
    search = serializers.CharField(
        max_length=100, required=False, allow_blank=False
    )
