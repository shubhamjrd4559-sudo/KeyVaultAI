"""Helpers for opaque, one-time email action tokens.

Only SHA-256 digests are persisted. Raw token values are returned once to the
email sender and must never be logged or written to audit records.
"""
import hashlib
import secrets


def create_email_token() -> tuple[str, str]:
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, token_hash


def hash_email_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
