"""M5 Security Engine tests.

Tests are grouped as:
  1. SecurityAnalyzer unit tests (no DB, no network)
  2. Credential repository — find_all_encrypted_for_user
  3. Security API view tests (authenticated / unauthenticated / isolation)

All tests use mocked dependencies so they can run without MongoDB or Redis.
No plaintext passwords appear in assertions — only hashes or labels.
"""
import hashlib
from unittest.mock import MagicMock, patch

import pytest
from django.test import RequestFactory
from rest_framework import status
from rest_framework.test import APIClient

from apps.security.services.analyzer import (
    ALERT_LOW_SCORE,
    ALERT_REUSED_PASSWORD,
    ALERT_WEAK_PASSWORD,
    CredentialSecurityInfo,
    SecurityAnalyzer,
    SecuritySummary,
)
from apps.users.authentication import AuthenticatedUser


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_scored_doc(
    credential_id="cid-1",
    website_name="TestSite",
    category="general",
    security_score=30,
    security_level="weak",
):
    return {
        "credential_id": credential_id,
        "website_name": website_name,
        "category": category,
        "security_score": security_score,
        "security_level": security_level,
    }


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Password scoring (from vault model — reused by Security Engine)
# ─────────────────────────────────────────────────────────────────────────────

class TestPasswordScoring:
    """Verify the existing score_password() function that the engine reuses."""

    def test_weak_password_short(self):
        from apps.vault.models import score_password
        score, level = score_password("abc")
        assert score < 40
        assert level == "weak"

    def test_weak_password_no_variety(self):
        from apps.vault.models import score_password
        score, level = score_password("aaaaaaa1")
        # Only lowercase + digit, length ≥8 → 10+10+10=30 → weak
        assert level in ("weak", "fair")

    def test_medium_password(self):
        from apps.vault.models import score_password
        score, level = score_password("Glider92")
        # length≥8(10) + upper(10) + lower(10) + digit(10) + unique≥8(10)=50
        assert 40 <= score < 80
        assert level in ("fair", "strong")

    def test_strong_password(self):
        from apps.vault.models import score_password
        score, level = score_password("Lime#76Paws")
        assert score >= 60
        assert level in ("strong", "very_strong")

    def test_very_strong_password(self):
        from apps.vault.models import score_password
        score, level = score_password("Tr0ub4dor&3!AbcXYZ")
        assert score >= 80
        assert level == "very_strong"

    def test_obvious_pattern_no_special(self):
        from apps.vault.models import score_password
        # All lowercase, no special char, no digit — weak
        score, level = score_password("password")
        assert level == "weak"

    def test_obvious_patterns_reduce_score(self):
        from apps.vault.models import score_password
        patterned_score, patterned_level = score_password("Password1234!")
        random_score, _ = score_password("N7!vK2@rQ9#x")
        assert patterned_score < random_score
        assert patterned_level in ("weak", "fair")

    def test_empty_password(self):
        from apps.vault.models import score_password
        score, level = score_password("")
        assert score == 0
        assert level == "weak"


# ─────────────────────────────────────────────────────────────────────────────
# 2. SecurityAnalyzer.detect_reuse
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectReuse:
    """Plaintext passwords are never asserted — only credential IDs."""

    def _make_decrypt_fn(self, mapping: dict):
        """Return a decrypt callable that maps ciphertext → plaintext."""
        def decrypt(ciphertext: str) -> str:
            return mapping[ciphertext]
        return decrypt

    def test_two_identical_passwords_flagged(self):
        items = [
            {"credential_id": "cid-1", "encrypted_password": "enc-A"},
            {"credential_id": "cid-2", "encrypted_password": "enc-B"},
        ]
        # Both 'decrypt' to same plaintext value
        decrypt_fn = self._make_decrypt_fn({"enc-A": "SamePass1!", "enc-B": "SamePass1!"})
        reused = SecurityAnalyzer.detect_reuse(items, decrypt_fn)
        assert "cid-1" in reused
        assert "cid-2" in reused

    def test_different_passwords_not_reused(self):
        items = [
            {"credential_id": "cid-1", "encrypted_password": "enc-A"},
            {"credential_id": "cid-2", "encrypted_password": "enc-B"},
        ]
        decrypt_fn = self._make_decrypt_fn({"enc-A": "UniquePass1!", "enc-B": "OtherPass2@"})
        reused = SecurityAnalyzer.detect_reuse(items, decrypt_fn)
        assert len(reused) == 0

    def test_three_items_two_reused_one_unique(self):
        items = [
            {"credential_id": "cid-1", "encrypted_password": "enc-A"},
            {"credential_id": "cid-2", "encrypted_password": "enc-B"},
            {"credential_id": "cid-3", "encrypted_password": "enc-C"},
        ]
        decrypt_fn = self._make_decrypt_fn({
            "enc-A": "SharedPass!", "enc-B": "SharedPass!", "enc-C": "UniquePass!"
        })
        reused = SecurityAnalyzer.detect_reuse(items, decrypt_fn)
        assert "cid-1" in reused
        assert "cid-2" in reused
        assert "cid-3" not in reused

    def test_decrypt_failure_skipped_gracefully(self):
        """A credential that fails decryption must not crash the engine."""
        items = [
            {"credential_id": "cid-1", "encrypted_password": "bad-enc"},
            {"credential_id": "cid-2", "encrypted_password": "enc-B"},
        ]
        def failing_decrypt(ciphertext: str) -> str:
            if ciphertext == "bad-enc":
                raise ValueError("decryption error")
            return "SomePass!"
        reused = SecurityAnalyzer.detect_reuse(items, failing_decrypt)
        # cid-1 failed, cid-2 is the only one — no reuse possible
        assert "cid-2" not in reused

    def test_empty_items_returns_empty_set(self):
        reused = SecurityAnalyzer.detect_reuse([], lambda _: "pw")
        assert reused == set()

    def test_single_item_never_reused(self):
        items = [{"credential_id": "cid-1", "encrypted_password": "enc-A"}]
        decrypt_fn = self._make_decrypt_fn({"enc-A": "SomePass!"})
        reused = SecurityAnalyzer.detect_reuse(items, decrypt_fn)
        assert len(reused) == 0

    def test_plaintext_not_in_return_value(self):
        """The return value must contain only credential IDs, never passwords."""
        items = [
            {"credential_id": "cid-1", "encrypted_password": "enc-A"},
            {"credential_id": "cid-2", "encrypted_password": "enc-B"},
        ]
        decrypt_fn = self._make_decrypt_fn({"enc-A": "SharedPass!", "enc-B": "SharedPass!"})
        reused = SecurityAnalyzer.detect_reuse(items, decrypt_fn)
        # Return type is a set of IDs — check no password values leak in
        for item in reused:
            assert "Pass" not in item
            assert len(item) < 50  # IDs are short, passwords are not returned


# ─────────────────────────────────────────────────────────────────────────────
# 3. SecurityAnalyzer.build_alerts
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildAlerts:
    def test_weak_credential_gets_alerts(self):
        alerts = SecurityAnalyzer.build_alerts(score=20, level="weak", is_reused=False)
        assert ALERT_WEAK_PASSWORD in alerts
        assert ALERT_LOW_SCORE in alerts

    def test_reused_credential_gets_alert(self):
        alerts = SecurityAnalyzer.build_alerts(score=70, level="strong", is_reused=True)
        assert ALERT_REUSED_PASSWORD in alerts
        assert ALERT_WEAK_PASSWORD not in alerts

    def test_strong_non_reused_no_alerts(self):
        alerts = SecurityAnalyzer.build_alerts(score=80, level="very_strong", is_reused=False)
        assert alerts == []

    def test_alerts_contain_no_passwords(self):
        alerts = SecurityAnalyzer.build_alerts(score=10, level="weak", is_reused=True)
        for alert in alerts:
            assert len(alert) < 100  # labels only, no password data
            assert "password" not in alert.lower() or alert in (
                ALERT_WEAK_PASSWORD, ALERT_REUSED_PASSWORD
            )


# ─────────────────────────────────────────────────────────────────────────────
# 4. SecurityAnalyzer.analyze
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyze:
    def test_analyze_produces_security_info(self):
        docs = [_make_scored_doc(credential_id="cid-1", security_score=30, security_level="weak")]
        results = SecurityAnalyzer().analyze(scored_docs=docs, reused_ids=set())
        assert len(results) == 1
        assert isinstance(results[0], CredentialSecurityInfo)

    def test_reused_id_flagged(self):
        docs = [_make_scored_doc(credential_id="cid-1", security_score=30, security_level="weak")]
        results = SecurityAnalyzer().analyze(scored_docs=docs, reused_ids={"cid-1"})
        assert results[0].is_reused is True

    def test_non_reused_id_not_flagged(self):
        docs = [_make_scored_doc(credential_id="cid-2", security_score=80, security_level="very_strong")]
        results = SecurityAnalyzer().analyze(scored_docs=docs, reused_ids={"cid-1"})
        assert results[0].is_reused is False

    def test_result_contains_no_password(self):
        docs = [_make_scored_doc()]
        results = SecurityAnalyzer().analyze(scored_docs=docs, reused_ids=set())
        d = results[0].to_dict()
        assert "password" not in d
        assert "encrypted" not in d

    def test_empty_docs_empty_results(self):
        results = SecurityAnalyzer().analyze(scored_docs=[], reused_ids=set())
        assert results == []


# ─────────────────────────────────────────────────────────────────────────────
# 5. SecurityAnalyzer.build_summary
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildSummary:
    def _make_info(self, credential_id, score, level, is_reused=False):
        return CredentialSecurityInfo(
            credential_id=credential_id,
            website_name="site",
            category="general",
            security_score=score,
            security_level=level,
            is_reused=is_reused,
        )

    def test_empty_vault_summary(self):
        summary = SecurityAnalyzer.build_summary([])
        assert summary.total == 0
        assert summary.overall_score == 0
        assert summary.overall_level == "weak"

    def test_single_strong_credential(self):
        info = self._make_info("cid-1", 90, "very_strong")
        summary = SecurityAnalyzer.build_summary([info])
        assert summary.total == 1
        assert summary.very_strong_count == 1
        assert summary.weak_count == 0
        assert summary.overall_score >= 70

    def test_mixed_vault(self):
        infos = [
            self._make_info("cid-1", 90, "very_strong"),
            self._make_info("cid-2", 30, "weak"),
            self._make_info("cid-3", 60, "strong"),
        ]
        summary = SecurityAnalyzer.build_summary(infos)
        assert summary.total == 3
        assert summary.very_strong_count == 1
        assert summary.weak_count == 1
        assert summary.strong_count == 1
        assert 0 <= summary.overall_score <= 100

    def test_reuse_penalty_applied(self):
        infos = [
            self._make_info("cid-1", 80, "very_strong", is_reused=True),
            self._make_info("cid-2", 80, "very_strong", is_reused=True),
        ]
        summary = SecurityAnalyzer.build_summary(infos)
        assert summary.reused_count == 2
        # Penalty: 2 * 5 = 10 → overall_score < average_score
        assert summary.overall_score < summary.average_score

    def test_overall_level_correct(self):
        infos = [self._make_info("cid-1", 85, "very_strong")]
        summary = SecurityAnalyzer.build_summary(infos)
        assert summary.overall_level in ("very_strong", "strong")

    def test_overall_score_in_range(self):
        infos = [self._make_info(f"cid-{i}", 50, "fair") for i in range(10)]
        summary = SecurityAnalyzer.build_summary(infos)
        assert 0 <= summary.overall_score <= 100

    def test_summary_contains_no_passwords(self):
        infos = [self._make_info("cid-1", 30, "weak")]
        summary = SecurityAnalyzer.build_summary(infos)
        d = summary.to_dict()
        for key, value in d.items():
            if isinstance(value, str):
                # Values are labels/levels — must not contain password text
                assert len(value) < 50


# ─────────────────────────────────────────────────────────────────────────────
# 6. Security API views (with mocked repository)
# ─────────────────────────────────────────────────────────────────────────────

MOCK_SCORED_DOCS = [
    {
        "credential_id": "cid-1",
        "website_name": "Instagram",
        "category": "social",
        "security_score": 30,
        "security_level": "weak",
    },
    {
        "credential_id": "cid-2",
        "website_name": "GitHub",
        "category": "work",
        "security_score": 90,
        "security_level": "very_strong",
    },
]

# Encrypted items for reuse detection — different ciphertexts, different passwords
MOCK_ENCRYPTED_ITEMS = [
    {"credential_id": "cid-1", "encrypted_password": "enc-weak"},
    {"credential_id": "cid-2", "encrypted_password": "enc-strong"},
]


def _mock_decrypt(ciphertext: str) -> str:
    """Deterministic mock decrypt for tests. Never returns real passwords."""
    return {"enc-weak": "UniqueWeak1!", "enc-strong": "UniqueStrong2@"}[ciphertext]


def _mock_repo(scored_docs=None, encrypted_items=None, raise_error=False):
    repo = MagicMock()
    if raise_error:
        from apps.vault.repositories.credentials import CredentialRepositoryError
        repo.find_all_by_user.side_effect = CredentialRepositoryError("DB error")
        repo.find_all_encrypted_for_user.side_effect = CredentialRepositoryError("DB error")
    else:
        repo.find_all_by_user.return_value = scored_docs or MOCK_SCORED_DOCS
        repo.find_all_encrypted_for_user.return_value = encrypted_items or MOCK_ENCRYPTED_ITEMS
    return repo


def _authenticated_request(user_id="user-abc", path="/api/v1/security/summary/"):
    factory = RequestFactory()
    request = factory.get(path)
    request.user = AuthenticatedUser(user_id=user_id, email="test@example.com")
    return request


@pytest.mark.django_db
class TestSecuritySummaryView:
    def _get_summary(self, user_id="user-abc", raise_repo_error=False):
        from apps.security.views import SecuritySummaryView
        from apps.vault.services.encryption import EncryptionService
        from apps.users.authentication import JWTAuthentication
        test_user = AuthenticatedUser(user_id=user_id, email="test@example.com")
        mock_enc = MagicMock(spec=EncryptionService)
        mock_enc.decrypt.side_effect = _mock_decrypt
        with (
            patch.object(JWTAuthentication, "authenticate",
                         return_value=(test_user, "dummy-token")),
            patch("apps.security.views._get_credential_repo",
                  return_value=_mock_repo(raise_error=raise_repo_error)),
            patch("apps.security.views.get_encryption_service", return_value=mock_enc),
        ):
            request = _authenticated_request(user_id=user_id)
            view = SecuritySummaryView.as_view()
            return view(request)

    def test_authenticated_returns_200(self):
        response = self._get_summary()
        assert response.status_code == status.HTTP_200_OK

    def test_response_contains_summary(self):
        response = self._get_summary()
        assert "summary" in response.data

    def test_summary_fields_present(self):
        response = self._get_summary()
        s = response.data["summary"]
        for field in ("total", "weak_count", "strong_count", "reused_count",
                      "overall_score", "overall_level", "average_score"):
            assert field in s, f"Missing field: {field}"

    def test_no_password_in_response(self):
        response = self._get_summary()
        # Serialize and check no password-like value
        import json
        text = json.dumps(response.data)
        assert "encrypted" not in text
        assert "plaintext" not in text

    def test_unauthenticated_returns_401(self):
        from apps.security.views import SecuritySummaryView
        client = APIClient()
        response = client.get("/api/v1/security/summary/")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_repo_unavailable_returns_503(self):
        response = self._get_summary(raise_repo_error=True)
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    def test_user_isolation_different_users_separate_calls(self):
        """Verify that user_id from JWT drives the repo query."""
        from apps.security.views import SecuritySummaryView
        from apps.vault.services.encryption import EncryptionService
        from apps.users.authentication import JWTAuthentication
        mock_enc = MagicMock(spec=EncryptionService)
        mock_enc.decrypt.side_effect = _mock_decrypt
        mock_repo = _mock_repo()
        captured_user_ids: list[str] = []

        def capture_user_id(user_id, **kwargs):
            captured_user_ids.append(user_id)
            return MOCK_SCORED_DOCS

        mock_repo.find_all_by_user.side_effect = capture_user_id

        user_a = AuthenticatedUser(user_id="user-A", email="a@example.com")
        user_b = AuthenticatedUser(user_id="user-B", email="b@example.com")

        with (
            patch("apps.security.views._get_credential_repo", return_value=mock_repo),
            patch("apps.security.views.get_encryption_service", return_value=mock_enc),
        ):
            # User A
            with patch.object(JWTAuthentication, "authenticate", return_value=(user_a, "tok-a")):
                req_a = _authenticated_request(user_id="user-A")
                SecuritySummaryView.as_view()(req_a)

            # User B
            with patch.object(JWTAuthentication, "authenticate", return_value=(user_b, "tok-b")):
                req_b = _authenticated_request(user_id="user-B")
                SecuritySummaryView.as_view()(req_b)

        assert captured_user_ids[0] == "user-A"
        assert captured_user_ids[1] == "user-B"


@pytest.mark.django_db
class TestSecurityCredentialsView:
    def _get_credentials(self, user_id="user-abc"):
        from apps.security.views import SecurityCredentialsView
        from apps.vault.services.encryption import EncryptionService
        from apps.users.authentication import JWTAuthentication
        test_user = AuthenticatedUser(user_id=user_id, email="test@example.com")
        mock_enc = MagicMock(spec=EncryptionService)
        mock_enc.decrypt.side_effect = _mock_decrypt
        with (
            patch.object(JWTAuthentication, "authenticate",
                         return_value=(test_user, "dummy-token")),
            patch("apps.security.views._get_credential_repo",
                  return_value=_mock_repo()),
            patch("apps.security.views.get_encryption_service", return_value=mock_enc),
        ):
            request = _authenticated_request(
                user_id=user_id, path="/api/v1/security/credentials/"
            )
            view = SecurityCredentialsView.as_view()
            return view(request)

    def test_authenticated_returns_200(self):
        response = self._get_credentials()
        assert response.status_code == status.HTTP_200_OK

    def test_response_contains_credentials_list(self):
        response = self._get_credentials()
        assert "credentials" in response.data
        assert "count" in response.data

    def test_credential_fields_present(self):
        response = self._get_credentials()
        first = response.data["credentials"][0]
        for field in ("credential_id", "website_name", "category",
                      "security_score", "security_level", "is_reused", "alerts"):
            assert field in first, f"Missing field: {field}"

    def test_no_password_in_credential_response(self):
        response = self._get_credentials()
        import json
        text = json.dumps(response.data)
        assert "encrypted_password" not in text
        assert "plaintext" not in text

    def test_alerts_are_safe_strings(self):
        response = self._get_credentials()
        for cred in response.data["credentials"]:
            for alert in cred["alerts"]:
                assert isinstance(alert, str)
                assert len(alert) < 100  # labels, not passwords

    def test_unauthenticated_returns_401(self):
        client = APIClient()
        response = client.get("/api/v1/security/credentials/")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_reuse_detection_works(self):
        """Two credentials with same decrypted password → both flagged."""
        from apps.security.views import SecurityCredentialsView
        from apps.vault.services.encryption import EncryptionService
        from apps.users.authentication import JWTAuthentication

        scored_docs = [
            {"credential_id": "cid-1", "website_name": "Site1", "category": "general",
             "security_score": 60, "security_level": "strong"},
            {"credential_id": "cid-2", "website_name": "Site2", "category": "general",
             "security_score": 60, "security_level": "strong"},
        ]
        encrypted_items = [
            {"credential_id": "cid-1", "encrypted_password": "enc-same"},
            {"credential_id": "cid-2", "encrypted_password": "enc-same2"},
        ]
        test_user = AuthenticatedUser(user_id="user-abc", email="test@example.com")
        mock_enc = MagicMock(spec=EncryptionService)
        # Both decrypt to same password
        mock_enc.decrypt.return_value = "SharedPassword!"
        with (
            patch.object(JWTAuthentication, "authenticate",
                         return_value=(test_user, "dummy-token")),
            patch("apps.security.views._get_credential_repo",
                  return_value=_mock_repo(
                      scored_docs=scored_docs, encrypted_items=encrypted_items
                  )),
            patch("apps.security.views.get_encryption_service", return_value=mock_enc),
        ):
            request = _authenticated_request()
            view = SecurityCredentialsView.as_view()
            response = view(request)

        reused_creds = [c for c in response.data["credentials"] if c["is_reused"]]
        assert len(reused_creds) == 2

    def test_plaintext_password_not_persisted(self):
        """Verify that decrypted values are not present in the response."""
        response = self._get_credentials()
        import json
        # The mock decrypt returns "UniqueWeak1!" and "UniqueStrong2@"
        # Neither should appear anywhere in the serialized API response.
        text = json.dumps(dict(response.data))
        assert "UniqueWeak1!" not in text
        assert "UniqueStrong2@" not in text
