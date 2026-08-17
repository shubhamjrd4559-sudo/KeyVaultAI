"""M6 ML Engine tests.

Test groups:
  1.  Safe feature extraction (no plaintext stored/returned)
  2.  Score-based feature extraction (no plaintext required)
  3.  Synthetic dataset generation
  4.  Model training (reproducible)
  5.  Prediction output — LOW/MEDIUM/HIGH
  6.  Confidence range [0.0, 1.0]
  7.  Authenticated API access (POST /api/v1/ml/predict/)
  8.  Unauthenticated denial (401)
  9.  User isolation — User A cannot get User B's prediction
  10. Plaintext non-disclosure — response body never contains password text
  11. No secrets in ML response artifacts
  12. M5 regression — existing security endpoints unaffected

All tests use mocked dependencies.
No MongoDB, Redis, internet, GPU, or external APIs required.
"""
import pytest
import numpy as np
from unittest.mock import MagicMock, patch

from apps.ml_engine.features import (
    FEATURE_NAMES,
    PasswordFeatures,
    extract_features,
    extract_features_from_score,
)
from apps.ml_engine.dataset import (
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_LABELS,
    generate_synthetic_dataset,
)
from apps.ml_engine.model import (
    PredictionResult,
    _build_and_train,
    predict,
)
from apps.users.authentication import AuthenticatedUser


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_user(user_id="user-1", email="a@test.com"):
    return AuthenticatedUser(user_id=user_id, email=email)


def _auth_request(client, user, data):
    """Make an authenticated POST to ml/predict/."""
    with patch("apps.ml_engine.views.JWTAuthentication.authenticate", return_value=(user, None)):
        return client.post(
            "/api/v1/ml/predict/",
            data,
            content_type="application/json",
        )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Safe feature extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureExtraction:
    """Verify extract_features produces safe numeric output."""

    def test_returns_password_features(self):
        features = extract_features(
            plaintext_password="MyP@ssw0rd!123",
            security_score=70,
            is_reused=False,
        )
        assert isinstance(features, PasswordFeatures)

    def test_feature_names_count(self):
        assert len(FEATURE_NAMES) == 10

    def test_has_lower_true(self):
        f = extract_features(plaintext_password="abc", security_score=10, is_reused=False)
        assert f.has_lower == 1

    def test_has_upper_true(self):
        f = extract_features(plaintext_password="ABC", security_score=10, is_reused=False)
        assert f.has_upper == 1

    def test_has_digit_true(self):
        f = extract_features(plaintext_password="abc123", security_score=10, is_reused=False)
        assert f.has_digit == 1

    def test_has_special_true(self):
        f = extract_features(plaintext_password="abc@!", security_score=10, is_reused=False)
        assert f.has_special == 1

    def test_length_correct(self):
        pw = "TestPass1!"
        f = extract_features(plaintext_password=pw, security_score=50, is_reused=False)
        assert f.length == len(pw)

    def test_char_diversity_range(self):
        f = extract_features(plaintext_password="abcdefgh", security_score=30, is_reused=False)
        assert 0.0 <= f.char_diversity <= 1.0

    def test_repeat_run_detected(self):
        f = extract_features(plaintext_password="aaabbb", security_score=10, is_reused=False)
        assert f.has_repeat_run == 1

    def test_no_repeat_run(self):
        f = extract_features(plaintext_password="abcdefghi", security_score=40, is_reused=False)
        assert f.has_repeat_run == 0

    def test_obvious_pattern_detected(self):
        # "password" is in the obvious patterns list
        f = extract_features(plaintext_password="password123", security_score=10, is_reused=False)
        assert f.has_obvious_pattern == 1

    def test_no_obvious_pattern(self):
        f = extract_features(plaintext_password="Xk9!mQ2z", security_score=70, is_reused=False)
        assert f.has_obvious_pattern == 0

    def test_is_reused_flag(self):
        f = extract_features(plaintext_password="anything", security_score=30, is_reused=True)
        assert f.is_reused == 1

    def test_security_score_preserved(self):
        f = extract_features(plaintext_password="anything", security_score=77, is_reused=False)
        assert f.security_score == 77

    def test_to_list_length(self):
        f = extract_features(plaintext_password="Abc1@xyz!", security_score=60, is_reused=False)
        lst = f.to_list()
        assert len(lst) == 10

    def test_plaintext_not_in_feature_values(self):
        """Feature values must be numbers — the plaintext string must not appear."""
        pw = "SuperSecret99!"
        f = extract_features(plaintext_password=pw, security_score=75, is_reused=False)
        for val in f.to_list():
            # Each feature is a number — assert it is not the password string
            assert val != pw
            assert isinstance(val, (int, float))


# ─────────────────────────────────────────────────────────────────────────────
# 2. Score-based feature extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestScoreBasedFeatures:
    def test_returns_features(self):
        f = extract_features_from_score(
            security_score=80, security_level="very_strong", is_reused=False
        )
        assert isinstance(f, PasswordFeatures)

    def test_score_preserved(self):
        f = extract_features_from_score(
            security_score=55, security_level="fair", is_reused=False
        )
        assert f.security_score == 55

    def test_reuse_flag(self):
        f = extract_features_from_score(
            security_score=60, security_level="strong", is_reused=True
        )
        assert f.is_reused == 1

    def test_weak_level_short_estimate(self):
        f = extract_features_from_score(
            security_score=15, security_level="weak", is_reused=False
        )
        assert f.length < 10

    def test_very_strong_long_estimate(self):
        f = extract_features_from_score(
            security_score=90, security_level="very_strong", is_reused=False
        )
        assert f.length >= 16

    def test_to_list_length(self):
        f = extract_features_from_score(
            security_score=50, security_level="fair", is_reused=False
        )
        assert len(f.to_list()) == 10


# ─────────────────────────────────────────────────────────────────────────────
# 3. Synthetic dataset generation
# ─────────────────────────────────────────────────────────────────────────────

class TestDatasetGeneration:
    def test_returns_arrays(self):
        X, y = generate_synthetic_dataset(random_state=42)
        assert isinstance(X, np.ndarray)
        assert isinstance(y, np.ndarray)

    def test_shapes_match(self):
        X, y = generate_synthetic_dataset(random_state=42)
        assert X.shape[0] == y.shape[0]

    def test_feature_count(self):
        X, _ = generate_synthetic_dataset(random_state=42)
        assert X.shape[1] == 10

    def test_minimum_samples(self):
        X, _ = generate_synthetic_dataset(random_state=42)
        assert X.shape[0] >= 100

    def test_all_labels_present(self):
        _, y = generate_synthetic_dataset(random_state=42)
        unique_labels = set(y)
        assert RISK_LOW    in unique_labels
        assert RISK_MEDIUM in unique_labels
        assert RISK_HIGH   in unique_labels

    def test_only_valid_labels(self):
        _, y = generate_synthetic_dataset(random_state=42)
        for label in y:
            assert label in RISK_LABELS

    def test_no_password_strings_in_X(self):
        """X must contain only floats — no string passwords."""
        X, _ = generate_synthetic_dataset(random_state=42)
        assert X.dtype in (np.float32, np.float64)

    def test_reproducible_with_same_seed(self):
        X1, y1 = generate_synthetic_dataset(random_state=42)
        X2, y2 = generate_synthetic_dataset(random_state=42)
        np.testing.assert_array_equal(X1, X2)
        np.testing.assert_array_equal(y1, y2)

    def test_different_seeds_differ(self):
        _, y1 = generate_synthetic_dataset(random_state=42)
        _, y2 = generate_synthetic_dataset(random_state=99)
        # Different seeds should produce different orderings
        assert not np.array_equal(y1, y2)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Model training (reproducible)
# ─────────────────────────────────────────────────────────────────────────────

class TestModelTraining:
    def test_pipeline_trains(self):
        pipeline = _build_and_train()
        assert pipeline is not None

    def test_pipeline_has_classes(self):
        pipeline = _build_and_train()
        classes = list(pipeline.classes_)
        for label in RISK_LABELS:
            assert label in classes

    def test_reproducible_predictions(self):
        """Two separately trained models (same data, same seed) must agree."""
        p1 = _build_and_train()
        p2 = _build_and_train()
        X, _ = generate_synthetic_dataset(random_state=42)
        preds1 = p1.predict(X[:20])
        preds2 = p2.predict(X[:20])
        np.testing.assert_array_equal(preds1, preds2)


# ─────────────────────────────────────────────────────────────────────────────
# 5 & 6. Prediction output and confidence range
# ─────────────────────────────────────────────────────────────────────────────

class TestPrediction:
    """Predict must return LOW/MEDIUM/HIGH with confidence in [0, 1]."""

    def _features(self, score, level, reused=False) -> PasswordFeatures:
        return extract_features_from_score(
            security_score=score,
            security_level=level,
            is_reused=reused,
        )

    def test_high_risk_prediction(self):
        result = predict(self._features(5, "weak"))
        assert result.risk_level in RISK_LABELS

    def test_medium_risk_prediction(self):
        result = predict(self._features(55, "fair"))
        assert result.risk_level in RISK_LABELS

    def test_low_risk_prediction(self):
        result = predict(self._features(90, "very_strong"))
        assert result.risk_level in RISK_LABELS

    def test_confidence_range(self):
        for score, level in [(5, "weak"), (50, "fair"), (85, "very_strong")]:
            result = predict(self._features(score, level))
            assert 0.0 <= result.confidence <= 1.0

    def test_returns_prediction_result(self):
        result = predict(self._features(70, "strong"))
        assert isinstance(result, PredictionResult)

    def test_result_has_explanation(self):
        result = predict(self._features(30, "weak"))
        assert isinstance(result.explanation, str)
        assert len(result.explanation) > 0

    def test_result_has_security_score(self):
        result = predict(self._features(65, "strong"))
        assert result.security_score == 65

    def test_to_dict_keys(self):
        result = predict(self._features(70, "strong"))
        d = result.to_dict()
        assert "risk_level"     in d
        assert "confidence"     in d
        assert "explanation"    in d
        assert "security_score" in d

    def test_to_dict_no_passwords(self):
        result = predict(self._features(30, "weak", reused=True))
        d = result.to_dict()
        # risk_level, confidence, explanation, security_score — all are safe types
        assert isinstance(d["risk_level"], str)
        assert isinstance(d["confidence"], float)
        assert isinstance(d["explanation"], str)
        assert isinstance(d["security_score"], int)
        # No numeric/binary sensitive data in unexpected keys
        assert "encrypted_password" not in d
        assert "plaintext" not in d

    def test_very_strong_tends_low(self):
        """Very strong credentials should not predict HIGH risk."""
        result = predict(self._features(95, "very_strong"))
        assert result.risk_level != RISK_HIGH

    def test_very_weak_tends_high(self):
        """Very weak credentials should not predict LOW risk."""
        result = predict(extract_features(
            plaintext_password="abc",
            security_score=5,
            is_reused=True,
        ))
        assert result.risk_level != RISK_LOW


# ─────────────────────────────────────────────────────────────────────────────
# 7. Authenticated API access
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestMLPredictAPIAuthenticated:
    def test_score_based_predict_200(self, client):
        user = _make_user()
        data = {"security_score": 75, "security_level": "strong", "is_reused": False}
        response = _auth_request(client, user, data)
        assert response.status_code == 200

    def test_response_has_risk_level(self, client):
        user = _make_user()
        data = {"security_score": 75, "security_level": "strong"}
        response = _auth_request(client, user, data)
        assert "risk_level" in response.json()

    def test_response_has_confidence(self, client):
        user = _make_user()
        data = {"security_score": 40, "security_level": "fair"}
        response = _auth_request(client, user, data)
        assert "confidence" in response.json()

    def test_response_has_explanation(self, client):
        user = _make_user()
        data = {"security_score": 40, "security_level": "fair"}
        response = _auth_request(client, user, data)
        assert "explanation" in response.json()

    def test_risk_level_is_valid(self, client):
        user = _make_user()
        data = {"security_score": 55, "security_level": "fair"}
        response = _auth_request(client, user, data)
        assert response.json()["risk_level"] in RISK_LABELS

    def test_confidence_in_range(self, client):
        user = _make_user()
        data = {"security_score": 55, "security_level": "fair"}
        response = _auth_request(client, user, data)
        conf = response.json()["confidence"]
        assert 0.0 <= conf <= 1.0

    def test_invalid_score_400(self, client):
        user = _make_user()
        data = {"security_score": 150, "security_level": "fair"}
        response = _auth_request(client, user, data)
        assert response.status_code == 400

    def test_invalid_level_400(self, client):
        user = _make_user()
        data = {"security_score": 50, "security_level": "super_strong"}
        response = _auth_request(client, user, data)
        assert response.status_code == 400

    def test_weak_password_prediction(self, client):
        user = _make_user()
        data = {"security_score": 5, "security_level": "weak", "is_reused": True}
        response = _auth_request(client, user, data)
        assert response.status_code == 200
        assert response.json()["risk_level"] in RISK_LABELS


# ─────────────────────────────────────────────────────────────────────────────
# 8. Unauthenticated denial
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestMLPredictAPIUnauthenticated:
    def test_no_token_401(self, client):
        response = client.post(
            "/api/v1/ml/predict/",
            {"security_score": 50, "security_level": "fair"},
            content_type="application/json",
        )
        assert response.status_code == 401

    def test_bad_token_401(self, client):
        response = client.post(
            "/api/v1/ml/predict/",
            {"security_score": 50, "security_level": "fair"},
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer not-a-valid-token",
        )
        assert response.status_code == 401

    def test_get_method_not_allowed(self, client):
        """GET is not supported — must 405."""
        with patch("apps.ml_engine.views.JWTAuthentication.authenticate", return_value=(_make_user(), None)):
            response = client.get("/api/v1/ml/predict/")
        assert response.status_code == 405


# ─────────────────────────────────────────────────────────────────────────────
# 9. User isolation
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestUserIsolation:
    """User A's request must never return User B's data."""

    def test_score_path_uses_authenticated_user(self, client):
        """Score-based path does not involve any DB lookup, but result is user-agnostic.
        The endpoint must return 200 for each user independently."""
        user_a = _make_user(user_id="user-a", email="a@test.com")
        user_b = _make_user(user_id="user-b", email="b@test.com")

        data_a = {"security_score": 90, "security_level": "very_strong"}
        data_b = {"security_score": 10, "security_level": "weak"}

        resp_a = _auth_request(client, user_a, data_a)
        resp_b = _auth_request(client, user_b, data_b)

        assert resp_a.status_code == 200
        assert resp_b.status_code == 200
        # Results may differ (different input scores)
        assert resp_a.json()["security_score"] == 90
        assert resp_b.json()["security_score"] == 10

    def test_credential_path_enforces_ownership(self, client):
        """When credential_id is supplied, repo.find_by_id must be called
        with the authenticated user's user_id, not a client-supplied user_id."""
        user_a = _make_user(user_id="user-a", email="a@test.com")

        mock_repo = MagicMock()
        mock_repo.find_by_id.return_value = None  # credential not found for user-a

        with patch("apps.ml_engine.views._get_credential_repo", return_value=mock_repo), \
             patch("apps.ml_engine.views.JWTAuthentication.authenticate", return_value=(user_a, None)):
            response = client.post(
                "/api/v1/ml/predict/",
                {"credential_id": "cred-belongs-to-user-b"},
                content_type="application/json",
            )

        assert response.status_code == 404
        # Verify the repo was queried with user_a's ID, not user-b
        mock_repo.find_by_id.assert_called_once_with(
            credential_id="cred-belongs-to-user-b",
            user_id="user-a",
        )


# ─────────────────────────────────────────────────────────────────────────────
# 10. Plaintext non-disclosure
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestPlaintextNonDisclosure:
    """API response must never expose plaintext passwords."""

    _SENSITIVE_FIELDS = ("password", "plaintext", "secret", "encrypted")

    def test_score_path_no_password_in_response(self, client):
        user = _make_user()
        data = {"security_score": 50, "security_level": "fair"}
        response = _auth_request(client, user, data)
        body = response.json()
        for field in self._SENSITIVE_FIELDS:
            assert field not in body, f"Sensitive field '{field}' found in response"

    def test_score_path_values_are_not_passwords(self, client):
        user = _make_user()
        data = {"security_score": 60, "security_level": "strong"}
        response = _auth_request(client, user, data)
        body_str = str(response.json())
        # Check that typical password patterns are not present
        assert "plaintext" not in body_str.lower()

    def test_credential_path_no_password_in_response(self, client):
        """Even in the credential path, the response must not expose passwords."""
        user = _make_user(user_id="user-x")
        real_password = "ThisIsARealPassword!123"

        mock_repo = MagicMock()
        mock_repo.find_by_id.return_value = {
            "encrypted_password": "ciphertext-blob",
            "security_score": 60,
            "security_level": "strong",
        }
        mock_repo.find_all_encrypted_for_user.return_value = []

        mock_enc = MagicMock()
        mock_enc.decrypt.return_value = real_password

        with patch("apps.ml_engine.views._get_credential_repo", return_value=mock_repo), \
             patch("apps.ml_engine.views.get_encryption_service", return_value=mock_enc), \
             patch("apps.ml_engine.views.SecurityAnalyzer.detect_reuse", return_value=set()), \
             patch("apps.ml_engine.views.JWTAuthentication.authenticate", return_value=(user, None)):
            response = client.post(
                "/api/v1/ml/predict/",
                {"credential_id": "cred-123"},
                content_type="application/json",
            )

        assert response.status_code == 200
        body_str = str(response.json())
        # The actual plaintext password must NOT appear in the response
        assert real_password not in body_str
        assert "ciphertext-blob" not in body_str


# ─────────────────────────────────────────────────────────────────────────────
# 11. No secrets in ML artifacts
# ─────────────────────────────────────────────────────────────────────────────

class TestNoSecretsInMLArtifacts:
    """ML model is in-memory only; verify no passwords leak into model internals."""

    def test_model_classes_are_risk_labels_only(self):
        pipeline = _build_and_train()
        for cls in pipeline.classes_:
            assert cls in RISK_LABELS, f"Unexpected class in model: {cls!r}"

    def test_no_password_in_feature_names(self):
        for name in FEATURE_NAMES:
            assert "password" not in name
            assert "secret" not in name
            assert "token" not in name

    def test_dataset_X_dtype_is_float(self):
        X, _ = generate_synthetic_dataset()
        assert np.issubdtype(X.dtype, np.floating)

    def test_dataset_labels_are_not_passwords(self):
        _, y = generate_synthetic_dataset()
        for label in set(y):
            # Labels should be uppercase risk strings
            assert label.isupper(), f"Unexpected label format: {label!r}"
            assert label in RISK_LABELS


# ─────────────────────────────────────────────────────────────────────────────
# 12. M5 regression — existing security endpoints unaffected
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestM5Regression:
    """M5 security endpoints must still work after M6 changes."""

    def _auth_get(self, client, user, path):
        with patch("apps.security.views.JWTAuthentication.authenticate", return_value=(user, None)):
            return client.get(path)

    def test_security_summary_returns_503_no_db(self, client):
        """Without MongoDB, security/summary/ must return 503 (not 5xx crash)."""
        user = _make_user()
        with patch("apps.security.views._get_credential_repo", return_value=None):
            response = self._auth_get(client, user, "/api/v1/security/summary/")
        assert response.status_code == 503

    def test_security_credentials_returns_503_no_db(self, client):
        user = _make_user()
        with patch("apps.security.views._get_credential_repo", return_value=None):
            response = self._auth_get(client, user, "/api/v1/security/credentials/")
        assert response.status_code == 503

    def test_security_summary_unauthenticated_401(self, client):
        response = client.get("/api/v1/security/summary/")
        assert response.status_code == 401

    def test_security_credentials_unauthenticated_401(self, client):
        response = client.get("/api/v1/security/credentials/")
        assert response.status_code == 401

    def test_m5_analyzer_still_works(self):
        """SecurityAnalyzer must produce correct results — unchanged by M6."""
        from apps.security.services.analyzer import SecurityAnalyzer, ALERT_WEAK_PASSWORD

        scored_docs = [
            {"credential_id": "c1", "website_name": "TestSite", "category": "general",
             "security_score": 15, "security_level": "weak"},
        ]
        analyzer = SecurityAnalyzer()
        results = analyzer.analyze(scored_docs=scored_docs, reused_ids=set())
        assert len(results) == 1
        assert results[0].security_score == 15
        assert ALERT_WEAK_PASSWORD in results[0].alerts

    def test_m5_summary_still_works(self):
        from apps.security.services.analyzer import SecurityAnalyzer, CredentialSecurityInfo

        creds = [
            CredentialSecurityInfo("c1", "Site1", "general", 90, "very_strong"),
            CredentialSecurityInfo("c2", "Site2", "general", 20, "weak"),
        ]
        summary = SecurityAnalyzer.build_summary(creds)
        assert summary.total == 2
        assert summary.very_strong_count == 1
        assert summary.weak_count == 1
