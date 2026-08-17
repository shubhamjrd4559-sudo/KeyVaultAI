"""ML model training and prediction for the M6 ML Engine.

Model: LogisticRegression (scikit-learn)
  - Lightweight, explainable, no GPU required.
  - Fixed random_state=42 for reproducibility.
  - Trained on the synthetic dataset (dataset.py) at first call.
  - Model is cached in memory — NOT serialised to disk by default, which
    avoids any risk of persisting sensitive data in model artifacts.

Outputs:
  risk_level  : "LOW" | "MEDIUM" | "HIGH"
  confidence  : float in [0.0, 1.0] — probability of predicted class
  explanation : short human-readable string safe for display

Privacy invariants:
  - Model weights are float arrays learned from synthetic data only.
  - No password text ever enters the model's train/predict path.
  - Plaintext passwords are NOT passed here; features.py extracts numbers.
"""
import logging
import threading
from typing import Optional

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from .dataset import RISK_HIGH, RISK_LABELS, RISK_LOW, RISK_MEDIUM, generate_synthetic_dataset
from .features import FEATURE_NAMES, PasswordFeatures

logger = logging.getLogger(__name__)

# ── Risk level ordering (for explanations) ───────────────────────────────────
_RISK_ORDER = {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2}

# ── Thread-safe singleton ─────────────────────────────────────────────────────
_model_lock = threading.Lock()
_pipeline: Optional[Pipeline] = None


def _build_and_train() -> Pipeline:
    """Train a LogisticRegression pipeline on the synthetic dataset.

    Called once per process. Result is cached in _pipeline.

    Returns:
        A fitted sklearn Pipeline (StandardScaler → LogisticRegression).
    """
    X, y = generate_synthetic_dataset(random_state=42)

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            random_state=42,
            max_iter=1000,
            solver="lbfgs",
            C=1.0,
        )),
    ])
    pipeline.fit(X, y)
    logger.info(
        "M6 ML Engine: LogisticRegression trained on %d synthetic samples. "
        "Classes: %s",
        len(y),
        list(pipeline.classes_),
    )
    return pipeline


def get_model() -> Pipeline:
    """Return the cached (or freshly trained) ML pipeline.

    Thread-safe via a module-level lock. Training happens once per process.
    """
    global _pipeline
    if _pipeline is None:
        with _model_lock:
            if _pipeline is None:
                _pipeline = _build_and_train()
    return _pipeline


# ── Prediction result ─────────────────────────────────────────────────────────

class PredictionResult:
    """Safe, serialisable ML prediction result.

    NEVER contains passwords, usernames, or other sensitive data.
    """

    __slots__ = ("risk_level", "confidence", "explanation", "security_score")

    def __init__(
        self,
        risk_level: str,
        confidence: float,
        explanation: str,
        security_score: int,
    ) -> None:
        self.risk_level    = risk_level
        self.confidence    = confidence
        self.explanation   = explanation
        self.security_score = security_score

    def to_dict(self) -> dict:
        return {
            "risk_level":     self.risk_level,
            "confidence":     round(self.confidence, 4),
            "explanation":    self.explanation,
            "security_score": self.security_score,
        }


def _build_explanation(
    risk_level: str,
    features: PasswordFeatures,
) -> str:
    """Return a short, safe explanation of the risk prediction.

    Only references feature values (numbers / booleans) — never the password.
    """
    if risk_level == RISK_HIGH:
        reasons = []
        if features.security_score < 30:
            reasons.append("very low deterministic score")
        if features.has_obvious_pattern:
            reasons.append("obvious pattern detected")
        if features.has_repeat_run:
            reasons.append("repeated characters")
        if features.is_reused:
            reasons.append("password reused")
        if features.length < 8:
            reasons.append(f"short length ({features.length} chars)")
        return "High risk: " + (", ".join(reasons) if reasons else "multiple weak indicators")

    if risk_level == RISK_MEDIUM:
        reasons = []
        if not features.has_special:
            reasons.append("no special characters")
        if features.is_reused:
            reasons.append("password reused across credentials")
        if features.security_score < 55:
            reasons.append("moderate score")
        if features.char_diversity < 0.70:
            reasons.append("low character diversity")
        return "Medium risk: " + (", ".join(reasons) if reasons else "moderate strength indicators")

    # LOW
    reasons = []
    if features.security_score >= 80:
        reasons.append(f"high score ({features.security_score}/100)")
    if features.length >= 16:
        reasons.append(f"good length ({features.length} chars)")
    if features.has_special:
        reasons.append("special characters present")
    return "Low risk: " + (", ".join(reasons) if reasons else "strong password indicators")


def predict(features: PasswordFeatures) -> PredictionResult:
    """Run the ML model on a PasswordFeatures vector.

    Args:
        features: A PasswordFeatures NamedTuple — safe numerical values only.

    Returns:
        PredictionResult with risk_level, confidence, explanation, security_score.

    Raises:
        RuntimeError: If the model fails unexpectedly (caller should handle).
    """
    model = get_model()
    X = np.array([features.to_list()], dtype=np.float32)

    risk_level: str = model.predict(X)[0]
    probabilities   = model.predict_proba(X)[0]
    classes         = list(model.classes_)

    confidence = float(probabilities[classes.index(risk_level)])

    explanation = _build_explanation(risk_level, features)

    return PredictionResult(
        risk_level=risk_level,
        confidence=round(confidence, 4),
        explanation=explanation,
        security_score=features.security_score,
    )
