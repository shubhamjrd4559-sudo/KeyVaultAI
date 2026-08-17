"""Synthetic training dataset generator for the M6 ML Engine.

PRIVACY GUARANTEE:
  - No real passwords are used.
  - No real user data is used.
  - Dataset is generated entirely from deterministic mathematical rules.
  - Dataset is generated in memory at import/train time — NOT persisted to disk.
  - ML model artifacts (joblib files) are explicitly checked to never contain
    password strings (they only hold float arrays + metadata).

Dataset structure:
  X: (n_samples, 10) float array of derived features (see features.FEATURE_NAMES)
  y: (n_samples,) string array of risk labels — "LOW" | "MEDIUM" | "HIGH"

Label semantics:
  LOW    → password is strong, unique, no obvious patterns
  MEDIUM → moderate strength or a single risk factor (e.g. reuse, no special chars)
  HIGH   → weak password, obvious pattern, or reused with low score

Dataset is intentionally small (≈ 300 samples) for zero-dependency local training.
"""

import numpy as np

# Risk label constants — uppercase to distinguish from M5 security_level strings
RISK_LOW    = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH   = "HIGH"
RISK_LABELS = [RISK_LOW, RISK_MEDIUM, RISK_HIGH]


def generate_synthetic_dataset(
    *,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate a small synthetic dataset of password-derived features + risk labels.

    All values are purely synthetic — no real passwords or user data.

    Returns:
        X: np.ndarray of shape (n_samples, 10), dtype float32
        y: np.ndarray of shape (n_samples,), dtype str

    Feature columns (see features.FEATURE_NAMES):
        0: length
        1: has_lower
        2: has_upper
        3: has_digit
        4: has_special
        5: char_diversity
        6: has_repeat_run
        7: has_obvious_pattern
        8: security_score
        9: is_reused
    """
    rng = np.random.default_rng(random_state)

    rows: list[list[float]] = []
    labels: list[str] = []

    def _add(features: list[float], label: str, repeat: int = 1) -> None:
        for _ in range(repeat):
            rows.append(features)
            labels.append(label)

    # ── HIGH risk examples ────────────────────────────────────────────────────
    # Very short, no variety, obvious pattern
    _add([4,  1, 0, 0, 0, 0.75, 0, 1,  5,  0], RISK_HIGH,   repeat=8)
    _add([6,  1, 0, 1, 0, 0.67, 0, 1,  10, 0], RISK_HIGH,   repeat=8)
    _add([5,  0, 0, 1, 0, 0.80, 0, 1,  8,  0], RISK_HIGH,   repeat=8)
    # Repeat runs present
    _add([8,  1, 0, 0, 0, 0.50, 1, 0,  15, 0], RISK_HIGH,   repeat=8)
    _add([7,  1, 0, 1, 0, 0.57, 1, 1,  12, 0], RISK_HIGH,   repeat=8)
    # Reused + weak
    _add([6,  1, 0, 0, 0, 0.67, 0, 0,  20, 1], RISK_HIGH,   repeat=8)
    _add([8,  1, 0, 1, 0, 0.63, 0, 0,  30, 1], RISK_HIGH,   repeat=8)
    # Very low score regardless of length
    _add([12, 1, 0, 0, 0, 0.75, 0, 1,  5,  0], RISK_HIGH,   repeat=8)
    _add([10, 1, 0, 0, 0, 0.80, 1, 0,  10, 0], RISK_HIGH,   repeat=8)
    # Numeric noise — slightly varied
    for _ in range(20):
        length     = int(rng.integers(4, 9))
        score      = int(rng.integers(0, 35))
        reused     = int(rng.integers(0, 2))
        diversity  = round(float(rng.uniform(0.3, 0.7)), 4)
        has_repeat = int(rng.integers(0, 2))
        has_obv    = int(rng.integers(0, 2))
        _add([length, 1, 0, 1, 0, diversity, has_repeat, has_obv, score, reused], RISK_HIGH)

    # ── MEDIUM risk examples ──────────────────────────────────────────────────
    # Moderate length, some diversity, no pattern, not reused
    _add([10, 1, 1, 1, 0, 0.80, 0, 0, 50, 0], RISK_MEDIUM,  repeat=8)
    _add([12, 1, 0, 1, 1, 0.75, 0, 0, 55, 0], RISK_MEDIUM,  repeat=8)
    _add([11, 1, 1, 0, 1, 0.82, 0, 0, 48, 0], RISK_MEDIUM,  repeat=8)
    # Good length but reused
    _add([14, 1, 1, 1, 0, 0.86, 0, 0, 60, 1], RISK_MEDIUM,  repeat=8)
    _add([16, 1, 1, 1, 0, 0.88, 0, 0, 65, 1], RISK_MEDIUM,  repeat=8)
    # Decent score, no special chars
    _add([13, 1, 1, 1, 0, 0.85, 0, 0, 57, 0], RISK_MEDIUM,  repeat=8)
    _add([10, 1, 1, 0, 1, 0.90, 0, 0, 52, 0], RISK_MEDIUM,  repeat=8)
    # Slight repeat but otherwise good
    _add([14, 1, 1, 1, 0, 0.79, 1, 0, 55, 0], RISK_MEDIUM,  repeat=8)
    # Numeric noise
    for _ in range(20):
        length    = int(rng.integers(8, 16))
        score     = int(rng.integers(35, 65))
        reused    = int(rng.integers(0, 2))
        diversity = round(float(rng.uniform(0.60, 0.90)), 4)
        _add([length, 1, 1, 1, 0, diversity, 0, 0, score, reused], RISK_MEDIUM)

    # ── LOW risk examples ─────────────────────────────────────────────────────
    # Long, all character classes, high diversity, no patterns, not reused
    _add([20, 1, 1, 1, 1, 0.95, 0, 0, 90,  0], RISK_LOW,   repeat=8)
    _add([18, 1, 1, 1, 1, 0.94, 0, 0, 85,  0], RISK_LOW,   repeat=8)
    _add([16, 1, 1, 1, 1, 0.94, 0, 0, 80,  0], RISK_LOW,   repeat=8)
    _add([22, 1, 1, 1, 1, 0.96, 0, 0, 95,  0], RISK_LOW,   repeat=8)
    _add([24, 1, 1, 1, 1, 0.96, 0, 0, 100, 0], RISK_LOW,   repeat=8)
    _add([17, 1, 1, 1, 1, 0.94, 0, 0, 83,  0], RISK_LOW,   repeat=8)
    _add([19, 1, 1, 1, 1, 0.95, 0, 0, 88,  0], RISK_LOW,   repeat=8)
    _add([15, 1, 1, 1, 0, 0.93, 0, 0, 75,  0], RISK_LOW,   repeat=8)
    # Numeric noise
    for _ in range(20):
        length    = int(rng.integers(16, 30))
        score     = int(rng.integers(70, 101))
        diversity = round(float(rng.uniform(0.85, 1.00)), 4)
        _add([length, 1, 1, 1, 1, diversity, 0, 0, score, 0], RISK_LOW)

    X = np.array(rows, dtype=np.float32)
    y = np.array(labels, dtype=object)

    # Shuffle
    idx = rng.permutation(len(y))
    return X[idx], y[idx]
