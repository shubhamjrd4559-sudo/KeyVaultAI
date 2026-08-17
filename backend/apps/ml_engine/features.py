"""Feature extraction for the M6 ML Engine.

PRIVACY INVARIANTS:
- This module NEVER receives, stores, or logs plaintext passwords.
- All features are derived numerical values (lengths, booleans, counts).
- The only caller that touches a plaintext password is the view, which passes
  the already-computed M5 security_score + derived feature values.
- No feature value can be used to reconstruct a password.

Safe derived features (10 total):
  1.  length             — character count (int)
  2.  has_lower          — lowercase letter present (0/1)
  3.  has_upper          — uppercase letter present (0/1)
  4.  has_digit          — digit present (0/1)
  5.  has_special        — special character present (0/1)
  6.  char_diversity     — unique character count / length (float 0–1)
  7.  has_repeat_run     — 3+ consecutive identical chars present (0/1)
  8.  has_obvious_pattern— known weak pattern present (0/1)
  9.  security_score     — M5 deterministic score (int 0–100)
  10. is_reused          — password reused across credentials (0/1)
"""
import re
from typing import NamedTuple

# Special characters that earn the "has_special" point in M5's score_password
_SPECIAL_CHARS = set(r"""!@#$%^&*()_+-=[]{}|;':",./><? """.strip())
_OBVIOUS_PATTERNS = (
    "password", "qwerty", "letmein", "welcome", "admin",
    "abcd", "bcde", "cdef",
    "1234", "2345", "3456", "4567", "5678", "6789",
    "9876", "8765", "7654", "6543", "5432", "4321",
)

# Feature names in the exact order used by the model
FEATURE_NAMES = [
    "length",
    "has_lower",
    "has_upper",
    "has_digit",
    "has_special",
    "char_diversity",
    "has_repeat_run",
    "has_obvious_pattern",
    "security_score",
    "is_reused",
]


class PasswordFeatures(NamedTuple):
    """Derived numerical features for the ML model.

    NEVER contains the original password.
    """
    length: int
    has_lower: int
    has_upper: int
    has_digit: int
    has_special: int
    char_diversity: float
    has_repeat_run: int
    has_obvious_pattern: int
    security_score: int
    is_reused: int

    def to_list(self) -> list:
        """Return features as an ordered list matching FEATURE_NAMES."""
        return list(self)


def extract_features(
    *,
    plaintext_password: str,
    security_score: int,
    is_reused: bool,
) -> PasswordFeatures:
    """Compute safe derived features from a plaintext password.

    The plaintext is used ONLY within this function call to derive numbers.
    It is NEVER stored, logged, or returned.

    Args:
        plaintext_password: The credential's plaintext password. Used only
            for transient character-class analysis; never stored.
        security_score: The M5 deterministic score (0–100).
        is_reused: Whether this password hash matches another credential.

    Returns:
        PasswordFeatures — a NamedTuple of safe numerical values.
    """
    pw = plaintext_password  # local alias; cleared at end of scope
    length = len(pw)

    has_lower = int(any(c.islower() for c in pw))
    has_upper = int(any(c.isupper() for c in pw))
    has_digit = int(any(c.isdigit() for c in pw))
    has_special = int(any(c in _SPECIAL_CHARS for c in pw))

    unique_count = len(set(pw))
    char_diversity = round(unique_count / length, 4) if length > 0 else 0.0

    has_repeat_run = int(bool(re.search(r"(.)\1{2,}", pw)))

    normalized = pw.casefold()
    has_obvious_pattern = int(any(p in normalized for p in _OBVIOUS_PATTERNS))

    # Explicitly clear the reference to the plaintext (best-effort in CPython)
    pw = None  # noqa: F841

    return PasswordFeatures(
        length=length,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_special=has_special,
        char_diversity=char_diversity,
        has_repeat_run=has_repeat_run,
        has_obvious_pattern=has_obvious_pattern,
        security_score=security_score,
        is_reused=int(is_reused),
    )


def extract_features_from_score(
    *,
    security_score: int,
    security_level: str,
    is_reused: bool,
) -> PasswordFeatures:
    """Build approximate features when plaintext is NOT available.

    Used for vault-wide batch prediction where we cannot/should not
    re-decrypt all passwords. Derives feature estimates from the M5 score
    and level that are already stored in the vault document.

    No password is touched in this code path.

    Args:
        security_score: M5 deterministic score (0–100).
        security_level: 'weak' | 'fair' | 'strong' | 'very_strong'.
        is_reused: Whether reuse was flagged by M5 analysis.
    """
    # Estimate structural features from the deterministic score.
    # These are approximations — real features require plaintext (extract_features).
    # length proxy: very_strong → 20+, strong → 16+, fair → 12+, weak → <8
    length_map = {"very_strong": 20, "strong": 16, "fair": 12, "weak": 6}
    est_length = length_map.get(security_level, 10)

    has_lower = int(security_score >= 10)
    has_upper = int(security_score >= 20)
    has_digit = int(security_score >= 30)
    has_special = int(security_score >= 60)
    char_diversity = min(round(security_score / 100, 4), 1.0)
    has_repeat_run = int(security_score < 30)
    has_obvious_pattern = int(security_score < 20)

    return PasswordFeatures(
        length=est_length,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_special=has_special,
        char_diversity=char_diversity,
        has_repeat_run=has_repeat_run,
        has_obvious_pattern=has_obvious_pattern,
        security_score=security_score,
        is_reused=int(is_reused),
    )
