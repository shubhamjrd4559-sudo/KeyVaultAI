"""Security Engine — pure deterministic analyzer.

Operates on already-scored credential metadata (security_score, security_level)
from the vault, plus decrypted password hashes for reuse detection.

CRITICAL security invariants:
1. Plaintext passwords are NEVER stored, returned, or logged here.
2. Reuse detection uses in-memory SHA-256 hashes only — hashes are discarded
   after the analysis call completes.
3. All analysis is scoped to a single user_id supplied by the authenticated JWT.
4. This module has zero side effects — it is a pure input→output computation.
5. No external network calls, no ML, no AI — fully deterministic.
"""
import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Score thresholds — must match vault/models/__init__.py ───────────────────
# weak: 0-39, fair: 40-59, strong: 60-79, very_strong: 80-100
_THRESHOLD_WEAK   = 40
_THRESHOLD_FAIR   = 60
_THRESHOLD_STRONG = 80

# Alert type constants — safe string labels, never contain passwords
ALERT_WEAK_PASSWORD   = "weak_password"
ALERT_REUSED_PASSWORD = "reused_password"
ALERT_LOW_SCORE       = "low_security_score"


# ── Data types ────────────────────────────────────────────────────────────────

class CredentialSecurityInfo:
    """Immutable security result for a single credential.

    Never contains a plaintext or encrypted password.
    """

    __slots__ = (
        "credential_id",
        "website_name",
        "category",
        "security_score",
        "security_level",
        "is_reused",
        "alerts",
    )

    def __init__(
        self,
        credential_id: str,
        website_name: str,
        category: str,
        security_score: int,
        security_level: str,
        is_reused: bool = False,
        alerts: Optional[list[str]] = None,
    ) -> None:
        self.credential_id  = credential_id
        self.website_name   = website_name
        self.category       = category
        self.security_score = security_score
        self.security_level = security_level
        self.is_reused      = is_reused
        self.alerts         = alerts or []

    def to_dict(self) -> dict:
        """Safe serializable representation — no passwords, no ciphertext."""
        return {
            "credential_id":  self.credential_id,
            "website_name":   self.website_name,
            "category":       self.category,
            "security_score": self.security_score,
            "security_level": self.security_level,
            "is_reused":      self.is_reused,
            "alerts":         self.alerts,
        }


class SecuritySummary:
    """Aggregate security posture for the authenticated user's vault."""

    __slots__ = (
        "total",
        "very_strong_count",
        "strong_count",
        "fair_count",
        "weak_count",
        "reused_count",
        "average_score",
        "overall_score",
        "overall_level",
    )

    def __init__(
        self,
        total: int,
        very_strong_count: int,
        strong_count: int,
        fair_count: int,
        weak_count: int,
        reused_count: int,
        average_score: float,
        overall_score: int,
        overall_level: str,
    ) -> None:
        self.total            = total
        self.very_strong_count = very_strong_count
        self.strong_count     = strong_count
        self.fair_count       = fair_count
        self.weak_count       = weak_count
        self.reused_count     = reused_count
        self.average_score    = average_score
        self.overall_score    = overall_score
        self.overall_level    = overall_level

    def to_dict(self) -> dict:
        return {
            "total":             self.total,
            "very_strong_count": self.very_strong_count,
            "strong_count":      self.strong_count,
            "fair_count":        self.fair_count,
            "weak_count":        self.weak_count,
            "reused_count":      self.reused_count,
            "average_score":     round(self.average_score, 1),
            "overall_score":     self.overall_score,
            "overall_level":     self.overall_level,
        }


# ── Analyzer ──────────────────────────────────────────────────────────────────

class SecurityAnalyzer:
    """Deterministic, self-contained security analysis for a user's vault.

    Dependencies are injected so this class is independently unit-testable
    without a running database.

    Usage:
        analyzer = SecurityAnalyzer()
        credentials = analyzer.analyze(scored_docs, encrypted_docs, decrypt_fn)
        summary = analyzer.build_summary(credentials)
    """

    # ── Reuse detection ───────────────────────────────────────────────────────

    @staticmethod
    def _hash_password(plaintext: str) -> str:
        """Return a SHA-256 hex digest of the plaintext password.

        The digest is used only for equality comparison inside a single
        analyze() call. It is never stored, logged, or returned.
        """
        return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    @staticmethod
    def detect_reuse(
        encrypted_items: list[dict],
        decrypt_fn,
    ) -> set[str]:
        """Return the set of credential_ids that reuse a password shared by
        at least one other credential in the same user's vault.

        Args:
            encrypted_items: List of dicts with keys:
                - credential_id (str)
                - encrypted_password (str)  ← ciphertext from MongoDB
            decrypt_fn: Callable[str] -> str  — the EncryptionService.decrypt method.
                        Called for each item. Plaintext is hashed immediately and
                        the local reference is deleted.

        Returns:
            A set of credential_ids that are flagged for password reuse.
            Passwords are NEVER stored or returned.

        Security:
            - Plaintext exists only within the for-loop body scope.
            - Hashes are stored in a local dict; discarded when detect_reuse returns.
            - No hash is returned to callers.
        """
        # Map: password_hash → list[credential_id]
        hash_to_ids: dict[str, list[str]] = {}

        for item in encrypted_items:
            cid = item["credential_id"]
            encrypted = item["encrypted_password"]
            try:
                plaintext = decrypt_fn(encrypted)
                pw_hash = SecurityAnalyzer._hash_password(plaintext)
                plaintext = None  # best-effort clear  # noqa: F841
            except Exception:
                logger.warning(
                    "Could not decrypt credential %s during reuse analysis.", cid
                )
                continue

            if pw_hash not in hash_to_ids:
                hash_to_ids[pw_hash] = []
            hash_to_ids[pw_hash].append(cid)

        # Collect all credential_ids that share a hash with at least one other
        reused: set[str] = set()
        for ids in hash_to_ids.values():
            if len(ids) > 1:
                reused.update(ids)

        # Discard the hash map — hashes must not persist beyond this method
        hash_to_ids.clear()
        return reused

    # ── Alert generation ──────────────────────────────────────────────────────

    @staticmethod
    def build_alerts(score: int, level: str, is_reused: bool) -> list[str]:
        """Return safe alert labels for a credential.

        Alert labels are strings that describe the issue category.
        They NEVER contain passwords, usernames, or sensitive data.
        """
        alerts: list[str] = []
        if level == "weak":
            alerts.append(ALERT_WEAK_PASSWORD)
        if score < _THRESHOLD_WEAK:
            alerts.append(ALERT_LOW_SCORE)
        if is_reused:
            alerts.append(ALERT_REUSED_PASSWORD)
        return list(dict.fromkeys(alerts))  # deduplicate, preserve order

    # ── Per-credential analysis ───────────────────────────────────────────────

    def analyze(
        self,
        scored_docs: list[dict],
        reused_ids: set[str],
    ) -> list[CredentialSecurityInfo]:
        """Build CredentialSecurityInfo for each credential.

        Args:
            scored_docs:  List of dicts from the vault repository list projection.
                          Each doc must have: credential_id, website_name,
                          category, security_score, security_level.
                          No password field is present or expected.
            reused_ids:   Set of credential_ids flagged for password reuse.
                          Produced by detect_reuse() — must be called separately
                          so that the decrypt operation has a clear scope.

        Returns:
            List of CredentialSecurityInfo — safe for serialization.
        """
        results: list[CredentialSecurityInfo] = []
        for doc in scored_docs:
            cid   = doc["credential_id"]
            score = doc.get("security_score", 0)
            level = doc.get("security_level", "weak")
            is_reused = cid in reused_ids

            alerts = self.build_alerts(score, level, is_reused)

            results.append(
                CredentialSecurityInfo(
                    credential_id=cid,
                    website_name=doc.get("website_name", ""),
                    category=doc.get("category", "general"),
                    security_score=score,
                    security_level=level,
                    is_reused=is_reused,
                    alerts=alerts,
                )
            )
        return results

    # ── Summary ───────────────────────────────────────────────────────────────

    @staticmethod
    def build_summary(credentials: list[CredentialSecurityInfo]) -> SecuritySummary:
        """Compute aggregate security metrics for the user's vault.

        Does not touch any password data — operates on CredentialSecurityInfo
        objects that already contain no password fields.
        """
        total = len(credentials)
        if total == 0:
            return SecuritySummary(
                total=0,
                very_strong_count=0,
                strong_count=0,
                fair_count=0,
                weak_count=0,
                reused_count=0,
                average_score=0.0,
                overall_score=0,
                overall_level="weak",
            )

        very_strong_count = sum(1 for c in credentials if c.security_level == "very_strong")
        strong_count      = sum(1 for c in credentials if c.security_level == "strong")
        fair_count        = sum(1 for c in credentials if c.security_level == "fair")
        weak_count        = sum(1 for c in credentials if c.security_level == "weak")
        reused_count      = sum(1 for c in credentials if c.is_reused)

        total_score   = sum(c.security_score for c in credentials)
        average_score = total_score / total

        # Overall score: penalise reuse (−5 per reused credential, max −20)
        reuse_penalty = min(reused_count * 5, 20)
        overall_score = max(0, round(average_score) - reuse_penalty)

        # Map overall_score to level
        if overall_score >= _THRESHOLD_STRONG:
            overall_level = "very_strong"
        elif overall_score >= _THRESHOLD_FAIR:
            overall_level = "strong"
        elif overall_score >= _THRESHOLD_WEAK:
            overall_level = "fair"
        else:
            overall_level = "weak"

        return SecuritySummary(
            total=total,
            very_strong_count=very_strong_count,
            strong_count=strong_count,
            fair_count=fair_count,
            weak_count=weak_count,
            reused_count=reused_count,
            average_score=average_score,
            overall_score=overall_score,
            overall_level=overall_level,
        )
