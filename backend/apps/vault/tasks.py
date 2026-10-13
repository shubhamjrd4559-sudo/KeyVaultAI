"""Celery tasks for vault maintenance.

SECURITY:
- permanent_delete_expired_credentials is idempotent and safe.
- Only credentials with is_deleted=True AND deleted_at older than 72 hours are removed.
- Active credentials (is_deleted != True) are NEVER affected.
- Restored credentials (is_deleted=False) are NEVER affected.
- No passwords are decrypted or logged during cleanup.

PRODUCTION REQUIREMENT:
  This task must be scheduled via Celery Beat with a periodic trigger, e.g.:

    from celery.schedules import crontab
    CELERY_BEAT_SCHEDULE = {
        'cleanup-expired-deleted-credentials': {
            'task': 'apps.vault.tasks.permanent_delete_expired_credentials',
            'schedule': crontab(minute=0, hour='*/1'),  # every hour
        },
    }

  In local development without a running Celery worker + Beat, this cleanup
  will not run automatically. You may trigger it manually with:
    celery -A config.celery call apps.vault.tasks.permanent_delete_expired_credentials
"""
import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def permanent_delete_expired_credentials(self):
    """Idempotent cleanup: permanently remove credentials soft-deleted > 72 hours ago.

    Safe to run multiple times. Only affects credentials where:
      - is_deleted == True
      - deleted_at <= now() - 72 hours

    Active credentials and restored credentials are NEVER touched.
    No passwords are decrypted or logged.

    Returns:
        int: count of permanently deleted credentials.
    """
    try:
        from apps.common.database import get_db
        from apps.vault.repositories.credentials import CredentialRepository

        db = get_db()
        if db is None:
            logger.warning(
                "[vault-cleanup] MongoDB not available — skipping expired credential cleanup."
            )
            return 0

        repo = CredentialRepository(db)
        count = repo.permanent_delete_expired()
        if count > 0:
            logger.info(
                "[vault-cleanup] Permanently deleted %d expired soft-deleted credential(s).",
                count,
            )
        else:
            logger.debug("[vault-cleanup] No expired soft-deleted credentials found.")
        return count
    except Exception as exc:
        logger.exception("[vault-cleanup] Unexpected error during expired credential cleanup.")
        raise self.retry(exc=exc)
