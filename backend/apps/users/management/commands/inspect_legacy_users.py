"""Management command to inspect legacy MongoDB user accounts.

SAFETY RULES:
- Read-only by default (dry-run).
- Never automatically marks unverified or legacy accounts as verified.
- Preserves all password hashes, user IDs, and audit records unchanged.
- With --apply: backfills missing fields (email_verified=False, account_status="pending_verification")
  strictly for documents where email_verified is missing entirely ($exists: False).
"""
from django.core.management.base import BaseCommand, CommandError

from apps.common.database import get_db


class Command(BaseCommand):
    help = "Inspect MongoDB user accounts and report legacy accounts missing email_verified."

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Backfill missing fields with email_verified=False and account_status='pending_verification'. Never marks accounts as verified.",
        )

    def handle(self, *args, **options):
        db = get_db()
        if db is None:
            raise CommandError("MongoDB is not configured or unavailable.")

        users_col = db["users"]
        total_users = users_col.count_documents({})
        verified_count = users_col.count_documents({"email_verified": True})
        explicit_unverified = users_col.count_documents({"email_verified": False})
        missing_verified_field = users_col.count_documents({"email_verified": {"$exists": False}})

        self.stdout.write(self.style.NOTICE("=== User Account Verification Audit ==="))
        self.stdout.write(f"Total user accounts:              {total_users}")
        self.stdout.write(f"Verified accounts (email_verified=True):  {verified_count}")
        self.stdout.write(f"Unverified accounts (email_verified=False): {explicit_unverified}")
        self.stdout.write(f"Legacy accounts (missing field):  {missing_verified_field}")

        if missing_verified_field == 0:
            self.stdout.write(self.style.SUCCESS("All user documents have explicit email_verified fields."))
            return

        if not options["apply"]:
            self.stdout.write(self.style.WARNING(
                f"\nFound {missing_verified_field} legacy account(s) without email_verified field.\n"
                "By security policy, legacy accounts fail closed at login and must re-verify via email.\n"
                "To backfill missing fields explicitly with email_verified=False, re-run with --apply."
            ))
            return

        result = users_col.update_many(
            {"email_verified": {"$exists": False}},
            {
                "$set": {
                    "email_verified": False,
                    "account_status": "pending_verification",
                }
            },
        )
        self.stdout.write(self.style.SUCCESS(
            f"Successfully updated {result.modified_count} legacy account(s) to email_verified=False."
        ))
