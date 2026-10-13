"""Explicitly inspect and initialize MongoDB application indexes."""
from django.core.management.base import BaseCommand, CommandError

from apps.common.database import get_db
from apps.users.repositories.users import UserRepository
from apps.vault.repositories.credentials import CredentialRepository


class Command(BaseCommand):
    help = "Preflight and, only with --apply, create required MongoDB indexes."

    UNIQUE_FIELDS = (
        ("users", "email"),
        ("users", "user_id"),
        ("refresh_tokens", "jti"),
        ("email_verification_tokens", "token_hash"),
        ("password_reset_tokens", "token_hash"),
        ("credentials", "credential_id"),
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Create indexes after duplicate-key preflight. Without this flag, perform a read-only preflight.",
        )

    def handle(self, *args, **options):
        db = get_db()
        if db is None:
            raise CommandError("MongoDB is not configured.")

        duplicates = []
        for collection_name, field in self.UNIQUE_FIELDS:
            pipeline = [
                {"$group": {"_id": f"${field}", "count": {"$sum": 1}}},
                {"$match": {"count": {"$gt": 1}}},
                {"$limit": 1},
            ]
            if next(db[collection_name].aggregate(pipeline), None) is not None:
                duplicates.append(f"{collection_name}.{field}")

        if duplicates:
            raise CommandError(
                "Duplicate values prevent unique index creation in: "
                + ", ".join(duplicates)
                + ". Resolve them with an approved data-cleanup procedure first."
            )

        if not options["apply"]:
            self.stdout.write(self.style.WARNING(
                "Preflight passed. No indexes were created. Rerun with --apply only after approval."
            ))
            return

        UserRepository(db).ensure_indexes()
        CredentialRepository(db).ensure_indexes()
        self.stdout.write(self.style.SUCCESS("MongoDB indexes created or already present."))
