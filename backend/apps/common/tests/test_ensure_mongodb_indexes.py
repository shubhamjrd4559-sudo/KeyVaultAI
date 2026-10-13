from unittest.mock import MagicMock, patch

import pytest
from django.core.management import call_command, CommandError


def test_index_command_defaults_to_read_only_preflight():
    db = MagicMock()
    db.__getitem__.return_value.aggregate.return_value = iter([])
    with patch("apps.common.management.commands.ensure_mongodb_indexes.get_db", return_value=db), \
         patch("apps.common.management.commands.ensure_mongodb_indexes.UserRepository.ensure_indexes") as users, \
         patch("apps.common.management.commands.ensure_mongodb_indexes.CredentialRepository.ensure_indexes") as credentials:
        call_command("ensure_mongodb_indexes", stdout=MagicMock())
    users.assert_not_called()
    credentials.assert_not_called()


def test_index_command_apply_requires_explicit_flag():
    db = MagicMock()
    db.__getitem__.return_value.aggregate.return_value = iter([])
    with patch("apps.common.management.commands.ensure_mongodb_indexes.get_db", return_value=db), \
         patch("apps.common.management.commands.ensure_mongodb_indexes.UserRepository.ensure_indexes") as users, \
         patch("apps.common.management.commands.ensure_mongodb_indexes.CredentialRepository.ensure_indexes") as credentials:
        call_command("ensure_mongodb_indexes", apply=True, stdout=MagicMock())
    users.assert_called_once()
    credentials.assert_called_once()


def test_index_preflight_refuses_duplicate_unique_values():
    db = MagicMock()
    db.__getitem__.return_value.aggregate.return_value = iter([{"_id": "duplicate", "count": 2}])
    with patch("apps.common.management.commands.ensure_mongodb_indexes.get_db", return_value=db):
        with pytest.raises(CommandError, match="Duplicate values prevent unique index creation"):
            call_command("ensure_mongodb_indexes", stdout=MagicMock())
