"""merge feature branches

Revision ID: 2d2ae36586a5
Revises: ee846255bf42, a424720f5029, ba884be8f077, b1cf87cc0066
Create Date: 2026-04-27 15:42:02.532260

"""
import warnings
from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from advanced_alchemy.types import EncryptedString, EncryptedText, GUID, ORA_JSONB, DateTimeUTC, StoredObject, PasswordHash
from sqlalchemy import Text  # pyright: ignore  # noqa: F401

if TYPE_CHECKING:
    from collections.abc import Sequence  # pyright: ignore

__all__ = ("downgrade", "upgrade", "schema_upgrades", "schema_downgrades", "data_upgrades", "data_downgrades")

sa.GUID = GUID # pyright: ignore
sa.DateTimeUTC = DateTimeUTC  # pyright: ignore
sa.ORA_JSONB = ORA_JSONB  # pyright: ignore
sa.EncryptedString = EncryptedString  # pyright: ignore
sa.EncryptedText = EncryptedText  # pyright: ignore
sa.StoredObject = StoredObject  # pyright: ignore
sa.PasswordHash = PasswordHash  # pyright: ignore

# revision identifiers, used by Alembic.
revision = '2d2ae36586a5'
down_revision = ('ee846255bf42', 'a424720f5029', 'ba884be8f077', 'b1cf87cc0066')
branch_labels = None
depends_on = None


def upgrade() -> None:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
        with op.get_context().autocommit_block():
            schema_upgrades()
            data_upgrades()

def downgrade() -> None:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
        with op.get_context().autocommit_block():
            data_downgrades()
            schema_downgrades()

def schema_upgrades() -> None:
    """schema upgrade migrations go here."""
    pass

def schema_downgrades() -> None:
    """schema downgrade migrations go here."""
    pass

def data_upgrades() -> None:
    """Add any optional data upgrade migrations here!"""

def data_downgrades() -> None:
    """Add any optional data downgrade migrations here!"""
