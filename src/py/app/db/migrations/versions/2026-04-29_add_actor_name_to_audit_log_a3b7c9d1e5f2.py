"""add actor_name to audit_log

Revision ID: a3b7c9d1e5f2
Revises: 0366db950d60
Create Date: 2026-04-29 00:00:00.000000

"""
import warnings
from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from advanced_alchemy.types import EncryptedString, EncryptedText, FernetBackend, GUID, ORA_JSONB, DateTimeUTC, StoredObject, PasswordHash
from sqlalchemy import Text  # pyright: ignore  # noqa: F401
from sqlalchemy.dialects import postgresql
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
revision = 'a3b7c9d1e5f2'
down_revision = '0366db950d60'
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
    """Schema upgrade migrations."""
    op.add_column('audit_log', sa.Column('actor_name', sa.String(length=255), nullable=True))

def schema_downgrades() -> None:
    """Schema downgrade migrations."""
    op.drop_column('audit_log', 'actor_name')

def data_upgrades() -> None:
    """Data upgrade migrations."""

def data_downgrades() -> None:
    """Data downgrade migrations."""
