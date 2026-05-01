"""add device template table

Revision ID: b5c6d7e8f9a0
Revises: 94e85cc5fbd3
Create Date: 2026-04-30 20:00:00.000000

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
revision = 'b5c6d7e8f9a0'
down_revision = '94e85cc5fbd3'
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
    conn = op.get_bind()
    table_exists = conn.execute(sa.text(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'device_template')"
    )).scalar()
    if table_exists:
        return
    op.create_table('device_template',
    sa.Column('id', sa.GUID(length=16), nullable=False),
    sa.Column('manufacturer', sa.String(length=100), nullable=False),
    sa.Column('model', sa.String(length=100), nullable=False),
    sa.Column('display_name', sa.String(length=255), nullable=False),
    sa.Column('device_type', sa.String(length=50), nullable=False),
    sa.Column('wireframe_data', sa.dialects.postgresql.JSONB(astext_type=Text()), nullable=False),
    sa.Column('provisioning_template', sa.Text(), nullable=True),
    sa.Column('template_variables', sa.dialects.postgresql.JSONB(astext_type=Text()), nullable=True),
    sa.Column('image_url', sa.String(length=500), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
    sa.Column('sa_orm_sentinel', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTimeUTC(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTimeUTC(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_device_template')),
    sa.UniqueConstraint('manufacturer', 'model', name='uq_device_template_manufacturer_model'),
    comment='Device templates with wireframe layouts and provisioning configs'
    )
    with op.batch_alter_table('device_template', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_template_manufacturer'), ['manufacturer'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_template_model'), ['model'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_template_device_type'), ['device_type'], unique=False)

def schema_downgrades() -> None:
    """schema downgrade migrations go here."""
    with op.batch_alter_table('device_template', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_device_template_device_type'))
        batch_op.drop_index(batch_op.f('ix_device_template_model'))
        batch_op.drop_index(batch_op.f('ix_device_template_manufacturer'))

    op.drop_table('device_template')

def data_upgrades() -> None:
    """Add any optional data upgrade migrations here!"""
    import json

    wireframe = json.dumps({
        "width": 400, "height": 380,
        "regions": [
            {"id": "handset", "type": "shape", "shape": "handset", "x": 10, "y": 40, "width": 60, "height": 200, "label": "Handset", "style": "outline"},
            {"id": "screen", "type": "screen", "x": 100, "y": 20, "width": 160, "height": 80, "label": "LCD Display"},
            {"id": "softkey1", "type": "button", "shape": "rect", "x": 100, "y": 108, "width": 38, "height": 16, "label": "Soft Key 1 (History)", "category": "softkey"},
            {"id": "softkey2", "type": "button", "shape": "rect", "x": 140, "y": 108, "width": 38, "height": 16, "label": "Soft Key 2 (Dir)", "category": "softkey"},
            {"id": "softkey3", "type": "button", "shape": "rect", "x": 180, "y": 108, "width": 38, "height": 16, "label": "Soft Key 3 (DND)", "category": "softkey"},
            {"id": "softkey4", "type": "button", "shape": "rect", "x": 220, "y": 108, "width": 38, "height": 16, "label": "Soft Key 4 (Menu)", "category": "softkey"},
            {"id": "line1", "type": "button", "shape": "rect", "x": 270, "y": 30, "width": 20, "height": 14, "label": "Line Key 1", "category": "line", "color": "green"},
            {"id": "line2", "type": "button", "shape": "rect", "x": 295, "y": 30, "width": 20, "height": 14, "label": "Line Key 2", "category": "line", "color": "red"},
            {"id": "nav_up", "type": "button", "shape": "circle", "cx": 310, "cy": 70, "r": 8, "label": "Navigation Up", "category": "navigation"},
            {"id": "nav_down", "type": "button", "shape": "circle", "cx": 310, "cy": 100, "r": 8, "label": "Navigation Down", "category": "navigation"},
            {"id": "nav_left", "type": "button", "shape": "circle", "cx": 290, "cy": 85, "r": 8, "label": "Navigation Left (Volume Down)", "category": "navigation"},
            {"id": "nav_right", "type": "button", "shape": "circle", "cx": 330, "cy": 85, "r": 8, "label": "Navigation Right (Volume Up)", "category": "navigation"},
            {"id": "nav_ok", "type": "button", "shape": "circle", "cx": 310, "cy": 85, "r": 6, "label": "OK / Confirm", "category": "navigation"},
            {"id": "redial", "type": "button", "shape": "rect", "x": 100, "y": 126, "width": 24, "height": 12, "label": "Redial", "category": "function"},
            {"id": "mute", "type": "button", "shape": "rect", "x": 128, "y": 126, "width": 24, "height": 12, "label": "Mute", "category": "function"},
            {"id": "headset", "type": "button", "shape": "rect", "x": 156, "y": 126, "width": 24, "height": 12, "label": "Headset", "category": "function"},
            {"id": "speakerphone", "type": "button", "shape": "rect", "x": 184, "y": 126, "width": 24, "height": 12, "label": "Speakerphone", "category": "function"},
            {"id": "voicemail", "type": "button", "shape": "rect", "x": 212, "y": 126, "width": 24, "height": 12, "label": "Voicemail", "category": "function"},
        ],
        "dialpad": {
            "startX": 100, "startY": 150, "buttonWidth": 36, "buttonHeight": 28, "gapX": 4, "gapY": 4,
            "keys": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#"],
            "subLabels": ["", "ABC", "DEF", "GHI", "JKL", "MNO", "PQRS", "TUV", "WXYZ", "", "+", "SEND"],
        },
    })
    provisioning = (
        "#!version:1.0.0.1\n"
        "account.1.enable = 1\n"
        "account.1.label = {{display_name}}\n"
        "account.1.auth_name = {{sip_username}}\n"
        "account.1.user_name = {{sip_username}}\n"
        "account.1.password = {{sip_password}}\n"
        "account.1.sip_server.1.address = {{sip_server}}\n"
        "account.1.sip_server.1.port = 5060\n"
        "account.1.sip_server.1.transport_type = 0\n"
        "\n"
        "network.ip_address_mode = 0\n"
        "network.dhcp_enable = 1\n"
        "\n"
        "phone_setting.ring_type = Ring1.wav\n"
        "phone_setting.backlight_time = 30\n"
        "\n"
        "lang.gui = English"
    )
    template_vars = json.dumps({"sip_password": "", "display_name": "", "sip_username": "", "sip_server": ""})
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "INSERT INTO device_template (id, manufacturer, model, display_name, device_type, "
            "wireframe_data, provisioning_template, template_variables, image_url, is_active, created_at, updated_at) "
            "VALUES (:id, :manufacturer, :model, :display_name, :device_type, "
            "CAST(:wireframe_data AS jsonb), :provisioning_template, CAST(:template_vars AS jsonb), NULL, true, NOW(), NOW()) "
            "ON CONFLICT (manufacturer, model) DO NOTHING"
        ),
        {
            "id": "0196329a-0000-7000-8000-000000000001",
            "manufacturer": "Yealink",
            "model": "T31P",
            "display_name": "Yealink T31P",
            "device_type": "desk_phone",
            "wireframe_data": wireframe,
            "provisioning_template": provisioning,
            "template_vars": template_vars,
        },
    )

def data_downgrades() -> None:
    """Add any optional data downgrade migrations here!"""
