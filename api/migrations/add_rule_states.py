"""Add rule states migration

This migration doesn't need to create any new tables since we'll use the existing settings table.
It just needs to ensure the settings table exists.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text
from alembic import op
import sqlalchemy as sa

def upgrade():
    # Check if settings table exists, create if it doesn't
    if not op.get_bind().dialect.has_table(op.get_bind(), 'settings'):
        op.create_table(
            'settings',
            Column('id', Integer, primary_key=True),
            Column('key', String, unique=True, nullable=False),
            Column('value', Text, nullable=True),
            Column('updated_at', DateTime, server_default=sa.text('CURRENT_TIMESTAMP')),
            Column('created_by', String, nullable=True),
            Column('last_used_at', DateTime, nullable=True)
        )

def downgrade():
    # We don't want to drop the settings table since it's used by other features
    pass