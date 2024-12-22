"""Add settings table

This migration adds the settings table for storing API keys and other configuration.
"""

from sqlalchemy import Column, Integer, String, DateTime, Text
from alembic import op
import sqlalchemy as sa
from datetime import datetime

# Revision identifiers
revision = 'add_settings_table'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        'settings',
        Column('id', Integer, primary_key=True),
        Column('key', String, unique=True, index=True),
        Column('value', Text),
        Column('created_at', DateTime, default=datetime.utcnow),
        Column('updated_at', DateTime, default=datetime.utcnow, onupdate=datetime.utcnow),
        Column('last_used_at', DateTime),
        Column('created_by', String)
    )

def downgrade():
    op.drop_table('settings')