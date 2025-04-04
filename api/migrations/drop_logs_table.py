"""Drop traditional logs table

Revision ID: drop_logs_table
Revises: add_ocsf_logs
Create Date: 2025-04-04 13:45:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'drop_logs_table'
down_revision = 'add_ocsf_logs'
branch_labels = None
depends_on = None


def upgrade():
    # Drop the traditional logs table
    op.drop_table('logs')


def downgrade():
    # Recreate the logs table if needed
    op.create_table('logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('source', sa.String(), nullable=True),
        sa.Column('level', sa.String(), nullable=True),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('processed', sa.Boolean(), nullable=True),
        sa.Column('log_metadata', sa.JSON(), nullable=True),
        sa.Column('alert_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ),
        sa.PrimaryKeyConstraint('id')
    )