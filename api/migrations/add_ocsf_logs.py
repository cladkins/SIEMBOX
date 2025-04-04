"""Add OCSF logs table

Revision ID: add_ocsf_logs
Revises: add_settings
Create Date: 2025-04-04 10:22:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_ocsf_logs'
down_revision = 'add_settings'
branch_labels = None
depends_on = None


def upgrade():
    # Create OCSF logs table
    op.create_table('ocsf_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('activity_id', sa.Integer(), nullable=True),
        sa.Column('activity_name', sa.String(), nullable=True),
        sa.Column('category_uid', sa.Integer(), nullable=True),
        sa.Column('category_name', sa.String(), nullable=True),
        sa.Column('class_uid', sa.Integer(), nullable=True),
        sa.Column('class_name', sa.String(), nullable=True),
        sa.Column('time', sa.DateTime(), nullable=True),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('severity_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('status_id', sa.Integer(), nullable=True),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('src_endpoint', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('dst_endpoint', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('device', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('raw_event', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('alert_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Add indexes for better query performance
    op.create_index(op.f('ix_ocsf_logs_time'), 'ocsf_logs', ['time'], unique=False)
    op.create_index(op.f('ix_ocsf_logs_category_name'), 'ocsf_logs', ['category_name'], unique=False)
    op.create_index(op.f('ix_ocsf_logs_severity'), 'ocsf_logs', ['severity'], unique=False)


def downgrade():
    # Drop indexes
    op.drop_index(op.f('ix_ocsf_logs_severity'), table_name='ocsf_logs')
    op.drop_index(op.f('ix_ocsf_logs_category_name'), table_name='ocsf_logs')
    op.drop_index(op.f('ix_ocsf_logs_time'), table_name='ocsf_logs')
    
    # Drop table
    op.drop_table('ocsf_logs')