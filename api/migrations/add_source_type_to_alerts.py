from sqlalchemy import Column, String
from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column('alerts', Column('source_type', String, server_default='sigma_rule'))

def downgrade():
    op.drop_column('alerts', 'source_type')