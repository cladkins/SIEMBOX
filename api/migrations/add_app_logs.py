"""Add internal logs table

This migration creates a new table for internal application logs
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Table, MetaData
from alembic import op
import sqlalchemy as sa
from datetime import datetime

def upgrade():
    # Create internal_logs table
    op.create_table(
        'internal_logs',  # Changed from app_logs to internal_logs
        Column('id', Integer, primary_key=True),
        Column('timestamp', DateTime, default=datetime.utcnow),
        Column('service', String, nullable=False),
        Column('level', String, nullable=False),
        Column('message', Text, nullable=False),
        Column('log_metadata', JSON, default={}),
        Column('component', String),
        Column('trace_id', String),
    )

    # Create indexes
    op.create_index('ix_internal_logs_timestamp', 'internal_logs', ['timestamp'])
    op.create_index('ix_internal_logs_service', 'internal_logs', ['service'])

    # If there are any existing logs from internal services in the logs table,
    # migrate them to the new internal_logs table
    conn = op.get_bind()
    meta = MetaData()
    
    logs_table = Table(
        'logs',
        meta,
        Column('id', Integer, primary_key=True),
        Column('timestamp', DateTime),
        Column('source', String),
        Column('level', String),
        Column('message', Text),
        Column('log_metadata', JSON),
        extend_existing=True
    )

    internal_logs_table = Table(
        'internal_logs',  # Changed from app_logs to internal_logs
        meta,
        Column('id', Integer, primary_key=True),
        Column('timestamp', DateTime),
        Column('service', String),
        Column('level', String),
        Column('message', Text),
        Column('log_metadata', JSON),
        Column('component', String),
        Column('trace_id', String),
        extend_existing=True
    )

    # Migrate internal service logs
    internal_services = {'api', 'collector', 'detection', 'iplookup', 'frontend'}
    for service in internal_services:
        internal_logs = conn.execute(
            logs_table.select().where(logs_table.c.source == service)
        ).fetchall()
        
        if internal_logs:
            for log in internal_logs:
                conn.execute(
                    internal_logs_table.insert().values(
                        timestamp=log.timestamp,
                        service=log.source,
                        level=log.level,
                        message=log.message,
                        log_metadata=log.log_metadata,
                        component=None,  # No component info in old logs
                        trace_id=None    # No trace_id in old logs
                    )
                )

def downgrade():
    # Drop indexes first
    op.drop_index('ix_internal_logs_timestamp')
    op.drop_index('ix_internal_logs_service')
    
    # Drop the table
    op.drop_table('internal_logs')