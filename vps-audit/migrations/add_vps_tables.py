"""Add VPS audit tables

This migration creates the necessary tables for the VPS audit functionality:
- servers: Stores server connection information
- audit_results: Stores the results of security audits
"""

from sqlalchemy import (
    create_engine, 
    Table, 
    Column, 
    Integer, 
    String, 
    DateTime, 
    ForeignKey, 
    JSON, 
    Text, 
    Enum,
    MetaData
)
from datetime import datetime
import enum
import os
from dotenv import load_dotenv

load_dotenv()

# Database configuration
POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "siembox")

DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

# Create database engine
engine = create_engine(DATABASE_URL)
metadata = MetaData()

# Define tables
servers = Table(
    'servers',
    metadata,
    Column('id', Integer, primary_key=True),
    Column('name', String(255), nullable=False),
    Column('ip_address', String(255), nullable=False),
    Column('ssh_username', String(255), nullable=False),
    Column('auth_type', String(50), nullable=False),
    Column('ssh_password', Text, nullable=True),
    Column('ssh_private_key', Text, nullable=True),
    Column('ssh_key_passphrase', Text, nullable=True),
    Column('created_at', DateTime, default=datetime.utcnow),
    Column('updated_at', DateTime, default=datetime.utcnow, onupdate=datetime.utcnow),
    Column('last_audit_at', DateTime, nullable=True)
)

audit_results = Table(
    'audit_results',
    metadata,
    Column('id', Integer, primary_key=True),
    Column('server_id', Integer, ForeignKey('servers.id', ondelete='CASCADE'), nullable=False),
    Column('timestamp', DateTime, default=datetime.utcnow),
    Column('status', String(50), nullable=False),
    Column('system_info', JSON, nullable=True),
    Column('security_checks', JSON, nullable=True),
    Column('vulnerabilities', JSON, nullable=True),
    Column('recommendations', JSON, nullable=True),
    Column('raw_output', JSON, nullable=True),
    Column('error_message', Text, nullable=True)
)

def upgrade():
    """Create tables."""
    metadata.create_all(engine)

def downgrade():
    """Drop tables."""
    metadata.drop_all(engine)

if __name__ == '__main__':
    upgrade()