"""Create VPS tables

This migration creates the initial VPS Audit tables in PostgreSQL.
"""
from sqlalchemy import create_engine, MetaData, text
from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
import os
from datetime import datetime

# Get database connection details from environment variables
DB_USER = os.getenv('POSTGRES_USER', 'siembox')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'changeme')
DB_HOST = os.getenv('POSTGRES_HOST', 'db')
DB_PORT = os.getenv('POSTGRES_PORT', '5432')
DB_NAME = os.getenv('POSTGRES_DB', 'siembox')

# Construct PostgreSQL connection URL
SQLALCHEMY_DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Create engine
engine = create_engine(SQLALCHEMY_DATABASE_URL)
Base = declarative_base()

class VPSServer(Base):
    __tablename__ = 'vps_servers'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    ip_address = Column(String)
    ssh_username = Column(String)
    sshPassword = Column(String, nullable=True)
    ssh_key_path = Column(String, nullable=True)

class AuditResult(Base):
    __tablename__ = 'audit_results'

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)
    results = Column(JSON)
def upgrade():
    try:
        print("Starting database table creation...")
        
        # Print table schemas before creation
        for table in Base.metadata.sorted_tables:
            print(f"\nCreating table: {table.name}")
            for column in table.columns:
                print(f"  Column: {column.name} ({column.type})")
        
        # Create tables
        Base.metadata.create_all(engine)
        
        # Verify tables were created
        with engine.connect() as conn:
            for table in Base.metadata.sorted_tables:
                result = conn.execute(text(f"SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '{table.name}'"))
                print(f"\nVerifying table: {table.name}")
                for row in result:
                    print(f"  Found column: {row[0]} ({row[1]})")
        
        print("Successfully created all tables")
        return True
    except Exception as e:
        print(f"Error creating tables: {str(e)}")
        return False

def downgrade():
    try:
        print("Starting database table removal...")
        # Drop tables
        Base.metadata.drop_all(engine)
        print("Successfully dropped all tables")
        return True
    except Exception as e:
        print(f"Error dropping tables: {str(e)}")
        return False

if __name__ == '__main__':
    try:
        print(f"Connecting to database at {DB_HOST}:{DB_PORT}...")
        # Test connection
        with engine.connect() as conn:
            print("Database connection successful")
            
            # Drop existing tables if they exist
            print("Dropping existing tables...")
            Base.metadata.drop_all(engine)
            print("Existing tables dropped")
            
            # Create tables fresh
            print("Creating tables...")
            Base.metadata.create_all(engine)
            
            # Verify tables were created correctly
            for table_name in ['vps_servers', 'audit_results']:
                result = conn.execute(text(f"""
                    SELECT column_name, data_type
                    FROM information_schema.columns
                    WHERE table_name = '{table_name}'
                    ORDER BY ordinal_position
                """))
                print(f"\nTable {table_name} columns:")
                for row in result:
                    print(f"  {row[0]} ({row[1]})")
            
            print("Migration completed successfully")
            exit(0)
    except Exception as e:
        print(f"Fatal error during migration: {str(e)}")
        exit(1)
    upgrade()