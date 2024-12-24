from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

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