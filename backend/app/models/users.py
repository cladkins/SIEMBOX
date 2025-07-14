"""
SIEM BOX - User Database Models
"""
from sqlalchemy import Column, String, Integer, Boolean, TIMESTAMP
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from app.db.database import Base
import uuid


class User(Base):
    """
    User accounts table for authentication and authorization
    """
    __tablename__ = "users"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    
    # User identification
    username = Column(String(50), unique=True, index=True, nullable=False,
                     comment="Unique username for login")
    email = Column(String(255), unique=True, index=True, nullable=False,
                  comment="User email address")
    
    # Authentication
    hashed_password = Column(String(255), nullable=False,
                           comment="Bcrypt hashed password")
    
    # User status
    is_active = Column(Boolean, default=True, nullable=False,
                      comment="Whether the user account is active")
    is_superuser = Column(Boolean, default=False, nullable=False,
                         comment="Whether the user has admin privileges")
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(),
                       comment="When the user account was created")
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=func.now(),
                       onupdate=func.now(), comment="When the user account was last updated")
    last_login = Column(TIMESTAMP(timezone=True), nullable=True,
                       comment="When the user last logged in")
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"