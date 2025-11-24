"""
SIEM BOX - Core Configuration Settings
"""
from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application
    app_name: str = "SIEM BOX"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # API
    api_v1_prefix: str = "/api/v1"
    
    # CORS
    allowed_origins: list = ["*"]  # Configure for production
    allowed_hosts: list = ["*"]
    
    # Database
    database_url: str
    database_echo: bool = False
    
    # Security
    secret_key: str
    access_token_expire_minutes: int = 30
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Notification Settings
    # Email Configuration
    smtp_server: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    email_from: Optional[str] = None
    
    # Discord Configuration
    discord_webhook_url: Optional[str] = None
    
    # Slack Configuration
    slack_webhook_url: Optional[str] = None
    slack_token: Optional[str] = None
    
    # SMS Configuration (Twilio)
    twilio_account_sid: Optional[str] = None
    twilio_auth_token: Optional[str] = None
    twilio_from_number: Optional[str] = None
    
    # Webhook Configuration
    webhook_timeout: int = 30
    webhook_retry_attempts: int = 3
    
    # Notification Rate Limiting
    notification_rate_limit_per_hour: int = 100
    notification_batch_size: int = 10
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
