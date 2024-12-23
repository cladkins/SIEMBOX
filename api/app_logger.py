import logging
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import InternalLog  # Updated from AppLog to InternalLog

class DatabaseLogHandler(logging.Handler):
    def __init__(self, service_name: str, get_db):
        super().__init__()
        self.service_name = service_name
        self.get_db = get_db
        self._db_session: Optional[AsyncSession] = None

    async def get_session(self) -> AsyncSession:
        if not self._db_session:
            self._db_session = await self.get_db()
        return self._db_session

    def emit(self, record: logging.LogRecord):
        try:
            # Create log entry
            log_entry = InternalLog(  # Updated from AppLog to InternalLog
                service=self.service_name,
                level=record.levelname,
                message=self.format(record),
                metadata={
                    'function': record.funcName,
                    'line': record.lineno,
                    'module': record.module
                },
                component=record.module,
                timestamp=datetime.fromtimestamp(record.created)
            )

            # Since we're in a sync context but need to do async operations,
            # we'll use asyncio.create_task to schedule the database write
            import asyncio
            asyncio.create_task(self._write_to_db(log_entry))
        except Exception as e:
            # Fallback to console logging if database logging fails
            print(f"Error in log handler: {str(e)}")
            print(f"Original log message: {record.getMessage()}")

    async def _write_to_db(self, log_entry: InternalLog):  # Updated from AppLog to InternalLog
        try:
            session = await self.get_session()
            session.add(log_entry)
            await session.commit()
        except Exception as e:
            print(f"Error writing to database: {str(e)}")
            if self._db_session:
                await self._db_session.rollback()

def setup_logging(service_name: str, get_db, log_level: str = "INFO") -> logging.Logger:
    """Set up logging with the database handler"""
    # Create logger
    logger = logging.getLogger(service_name)
    logger.setLevel(getattr(logging, log_level))
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and add database handler
    db_handler = DatabaseLogHandler(service_name, get_db)
    db_handler.setFormatter(formatter)
    logger.addHandler(db_handler)
    
    # Also add console handler for immediate feedback
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger