import logging
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import InternalLog  # Updated from AppLog to InternalLog
from database import async_session
import asyncio

class DatabaseLogHandler(logging.Handler):
    def __init__(self, service_name: str, get_db):
        super().__init__()
        self.service_name = service_name
        self.get_db = get_db

    async def get_session(self) -> AsyncSession:
        return async_session()

    def emit(self, record: logging.LogRecord):
        try:
            # Create log entry
            log_entry = InternalLog(  # Updated from AppLog to InternalLog
                service=self.service_name,
                level=record.levelname,
                message=self.format(record),
                log_metadata={  # Changed from metadata to log_metadata
                    'function': record.funcName,
                    'line': record.lineno,
                    'module': record.module
                },
                component=record.module,
                timestamp=datetime.fromtimestamp(record.created)
            )

            # Get or create event loop
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            # Create and run the task
            task = loop.create_task(self._write_to_db(log_entry))
            
            # Add a callback to handle any errors
            def handle_result(future):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error in async log write: {str(e)}")
            
            task.add_done_callback(handle_result)

        except Exception as e:
            # Fallback to console logging if database logging fails
            print(f"Error in log handler: {str(e)}")
            print(f"Original log message: {record.getMessage()}")

    async def _write_to_db(self, log_entry: InternalLog):
        session = None
        try:
            session = await self.get_session()
            async with session as s:
                s.add(log_entry)
                await s.commit()
        except Exception as e:
            print(f"Error writing to database: {str(e)}")
            if session:
                await session.rollback()
        finally:
            if session:
                await session.close()

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