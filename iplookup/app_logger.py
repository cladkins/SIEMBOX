import logging
import aiohttp
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional
import json

class APILogHandler(logging.Handler):
    def __init__(self, service_name: str, api_url: str = "http://api:8080"):
        super().__init__()
        self.service_name = service_name
        self.api_url = api_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.buffer = []
        self.buffer_size = 100
        self.flush_interval = 5  # seconds
        self.last_flush = datetime.now()

    async def init_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    def emit(self, record: logging.LogRecord):
        try:
            # Create log entry
            log_entry = {
                "service": self.service_name,
                "message": self.format(record),
                "level": record.levelname,
                "log_metadata": {  # Changed from metadata to log_metadata
                    "function": record.funcName,
                    "line": record.lineno,
                    "module": record.module
                },
                "component": record.module,
                "trace_id": getattr(record, 'trace_id', None)
            }
            
            # Add to buffer
            self.buffer.append(log_entry)
            
            # Check if we should flush
            if len(self.buffer) >= self.buffer_size or \
               (datetime.now() - self.last_flush).total_seconds() >= self.flush_interval:
                asyncio.create_task(self.flush_buffer())
        except Exception as e:
            # Fallback to console logging if API logging fails
            print(f"Error in log handler: {str(e)}")
            print(f"Original log message: {record.getMessage()}")

    async def flush_buffer(self):
        if not self.buffer:
            return

        try:
            await self.init_session()
            
            # Send logs in batches
            while self.buffer:
                batch = self.buffer[:self.buffer_size]
                self.buffer = self.buffer[self.buffer_size:]
                
                for log_entry in batch:
                    try:
                        async with self.session.post(
                            f"{self.api_url}/api/app-logs",
                            json=log_entry
                        ) as response:
                            if response.status != 200:
                                print(f"Failed to send log: {await response.text()}")
                                # Re-add failed logs to buffer
                                self.buffer.append(log_entry)
                                if len(self.buffer) > self.buffer_size * 2:
                                    # Prevent buffer from growing too large
                                    self.buffer = self.buffer[-self.buffer_size:]
                                break
                    except Exception as e:
                        print(f"Error sending log: {str(e)}")
                        # Re-add failed logs to buffer
                        self.buffer.append(log_entry)
                        if len(self.buffer) > self.buffer_size * 2:
                            # Prevent buffer from growing too large
                            self.buffer = self.buffer[-self.buffer_size:]
                        break
            
            self.last_flush = datetime.now()
        except Exception as e:
            print(f"Error flushing log buffer: {str(e)}")

def setup_logging(service_name: str, api_url: str = "http://api:8080", log_level: str = "INFO") -> logging.Logger:
    """Set up logging with the API handler"""
    # Create logger
    logger = logging.getLogger(service_name)
    logger.setLevel(getattr(logging, log_level))
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and add API handler
    api_handler = APILogHandler(service_name, api_url)
    api_handler.setFormatter(formatter)
    logger.addHandler(api_handler)
    
    # Also add console handler for immediate feedback
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

# Helper function to add trace ID to logs
def log_with_trace(logger: logging.Logger, level: str, message: str, trace_id: str, **kwargs):
    """Log a message with a trace ID"""
    extra = {'trace_id': trace_id}
    extra.update(kwargs)
    getattr(logger, level.lower())(message, extra=extra)