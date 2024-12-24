import logging
import sys
from logging.handlers import RotatingFileHandler

def setup_logger(name):
    """
    Set up a logger with both file and console handlers
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Create formatters
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # Create file handler
    file_handler = RotatingFileHandler(
        'vps_audit.log',
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger