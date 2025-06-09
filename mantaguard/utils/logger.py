"""
Centralized logging configuration for MantaGuard.
"""

import logging
import logging.config
from pathlib import Path
from .config import config


def setup_logging(log_level: str = "INFO") -> None:
    """
    Set up centralized logging for MantaGuard.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    log_file = config.LOGS_DIR / "mantaguard.log"
    
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            },
            'detailed': {
                'format': '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            }
        },
        'handlers': {
            'console': {
                'level': log_level,
                'class': 'logging.StreamHandler',
                'formatter': 'standard',
                'stream': 'ext://sys.stdout'
            },
            'file': {
                'level': 'DEBUG',
                'class': 'logging.FileHandler',
                'formatter': 'detailed',
                'filename': str(log_file),
                'mode': 'a'
            }
        },
        'loggers': {
            'mantaguard': {
                'handlers': ['console', 'file'],
                'level': log_level,
                'propagate': False
            }
        },
        'root': {
            'handlers': ['console'],
            'level': log_level
        }
    }
    
    logging.config.dictConfig(logging_config)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.
    
    Args:
        name: Name of the module (usually __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(f"mantaguard.{name}")