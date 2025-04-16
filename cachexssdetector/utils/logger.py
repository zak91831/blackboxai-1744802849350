"""
Logging configuration for CacheXSSDetector.
Provides centralized logging setup used across all modules.
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from rich.logging import RichHandler

def setup_logger(
    name: str = "cachexssdetector",
    level: int = logging.INFO,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Set up and configure logger with both console and file handlers.
    
    Args:
        name (str): Name of the logger
        level (int): Logging level (default: logging.INFO)
        log_file (Optional[str]): Path to log file (default: None)
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Create formatters
    console_formatter = logging.Formatter(
        '%(message)s',
        datefmt='[%X]'
    )
    
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler (using Rich for better formatting)
    console_handler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        show_path=False
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler (if log_file specified)
    if log_file:
        try:
            # Create directory if it doesn't exist
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to create log file: {str(e)}")

    # Capture unhandled exceptions
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            # Call the default handler for KeyboardInterrupt
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return

        logger.error(
            "Uncaught exception",
            exc_info=(exc_type, exc_value, exc_traceback)
        )

    sys.excepthook = handle_exception

    return logger

def get_logger(name: str = "cachexssdetector") -> logging.Logger:
    """
    Get an existing logger or create a new one.
    
    Args:
        name (str): Name of the logger
    
    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(name)

# Example usage of different log levels
def log_example():
    """Example function showing different logging levels."""
    logger = get_logger()
    
    logger.debug("Debug message - Detailed information for debugging")
    logger.info("Info message - General information about program execution")
    logger.warning("Warning message - An indication of a potential problem")
    logger.error("Error message - The software has failed to perform some function")
    logger.critical("Critical message - The program itself may be unable to continue running")

if __name__ == "__main__":
    # Test logger configuration
    logger = setup_logger(level=logging.DEBUG)
    log_example()
