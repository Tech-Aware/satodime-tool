import logging
import sys
import time
import inspect
import traceback
import os
from functools import wraps
from typing import Optional, Any, Callable


# Define custom levels
SUCCESS_LEVEL = 25  # Between INFO (20) and WARNING (30)
ENTERING_LEVEL = 21  # Just after INFO
EXITING_LEVEL = 22  # Between ENTERING and SUCCESS

# Add custom levels
logging.addLevelName(SUCCESS_LEVEL, 'SUCCESS')
logging.addLevelName(ENTERING_LEVEL, 'ENTERING')
logging.addLevelName(EXITING_LEVEL, 'EXITING')


def success(self, message, *args, **kwargs):
    """Log with severity 'SUCCESS'."""
    if self.isEnabledFor(SUCCESS_LEVEL):
        frame = inspect.stack()[1]
        kwargs["extra"] = {
            "caller_file": os.path.basename(frame.filename),
            "caller_line": frame.lineno
        }
        self._log(SUCCESS_LEVEL, message, args, **kwargs)


def entering(self, message, *args, **kwargs):
    if self.isEnabledFor(ENTERING_LEVEL):
        self._log(ENTERING_LEVEL, message, args, **kwargs)

def exiting(self, message, *args, **kwargs):
    if self.isEnabledFor(EXITING_LEVEL):
        self._log(EXITING_LEVEL, message, args, **kwargs)




# Add methods to Logger class
logging.Logger.success = success
logging.Logger.entering = entering
logging.Logger.exiting = exiting

# Ensure root logger has all custom methods
logging.getLogger('').success = success.__get__(logging.getLogger(''), logging.Logger)
logging.getLogger('').entering = entering.__get__(logging.getLogger(''), logging.Logger)
logging.getLogger('').exiting = exiting.__get__(logging.getLogger(''), logging.Logger)


class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[37m',  # Light grey
        'INFO': '\033[94m',  # Blue
        'SUCCESS': '\033[92m',  # Green
        'ENTERING': '\033[96m',  # Cyan
        'EXITING': '\033[95m',  # Magenta
        'WARNING': '\033[38;5;214m',  # Orange
        'ERROR': '\033[91m',  # Red
        'CRITICAL': '\033[41;97m'  # White on Red
    }
    RESET = '\033[0m'
    HIGHLIGHT_UTILS = '\033[30;43m'  # Noir sur fond jaune

    def format(self, record):
        # Sauvegarder le format original
        original_format = self._style._fmt

        # Appliquer un format sans filename et lineno pour ENTERING et EXITING
        if record.levelname in ['ENTERING', 'EXITING']:
            self._style._fmt = '%(asctime)s - %(levelname)s | %(message)s'
        elif record.levelname in ['SUCCESS']:
            record.filename = getattr(record, "caller_file", record.filename)
            record.lineno = getattr(record, "caller_line", record.lineno)
        else:
            self._style._fmt = '%(asctime)s - [%(filename)s:%(lineno)d] %(levelname)s | %(message)s'

        # Formater le message
        color = self.COLORS.get(record.levelname, self.RESET)
        formatted_message = f"{color}{super().format(record)}{self.RESET}"

        # Appliquer un style spécial à "utils" s'il est détecté
        if "utils | " in formatted_message.lower():
            formatted_message = formatted_message.replace(
                "utils", f"{self.HIGHLIGHT_UTILS}utils"
            )

        # Restaurer le format original
        self._style._fmt = original_format
        return formatted_message


def setup_logging(name: str = None) -> logging.Logger:
    """Configure logging with standardized format and levels."""
    level = logging.DEBUG if (len(sys.argv) >= 2 and sys.argv[1] in ['-v', '--verbose']) else logging.INFO

    formatter = ColoredFormatter(
        '%(asctime)s - [%(filename)s:%(lineno)d] %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    if not root_logger.handlers:
        root_logger.setLevel(level)
        root_handler = logging.StreamHandler()
        root_handler.setFormatter(formatter)
        root_logger.addHandler(root_handler)

    # Get the logger and ensure it has all custom methods
    logger = logging.getLogger(name) if name else root_logger
    logger.success = success.__get__(logger, logging.Logger)
    logger.entering = entering.__get__(logger, logging.Logger)
    logger.exiting = exiting.__get__(logger, logging.Logger)

    return logger


def log_method(level: int = logging.INFO, exclude_args: bool = False) -> Callable:
    """Decorator to automatically log method entry/exit with file and line info."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            logger = logging.getLogger(func.__module__)

            # Récupérer le contexte d'appel du décorateur (là où log_method est appliqué)
            frame = inspect.stack()[1]
            file_name = os.path.basename(frame.filename)
            line_number = func.__code__.co_firstlineno

            # Construire le message de log avec la ligne du décorateur
            log_prefix = f"[{file_name}:{line_number}] {func.__name__}"

            if not exclude_args:
                logger.entering(f"↓ ↓ ↓ {log_prefix} | with args={args}, kwargs={kwargs} ↓ ↓ ↓")
            else:
                logger.entering(f"↓ ↓ ↓ {log_prefix} ↓ ↓ ↓")

            try:
                result = func(*args, **kwargs)
                if not exclude_args:
                    logger.exiting(f"↑ ↑ ↑ {log_prefix} | with result={result} ↑ ↑ ↑")
                else:
                    logger.exiting(f"↑ ↑ ↑ {log_prefix} ↑ ↑ ↑")
                return result

            except Exception as e:
                logger.error(f"Exception in {log_prefix} : {str(e)}")
                logger.debug(f"Stack trace: {traceback.format_exc()}")
                raise

        return wrapper

    return decorator


# Example usage
if __name__ == "__main__":
    logger = setup_logging(__name__)


    @log_method()
    def example_function(x: int, y: int) -> int:
        """Example function for testing logging."""
        logger.info(f"Processing {x} and {y}")
        return x + y


    result = example_function(5, 3)