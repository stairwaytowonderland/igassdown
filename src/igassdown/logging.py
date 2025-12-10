import logging
import os
from pathlib import Path
from typing import Optional, Union

from .base import Base

LOG_DEFAULT_LEVEL: str = "INFO"
LOG_DEFAULT_FORMAT: str = (
    "%(asctime)s - %(levelname)-8s : %(filename)-16s : %(message)s"
)
LOG_FILE_DEFAULT_LEVEL: str = "DEBUG"
LOG_FILE_DEFAULT_FORMAT: str = (
    "%(asctime)s::%(levelname)s::%(filename)s::%(funcName)s::%(lineno)d::%(message)s"
)
LOG_FILE_DEFAULT_EXT: str = "log"
LOG_DEFAULT_STACKLEVEL: int = 1


def _default_log_file_name(
    name: str = __name__, ext: str = LOG_FILE_DEFAULT_EXT
) -> str:
    """Generate a default log file name based on the module name.

    Args:
        name (str): The module name.

    Returns:
        str: The default log file name.
    """
    module_name = name.split(".")[-1]
    return f"{module_name}.{ext}"


class LoggingConfig(Base):
    """Configuration for logging."""

    def __init__(
        self,
        name: Optional[str] = None,
        log_file: Optional[str] = None,
        stacklevel: int = LOG_DEFAULT_STACKLEVEL,
    ) -> None:
        super().__init__(name)

        _name = self._package_name
        self._log_file = _default_log_file_name(log_file or _name)
        self._stacklevel = stacklevel

        _logger = logging.getLogger(_name)
        _logger.setLevel(
            getattr(
                logging,
                os.getenv("LOG_FILE_LEVEL", LOG_FILE_DEFAULT_LEVEL).upper(),
                logging.DEBUG,
            )
        )

        if not _logger.handlers:

            console_handler = self._new_handler(
                level=os.getenv("LOG_LEVEL", LOG_DEFAULT_LEVEL),
                format=LOG_DEFAULT_FORMAT,
                file=False,
            )

            _logger.addHandler(console_handler)

            for file_handler_level in [logging.INFO, logging.DEBUG]:
                file_handler = self._new_handler(
                    level=file_handler_level,
                    format=LOG_FILE_DEFAULT_FORMAT,
                    file=self.log_level_file_name(self._log_file, file_handler_level),
                )
                _logger.addHandler(file_handler)

        self._logger = _logger

    @property
    def stacklevel(self) -> int:
        return self._stacklevel

    @property
    def logger(self) -> logging.Logger:
        """Returns the configured logger.

        Returns:
            logging.Logger: The configured logger.
        """
        return self._logger

    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """Get a logger with the specified name.

        Args:
            name (str): The name of the logger.

        Returns:
            logging.Logger: The logger with the specified name.
        """
        return logging.getLogger(name)

    @staticmethod
    def log_level_file_name(filename: str, level: int) -> str:
        name = Path(filename).stem
        return f"{name.split('.')[-1]}_{logging.getLevelName(level).lower()}.log"

    def _new_handler(
        self,
        level: Union[int, str] = logging.INFO,
        format: str = logging.BASIC_FORMAT,
        file: Union[bool, str] = False,
    ) -> logging.Handler:
        class LevelFilter(logging.Filter):
            def __init__(self, level):
                self.level = level

            def filter(self, record):
                return record.levelno == self.level

        class AttributeFilter(logging.Filter):
            def filter(self, record):
                """Add attributes to log record.

                https://docs.python.org/3/library/logging.html#logrecord-attributes

                :note: Doesn't obey stacklevel
                """
                record.modulename = modulename = record.name.rsplit(".", 1)[-1]
                record.modulefile = f"{modulename}.py"
                return True

        is_file = isinstance(file, str) or file is True

        if not is_file:
            handler = logging.StreamHandler()
            _level = (
                level
                if isinstance(level, int)
                else getattr(logging, level.upper(), LOG_DEFAULT_LEVEL.upper())
            )
            _fmt = format or LOG_DEFAULT_FORMAT
        else:
            _level = (
                level
                if isinstance(level, int)
                else getattr(
                    logging,
                    level.upper(),
                    os.getenv("LOG_FILE_LEVEL", LOG_FILE_DEFAULT_LEVEL).upper(),
                )
            )

            _file = file if isinstance(file, str) else self.log_level_file_name(_level)
            _fmt = format or LOG_FILE_DEFAULT_FORMAT
            handler = logging.FileHandler(_file)

        handler.setLevel(_level)
        handler.setFormatter(logging.Formatter(_fmt))
        handler.addFilter(AttributeFilter())
        handler.addFilter(LevelFilter(_level))

        return handler
