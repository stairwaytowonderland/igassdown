import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from .base import Base


@dataclass
class LoggingConfigDefaults:
    """Default logging configuration values."""

    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = (
        "%(asctime)s - %(levelname)-8s : %(filename)-16s : %(lineno)-5d : %(message)s"
    )
    LOG_FILE_LEVEL: str = "DEBUG"
    LOG_FILE_FORMAT: str = (
        "%(asctime)s::%(levelname)s::%(filename)s::%(funcName)s::%(lineno)d::%(message)s"
    )
    LOG_FILE_EXT: str = "log"
    LOG_STACKLEVEL: int = 2


class LoggingConfig(Base):
    """Configuration for logging."""

    USE_ROOT_LOGGER: bool = True

    def __init__(
        self,
        name: Optional[str] = None,
        use_root_logger: bool = USE_ROOT_LOGGER,
        **kwargs,
    ) -> None:
        super().__init__(name)
        self.USE_ROOT_LOGGER = use_root_logger
        self.__logging_config = LoggingConfigDefaults(**kwargs)
        self.__stacklevel = self.__logging_config.LOG_STACKLEVEL

        self.calibrate()

        self.__logger.debug(
            f"Initialized LoggingConfig for package '{self.__package__}' with handlers: {self.__handlers}"
        )

    def calibrate(self) -> None:
        """Calibrate logging configuration."""
        if self.logger:
            return

        self.__logger = self.setup_logging()

        if self.USE_ROOT_LOGGER:
            self.__logger.debug("Using root logger; skipping handler cleanup.")
            self.__logger.debug(
                f"Logging configured for package '{self.__package__}' with handlers: {logging.getLogger().handlers}"
            )
        else:
            self.close_handlers()
            self.__logger.debug(
                f"Logging configured for package '{self.__package__}' with handlers: {self.__logger.handlers}"
            )

    def setup_logging(self) -> logging.Logger:
        _name = self.__package__
        _log_file_base = self._log_file_base_name(_name)

        _handlers = getattr(self, "_LoggingConfig__handlers", [])

        if len(_handlers) == 0:
            handlers = []
            console_handler = self._new_handler(
                level=os.getenv("LOG_LEVEL", self.__logging_config.LOG_LEVEL),
                format=self.__logging_config.LOG_FORMAT,
                file=False,
            )
            handlers.append(console_handler)
            # _logger.addHandler(console_handler)

            for file_handler_level in [logging.INFO, logging.DEBUG]:
                file_handler = self._new_handler(
                    level=file_handler_level,
                    format=self.__logging_config.LOG_FILE_FORMAT,
                    file=self.log_level_file_name(_log_file_base, file_handler_level),
                )
                handlers.append(file_handler)
                # _logger.addHandler(file_handler)

        if self.USE_ROOT_LOGGER:
            logging.basicConfig(handlers=handlers, force=True)
            _logger = logging.getLogger(_name)
            self.__handlers = handlers or []
        else:
            _logger = logging.getLogger(_name)
            for handler in handlers:
                _logger.addHandler(handler)
            self.__handlers = _logger.handlers or []

        logger = None
        if _logger is not None:
            logger = _logger

            logger.setLevel(
                getattr(
                    logging,
                    os.getenv(
                        "LOG_FILE_LEVEL", self.__logging_config.LOG_FILE_LEVEL
                    ).upper(),
                    logging.DEBUG,
                )
            )

        return logger

    @property
    def log_stacklevel(self) -> int:
        """Returns the stack level for logging.

        Returns:
            int: The stack level for logging.
        """
        return self.__stacklevel

    @property
    def logger(self) -> logging.Logger:
        """Returns the configured logger.

        Returns:
            logging.Logger: The configured logger.
        """
        return getattr(self, "_LoggingConfig__logger", None)

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

    def _log_file_base_name(
        self, name: str = __name__, ext: Optional[str] = None
    ) -> str:
        """Generate a default log file name based on the module name.

        Args:
            name (str): The module name.
            ext (Optional[str]): The file extension for the log file.

        Returns:
            str: The default log file name.
        """
        module_name = name.split(".")[-1]
        return f"{module_name}.{ext or self.__logging_config.LOG_FILE_EXT}"

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
                else getattr(
                    logging, level.upper(), self.__logging_config.LOG_LEVEL.upper()
                )
            )
            _fmt = format or self.__logging_config.LOG_FORMAT
        else:
            _level = (
                level
                if isinstance(level, int)
                else getattr(
                    logging,
                    level.upper(),
                    os.getenv(
                        "LOG_FILE_LEVEL", self.__logging_config.LOG_FILE_LEVEL
                    ).upper(),
                )
            )

            _file = file if isinstance(file, str) else self.log_level_file_name(_level)
            _fmt = format or self.__logging_config.LOG_FILE_FORMAT
            handler = logging.FileHandler(_file)

        handler.setLevel(_level)
        handler.setFormatter(logging.Formatter(_fmt))
        handler.addFilter(AttributeFilter())
        handler.addFilter(LevelFilter(_level))

        return handler

    def close_handlers(self) -> None:
        if self.USE_ROOT_LOGGER:
            return
        Base.close(self, self.__handlers)
