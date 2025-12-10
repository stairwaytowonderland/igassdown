import logging
import os


class LoggingConfig:
    """Configuration for logging.

    Attributes:
        LOG_LEVEL: The default logging level.
        LOG_FILE: The default log file name.
    """

    LOG_LEVEL: str = "INFO"
    LOG_FILE_LEVEL: str = "DEBUG"
    LOG_STACKLEVEL: int = 1
    LOG_FORMAT: str = "%(asctime)s - %(levelname)-8s : %(filename)-16s : %(message)s"
    LOG_FILE_FORMAT: str = (
        "%(asctime)s::%(levelname)s::%(filename)s::%(funcName)s::%(lineno)d::%(message)s"
    )

    def __init__(
        self, name: str = __name__, log_file: str = None, stacklevel: int = 1
    ) -> None:
        l = logging.getLogger(name)
        l.setLevel(
            os.getenv(
                "LOG_LEVEL", getattr(logging, self.LOG_LEVEL.upper(), logging.INFO)
            )
        )

        self._name = name
        self._log_file = log_file or name.split(".")[-1] + ".log"
        self.LOG_STACKLEVEL = stacklevel

        if not l.handlers:

            class ModuleNameFilter(logging.Filter):
                def filter(self, record):
                    """Add attributes to log record.

                    https://docs.python.org/3/library/logging.html#logrecord-attributes

                    :note: Doesn't handle stacklevel
                    """
                    record.modulename = modulename = record.name.rsplit(".", 1)[-1]
                    record.modulefile = f"{modulename}.py"
                    return True

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(self.LOG_FORMAT))
            console_handler.addFilter(ModuleNameFilter())
            file_handler = logging.FileHandler(self._log_file)
            file_handler.setLevel(
                getattr(logging, self.LOG_FILE_LEVEL.upper(), logging.DEBUG)
            )
            file_handler.setFormatter(logging.Formatter(self.LOG_FILE_FORMAT))
            file_handler.addFilter(ModuleNameFilter())

            l.addHandler(console_handler)
            l.addHandler(file_handler)

        self._logger = l

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
