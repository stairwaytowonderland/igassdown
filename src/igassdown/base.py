import logging
from functools import wraps
from typing import Optional

from . import __name__ as package_name


class Base:
    """Base class for all classes in this package.

    Provides common functionality and attributes.

    Attributes:
        _package_name (str): The name of the package/module.
    """

    __base_stacklevel: int = 2

    def __init__(self, name: Optional[str] = None, stacklevel: int = 2) -> None:
        """Initialize the Base class.

        Args:
            name (Optional[str]): The name of the package/module.
            stacklevel (int): The stack level for logging.
        """
        # from . import __name__ as package_name

        self.__package_name = name or package_name
        self.__base_stacklevel = stacklevel

    @property
    def package_name(self) -> str:
        """Get the name of the class.

        Returns:
            str: The name of the class.
        """
        return self.__package_name

    @property
    def base_stacklevel(self) -> int:
        """Get the base stack level for logging.

        Returns:
            int: The base stack level.
        """
        return self.__base_stacklevel

    def clean_up_on_error(func):
        logger = logging.getLogger(__name__)

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            return_object = None
            try:
                # try to run the input function as normal
                return_object = func(self, *args, **kwargs)

            # if the user hit ctrl-c
            except KeyboardInterrupt:
                logger.info(
                    "Ctrl-C pressed, stopping and cleaning up.",
                    stacklevel=self.config.base_stacklevel,
                )

            # if some other exception got raised which
            # we didn't expect and thus need to be aware of
            except Exception as error:
                logger.error(
                    "Unexpected Exception: %r. Cleaning up.",
                    error,
                    stacklevel=self.config.base_stacklevel,
                )

            # no matter what, close handlers
            finally:
                self.close()  # Classes that implement the annotation must have a close method
                logger.info(
                    f"Running {__name__}.{func.__name__}{(args)}...",
                    stacklevel=self.config.base_stacklevel,
                )

            # make sure to return
            return return_object

        return wrapper
