import logging
from functools import wraps

from . import __name__ as package_name


class Base:
    """Base class for all classes in this package.

    Provides common functionality and attributes.

    Attributes:
        _package_name (str): The name of the package/module.
    """

    def __init__(self, name: str) -> None:
        """Initialize the Base class.

        Args:
            name (str): The name of the package/module.
        """
        # from . import __name__ as package_name

        self._package_name = name or package_name

    @property
    def package_name(self) -> str:
        """Get the name of the class.

        Returns:
            str: The name of the class.
        """
        return self._package_name

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
                logger.info("Ctrl-C pressed, stopping and cleaning up.")

            # if some other exception got raised which
            # we didn't expect and thus need to be aware of
            except Exception as error:
                logger.error("Unexpected Exception: %r. Cleaning up.", error)

            # no matter what, close handlers
            finally:
                logger.info(f"Running {__name__}.{func.__name__}{(args)}...")

            # make sure to return
            return return_object

        return wrapper
