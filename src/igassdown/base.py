import logging
from functools import wraps
from typing import Any, Callable, List, Optional

PACKAGE_NAME = __package__

_logger = logging.getLogger(__name__)


def clean_up_on_error(func, close_method_name: str = "close") -> Callable:
    return Base.clean_up_on_error(func, close_method_name)


class Base:
    """Base class for all classes in this package.

    Provides common functionality and attributes.

    Attributes:
        __name (str): The name of the package/module.
        base_stacklevel (int): The stack level for logging.
    """

    __name: str = PACKAGE_NAME
    base_stacklevel: int = 2

    def __init__(
        self, name: Optional[str] = None, stacklevel: Optional[int] = None
    ) -> None:
        """Initialize the Base class.

        Args:
            name (Optional[str]): The name of the package/module.
            stacklevel (Optional[int]): The stack level for logging.
        """
        if name is not None:
            self.__name = name
        if stacklevel is not None:
            self.base_stacklevel = stacklevel

    @property
    def __package__(self) -> str:
        """Returns the package name.

        Returns:
            str: The package name.
        """
        return self.__name

    def close(
        handlers: List[logging.Handler] = [], close_method: Callable = None, **kwargs
    ) -> None:
        if callable(close_method):
            return close_method()

        root_logger = logging.getLogger()
        stacklevel = kwargs.get("stacklevel", Base.base_stacklevel)
        _handlers = handlers or _logger.handlers
        _logger.info(
            f"Cleaning up {len(_handlers)} handlers from root logger {root_logger}",
            stacklevel=stacklevel,
        )
        for handler in _handlers:
            try:
                _logger.info(
                    f"If it exists, handler {handler} will be removed from root logger {root_logger}",
                    stacklevel=stacklevel,
                )
                root_logger.removeHandler(handler)
                handler.close()
            except ValueError:
                # not in the list of handlers
                pass

    def clean_up_on_error(
        func: Callable, close_method_name: str = None, **kwargs
    ) -> Callable:

        _stacklevel = kwargs.get("stacklevel", Base.base_stacklevel)

        def class_func(self, *args, **kwargs):
            return func(self, *args, **kwargs)

        def standalone_func(*args, **kwargs):
            return func(*args, **kwargs)

        def call_func(self: Optional[Any] = None, *args, **kwargs):
            if self is not None:
                return class_func(self, *args, **kwargs)
            else:
                return standalone_func(*args, **kwargs)

        def _wrapper(
            instance: Optional[Any] = None,
            logger: Optional[logging.Logger] = None,
            stacklevel: Optional[int] = None,
            close_method: Optional[Callable] = None,
            *args,
            **kwargs,
        ):
            return_object = None
            try:
                return_object = call_func(instance, *args, **kwargs)

            # if the user hit ctrl-c
            except KeyboardInterrupt:
                logger.info(
                    "Ctrl-C pressed, stopping and cleaning up.",
                    stacklevel=stacklevel,
                )

            # if some other exception got raised which
            # we didn't expect and thus need to be aware of
            except Exception as error:
                logger.error(
                    "Unexpected Exception: %r. Cleaning up.",
                    error,
                    stacklevel=stacklevel,
                )

            # no matter what, close handlers
            finally:
                # self.close()  # Requires that functions have a 'close' method
                Base.close(logger.handlers, close_method)
                if instance == args[0]:
                    del args[0]
                logger.info(
                    f"Running {func.__name__}{(args)}...",
                    stacklevel=stacklevel,
                )

            # make sure to return
            return return_object

        if close_method_name:

            @wraps(func)
            def wrapper(self, *args, **kwargs):
                config = getattr(self, "config", None)  # type: Base
                if not isinstance(config, Base):
                    raise ValueError(
                        "Instance does not have a 'config' attribute of type 'Base'."
                    )
                logger = getattr(self, "logger", _logger)
                stacklevel = config.base_stacklevel
                close_method = getattr(self, close_method_name or "close", None)

                return _wrapper(self, logger, stacklevel, close_method, *args, **kwargs)

            return wrapper
        else:

            @wraps(func)
            def wrapper(*args, **kwargs):
                logger = _logger
                stacklevel = _stacklevel
                close_method = None

                return _wrapper(None, logger, stacklevel, close_method, *args, **kwargs)

            return wrapper
