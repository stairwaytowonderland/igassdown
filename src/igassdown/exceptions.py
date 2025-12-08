class IgdownloaderException(Exception):
    """Base exception for this script.

    :note: This exception should not be raised directly."""


class QueryReturnedBadRequestException(IgdownloaderException):
    pass


class QueryReturnedForbiddenException(IgdownloaderException):
    pass


class LoginRequiredException(IgdownloaderException):
    pass


class LoginException(IgdownloaderException):
    pass


class TwoFactorAuthRequiredException(LoginException):
    pass


class InvalidArgumentException(IgdownloaderException):
    pass


class BadCredentialsException(LoginException):
    pass


class ConnectionException(IgdownloaderException):
    pass


class QueryReturnedNotFoundException(ConnectionException):
    pass


class TooManyRequestsException(ConnectionException):
    pass


class FileSaveException(IgdownloaderException):
    pass


class AbortDownloadException(Exception):
    """
    Exceptions that are not caught in the error catchers inside the download loop,
    and so aborts the download loop.

    This exception is not a subclass of ``IgdownloaderException``.
    """
