"""Download pictures (or videos) along with post metadata from Instagram."""

try:
    # pylint:disable=wrong-import-position
    import win_unicode_console  # type: ignore
except ImportError:
    pass
else:
    win_unicode_console.enable()

from .client import Igdownloader as Igdownloader
from .context import IgdownloaderContext as IgdownloaderContext
from .exceptions import *
from .logging import LoggingConfig

logging_config = LoggingConfig(__name__, stacklevel=2)
