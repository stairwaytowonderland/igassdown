"""Download pictures (or videos) along with post metadata from Instagram."""

try:
    # pylint:disable=wrong-import-position
    import win_unicode_console  # type: ignore
except ImportError:
    pass
else:
    win_unicode_console.enable()

from pathlib import Path

from .client import Igdownloader as Igdownloader
from .context import IgdownloaderContext as IgdownloaderContext
from .exceptions import *

OUTPUT_DIR = f"{Path(__file__).parent.parent.parent}/output"
PACKAGE_NAME = __package__ or __name__
