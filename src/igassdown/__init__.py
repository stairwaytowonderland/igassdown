"""Download pictures (or videos) along with post metadata from Instagram."""

import logging
import os
import sys

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

logger = logging.getLogger(__name__)
logger.setLevel(os.getenv("LOG_LEVEL", logging.INFO))

if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    # fmt = f"%(asctime)s %(message)s"
    fmt = f"%(asctime)s - %(levelname)-8s : %(filename)-16s : %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
    logfile = logging.FileHandler(
        os.getenv("LOG_FILE", __name__.split(".")[-1] + ".log")
    )
    logger.addHandler(logfile)
