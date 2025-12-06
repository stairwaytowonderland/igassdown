import getpass
import os
import platform
import sys
import tempfile
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

import requests
import urllib3

from .config import AssetExtensions, Config
from .context import IgdownloaderContext
from .exceptions import *
from .igstructures import IGFeedRequestVariables, PostNode, TimelineData, VideoCandidate
from .structures import IGAsset
from .utils import convert_timestamp, dataclass_from_dict


def _get_config_dir() -> str:
    """Returns configuration directory path.

    Returns:
        str: Configuration directory path.
    """
    if platform.system() == "Windows":
        # on Windows, use %LOCALAPPDATA%\Igdownloader
        localappdata = os.getenv("LOCALAPPDATA")
        if localappdata is not None:
            return os.path.join(localappdata, "IGAssDown")
        # legacy fallback - store in temp dir if %LOCALAPPDATA% is not set
        return os.path.join(tempfile.gettempdir(), ".igassdown-" + getpass.getuser())
    # on Unix, use ~/.config/igassdown
    return os.path.join(
        os.getenv("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "igassdown"
    )


def get_default_session_filename(username: str) -> str:
    """Returns default session filename for given username.

    Args:
        username: Instagram username.

    Returns:
        str: Default session filename.
    """
    configdir = _get_config_dir()
    sessionfilename = "session-{}".format(username)
    return os.path.join(configdir, sessionfilename)


def _requires_login(func: Callable) -> Callable:
    """Decorator to raise an exception if herewith-decorated function is called without being logged in

    Args:
        func: Function to decorate.

    Returns:
        Callable: Decorated function.
    """

    @wraps(func)
    def call(igdownloader, *args, **kwargs):
        if not igdownloader.context.is_logged_in:
            raise LoginRequiredException("Login required.")
        return func(igdownloader, *args, **kwargs)

    return call


def _retry_on_connection_error(func: Callable) -> Callable:
    """Decorator to retry the function max_connection_attempts number of times.

    Herewith-decorated functions need an ``_attempt`` keyword argument.

    This is to decorate functions that do network requests that may fail. Note that
    :meth:`.get_json`, :meth:`.get_iphone_json` and :meth:`.graphql_query` already have
    their own logic for retrying, hence functions that only use these for network access must not be decorated with this
    decorator.

    Args:
        func: Function to decorate.

    Returns:
        Callable: Decorated function.
    """

    @wraps(func)
    def call(igdownloader, *args, **kwargs):
        try:
            return func(igdownloader, *args, **kwargs)
        except (
            urllib3.exceptions.HTTPError,
            requests.exceptions.RequestException,
            ConnectionException,
        ) as err:
            error_string = "{}({}): {}".format(
                func.__name__, ", ".join([repr(arg) for arg in args]), err
            )
            if (
                kwargs.get("_attempt") or 1
            ) == igdownloader.context.max_connection_attempts:
                raise ConnectionException(error_string) from None
            igdownloader.context.error(
                error_string + " [retrying; skip with ^C]", repeat_at_end=False
            )
            try:
                if kwargs.get("_attempt"):
                    kwargs["_attempt"] += 1
                else:
                    kwargs["_attempt"] = 2
                igdownloader.context.do_sleep()
                return call(igdownloader, *args, **kwargs)
            except KeyboardInterrupt:
                igdownloader.context.error("[skipped by user]", repeat_at_end=False)
                raise ConnectionException(error_string) from None

    return call


class Igdownloader:
    """Igdownloader Class.

    Attributes:
        context: The associated :class:`IgdownloaderContext` with low-level communication functions and logging.
        has_stored_errors: Returns whether any error has been reported and stored to be repeated at program termination.
    """

    def __init__(
        self,
        config: Config,
        sleep: bool = True,
        quiet: bool = False,
        user_agent: Optional[str] = None,
        max_connection_attempts: int = 3,
        request_timeout: float = 300.0,
        fatal_status_codes: Optional[List[int]] = None,
    ):
        """Initialize Igdownloader instance.

        Args:
            config: Configuration object.
            sleep: Whether to sleep between requests to avoid rate-limiting.
            quiet: Whether to suppress output messages.
            user_agent: User-Agent string to use for requests. If None, uses default from config
            max_connection_attempts: Maximum number of connection attempts for network requests.
            request_timeout: Timeout for network requests in seconds.
            fatal_status_codes: List of HTTP status codes that should be treated as fatal errors.
        """

        self._context = IgdownloaderContext(
            config,
            sleep,
            quiet,
            user_agent,
            max_connection_attempts,
            request_timeout,
            fatal_status_codes,
        )

    @property
    def context(self) -> IgdownloaderContext:
        """The associated :class:`IgdownloaderContext` with low-level communication functions and logging.

        Returns:
            IgdownloaderContext: The associated context.
        """
        return self._context

    @property
    def has_stored_errors(self) -> bool:
        """Returns whether any error has been reported and stored to be repeated at program termination.

        Returns:
            bool: True if there are stored errors, False otherwise.
        """
        return self.context.has_stored_errors

    @contextmanager
    def anonymous_copy(self):
        """Yield an anonymous, otherwise equally-configured copy of an :class:`Igdownloader` instance; Then copy its error log."""
        new_loader = Igdownloader(
            config=self.context.config,
            sleep=self.context.sleep,
            quiet=self.context.quiet,
            user_agent=self.context.user_agent,
            max_connection_attempts=self.context.max_connection_attempts,
            request_timeout=self.context.request_timeout,
            fatal_status_codes=self.context.fatal_status_codes,
        )
        yield new_loader
        self.context.error_log.extend(new_loader.context.error_log)
        new_loader.context.error_log = []  # avoid double-printing of errors
        new_loader.close()

    def close(self) -> None:
        """Close associated session objects and repeat error log."""
        self.context.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @_requires_login
    def save_session(self) -> dict:
        """Saves internally stored :class:`requests.Session` object to ``dict``.

        Raises:
            LoginRequiredException: If called without being logged in.

        Returns:
            dict: Session data as a ``dict``.
        """
        return self.context.save_session()

    def load_session(self, username: str, session_data: dict) -> None:
        """Internally stores :class:`requests.Session` object from ``dict``.

        Args:
            username: Instagram username to load session for
            session_data: Session data as returned by :meth:`save_session`
        """
        self.context.load_session(username, session_data)

    @_requires_login
    def save_session_to_file(self, filename: Optional[str] = None) -> None:
        """Saves internally stored :class:`requests.Session` object.

        Args:
            filename: Filename, or None to use default filename.
        Raises:
            LoginRequiredException: If called without being logged in.
        """
        if filename is None:
            assert self.context.username is not None
            filename = get_default_session_filename(self.context.username)
        dirname = os.path.dirname(filename)
        if dirname != "" and not os.path.exists(dirname):
            os.makedirs(dirname)
            os.chmod(dirname, 0o700)
        with open(filename, "wb") as sessionfile:
            os.chmod(filename, 0o600)
            self.context.save_session_to_file(sessionfile)
            self.context.log("Saved session to '%s'." % filename)

    def load_session_from_file(
        self, username: str, filename: Optional[str] = None
    ) -> None:
        """Internally stores :class:`requests.Session` object loaded from file.

        If filename is None, the file with the default session path is loaded.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if filename is None:
            filename = get_default_session_filename(username)
        with open(filename, "rb") as sessionfile:
            self.context.load_session_from_file(username, sessionfile)
            self.context.log("Loaded session from '%s'." % filename)

    def test_login(self) -> Optional[str]:
        """Returns the Instagram username to which given :class:`requests.Session` object belongs, or None.

        Returns:
            Optional[str]: Instagram username if logged in, None otherwise.
        """
        return self.context.test_login()

    def login(self, user: str, passwd: str) -> None:
        """Log in to instagram with given username and password and internally store session object.

        Args:
            user: Instagram username
            passwd: Instagram password
        Raises:
            BadCredentialsException: If the provided password is wrong.
            TwoFactorAuthRequiredException: First step of 2FA login done, now call :meth:`Igdownloader.two_factor_login`.
            LoginException: An error happened during login (for example, an invalid response was received), or if the provided username does not exist.
        """
        self.context.login(user, passwd)

    def two_factor_login(self, two_factor_code) -> None:
        """Second step of login if 2FA is enabled.

        Not meant to be used directly, use :meth:`Igdownloader.two_factor_login`.

        Args:
            two_factor_code: 2FA verification code
        Raises:
            InvalidArgumentException: No two-factor authentication pending.
            BadCredentialsException: 2FA verification code invalid.
        """
        self.context.two_factor_login(two_factor_code)

    def interactive_login(self, username: str) -> None:
        """Logs in and internally stores session, asking user for password interactively.

        Args:
            username: Instagram username to log in as
        Raises:
            InvalidArgumentException: when in quiet mode.
            LoginException: If the provided username does not exist.
            ConnectionException: If connection to Instagram failed.
        """
        if self.context.quiet:
            raise InvalidArgumentException(
                "Quiet mode requires given password or valid session file."
            )
        try:
            password = None
            while password is None:
                password = getpass.getpass(
                    prompt="Enter Instagram password for %s: " % username
                )
                try:
                    self.login(username, password)
                except BadCredentialsException as err:
                    print(err, file=sys.stderr)
                    password = None
        except TwoFactorAuthRequiredException:
            while True:
                try:
                    code = input("Enter 2FA verification code: ")
                    self.two_factor_login(code)
                    break
                except BadCredentialsException as err:
                    print(err, file=sys.stderr)

    @_requires_login
    def get_posts(
        self,
        username: str,
        output_dir: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve all posts for a given username, saving metadata and assets to output directory.

        Args:
            username: Instagram username to fetch posts for
            output_dir: Base directory in which to save data
        Returns:
            List[Dict[str, Any]]: List of post metadata dicts.
        """
        self.context.log(f"Preparing to retrieve posts for user '{username}'...")
        self.context.prepare_target(username, output_dir)
        all_posts = list(self.paginate_posts())
        return all_posts

    def paginate_posts(
        self,
        username: Optional[str] = None,
        output_dir: Optional[str] = None,
        after: str = None,
        _posts: List = None,
    ) -> List[Dict[str, Any]]:
        """Recursively paginate through all posts for a given username.

        Args:
            username: Instagram username to fetch posts for
            output_dir: Directory to save output files
            after: Cursor for pagination (None for first request)
            _posts: Accumulated list of posts (used internally for recursion)

        Returns:
            List[Dict[str, Any]]: List of all posts from all pages
        """
        if username and output_dir:
            self.context.prepare_target(username, output_dir)

        target = username or self.context.target
        posts = _posts or []

        self.context.log(f"Fetching posts (cursor: {after})...")

        variables = IGFeedRequestVariables(
            after=after,
            count=12,
            username=target,
        ).to_dict()

        response = self.context.doc_id_graphql_query(
            self.context.browser_defaults.DOC_ID.value, variables
        )

        # Navigate to the posts data structure
        # timeline_data = response.get("data", {}).get(
        #     "xdt_api__v1__feed__user_timeline_graphql_connection", {}
        # )
        # edges = timeline_data.get("edges", [])
        # page_info = timeline_data.get("page_info", {})

        timeline_data = dataclass_from_dict(
            TimelineData,
            TimelineData(
                response.get("data", {}).get(
                    "xdt_api__v1__feed__user_timeline_graphql_connection", {}
                )
            ).__dict__,
        )  # type: TimelineData

        feed_data = timeline_data.xdt_api__v1__feed__user_timeline_graphql_connection
        edges = feed_data.edges
        page_info = feed_data.page_info

        for post in edges:
            self._extract_asset(post)

        # Add current page's posts
        posts.extend(edges)

        # Check if there are more pages
        has_next_page = page_info.get("has_next_page", False)
        end_cursor = page_info.get("end_cursor")

        if has_next_page and end_cursor:
            # Recursive call with the next cursor
            return self.paginate_posts(
                username, output_dir, after=end_cursor, _posts=posts
            )
        else:
            self.context.log(f"Pagination complete. Total posts fetched: {len(posts)}")
            return posts

    def _extract_asset(self, post: Dict[str, Any]) -> None:
        """Extract and download media asset from a post edge.

        Args:
            post: A single post edge from the API response
        """
        self.context.write_json(
            post,
            self.context.post_metadata_file,
            log=False,
        )

        node = post.get("node", {})
        videos = node.get("video_versions", None)

        media = dataclass_from_dict(
            PostNode,
            {
                "id": node.get("id"),
                "code": node.get("code"),
                "taken_at": node.get("taken_at"),
                "image_versions2": node.get("image_versions2", {}),
                "video_versions": (
                    [dataclass_from_dict(VideoCandidate, v) for v in videos]
                    if videos
                    else None
                ),
            },
        )

        # TODO: Does iphone endpoint provide higher quality assets?
        # self.get_iphone_json(path='api/v1/media/{}/info/'.format(media.id), params={})

        media_asset = self.extract_asset_info(media)

        if media_asset and media_asset.url:
            self.context.write(
                media_asset.url,
                self.context.asset_urls_file,
            )
            self.context.write_json(
                media_asset.__dict__,
                self.context.asset_json_file,
            )
            self.download_asset(
                media_asset,
                self.context.asset_dir,
            )

    @staticmethod
    def extract_asset_info(media: PostNode, index: int = 0) -> Optional[IGAsset]:
        """Extract the image URL from a post's image_versions2.candidates, using the specified index.

        Args:
            media: PostNode object containing media information
            index: Index of the candidate to extract (default is 0 for largest image)

        Returns:
            IGAsset: An IGAsset object containing media details, or None if no media found
        """

        # node = post.get("node", {})
        # image_versions2 = node.get("image_versions2", {})
        # candidates = image_versions2.get("candidates", [])
        # video_versions = node.get("video_versions", [])
        image_candidates = media.image_versions2.candidates
        video_versions = media.video_versions
        media_asset = IGAsset(
            id=media.id,
            code=media.code,
            date=convert_timestamp(media.taken_at, pretty=True),
            timestamp=media.taken_at,
        )

        # If it's a video post, return the video URL
        if video_versions and len(video_versions) > 0:
            ext = AssetExtensions.VID.value
            url = video_versions[index].url
            media_asset.ext = ext
            media_asset.url = url
            return media_asset

        elif image_candidates and len(image_candidates) > 0:
            ext = AssetExtensions.PIC.value
            url = image_candidates[index].url
            media_asset.ext = ext
            media_asset.url = url
            return media_asset

        return None

    @_retry_on_connection_error
    def download_asset(
        self,
        media: IGAsset,
        output_dir: str,
        _attempt: int = 1,
    ) -> bool:
        """Download a single image from a URL to the specified directory.

        Retries on connection errors.

        Args:
            media: IGAsset object containing media details
            output_dir: Directory to save the downloaded image
            _attempt: Current attempt number for retry logic (used internally)

        Returns:
            bool: True if download was successful, False otherwise
        """
        try:
            self.context.log(
                "Downloading {} from '{}'...".format(
                    (AssetExtensions[media.ext.upper()].value.lower()),
                    media.url,
                )
            )

            # Download the image
            response = requests.get(media.url, timeout=30)
            response.raise_for_status()

            # Extract filename from URL or create one based on timestamp
            filename = f"{media.id}_{media.code}_{convert_timestamp(media.timestamp)}.{media.ext}"
            filepath = os.path.join(output_dir, filename)

            # Save the image
            self.context.write_raw(response.content, filepath)

            return True

        except Exception as e:
            self.context.error(f"Failed to download image from {media.url}: {e}")
            return False
