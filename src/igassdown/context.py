import json
import logging
import os
import pickle
import random
import shutil
import sys
import textwrap
import time
import urllib.parse
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import requests
import requests.utils

from .config import BrowserDefaults, Config, IphoneDefaults, StandardHeaders
from .exceptions import *
from .utils import json_decode, json_encode

logger = logging.getLogger(__name__)


def copy_session(
    session: requests.Session, request_timeout: Optional[float] = None
) -> requests.Session:
    """Duplicates a requests.Session.

    Args:
        session: The requests.Session to duplicate.
        request_timeout: Optional timeout for requests made with the new session.

    Returns:
        requests.Session: A new requests.Session object with the same cookies and headers as the original.
    """
    new = requests.Session()
    new.cookies = requests.utils.cookiejar_from_dict(
        requests.utils.dict_from_cookiejar(session.cookies)
    )
    new.headers = session.headers.copy()
    # Override default timeout behavior.
    new.request = partial(new.request, timeout=request_timeout)
    return new


class SessionRequest:
    """Parameters for a JSON request to Instagram.

    Attributes:
        path: Path part of the URL (without host).
        params: Parameters for the JSON request.
        host: Host part of the URL.
        session: requests.Session to use for this request.
        response_headers: If set, the response headers will be written to this dictionary.
        use_post: Whether to use POST instead of GET for this request.
        allow_redirects: Whether to allow redirects for this request.
    """

    def __init__(
        self,
        session: requests.Session = requests.Session(),
        path: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        host: str = StandardHeaders.HOST,
        allow_redirects: bool = False,
    ):
        self._path = path
        self._params = params
        self._host = host
        self._session = session
        self._allow_redirects = allow_redirects

    """Initializes a SessionRequest instance.

    Args:
        path: Path part of the URL (without host).
        params: Parameters for the JSON request.
        host: Host part of the URL.
        session: requests.Session to use for this request.
        allow_redirects: Whether to allow redirects for this request.
    """

    @property
    def session(self) -> Optional[requests.Session]:
        return self._session

    @session.setter
    def session(self, value: Optional[requests.Session]) -> None:
        self._session = value

    @property
    def params(self) -> Optional[Dict[str, Any]]:
        return self._params

    @params.setter
    def params(self, value: Optional[Dict[str, Any]]) -> None:
        self._params = value

    @property
    def is_graphql_query(self) -> bool:
        return "query_hash" in self._params and "graphql/query" in self._path

    @property
    def is_doc_id_query(self) -> bool:
        return "doc_id" in self._params and "graphql/query" in self._path

    @property
    def is_iphone_query(self) -> bool:
        return self._host == "i.instagram.com"

    @property
    def is_other_query(self) -> bool:
        return (
            not self.is_graphql_query
            and not self.is_doc_id_query
            and self._host == "www.instagram.com"
        )

    def _normalize_args(self, keys: List[str] | Dict[str, Any], **kwargs) -> None:
        """Normalize kwargs for requests.

        Args:
            kwargs: Keyword arguments to normalize.
        Returns:
            Dict[str, Any]: Normalized keyword arguments.
        """
        if isinstance(keys, Dict):
            for key, value in keys.items():
                kwargs[key] = value

        elif isinstance(keys, List):
            for key in keys:
                if key in kwargs:
                    del kwargs[key]

        else:
            raise ValueError("keys must be a list or dict")

        return kwargs

    def get(self, url: Optional[str] = None, **kwargs) -> requests.Response:
        response = self._session.get(
            url or "https://{0}/{1}".format(self._host, self._path),
            **self._normalize_args(
                {
                    "allow_redirects": kwargs.get(
                        "allow_redirects", self._allow_redirects
                    ),
                    "params": kwargs.get("params", self._params),
                },
                **kwargs,
            ),
        )
        return response

    def post(self, url: Optional[str] = None, **kwargs) -> requests.Response:
        response = self._session.post(
            url or "https://{0}/{1}".format(self._host, self._path),
            **self._normalize_args(
                {
                    "allow_redirects": kwargs.get(
                        "allow_redirects", self._allow_redirects
                    ),
                    "data": kwargs.get("data", self._params),
                },
                **kwargs,
            ),
        )
        return response


class IgdownloaderContext:
    """Class providing methods for (error) logging and low-level communication with Instagram.

    It is not meant to be instantiated directly, rather :class:`Igdownloader` instances maintain a context
    object.

    For logging, it provides :meth:`log`, :meth:`error`, :meth:`error_catcher`.

    It provides low-level communication routines like :meth:`get_json`, :meth:`doc_id_graphql_query`,
    :meth:`get_and_write_raw` and implements mechanisms for rate controlling and error handling.

    Further, it provides methods for logging in and general session handles, which are used by that routines in
    class :class:`Igdownloader`.

    Attributes:
        config: The associated :class:`Config` object.
        sleep: Whether to sleep a short time before each request to instagram.com.
        quiet: If set, suppresses all non-error output.
        user_agent: User-Agent string to use for requests.
        request_timeout: Timeout for requests to Instagram.
        _session: The requests.Session object used for requests.
        username: The logged-in Instagram username, or None if not logged in.
        user_id: The logged-in Instagram user ID, or None if not logged in.
        max_connection_attempts: Maximum number of attempts for a single request.
        _graphql_page_length: Number of items to request per GraphQL page.
        two_factor_auth_pending: If two-factor authentication is pending, holds the necessary data to complete it.
        error_log: List of non-fatal error messages to be printed at program termination.
        _rate_controller: The RateController instance used for rate limiting.
        raise_all_errors: If set to True, disables suppression of IgdownloaderContext._error_catcher.
        fatal_status_codes: HTTP status codes that should cause an AbortDownloadException.
        profile_id_cache: Cache mapping from profile IDs to profile data.
    """

    def __init__(
        self,
        config: Config,
        sleep: bool = True,
        quiet: bool = False,
        user_agent: Optional[str] = None,
        max_connection_attempts: int = 3,
        request_timeout: float = 300.0,
        rate_controller: Optional[
            Callable[["IgdownloaderContext"], "RateController"]
        ] = None,
        fatal_status_codes: Optional[List[int]] = None,
    ):
        """Initializes an IgdownloaderContext instance.

        Args:
            config: Configuration object.
            sleep: Whether to sleep a short time before each request to instagram.com.
            quiet: If set, suppresses all non-error output.
            user_agent: User-Agent string to use for requests.
            max_connection_attempts: Maximum number of attempts for a single request.
            request_timeout: Timeout for requests to Instagram.
            rate_controller: Callable to create a RateController instance.
            fatal_status_codes: HTTP status codes that should cause an AbortDownloadException.
        """

        self.config = config
        self.sleep = sleep
        self.quiet = quiet
        self.user_agent = user_agent or config.default_user_agent()
        self.request_timeout = request_timeout
        self._session = self.get_anonymous_session()
        self.username = None
        self.user_id = None
        self.max_connection_attempts = max_connection_attempts
        self._graphql_page_length = 50
        self.two_factor_auth_pending = None
        self.iphone_headers = config.default_iphone_headers()

        # error log, filled with error() and printed at the end of Igdownloader.main()
        self.error_log: List[str] = []

        self._rate_controller = (
            rate_controller(self)
            if rate_controller is not None
            else RateController(self)
        )

        # Can be set to True for testing, disables suppression of IgdownloaderContext._error_catcher
        self.raise_all_errors = False

        # HTTP status codes that should cause an AbortDownloadException
        self.fatal_status_codes = fatal_status_codes or []

        # Cache profile from id (mapping from id to Profile)
        self.profile_id_cache: Dict[int, Any] = dict()

        self._download_count: int = 0
        self._save_count: int = 0

    @property
    def download_count(self) -> int:
        """Number of downloads performed so far.

        Returns:
            int: Number of downloads performed so far.
        """
        return self._download_count

    @download_count.setter
    def download_count(self, value: int) -> None:
        self._download_count = value

    @property
    def save_count(self) -> int:
        """Number of downloads performed so far.

        Returns:
            int: Number of downloads performed so far.
        """
        return self._save_count

    @save_count.setter
    def save_count(self, value: int) -> None:
        self._save_count = value

    @property
    def has_save_errors(self) -> bool:
        """Returns whether any download has failed to save.

        Returns:
            bool: True if any download has failed to save, False otherwise.
        """
        return self.download_count > self.save_count

    @property
    def browser_defaults(self) -> BrowserDefaults:
        """Returns the browser default settings.

        Returns:
            BrowserDefaults: The browser default settings.
        """
        return self.config.browser_defaults

    @property
    def iphone_defaults(self) -> IphoneDefaults:
        """Returns the iPhone default settings.

        Returns:
            IphoneDefaults: The iPhone default settings.
        """
        return self.config.iphone_defaults

    @property
    def default_http_headers(self) -> Dict[str, str]:
        """Returns default HTTP headers we use for requests.

        Returns:
            Dict[str, str]: Default HTTP headers.
        """
        return self.config.default_http_headers()

    @property
    def default_iphone_headers(self) -> Dict[str, str]:
        """Returns default iPhone HTTP headers we use for requests.

        Returns:
            Dict[str, str]: Default iPhone HTTP headers.
        """
        return self.config.default_iphone_headers()

    @property
    def output_dir(self) -> Path:
        """Returns the default output directory path.

        Returns:
            Path: The default output directory path.
        """
        return self.config.output_dir

    @property
    def is_logged_in(self) -> bool:
        """True, if this Igdownloader instance is logged in.

        Returns:
            bool: True if logged in, False otherwise.
        """
        return bool(self.username)

    @property
    def has_stored_errors(self) -> bool:
        """Returns whether any error has been reported and stored to be repeated at program termination.

        Returns:
            bool: True if there are stored errors, False otherwise.
        """
        return bool(self.error_log)

    def close(self) -> None:
        """Print error log and close session"""
        if self.error_log and not self.quiet:
            print("\nErrors or warnings occurred:", file=sys.stderr)
            for err in self.error_log:
                print(err, file=sys.stderr)
        self._session.close()

    @contextmanager
    def anonymous_copy(self):
        """Yield an anonymous, otherwise equally-configured copy of this IgdownloaderContext; Then copy its error log.

        Yields:
            An anonymous IgdownloaderContext instance.
        """
        session = self._session
        username = self.username
        user_id = self.user_id
        iphone_headers = self.iphone_headers
        self._session = self.get_anonymous_session()
        self.username = None
        self.user_id = None
        self.iphone_headers = self.config.default_iphone_headers()
        try:
            yield self
        finally:
            self._session.close()
            self.username = username
            self._session = session
            self.user_id = user_id
            self.iphone_headers = iphone_headers

    @contextmanager
    def error_catcher(self, extra_info: Optional[str] = None):
        """Context manager to catch, print and record IgdownloaderExceptions.

        Args:
            extra_info: String to prefix error message with.
        Yields:
            None
        Raises:
            IgdownloaderException: If an IgdownloaderException is caught.
        """
        try:
            yield
        except IgdownloaderException as err:
            if extra_info:
                self.error("{}: {}".format(extra_info, err))
            else:
                self.error("{}".format(err))
            if self.raise_all_errors:
                raise

    def print_log(self, *msg, sep="", end="\n", flush=False) -> None:
        """Log a message to stdout that can be suppressed with --quiet.

        Args:
            *msg: Variable length argument list to be printed.
            sep: Separator between arguments.
            end: String appended after the last value.
            flush: Whether to forcibly flush the stream.
        """
        if not self.quiet:
            print(*msg, sep=sep, end=end, flush=flush)

    def log(
        self,
        msg,
        *args,
        print_args: Optional[Dict[str, Any]] = None,
        print_only: bool = False,
        **kwargs,
    ) -> None:
        """Log a message to stdout that can be suppressed with --quiet.

        Args:
            *msg: Variable length argument list to be printed.
            sep: Separator between arguments.
            end: String appended after the last value.
            flush: Whether to forcibly flush the stream.
        """
        if not self.quiet:
            if print_only:
                kwargs.update(print_args or {})
                self.print_log(*msg, **kwargs)
            else:
                logger.info(msg, *args, **kwargs)

    def print_error(self, msg) -> None:
        """Log a non-fatal error message to stderr, which is repeated at program termination.

        Args:
            msg: Message to be printed.
            repeat_at_end: Set to false if the message should be printed, but not repeated at program termination.
        """
        print(msg, file=sys.stderr)

    def error(
        self,
        msg,
        *args,
        repeat_at_end=False,
        print_args: Optional[Dict[str, Any]] = None,
        print_only: bool = False,
        **kwargs,
    ) -> None:
        """Log a non-fatal error message to stderr, which is repeated at program termination.

        Args:
            msg: Message to be printed.
            repeat_at_end: Set to false if the message should be printed, but not repeated at program termination.
        """
        if print_only:
            kwargs.update(print_args or {})
            self.print_error(msg, **kwargs)
        else:
            logger.error(msg, *args, **kwargs)
        if repeat_at_end:
            print(msg, file=sys.stderr)

    def get_anonymous_session(self) -> requests.Session:
        """Returns our default anonymous requests.Session object.

        Returns:
            requests.Session: A new anonymous session object.
        """
        session = requests.Session()
        session.cookies.update(
            {
                "sessionid": "",
                "mid": "",
                "ig_pr": "1",
                "ig_vw": "1920",
                "csrftoken": "",
                "s_network": "",
                "ds_user_id": "",
            }
        )
        session.headers.update(
            self.config.default_http_headers(empty_session_only=True)
        )
        # Override default timeout behavior.
        session.request = partial(session.request, timeout=self.request_timeout)
        return session

    def save_session(self) -> dict:
        """Not meant to be used directly, use :meth:`Igdownloader.save_session`.

        Returns:
            dict: A dictionary representation of the current session cookies.
        """
        return requests.utils.dict_from_cookiejar(self._session.cookies)

    def update_cookies(self, cookie) -> None:
        """Update session cookies.

        Args:
            cookie: Cookies to update the session with.
        """
        self._session.cookies.update(cookie)

    def load_session(self, username, sessiondata) -> None:
        """Not meant to be used directly, use :meth:`Igdownloader.load_session`.

        Args:
            username: Instagram username
            sessiondata: Session data to load
        """
        session = requests.Session()
        session.cookies = requests.utils.cookiejar_from_dict(sessiondata)
        session.headers.update(self.config.default_http_headers())
        session.headers.update({"X-CSRFToken": session.cookies.get_dict()["csrftoken"]})
        # Override default timeout behavior.
        session.request = partial(session.request, timeout=self.request_timeout)
        self._session = session
        self.username = username

    def save_session_to_file(self, sessionfile) -> None:
        """Save session to a file.

        Not meant to be used directly, use :meth:`Igdownloader.save_session_to_file`.

        Args:
            sessionfile: A file-like object to write the session data to.
        """
        pickle.dump(self.save_session(), sessionfile)

    def load_session_from_file(self, username, sessionfile) -> None:
        """Not meant to be used directly, use :meth:`Igdownloader.load_session_from_file`.

        Args:
            username: Instagram username
            sessionfile: A file-like object to read the session data from.
        """
        self.load_session(username, pickle.load(sessionfile))

    def test_login(self) -> Optional[str]:
        """Not meant to be used directly, use :meth:`Igdownloader.test_login`.

        Returns:
            Optional[str]: The username if login is successful, None otherwise.
        """
        try:
            self.log("Testing login for username '%s'..." % self.username)
            data = self.username_query(self.username)
            user_id = self.user_id = (
                data["data"]["user"]["id"] if data["data"]["user"] is not None else None
            )
            self.log("Login OK, user id '%s'." % user_id)
            # gql = self.graphql_query("d6f4427fbe92d846298cf93df0b937d3", {})
            return (
                data["data"]["user"]["username"]
                if data["data"]["user"] is not None
                else None
            )
        except (AbortDownloadException, ConnectionException) as err:
            self.error(f"Error when checking if logged in: {err}")
            return None

    def login(self, user, passwd) -> None:
        """Not meant to be used directly, use :meth:`Igdownloader.login`.

        Args:
            user: Instagram username
            passwd: Instagram password
        Raises:
            BadCredentialsException: If the provided password is wrong.
            TwoFactorAuthRequiredException: First step of 2FA login done, now call :meth:`Igdownloader.two_factor_login`.
            LoginException: An error happened during login (for example, and invalid response), or if the provided username does not exist.
        """
        # pylint:disable=import-outside-toplevel
        import http.client

        # pylint:disable=protected-access
        http.client._MAXHEADERS = 200
        session = requests.Session()
        session.cookies.update(
            {
                "sessionid": "",
                "mid": "",
                "ig_pr": "1",
                "ig_vw": "1920",
                "ig_cb": "1",
                "csrftoken": "",
                "s_network": "",
                "ds_user_id": "",
            }
        )
        session.headers.update(self.config.default_http_headers())
        # Override default timeout behavior.
        session.request = partial(session.request, timeout=self.request_timeout)

        # Make a request to Instagram's root URL, which will set the session's csrftoken cookie
        # Not using self.get_json() here, because we need to access the cookie
        # session.get("https://www.instagram.com/")
        request = SessionRequest(session)
        request.get("https://www.instagram.com/")

        # Add session's csrftoken cookie to session headers
        csrf_token = session.cookies.get_dict()["csrftoken"]
        request.session.headers.update({"X-CSRFToken": csrf_token})

        self.do_sleep()
        enc_password = "#PWD_INSTAGRAM_BROWSER:0:{}:{}".format(
            int(datetime.now().timestamp()), passwd
        )
        login = request.post(
            "https://www.instagram.com/api/v1/web/accounts/login/ajax/",
            data={"enc_password": enc_password, "username": user},
            allow_redirects=True,
        )
        try:
            resp_json = login.json()

        except json.decoder.JSONDecodeError as err:
            raise LoginException(
                "Login error: JSON decode fail, {} - {}.".format(
                    login.status_code, login.reason
                )
            ) from err
        if resp_json.get("two_factor_required"):
            two_factor_session = copy_session(session, self.request_timeout)
            two_factor_session.headers.update({"X-CSRFToken": csrf_token})
            two_factor_session.cookies.update({"csrftoken": csrf_token})
            self.two_factor_auth_pending = (
                two_factor_session,
                user,
                resp_json["two_factor_info"]["two_factor_identifier"],
            )
            raise TwoFactorAuthRequiredException(
                "Login error: two-factor authentication required."
            )
        if resp_json.get("checkpoint_url"):
            raise LoginException(
                f"Login: Checkpoint required. Point your browser to {resp_json.get('checkpoint_url')} - "
                f"follow the instructions, then retry."
            )
        if resp_json["status"] != "ok":
            if "message" in resp_json:
                raise LoginException(
                    'Login error: "{}" status, message "{}".'.format(
                        resp_json["status"], resp_json["message"]
                    )
                )
            else:
                raise LoginException(
                    'Login error: "{}" status.'.format(resp_json["status"])
                )
        if "authenticated" not in resp_json:
            if "message" in resp_json:
                raise LoginException(
                    'Login error: Unexpected response, "{}".'.format(
                        resp_json["message"]
                    )
                )
            else:
                raise LoginException(
                    "Login error: Unexpected response, this might indicate a blocked IP."
                )
        if not resp_json["authenticated"]:
            if resp_json["user"]:
                # '{"authenticated": false, "user": true, "status": "ok"}'
                raise BadCredentialsException("Login error: Wrong password.")
            else:
                # '{"authenticated": false, "user": false, "status": "ok"}'
                # Raise LoginException rather than BadCredentialException, because BadCredentialException
                # triggers re-asking of password in Igdownloader.interactive_login(), which makes no sense if the
                # username is invalid.
                raise LoginException(
                    "Login error: User {} does not exist.".format(user)
                )
        # '{"authenticated": true, "user": true, "userId": ..., "oneTapPrompt": false, "status": "ok"}'
        request.session.headers.update({"X-CSRFToken": login.cookies["csrftoken"]})
        self._session = request.session
        self.username = user
        self.user_id = resp_json["userId"]

    def two_factor_login(self, two_factor_code) -> None:
        """Second step of login if 2FA is enabled.

        Not meant to be used directly, use :meth:`Igdownloader.two_factor_login`.

        Args:
            two_factor_code: 2FA verification code
        Raises:
            InvalidArgumentException: No two-factor authentication pending.
            BadCredentialsException: 2FA verification code invalid.
        """

        if not self.two_factor_auth_pending:
            raise InvalidArgumentException("No two-factor authentication pending.")
        (session, user, two_factor_id) = self.two_factor_auth_pending

        login = SessionRequest(session).post(
            "https://www.instagram.com/accounts/login/ajax/two_factor/",
            data={
                "username": user,
                "verificationCode": two_factor_code,
                "identifier": two_factor_id,
            },
            allow_redirects=True,
        )
        resp_json = login.json()
        if resp_json["status"] != "ok":
            if "message" in resp_json:
                raise BadCredentialsException(
                    "2FA error: {}".format(resp_json["message"])
                )
            else:
                raise BadCredentialsException(
                    '2FA error: "{}" status.'.format(resp_json["status"])
                )
        session.headers.update({"X-CSRFToken": login.cookies["csrftoken"]})
        self._session = session
        self.username = user
        self.two_factor_auth_pending = None
        self.user_id = resp_json["userId"]

        if not self.quiet:
            print("Two-factor authentication successful.")

    def prepare_target(self, username: str, output_dir: str) -> None:
        """Prepare file paths for target profile.

        Args:
            username: Target profile username.
            output_dir: Directory to resolve relative file paths against.
        Raises:
            InvalidArgumentException: If the target file could not be read.
        """
        self.log(f"Preparing directory '{output_dir}'.")

        dir = f"{output_dir}/{username}"
        asset_dir = f"{dir}/assets"
        Path(asset_dir).mkdir(parents=True, exist_ok=True)

        self.target = username
        self.asset_dir = asset_dir
        self.asset_urls_file = f"{dir}/{username}_urls.txt"
        self.asset_json_file = f"{dir}/{username}_media.json"
        self.post_metadata_file = f"{dir}/{username}_posts.json"

        open(self.post_metadata_file, "w").close()
        open(self.asset_json_file, "w").close()
        open(self.asset_urls_file, "w").close()

    def do_sleep(self) -> None:
        """Sleep a short time if self.sleep is set. Called before each request to instagram.com."""
        if self.sleep:
            time.sleep(min(random.expovariate(0.6), 15.0))

    @staticmethod
    def _response_error(resp: requests.Response) -> str:
        """Generate an error message from a requests.Response object.

        Args:
            resp: The requests.Response object.
        Returns:
            A string describing the error.
        """
        extra_from_json: Optional[str] = None
        with suppress(json.decoder.JSONDecodeError):
            resp_json = resp.json()
            if "status" in resp_json:
                extra_from_json = (
                    f"\"{resp_json['status']}\" status, message \"{resp_json['message']}\""
                    if "message" in resp_json
                    else f"\"{resp_json['status']}\" status"
                )
        return (
            f"{resp.status_code} {resp.reason}"
            f"{f' - {extra_from_json}' if extra_from_json is not None else ''}"
            f" when accessing {resp.url}"
        )

    def get_json(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        host: str = StandardHeaders.HOST,
        session: Optional[requests.Session] = None,
        response_headers: Optional[Dict[str, Any]] = None,
        use_post: bool = False,
        allow_redirects: bool = False,
        _attempt=1,
    ) -> Dict[str, Any]:
        """JSON request to Instagram.

        Args:
            path: Path part of the URL (without host).
            params: Parameters for the JSON request.
            host: Host part of the URL.
            session: requests.Session to use for this request.
            response_headers: If set, the response headers will be written to this dictionary.
            use_post: Whether to use POST instead of GET for this request.
            allow_redirects: Whether to allow redirects for this request.
            _attempt: Current attempt number for this request.

        Returns:
            Dict[str, Any]: The decoded JSON response as a dictionary.

        Raises:
            AbortDownloadException: When the server responds with 'feedback_required'/'checkpoint_required'/'challenge_required'
            QueryReturnedBadRequestException: When the server responds with a 400 (and not 'feedback_required'/'checkpoint_required'/'challenge_required').
            QueryReturnedNotFoundException: When the server responds with a 404.
            ConnectionException: When query repeatedly failed.
        """
        request = SessionRequest(
            session or self._session,
            path,
            params,
            host,
            allow_redirects,
        )
        try:
            self.do_sleep()
            if request.is_graphql_query:
                self._rate_controller.wait_before_query(params["query_hash"])
            if request.is_doc_id_query:
                self._rate_controller.wait_before_query(params["doc_id"])
            if request.is_iphone_query:
                self._rate_controller.wait_before_query("iphone")
            if request.is_other_query:
                self._rate_controller.wait_before_query("other")
            if use_post:
                response = request.post(params=params)
            else:
                response = request.get(params=params)
            if response.status_code in self.fatal_status_codes:
                redirect = (
                    " redirect to {}".format(response.headers["location"])
                    if "location" in response.headers
                    else ""
                )
                body = ""
                if response.headers["Content-Type"].startswith("application/json"):
                    body = (
                        ": "
                        + response.text[:500]
                        + ("…" if len(response.text) > 501 else "")
                    )
                raise AbortDownloadException(
                    'Query to https://{}/{} responded with "{} {}"{}{}'.format(
                        host,
                        path,
                        response.status_code,
                        response.reason,
                        redirect,
                        body,
                    )
                )
            while response.is_redirect:
                redirect_url = response.headers["location"]
                self.log(
                    "\nHTTP redirect from https://{0}/{1} to {2}".format(
                        host, path, redirect_url
                    )
                )
                if redirect_url.startswith(
                    "https://www.instagram.com/accounts/login"
                ) or redirect_url.startswith("https://i.instagram.com/accounts/login"):
                    if not self.is_logged_in:
                        raise LoginRequiredException(
                            "Redirected to login page. Use --login or --load-cookies."
                        )
                    raise AbortDownloadException(
                        "Redirected to login page. You've been logged out, please wait "
                        + "some time, recreate the session and try again"
                    )
                if redirect_url.startswith("https://{}/".format(host)):
                    response = request.get(
                        (
                            redirect_url
                            if redirect_url.endswith("/")
                            else redirect_url + "/"
                        ),
                        params=params,
                    )
                else:
                    break
            if response_headers is not None:
                response_headers.clear()
                response_headers.update(response.headers)
            if response.status_code == 400:
                with suppress(json.decoder.JSONDecodeError):
                    if response.json().get("message") in [
                        "feedback_required",
                        "checkpoint_required",
                        "challenge_required",
                    ]:
                        # Raise AbortDownloadException in case of substantial Instagram
                        # requirements to stop producing more requests
                        raise AbortDownloadException(self._response_error(response))
                raise QueryReturnedBadRequestException(self._response_error(response))
            if response.status_code == 404:
                raise QueryReturnedNotFoundException(self._response_error(response))
            if response.status_code == 429:
                raise TooManyRequestsException(self._response_error(response))
            if response.status_code != 200:
                raise ConnectionException(self._response_error(response))
            else:
                resp_json = response.json()
            if "status" in resp_json and resp_json["status"] != "ok":
                raise ConnectionException(self._response_error(response))
            return resp_json
        except (
            ConnectionException,
            json.decoder.JSONDecodeError,
            requests.exceptions.RequestException,
        ) as err:
            error_string = "JSON Query to {}: {}".format(path, err)
            if _attempt == self.max_connection_attempts:
                if isinstance(err, QueryReturnedNotFoundException):
                    raise QueryReturnedNotFoundException(error_string) from err
                else:
                    raise ConnectionException(error_string) from err
            self.error(error_string + " [retrying; skip with ^C]", repeat_at_end=False)
            try:
                if isinstance(err, TooManyRequestsException):
                    if request.is_graphql_query:
                        self._rate_controller.handle_429(params["query_hash"])
                    if request.is_doc_id_query:
                        self._rate_controller.handle_429(params["doc_id"])
                    if request.is_iphone_query:
                        self._rate_controller.handle_429("iphone")
                    if request.is_other_query:
                        self._rate_controller.handle_429("other")

                return self.get_json(
                    path,
                    params=params,
                    host=host,
                    session=session,
                    response_headers=response_headers,
                    use_post=use_post,
                    allow_redirects=allow_redirects,
                    _attempt=_attempt + 1,
                )
            except KeyboardInterrupt:
                self.error("[skipped by user]", repeat_at_end=False)
                raise ConnectionException(error_string) from err

    def graphql_query(
        self, query_hash: str, variables: Dict[str, Any], referer: Optional[str] = None
    ) -> Dict[str, Any]:
        """Do a GraphQL Query.

        Args:
            query_hash: Query hash for the query.
            variables: Variables for the Query.
            referer: HTTP referer, or None.

        Returns:
            Dict[str, Any]: The server's response dictionary.
        """
        with copy_session(self._session, self.request_timeout) as tmpsession:
            tmpsession.headers.update(
                self.config.default_http_headers(empty_session_only=True)
            )
            del tmpsession.headers["Connection"]
            del tmpsession.headers["Content-Length"]
            tmpsession.headers["authority"] = "www.instagram.com"
            tmpsession.headers["scheme"] = "https"
            tmpsession.headers["accept"] = "*/*"
            if referer is not None:
                tmpsession.headers["referer"] = urllib.parse.quote(referer)

            variables_json = json.dumps(variables, separators=(",", ":"))

            resp_json = self.get_json(
                "graphql/query",
                params={"query_hash": query_hash, "variables": variables_json},
                session=tmpsession,
            )
        if "status" not in resp_json:
            self.error('GraphQL response did not contain a "status" field.')
        return resp_json

    def doc_id_graphql_query(
        self, doc_id: str, variables: Dict[str, Any], referer: Optional[str] = None
    ) -> Dict[str, Any]:
        """Do a doc_id-based GraphQL Query using method POST.

        Args:
            doc_id: Document ID for the query.
            variables: Variables for the Query.
            referer: HTTP referer, or None.

        Returns:
            Dict[str, Any]: The server's response dictionary.
        """
        with copy_session(self._session, self.request_timeout) as tmpsession:
            tmpsession.headers.update(
                self.config.default_http_headers(empty_session_only=True)
            )
            del tmpsession.headers["Connection"]
            del tmpsession.headers["Content-Length"]
            tmpsession.headers["authority"] = "www.instagram.com"
            tmpsession.headers["scheme"] = "https"
            tmpsession.headers["accept"] = "*/*"
            if referer is not None:
                tmpsession.headers["referer"] = urllib.parse.quote(referer)

            variables_json = json.dumps(variables, separators=(",", ":"))

            resp_json = self.get_json(
                "graphql/query",
                params={
                    "variables": variables_json,
                    "doc_id": doc_id,
                    "server_timestamps": "true",
                },
                session=tmpsession,
                use_post=True,
            )
        if "status" not in resp_json:
            self.error('GraphQL response did not contain a "status" field.')
        return resp_json

    def username_query(self, username: str) -> Dict[str, Any]:
        """Get user profile information by username.

        Args:
            username: Instagram username.

        Returns:
            Dict[str, Any]: The server's response dictionary.
        """
        resp_json = self.get_iphone_json(
            f"api/v1/users/web_profile_info/?username={username}", {}
        )
        if "status" not in resp_json:
            self.error('Response did not contain a "status" field.')
        return resp_json

    def get_iphone_json(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """JSON request to ``i.instagram.com``.

        Args:
            path: URL, relative to ``i.instagram.com/``
            params: GET parameters

        Returns:
            Dict[str, Any]: Decoded response dictionary

        Raises:
            QueryReturnedBadRequestException: When the server responds with a 400.
            QueryReturnedNotFoundException: When the server responds with a 404.
            ConnectionException: When query repeatedly failed.
        """
        with copy_session(self._session, self.request_timeout) as tempsession:
            # Set headers to simulate an API request from iPad
            tempsession.headers["ig-intended-user-id"] = str(self.user_id)
            tempsession.headers["x-pigeon-rawclienttime"] = "{:.6f}".format(time.time())

            # Add headers obtained from previous iPad request
            tempsession.headers.update(self.iphone_headers)

            # Extract key information from cookies if we haven't got it already from a previous request
            header_cookies_mapping = {
                "x-mid": "mid",
                "ig-u-ds-user-id": "ds_user_id",
                "x-ig-device-id": "ig_did",
                "x-ig-family-device-id": "ig_did",
                "family_device_id": "ig_did",
            }

            # Map the cookie value to the matching HTTP request header
            cookies = tempsession.cookies.get_dict().copy()
            for key, value in header_cookies_mapping.items():
                if value in cookies:
                    if key not in tempsession.headers:
                        tempsession.headers[key] = cookies[value]
                    else:
                        # Remove the cookie value if it's already specified as a header
                        tempsession.cookies.pop(value, None)

            # Edge case for ig-u-rur header due to special string encoding in cookie
            if "rur" in cookies:
                if "ig-u-rur" not in tempsession.headers:
                    tempsession.headers["ig-u-rur"] = (
                        cookies["rur"]
                        .strip('"')
                        .encode("utf-8")
                        .decode("unicode_escape")
                    )
                else:
                    tempsession.cookies.pop("rur", None)

            # No need for cookies if we have a bearer token
            if "authorization" in tempsession.headers:
                tempsession.cookies.clear()

            response_headers = dict()  # type: Dict[str, Any]
            response = self.get_json(
                path,
                params=params,
                host="i.instagram.com",
                session=tempsession,
                response_headers=response_headers,
            )

            # Extract the ig-set-* headers and use them in the next request
            for key, value in response_headers.items():
                if key.startswith("ig-set-"):
                    self.iphone_headers[key.replace("ig-set-", "")] = value
                elif key.startswith("x-ig-set-"):
                    self.iphone_headers[key.replace("x-ig-set-", "x-ig-")] = value

            return response

    def write_raw(self, resp: Union[bytes, requests.Response], filename: str) -> None:
        """Write raw response data into a file.

        Args:
            resp: Raw response data as bytes or requests.Response with stream=True.
            filename: Filename to write data into.
        """
        # self.print_log(f"Saving asset to '{filename}'...", flush=True)
        self.log(f"Saving asset to '{filename}'...", print_args={"flush": True})
        with open(filename + ".temp", "wb") as file:
            if isinstance(resp, requests.Response):
                shutil.copyfileobj(resp.raw, file)
            else:
                file.write(resp)
        os.replace(filename + ".temp", filename)

    def read(self, filename: str) -> None:
        """Read response data from a file.

        Args:
            resp: Raw response data as bytes or requests.Response with stream=True.
            filename: Filename to write data into.
        """
        data = None
        with open(filename, "r") as file:
            data = file.read()
        return data

    def write(
        self, content: Union[str, bytes], filename: str, end="\n", log: bool = True
    ) -> None:
        """Write (append) response data into a file.

        Args:
            content: Content to write into the file.
            filename: Filename to write data into.
            end: String appended after the response.
            log: Whether to log the content being written.
        """
        with open(filename, "a") as file:
            if log:
                self.log(content, print_args={"end": end, "flush": True})
            file.write("{}{}".format(content, end))

    def write_json(
        self, content: dict, filename: str, end="\n", log: bool = True
    ) -> None:
        """Write (append) response data into a file.

        Args:
            content: Content to write into the file.
            filename: Filename to write data into.
            end: String appended after the response.
            log: Whether to log the content being written.
        """

        with open(filename, "r") as file:
            # Attempt to read the first character to check if the file is truly empty
            if not file.read(1):
                json_data = []
            else:
                # If not empty, seek back to the beginning and load the JSON
                file.seek(0)
                json_data = json_encode(file)

        json_data.append(content)

        with open(filename, "w") as file:
            if log:
                self.log(
                    json_decode(content, pretty=True),
                    print_args={"end": end, "flush": True},
                )
            # file.write(json_decode(json_data, pretty=True, file=file))
            json_decode(json_data, pretty=True, file=file)

    def get_raw(self, url: str, _attempt=1) -> requests.Response:
        """Downloads a file anonymously.

        Args:
            url: URL to download from.
            _attempt: Current attempt number for this download.

        Returns:
            requests.Response: The server's response with stream=True.

        Raises:
            QueryReturnedNotFoundException: When the server responds with a 404.
            QueryReturnedForbiddenException: When the server responds with a 403.
            ConnectionException: When download failed.
        """
        with self.get_anonymous_session() as anonymous_session:
            response = SessionRequest(anonymous_session).get(url, stream=True)
        if response.status_code == 200:
            response.raw.decode_content = True
            return response
        else:
            if response.status_code == 403:
                # suspected invalid URL signature
                raise QueryReturnedForbiddenException(self._response_error(response))
            if response.status_code == 404:
                # 404 not worth retrying.
                raise QueryReturnedNotFoundException(self._response_error(response))
            raise ConnectionException(self._response_error(response))

    def get_and_write_raw(self, url: str, filename: str) -> None:
        """Downloads and writes anonymously-requested raw data into a file.

        Args:
            url: URL to download from.
            filename: Filename to write data into.

        Raises:
            QueryReturnedNotFoundException: When the server responds with a 404.
            QueryReturnedForbiddenException: When the server responds with a 403.
            ConnectionException: When download repeatedly failed.
        """
        self.write_raw(self.get_raw(url), filename)


class RateController:
    """Class providing request tracking and rate controlling to stay within rate limits.

    It can be overridden to change Igdownloader's behavior regarding rate limits, for example to raise a custom
    exception when the rate limit is hit::

       import igdownloader

       class MyRateController(igdownloader.RateController):
           def sleep(self, secs):
               raise MyCustomException()

       L = igdownloader.Igdownloader(rate_controller=lambda ctx: MyRateController(ctx))

    Attributes:
        _context: IgdownloaderContext The context to use for logging.
        _query_timestamps: Dict[str, List[float]] Timestamps of previous requests grouped by query type.
        _earliest_next_request_time: float The earliest time when the next request can be made.
        _iphone_earliest_next_request_time: float The earliest time when the next iPhone request can be made.
    """

    def __init__(self, context: IgdownloaderContext):
        """Initialize RateController.

        Args:
            context: IgdownloaderContext The context to use for logging.
        """
        self._context = context
        self._query_timestamps: Dict[str, List[float]] = dict()
        self._earliest_next_request_time = 0.0
        self._iphone_earliest_next_request_time = 0.0

    def sleep(self, secs: float) -> None:
        """Wait given number of seconds.

        Args:
            secs: Number of seconds to wait.
        """
        # Not static, to allow for the behavior of this method to depend on context-inherent properties, such as
        # whether we are logged in.
        time.sleep(secs)

    def _dump_query_timestamps(
        self, current_time: float, failed_query_type: str
    ) -> None:
        """Log the number of requests within various sliding windows grouped by query type.

        Args:
            current_time: The current time as a float timestamp.
            failed_query_type: The query type that failed, to highlight in the log.
        """
        windows = [10, 11, 20, 22, 30, 60]
        self._context.error(
            "Number of requests within last {} minutes grouped by type:".format(
                "/".join(str(w) for w in windows)
            ),
            repeat_at_end=False,
        )
        for query_type, times in self._query_timestamps.items():
            reqs_in_sliding_window = [
                sum(t > current_time - w * 60 for t in times) for w in windows
            ]
            self._context.error(
                " {} {:>32}: {}".format(
                    "*" if query_type == failed_query_type else " ",
                    query_type,
                    " ".join("{:4}".format(reqs) for reqs in reqs_in_sliding_window),
                ),
                repeat_at_end=False,
            )

    def count_per_sliding_window(self, query_type: str) -> int:
        """Return how many requests of the given type can be done within a sliding window of 11 minutes.

        This is called by :meth:`RateController.query_waittime` and allows to simply customize wait times before queries
        at query_type granularity. Consider overriding :meth:`RateController.query_waittime` directly if you need more
        control.

        Args:
            query_type: The query type for which the count is requested.

        Returns:
            int: The number of requests allowed within the sliding window.
        """
        # Not static, to allow for the count_per_sliding_window to depend on context-inherent properties, such as
        # whether we are logged in.
        return 75 if query_type == "other" else 200

    def _reqs_in_sliding_window(
        self, query_type: Optional[str], current_time: float, window: float
    ) -> List[float]:
        """Return timestamps of requests within the given sliding window.

        Args:
            query_type: The query type for which the timestamps are requested. If None, all GraphQL query types
                (i.e. not 'iphone' or 'other') are considered.
            current_time: The current time as a float timestamp.
            window: The sliding window size in seconds.

        Returns:
            List[float]: List of timestamps of requests within the sliding window.
        """

        if query_type is not None:
            # timestamps of type query_type
            relevant_timestamps = self._query_timestamps[query_type]
        else:
            # all GraphQL queries, i.e. not 'iphone' or 'other'
            graphql_query_timestamps = filter(
                lambda tp: tp[0] not in ["iphone", "other"],
                self._query_timestamps.items(),
            )
            relevant_timestamps = [
                t for times in (tp[1] for tp in graphql_query_timestamps) for t in times
            ]
        return list(filter(lambda t: t > current_time - window, relevant_timestamps))

    def query_waittime(
        self, query_type: str, current_time: float, untracked_queries: bool = False
    ) -> float:
        """Calculate time needed to wait before query can be executed.

        Args:
            query_type: The query type for which the wait time is requested.
            current_time: The current time as a float timestamp.
            untracked_queries: Whether untracked queries have been made since last query.

        Returns:
            float: The number of seconds to wait before the query can be executed.
        """
        per_type_sliding_window = 660
        iphone_sliding_window = 1800
        if query_type not in self._query_timestamps:
            self._query_timestamps[query_type] = []
        self._query_timestamps[query_type] = list(
            filter(
                lambda t: t > current_time - 60 * 60, self._query_timestamps[query_type]
            )
        )

        def per_type_next_request_time():
            reqs_in_sliding_window = self._reqs_in_sliding_window(
                query_type, current_time, per_type_sliding_window
            )
            if len(reqs_in_sliding_window) < self.count_per_sliding_window(query_type):
                return 0.0
            else:
                return min(reqs_in_sliding_window) + per_type_sliding_window + 6

        def gql_accumulated_next_request_time():
            if query_type in ["iphone", "other"]:
                return 0.0
            gql_accumulated_sliding_window = 600
            gql_accumulated_max_count = 275
            reqs_in_sliding_window = self._reqs_in_sliding_window(
                None, current_time, gql_accumulated_sliding_window
            )
            if len(reqs_in_sliding_window) < gql_accumulated_max_count:
                return 0.0
            else:
                return min(reqs_in_sliding_window) + gql_accumulated_sliding_window

        def untracked_next_request_time():
            if untracked_queries:
                if query_type == "iphone":
                    reqs_in_sliding_window = self._reqs_in_sliding_window(
                        query_type, current_time, iphone_sliding_window
                    )
                    self._iphone_earliest_next_request_time = (
                        min(reqs_in_sliding_window) + iphone_sliding_window + 18
                    )
                else:
                    reqs_in_sliding_window = self._reqs_in_sliding_window(
                        query_type, current_time, per_type_sliding_window
                    )
                    self._earliest_next_request_time = (
                        min(reqs_in_sliding_window) + per_type_sliding_window + 6
                    )
            return max(
                self._iphone_earliest_next_request_time,
                self._earliest_next_request_time,
            )

        def iphone_next_request():
            if query_type == "iphone":
                reqs_in_sliding_window = self._reqs_in_sliding_window(
                    query_type, current_time, iphone_sliding_window
                )
                if len(reqs_in_sliding_window) >= 199:
                    return min(reqs_in_sliding_window) + iphone_sliding_window + 18
            return 0.0

        return max(
            0.0,
            max(
                per_type_next_request_time(),
                gql_accumulated_next_request_time(),
                untracked_next_request_time(),
                iphone_next_request(),
            )
            - current_time,
        )

    def wait_before_query(self, query_type: str) -> None:
        """This method is called before a query to Instagram.

        It calls :meth:`RateController.query_waittime` to determine the time needed to wait and then calls
        :meth:`RateController.sleep` to wait until the request can be made.

        Args:
            query_type: The query type about to be made.
        """
        waittime = self.query_waittime(query_type, time.monotonic(), False)
        assert waittime >= 0
        if waittime > 15:
            formatted_waittime = (
                "{} seconds".format(round(waittime))
                if waittime <= 666
                else "{} minutes".format(round(waittime / 60))
            )
            self._context.log(
                "\nToo many queries in the last time. Need to wait {}, until {:%H:%M}.".format(
                    formatted_waittime, datetime.now() + timedelta(seconds=waittime)
                )
            )
        if waittime > 0:
            self.sleep(waittime)
        if query_type not in self._query_timestamps:
            self._query_timestamps[query_type] = [time.monotonic()]
        else:
            self._query_timestamps[query_type].append(time.monotonic())

    def handle_429(self, query_type: str) -> None:
        """This method is called to handle a 429 Too Many Requests response.

        It calls :meth:`RateController.query_waittime` to determine the time needed to wait and then calls
        :meth:`RateController.sleep` to wait until we can repeat the same request.

        Args:
            query_type: The query type that caused the 429 response.
        """
        current_time = time.monotonic()
        waittime = self.query_waittime(query_type, current_time, True)
        assert waittime >= 0
        self._dump_query_timestamps(current_time, query_type)
        text_for_429 = (
            'Instagram responded with HTTP error "429 - Too Many Requests". Please do not run multiple '
            "instances of Igdownloader in parallel or within short sequence. Also, do not use any Instagram "
            "App while Igdownloader is running."
        )
        self._context.error(textwrap.fill(text_for_429), repeat_at_end=False)
        if waittime > 1.5:
            formatted_waittime = (
                "{} seconds".format(round(waittime))
                if waittime <= 666
                else "{} minutes".format(round(waittime / 60))
            )
            self._context.error(
                "The request will be retried in {}, at {:%H:%M}.".format(
                    formatted_waittime, datetime.now() + timedelta(seconds=waittime)
                ),
                repeat_at_end=False,
            )
        if waittime > 0:
            self.sleep(waittime)
