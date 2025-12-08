import random
import uuid
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Union


class BrowserDefaults(Enum):
    """Default values for browser emulation.

    Attributes:
        USER_AGENT: The default User-Agent string for browser emulation.
        APP_ID: The default application ID for browser emulation.
        DOC_ID: The default document ID for browser emulation.
    """

    USER_AGENT: str = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
    )
    APP_ID: str = "936619743392459"
    DOC_ID: str = "32820268350897851"


class IphoneDefaults(Enum):
    """Default values for iPhone emulation.

    Attributes:
        USER_AGENT: The default User-Agent string for iPhone emulation.
        APP_ID: The default application ID for iPhone emulation.
        BLOCKS_VERSION_ID: The default blocks version ID for iPhone emulation.
        CAPABILITIES: The default capabilities string for iPhone emulation.
        HTTP_ENGINE: The default HTTP engine for iPhone emulation.
    """

    USER_AGENT: str = (
        "Instagram 361.0.0.35.82 (iPad13,8; iOS 18_0; en_US; en-US; scale=2.00; 2048x2732; 674117118) AppleWebKit/420+"
    )
    APP_ID: str = "124024574287414"
    BLOCKS_VERSION_ID: str = (
        "16b7bd25c6c06886d57c4d455265669345a2d96625385b8ee30026ac2dc5ed97"
    )
    CAPABILITIES: str = "36r/F/8="
    HTTP_ENGINE: str = "Liger"


class StandardHeaders:
    """Default HTTP header values.

    Attributes:
        ACCEPT_ENCODING: Value for the Accept-Encoding header.
        ACCEPT_LANGUAGE: Value for the Accept-Language header.
        CONNECTION: Value for the Connection header.
        CONTENT_LENGTH: Value for the Content-Length header.
        HOST: Value for the Host header.
        ORIGIN: Value for the Origin header.
        REFERER: Value for the Referer header.
        USER_AGENT: Value for the User-Agent header.
        X_INSTAGRAM_AJAX: Value for the X-Instagram-AJAX header.
        X_REQUESTED_WITH: Value for the X-Requested-With header.
    """

    ACCEPT_ENCODING: str = "gzip, deflate"
    ACCEPT_LANGUAGE: str = "en-US,en;q=0.8"
    CONNECTION: str = "keep-alive"
    CONTENT_LENGTH: int = 0
    ORIGIN: str = "https://www.instagram.com"
    HOST: str = "www.instagram.com"
    REFERER: str = "https://www.instagram.com/"
    USER_AGENT: str = BrowserDefaults.USER_AGENT.value
    X_INSTAGRAM_AJAX: int = 1
    X_REQUESTED_WITH: str = "XMLHttpRequest"

    def __init__(
        self,
        user_agent: str = BrowserDefaults.USER_AGENT.value,
        additional_headers: Dict[str, Union[str, int]] = {},
    ) -> None:
        self.ACCEPT_ENCODING = additional_headers.get(
            "Accept-Encoding", self.ACCEPT_ENCODING
        )
        self.ACCEPT_LANGUAGE = additional_headers.get(
            "Accept-Language", self.ACCEPT_LANGUAGE
        )
        self.CONNECTION = additional_headers.get("Connection", self.CONNECTION)
        self.ACCEPT_LANGUAGE = additional_headers.get(
            "Accept-Language", self.ACCEPT_LANGUAGE
        )
        self.CONNECTION = additional_headers.get("Connection", self.CONNECTION)
        self.CONTENT_LENGTH = additional_headers.get(
            "Content-Length", self.CONTENT_LENGTH
        )
        self.HOST = additional_headers.get("Host", self.HOST)
        self.ORIGIN = additional_headers.get("Origin", self.ORIGIN)
        self.REFERER = additional_headers.get("Referer", self.REFERER)
        self.USER_AGENT = additional_headers.get("User-Agent", user_agent)
        self.X_INSTAGRAM_AJAX = additional_headers.get(
            "X-Instagram-AJAX", self.X_INSTAGRAM_AJAX
        )
        self.X_REQUESTED_WITH = additional_headers.get(
            "X-Requested-With", self.X_REQUESTED_WITH
        )

    """Initialize StandardHeaders with optional custom values.

    Args:
        user_agent: Custom User-Agent string.
        additional_headers: Dictionary of additional headers to override defaults.
    """

    def for_empty(self) -> Dict[str, Union[str, int]]:
        """Sets headers suitable for an anonymous session.

        Returns:
            Dict[str, Union[str, int]]: A dictionary of HTTP headers for an anonymous session
        """

        headers = self.to_dict()
        remove = ["Host", "Origin", "X-Instagram-AJAX", "X-Requested-With"]
        for key in remove:
            headers.pop(key, None)

        return headers

    def for_iphone(self) -> Dict[str, Union[str, int]]:
        """Sets headers suitable for iPhone emulation.

        Returns:
            Dict[str, Union[str, int]]: A dictionary of HTTP headers for iPhone emulation
        """

        headers = self.to_dict()
        remove = ["Host", "Origin", "Referer", "X-Instagram-AJAX", "X-Requested-With"]
        for key in remove:
            headers.pop(key, None)
        # headers["User-Agent"] = IphoneDefaults.USER_AGENT.value
        return headers

    def to_dict(self) -> Dict[str, Union[str, int]]:
        """Returns the headers as a dictionary.

        Returns:
            Dict[str, Union[str, int]]: A dictionary of HTTP headers.
        """
        return {
            "Accept-Encoding": self.ACCEPT_ENCODING,
            "Accept-Language": self.ACCEPT_LANGUAGE,
            "Connection": self.CONNECTION,
            "Content-Length": str(self.CONTENT_LENGTH),
            "Host": self.HOST,
            "Origin": self.ORIGIN,
            "Referer": self.REFERER,
            "User-Agent": str(self.USER_AGENT),
            "X-Instagram-AJAX": str(self.X_INSTAGRAM_AJAX),
            "X-Requested-With": self.X_REQUESTED_WITH,
        }


class Config:
    """Default output directory.

    Attributes:
        output_dir: The default output directory path.
        browser_defaults: The default browser emulation settings.
        iphone_defaults: The default iPhone emulation settings.
    """

    def __init__(self, script_dir: Union[str, Path] = Path(__file__).parent) -> None:
        """
        Initialize the Config class.

        Args:
            script_dir: The directory of the current script.
        """
        self._output_dir = Path(f"{script_dir.parent.parent}/output")
        self._browser_defaults = BrowserDefaults
        self._iphone_defaults = IphoneDefaults

    @property
    def output_dir(self) -> Path:
        """Returns the default output directory path.

        Returns:
            Path: The default output directory path.
        """
        return self._output_dir

    @property
    def browser_defaults(self) -> BrowserDefaults:
        """Returns the browser default settings.

        Returns:
            BrowserDefaults: The browser default settings.
        """
        return self._browser_defaults

    @property
    def iphone_defaults(self) -> IphoneDefaults:
        """Returns the iPhone default settings.

        Returns:
            IphoneDefaults: The iPhone default settings.
        """
        return self._iphone_defaults

    def default_user_agent(self) -> str:
        """Returns the default browser User-Agent string.

        Returns:
            str: The default User-Agent string.
        """
        return BrowserDefaults.USER_AGENT.value

    def default_http_headers(
        self, user_agent: str = None, empty_session_only: bool = False
    ) -> Dict[str, str]:
        """Returns default HTTP header we use for requests.

        Args:
            user_agent: The User-Agent string to use. If None, uses the default browser User-Agent.
            empty_session_only: If True, returns headers suitable for an anonymous session.

        Returns:
            Dict[str, str]: A dictionary of HTTP headers.
        """

        header = StandardHeaders(user_agent)
        if empty_session_only:
            return header.for_empty()
        return header.to_dict()

    def default_iphone_headers(self) -> Dict[str, Any]:
        """Returns default HTTP headers for iPhone emulation.

        Returns:
            Dict[str, Any]: A dictionary of HTTP headers for iPhone emulation.
        """
        return StandardHeaders(
            IphoneDefaults.USER_AGENT.value,
            {
                "x-ads-opt-out": "1",
                "x-bloks-is-panorama-enabled": "true",
                "x-bloks-version-id": IphoneDefaults.BLOCKS_VERSION_ID.value,
                "x-fb-client-ip": "True",
                "x-fb-connection-type": "wifi",
                "x-fb-http-engine": IphoneDefaults.HTTP_ENGINE.value,
                "x-fb-server-cluster": "True",
                "x-fb": "1",
                "x-ig-abr-connection-speed-kbps": "2",
                "x-ig-app-id": IphoneDefaults.APP_ID.value,
                "x-ig-app-locale": "en-US",
                "x-ig-app-startup-country": "US",
                "x-ig-bandwidth-speed-kbps": "0.000",
                "x-ig-capabilities": IphoneDefaults.CAPABILITIES.value,
                "x-ig-connection-speed": "{}kbps".format(random.randint(1000, 20000)),
                "x-ig-connection-type": "WiFi",
                "x-ig-device-locale": "en-US",
                "x-ig-mapped-locale": "en-US",
                "x-ig-timezone-offset": str(
                    (
                        datetime.now().astimezone().utcoffset() or timedelta(seconds=0)
                    ).seconds
                ),
                "x-ig-www-claim": "0",
                "x-pigeon-session-id": str(uuid.uuid4()),
                "x-tigon-is-retry": "False",
                "x-whatsapp": "0",
            },
        ).for_iphone()


class AssetExtensions(str, Enum):
    """Supported file extensions.

    Attributes:
        PIC: Extension for picture files.
        VID: Extension for video files.
        JPG: MIME type for JPEG images.
        MP4: MIME type for MP4 videos.
    """

    PIC: str = "jpg"
    VID: str = "mp4"
    JPG: str = "image"
    MP4: str = "video"

    def __str__(self) -> str:
        return str(self.value)


class JsonConfig(Enum):
    """Configuration for JSON output.

    Attributes:
        INDENT: Number of spaces for indentation in JSON output.
        FILE_INDENT: Number of spaces for indentation in JSON files.
        SORT_KEYS: Whether to sort keys in JSON output.
    """

    INDENT: int = 4
    FILE_INDENT: int = 2
    SORT_KEYS: bool = False

    def __str__(self) -> str:
        return str(self.value)
