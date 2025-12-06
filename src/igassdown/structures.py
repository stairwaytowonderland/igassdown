from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from .config import StandardHeaders


@dataclass
class JSONRequest:
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

    path: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    host: str = StandardHeaders.HOST
    session: Optional[requests.Session] = None
    response_headers: Optional[Dict[str, Any]] = None
    use_post: bool = False
    allow_redirects: bool = False


@dataclass
class IGAsset:
    """Represents an Instagram media asset.

    Attributes:
        url: URL of the media asset.
        code: Shortcode of the Instagram post.
        taken_at: Timestamp when the media was taken.
    """

    id: str
    code: str
    date: str
    timestamp: int
    ext: Optional[str] = None
    url: Optional[str] = None
