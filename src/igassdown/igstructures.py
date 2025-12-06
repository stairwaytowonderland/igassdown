from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class IGFeedRequestVariables:
    """Variables for Instagram feed GraphQL requests.

    Attributes:
        username: Instagram username to fetch posts for.
        after: Cursor for pagination (None for first request).
        before: Cursor for pagination (None for first request).
        data: Additional data for the request.
        first: Number of posts to fetch per request.
        last: Not used, always None.
        relay_internal__pv__PolarisIsLoggedInrelayprovider: Internal flag for Instagram.
    """

    username: str
    after: Optional[str] = None
    before: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    first: int = 12
    last: Optional[int] = None
    relay_internal__pv__PolarisIsLoggedInrelayprovider: bool = True

    def __init__(self, username: str, count: int = 12, after: Optional[str] = None):
        """Initialize IGFeedRequestVariables.

        Args:
            username: Instagram username to fetch posts for.
            after: Cursor for pagination (None for first request).
            count: Number of posts to fetch per request.
        """
        self.username = username
        self.after = after
        self.before = None
        self.data = {"count": count}
        self.first = count
        self.last = None
        self.relay_internal__pv__PolarisIsLoggedInrelayprovider = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert IGFeedRequestVariables to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of IGFeedRequestVariables.
        """
        return {
            "after": self.after,
            "before": self.before,
            "data": self.data,
            "first": self.first,
            "last": self.last,
            "username": self.username,
            "__relay_internal__pv__PolarisIsLoggedInrelayprovider": self.relay_internal__pv__PolarisIsLoggedInrelayprovider,
        }


@dataclass
class ImageCandidate:
    url: str
    width: int
    height: int


@dataclass
class VideoCandidate:
    url: str
    width: int
    height: int
    type: Optional[int] = None


@dataclass
class ImageCandidates:
    candidates: List[ImageCandidate]


@dataclass
class PostNode:
    id: str
    code: str
    taken_at: int
    image_versions2: ImageCandidates
    video_versions: Optional[List[ImageCandidate]] = None


@dataclass
class FeedData:
    edges: List[Dict[str, Any]]
    page_info: Dict[str, Any]


@dataclass
class TimelineData:
    xdt_api__v1__feed__user_timeline_graphql_connection: FeedData
