import json
from io import TextIOWrapper
from typing import Any, Dict, List, Optional, Union

from .config import JsonConfig


def json_decode(
    str: str,
    pretty: Optional[bool] = None,
    sort: Optional[bool] = None,
    file: Optional[TextIOWrapper] = None,
    **kwargs,
) -> str:
    """Convert a JSON object to its string representation.

    Args:
        obj: The JSON object to convert.
        pretty: If True, returns a pretty-printed string.
        sort: If True, sorts the keys in the JSON object.
        file: If True, formats the JSON for file output.
        **kwargs: Additional keyword arguments for json.dumps/json.dump.

    Returns:
        str: A string representation of the JSON object.
    """
    ind = (
        JsonConfig.INDENT.value
        if pretty and not file
        else JsonConfig.FILE_INDENT.value if file is not None and pretty else None
    )
    sk = JsonConfig.SORT_KEYS.value if sort else None
    sep = None

    if not ind or ind <= 0:
        sep = (",", ":")

    if file is not None:
        json.dump(str, file, indent=ind, sort_keys=sk, separators=sep, **kwargs)

    return json.dumps(str, indent=ind, sort_keys=sk, separators=sep, **kwargs)


def json_encode(str: Union[TextIOWrapper, str], **kwargs) -> Dict[str, Any]:
    """Convert a JSON string to its object representation.

    Args:
        str: The JSON string to convert.
        **kwargs: Additional keyword arguments for json.loads/json.load.

    Returns:
        Dict[str, Any]: A JSON object representation of the string.
    """
    is_file = isinstance(str, TextIOWrapper)

    return json.load(str, **kwargs) if is_file else json.loads(str, **kwargs)


def dataclass_from_dict(klass, dikt):
    """Convert a dictionary to a dataclass object.

    Args:
        klass: The dataclass type to convert to.
        dikt: The dictionary to convert.

    Returns:
        The dataclass object.
    """
    try:
        fieldtypes = klass.__annotations__
        return klass(**{f: dataclass_from_dict(fieldtypes[f], dikt[f]) for f in dikt})
    except AttributeError:
        if isinstance(dikt, (tuple, list)):
            return [dataclass_from_dict(klass.__args__[0], f) for f in dikt]
        return dikt


def asdikt(obj) -> Dict[str, Any] | List[Any]:
    """Convert a dataclass object to a dictionary.

    Args:
        obj: The dataclass object to convert.
        jsonify: If True, returns a JSON object instead of a dictionary.

    Returns:
        Dict[str, Any] | List[Any]: A dictionary representation of the dataclass object.
    """
    if hasattr(obj, "__dataclass_fields__"):
        result = {}
        for field in obj.__dataclass_fields__:
            value = getattr(obj, field)
            if hasattr(value, "__dataclass_fields__"):
                result[field] = asdikt(value)
            elif isinstance(value, list):
                result[field] = [
                    asdikt(item) if hasattr(item, "__dataclass_fields__") else item
                    for item in value
                ]
            else:
                result[field] = value
        return result
    elif isinstance(obj, dict):
        return {
            key: asdikt(value) if hasattr(value, "__dataclass_fields__") else value
            for key, value in obj.items()
        }
    elif isinstance(obj, (list, tuple)):
        return [
            asdikt(item) if hasattr(item, "__dataclass_fields__") else item
            for item in obj
        ]
    else:
        raise ValueError(
            "Provided object is invalid; expected dataclass/dict/list/tuple, got {}".format(
                type(obj)
            )
        )


def convert_timestamp(timestamp: int, pretty: bool = False) -> str:
    """Convert a UNIX timestamp to a human-readable string.

    Args:
        timestamp: The UNIX timestamp to convert.
        pretty: If True, returns a more human-readable format.

    Returns:
        str: A formatted date string.
    """
    from datetime import datetime

    return datetime.fromtimestamp(timestamp).strftime(
        "%Y%m%d_%H%M%S" if not pretty else "%Y-%m-%d %H:%M:%S"
    )
