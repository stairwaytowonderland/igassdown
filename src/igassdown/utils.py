from typing import Any, Dict, List, Optional

from .config import JsonConfig


def json_decode(
    str: str,
    pretty: Optional[bool] = None,
    sort: Optional[bool] = None,
    file: bool = False,
) -> str:
    """Convert a JSON object to its string representation.

    Args:
        obj: The JSON object to convert.
        pretty: If True, returns a pretty-printed string.
        sort: If True, sorts the keys in the JSON object.
        file: If True, formats the JSON for file output.

    Returns:
        str: A string representation of the JSON object.
    """
    import json

    ind = (
        JsonConfig.INDENT.value
        if pretty and not file
        else JsonConfig.FILE_INDENT.value if file and pretty else None
    )
    sk = JsonConfig.SORT_KEYS.value if sort else None
    sep = None

    if not ind or ind <= 0:
        sep = (",", ":")

    return json.dumps(str, indent=ind, sort_keys=sk, separators=sep)


def json_encode(str: str, file: bool = False) -> Dict[str, Any]:
    """Convert a JSON string to its object representation.

    Args:
        str: The JSON string to convert.
        file: If True, treats the string as file content.

    Returns:
        Dict[str, Any]: A JSON object representation of the string.
    """
    import json

    return json.load(str) if file else json.loads(str)


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
