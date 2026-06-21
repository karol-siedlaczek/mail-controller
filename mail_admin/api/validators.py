from flask import request
from typing import Any, Callable, TypeVar
from mail_admin.exception.api_exceptions import InvalidRequestError

T = TypeVar("T")

def query_list(
    name: str,
    *,
    default: list[str] = None,
    required: bool = False,
    strip: bool = True
) -> list[str]:
    vals = request.args.getlist(name)
    if strip:
        vals = [v.strip() for v in vals if isinstance(v, str)]

    vals = [v for v in vals if v] # Remove empty values

    if not vals:
        if required:
            raise InvalidRequestError("Missing required query parameter", detail={ "parameter": name, "example": f"?{name}=val_1&{name}=val_2" })
        elif default:
            return default
        else:
            return []

    if "*" in vals:
        return ["*"]

    return vals


def query_str(
    name: str,
    *,
    default: str,
    required: bool = False
) -> str | None:
    val = request.args.get(name)

    if val is None:
        if required:
            raise InvalidRequestError("Missing required query parameter", detail={ "parameter": name })
        elif default:
            return default
        else:
            return None

    return str(val).strip()


def query_bool(
    name: str,
    *,
    default: bool = None,
    required: bool = False
) -> bool:
    val = request.args.get(name)

    if val is None:
        if required:
            raise InvalidRequestError("Missing required query parameter", detail={ "parameter": name })
        elif default:
            return default
        else:
            return False

    true_values = ["1", "true", "True", "yes", "Yes", ""]
    false_values = ["0", "false", "False", "no", "No"]

    if val in true_values:
        return True
    elif val in false_values:
        return False
    else:
        raise InvalidRequestError("Invalid query parameter", detail={ "parameter": name, "expected": "bool", "allowed_choices": true_values + false_values })


def query_int(
    name: str,
    *,
    default: int = None,
    required: bool = False,
    min_val: int | None = None,
    max_val: int | None = None
) -> int | None:
    raw_val = request.args.get(name)

    if raw_val is None or raw_val == "":
        if required:
            raise InvalidRequestError("Missing required query parameter", detail={ "parameter": name })
        elif default:
            return default
        else:
            return None

    try:
        val = int(raw_val)
    except ValueError:
        raise InvalidRequestError("Invalid query parameter", detail={ "parameter": name, "expected": "integer" })

    if min_val is not None and val < min_val:
        raise InvalidRequestError("Invalid query parameter", detail={ "parameter": name, "min": min_val })
    if max_val is not None and val > max_val:
        raise InvalidRequestError("Invalid query parameter", detail={ "parameter": name, "max": max_val })

    return val


def json_body(
    *,
    default: dict = None,
    required=True
) -> dict[str, Any]:
    data = request.get_json(silent=True)

    if data is None:
        if required:
            raise InvalidRequestError("Missing JSON body", detail={ "expected": "application/json" })
        if default:
            return default
        else:
            return {}

    if not isinstance(data, dict):
        raise InvalidRequestError("Invalid JSON body", detail={ "expected": "JSON object" })

    return data


def json_body_field(
    data: dict[str, Any],
    name: str,
    *,
    required: bool = True,
    cast_fn: Callable[[Any], T] | None = None
) -> T | Any | None:
    if name not in data or data[name] in (None, ""):
        if required:
            raise InvalidRequestError("Missing required JSON field in body", detail={ "field": name })
        return None

    val: Any = data[name]
    if cast_fn is None:
        return val

    try:
        return cast_fn(val)
    except Exception:
        expected_type = getattr(cast_fn, "__name__", "value")
        raise InvalidRequestError("Invalid JSON field in body", detail={ "field": name, "expected": expected_type })
