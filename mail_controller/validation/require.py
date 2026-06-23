import re
import os
import base64
import binascii
import ipaddress
import importlib.util
from mail_controller.exception.validator_exceptions import ValidationError
from pathlib import Path
from typing import Any, Match, Type, TypeVar, Pattern, Iterable

T = TypeVar("T")


class Require():
    @staticmethod
    def present(
        field: str,
        val: Any,
        custom_err: str | None = None
    ) -> None:
        if val is None or val == "":
            Require._raise_error(
                default_err=f"Field '{field}' is required",
                custom_err=custom_err
            )

    @staticmethod
    def match(
        field: str,
        val: Any,
        pattern: str | Pattern[str],
        custom_err: str | None = None
    ) -> Match[str]:
        match = re.fullmatch(pattern, str(val))
        if not match:
            Require._raise_error(
                default_err=f"Value '{field}={val}' does not match to '{pattern}' pattern",
                custom_err=custom_err
            )
        return match

    @staticmethod
    def min(
        field: str,
        val: int,
        min_val: int,
        custom_err: str | None = None
    ) -> None:
        if val < min_val:
            Require._raise_error(
                default_err=f"Value '{field}={val}' is too small, minimal value is {min_val}",
                custom_err=custom_err
            )

    @staticmethod
    def max(
        field: str,
        val: int,
        max_val: int,
        custom_err: str | None = None
    ) -> None:
        if val > max_val:
            Require._raise_error(
                default_err=f"Value '{field}={val}' is too big, maximum value is {max_val}",
                custom_err=custom_err
            )

    @staticmethod
    def min_len(
        field: str,
        val: str,
        min_len: int,
        custom_err: str | None = None
    ) -> None:
        if len(val) < min_len:
            Require._raise_error(
                default_err=f"Value '{field}={val}' is too short, minimal length is {min_len}",
                custom_err=custom_err
            )

    @staticmethod
    def port(
        field: str,
        val: int,
        custom_err: str | None = None
    ) -> None:
        min_val = 1
        max_val = 65535
        try:
            Require.type(field, val, int)
            Require.min(field, val, min_val)
            Require.max(field, val, max_val)
        except ValidationError:
            Require._raise_error(
                default_err=f"Value '{field}={val}' is not valid port number, value is out of range ({min_val}-{max_val})",
                custom_err=custom_err
            )

    @staticmethod
    def env(
        env: str,
        custom_err: str | None = None
    ) -> str:
        val = os.getenv(env)
        if not val:
            Require._raise_error(
                default_err=f"Required environment '{env}' is not set",
                custom_err=custom_err,
            )
        return val

    @staticmethod
    def envs(
        required_envs: Iterable[str],
        custom_err: str | None = None
    ) -> None:
        missing: list[str] = []

        for env in required_envs:
            val = os.getenv(env)
            if val is None:
                missing.append(env)

        if missing:
            Require._raise_error(
                default_err=f"Missing required environments: {', '.join(missing)}",
                custom_err=custom_err
            )

    @staticmethod
    def ip_address(
        field: str,
        val: str,
        custom_err: str | None = None
    ) -> None:
        try:
            ipaddress.ip_network(val, strict=False)
        except ValueError as e:
            Require._raise_error(
                default_err=f"Value '{field}={val}' is invalid CIDR, details: {e}",
                custom_err=custom_err
            )


    @staticmethod
    def email(
        field: str,
        val: str,
        custom_err: str | None = None
    ) -> None:
        email_pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
        Require.match(
            field=field,
            val=val,
            pattern=email_pattern,
            custom_err=custom_err or f"Value '{field}={val}' is not a valid email address"
        )

    @staticmethod
    def domain(
        field: str,
        val: str,
        custom_err: str | None = None
    ) -> None:
        domain_pattern = (
            r"^(?:\*\.)?" # optional wildcard
            r"(?:[a-zA-Z0-9]" # label start
            r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+" # middle labels
            r"[A-Za-z]{2,}$" # TLD
        )
        Require.match(
            field=field,
            val=val,
            pattern=domain_pattern,
            custom_err=custom_err or f"Value '{field}={val}' is not a valid domain"
        )

    @staticmethod
    def type(
        field: str,
        val: object,
        class_type: Type[T],
        custom_err: str | None = None
    ) -> None:
        if not isinstance(val, class_type):
            Require._raise_error(
                default_err=f"Value '{field}={val}' has invalid type, must be a {class_type.__name__}",
                custom_err=custom_err
            )

    @staticmethod
    def file_exists(
        field: str,
        val: str,
        custom_err: str | None = None
    ) -> Path:
        if not os.path.exists(val):
            Require._raise_error(
                default_err=f"No file found at path provided for '{field}={val}'",
                custom_err=custom_err
            )
        return Path(val).expanduser()

    @staticmethod
    def one_of(
        field: str,
        val: str,
        allowed_values: list[Any],
        custom_err: str | None = None
    ) -> None:
        if val not in allowed_values:
            Require._raise_error(
                default_err=f"Value '{field}={val}' is invalid, allowed choices: {(', ').join(allowed_values)}",
                custom_err=custom_err
            )

    @staticmethod
    def not_one_of(
        field: str,
        val: str,
        not_allowed_values: list[Any],
        custom_err: str | None = None
    ) -> None:
        if val in not_allowed_values:
            Require._raise_error(
                default_err=f"Value '{field}={val}' is duplicated, cannot be one of: {(', ').join(not_allowed_values)}",
                custom_err=custom_err
            )

    @staticmethod
    def installed_module(
        field: str,
        val: str,
        module_name: str,
        custom_err: str | None = None
    ) -> None:
        if importlib.util.find_spec(module_name) is None:
            Require._raise_error(
                default_err=f"Value '{field}={val}' requires module '{module_name}' to be installed",
                custom_err=custom_err
            )

    @staticmethod
    def base64(
        field: str,
        val: str,
        min_bytes: int = 0,
        custom_err: str | None = None
    ) -> None:
        try:
            decoded = base64.b64decode(val, validate=True)
        except binascii.Error:
            Require._raise_error(
                default_err=f"Value '{field}={val}' is not decodable base64",
                custom_err=custom_err
            )

        if len(decoded) < min_bytes:
            Require._raise_error(
                default_err=f"Value '{field}={val}' must be at least {min_bytes} bytes after decoding",
                custom_err=None
            )

    @staticmethod
    def _raise_error(
        default_err: str,
        custom_err: str | None = None
    ) -> None:
        raise ValidationError(custom_err or default_err)
