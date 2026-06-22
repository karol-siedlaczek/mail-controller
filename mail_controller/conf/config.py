import os
import base64
import yaml
from pathlib import Path
from typing import ClassVar, Any, cast
from dataclasses import dataclass, field
from flask import current_app as app, g
from mail_controller.validation.require import Require
from mail_controller.domain.identity import Identity
from mail_controller.security.password import SUPPORTED_SCHEMES
from mail_controller.exception.validator_exceptions import ValidationError


@dataclass(frozen=True)
class Config:
    REQUIRED_ENVS: ClassVar[set[str]] = {"HMAC_KEY_B64", "PG_HOST", "PG_DBNAME", "PG_USER"}
    ALLOWED_LOG_LEVELS: ClassVar[set[str]] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    log_level: str = "INFO"
    logs_dir: str = "/logs"
    conf_file: str = "/config/config.yaml"
    pg_host: str = None
    pg_port: int = 5432
    pg_dbname: str = None
    pg_user: str = None
    pg_password: str = None
    password_scheme: str = "ARGON2ID"
    hmac_key: bytes = None
    identities: list[Identity] = field(default_factory=list)

    @classmethod
    def load(cls) -> "Config":
        Require.envs(cls.REQUIRED_ENVS)

        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        Require.one_of("LOG_LEVEL", log_level, list(cls.ALLOWED_LOG_LEVELS))

        Require.base64("HMAC_KEY_B64", os.getenv("HMAC_KEY_B64"), 32)
        hmac_key = base64.b64decode(os.getenv("HMAC_KEY_B64"), validate=True)

        pg_port = int(os.getenv("PG_PORT", "5432"))
        Require.port("PG_PORT", pg_port)

        password_scheme = os.getenv("PASSWORD_SCHEME", "ARGON2ID").upper()
        Require.one_of("PASSWORD_SCHEME", password_scheme, list(SUPPORTED_SCHEMES))

        pg_password = cls._resolve_secret("PG_PASSWORD")

        conf_file = os.getenv("CONF_FILE", "/config/config.yaml")
        conf_path = Require.file_exists("CONF_FILE", conf_file)
        try:
            raw_conf = yaml.safe_load(conf_path.read_text(encoding="UTF-8")) or {}
        except yaml.YAMLError as e:
            raise ValidationError(f"Failed to parse '{conf_file}' as YAML: {e}")

        try:
            identities = cls._parse_identities(raw_conf.get("identities"))
        except ValidationError as e:
            raise ValidationError(f"Failed to parse '{conf_file}': {e}")

        return cls(
            log_level=log_level,
            logs_dir=os.getenv("LOGS_DIR", "/logs"),
            conf_file=conf_file,
            pg_host=os.getenv("PG_HOST"),
            pg_port=pg_port,
            pg_dbname=os.getenv("PG_DBNAME"),
            pg_user=os.getenv("PG_USER"),
            pg_password=pg_password,
            password_scheme=password_scheme,
            hmac_key=hmac_key,
            identities=identities,
        )

    @staticmethod
    def _resolve_secret(name: str) -> str | None:
        file_var = f"{name}__FILE"
        if os.getenv(file_var):
            path = Require.file_exists(file_var, os.getenv(file_var))
            return path.read_text(encoding="UTF-8").rstrip("\n")
        return os.getenv(name)

    @staticmethod
    def _parse_identities(identities_raw: Any) -> list[Identity]:
        if identities_raw is None:
            return []
        Require.type("identities", identities_raw, list)
        identities: list[Identity] = []
        for i, item in enumerate(identities_raw):
            Require.type(f"identities[{i}]", item, dict)
            Require.not_one_of(f"identities[{i}].id", item.get("id"), [x.id for x in identities])
            try:
                identities.append(Identity.from_dict(item))
            except ValidationError as e:
                raise ValidationError(f"Error found at identities[{i}]: {e}")
        return identities

    @staticmethod
    def get_from_global_context() -> "Config":
        if "conf" not in g:
            g.conf = cast(Config, app.extensions["config"])
        return g.conf
