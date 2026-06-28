#!/usr/bin/env python3

# Karol Siedlaczek 2026

import json
import logging
import base64
import hmac
import hashlib
import binascii
import typer
import click
import requests
from logging.handlers import RotatingFileHandler
from enum import Enum
from getpass import getpass
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Optional, NoReturn
from rich.console import Console
from rich.table import Table, box

ENV_VAR_API_URL = "MAILCTL_API_URL"
ENV_VAR_TOKEN = "MAILCTL_TOKEN"
ENV_VAR_LOG_FILE = "MAILCTL_LOG_FILE"
ENV_VAR_LOG_LEVEL = "MAILCTL_LOG_LEVEL"
SETTINGS_FILE = Path("~/.mailctl").expanduser()
LOGGER = logging.getLogger("mailctl-cli")
QUOTA_UNITS = {
    "B": 1,
    "KB": 1024,
    "MB": 1024 ** 2,
    "GB": 1024 ** 3,
    "TB": 1024 ** 4,
}

app = typer.Typer(add_completion=True, help="CLI for managing mailboxes via Mail controller")
domain_app = typer.Typer(help="Manage domains")
user_app = typer.Typer(help="Manage mailboxes")
forward_app = typer.Typer(help="Manage forwardings")
sendas_app = typer.Typer(help="Manage send-as (sender-login) grants")
token_app = typer.Typer(help="Token identity / scope / HMAC generation")
app.add_typer(domain_app, name="domain")
app.add_typer(user_app, name="user")
app.add_typer(forward_app, name="forward")
app.add_typer(sendas_app, name="sendas")
app.add_typer(token_app, name="token")
console = Console()

# ── base classes ────────────────────────────────────────────────────────

class ExitCode(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


class Format(Enum):
    TABLE = "table"
    JSON = "json"
    KEY_VALUE = "kv"
    VALUE = "value"

    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]

    @classmethod
    def default(cls) -> "Format":
        return Format.TABLE

    @classmethod
    def from_string(cls, val: str) -> "Format":
        try:
            return Format(val)
        except ValueError:
            raise typer.BadParameter(f"Unknown format: {val}, must be one of: {', '.join(Format.values())}")


class AuditEventType(str, Enum):
    AUTH = "auth"
    DELIVERY = "delivery"
    SEND = "send"


class Opt:
    @staticmethod
    def timeout(default: int = 10) -> Any:
        return typer.Option(
            default, "--timeout", "-t", 
            help="API request timeout in seconds"
        )

    @staticmethod
    def format(default: str | None = None) -> Any:
        return typer.Option(
            default or Format.default().value, "--format", "-f",
            help=f"Output format: {', '.join(Format.values())}"
        )

    @staticmethod
    def columns() -> Any:
        return typer.Option(
            None, "-c", "--column",
            help="Column(s) to include; repeat for multiple"
        )

    @staticmethod
    def domain() -> Any:
        return typer.Option(
            None, "-d", "--domain",
            help="Filter by domain"
        )

    @staticmethod
    def quota(default: str | None = 0) -> Any:
        return typer.Option(
            default, "--quota",
            help="Mailbox quota with unit, e.g. 500B, 256MB, 2GB (0 = unlimited)"
        )

    @staticmethod
    def filter(help: str = "Case-insensitive substring filter") -> Any:
        return typer.Option(
            None, "--filter",
            help=help
        )

    @staticmethod
    def active() -> Any:
        return typer.Option(
            None, "--active/--inactive",
            help="Filter by active state"
        )

    @staticmethod
    def created_since() -> Any:
        return typer.Option(
            None, "--created-since",
            help="Only entries created since this timestamp (e.g. 2026-06-01)"
        )

    @staticmethod
    def created_until() -> Any:
        return typer.Option(
            None, "--created-until",
            help="Only entries created up to this timestamp (e.g. 2026-06-30)"
        )


@dataclass
class Settings:
    api_url: str | None
    token: str | None
    log_file: str | None
    log_level: str | None
    format: Format | None


@dataclass
class CmdResult:
    data: dict | list[dict]
    exit_code: ExitCode

    @classmethod
    def from_response(
        cls,
        response: requests.Response,
        exit_code: ExitCode | None = None
    ) -> "CmdResult":
        data = cls._parse_response(response)
        exit_code = exit_code or (ExitCode.OK if response.ok else ExitCode.CRITICAL)

        return cls(data, exit_code)

    @classmethod
    def from_dict(
        cls,
        data: dict | list[dict],
        exit_code: ExitCode | None = None
    ) -> "CmdResult":
        return cls(data, exit_code or ExitCode.OK)

    @staticmethod
    def _parse_response(response: requests.Response) -> dict | list[dict]:
        try:
            payload = response.json()
        except ValueError:
            return {"message": response.text}

        if not isinstance(payload, dict):
            return payload

        payload.pop("timestamp", None)
        if response.ok:
            payload = payload.get("data", payload)

        return payload

    def _filter_data(self, columns: tuple[str] | None = None) -> Any:
        if not columns:
            return self.data

        available_columns: set[str] = set()

        if isinstance(self.data, dict):
            available_columns = set(self.data.keys())
        elif isinstance(self.data, list):
            for row in self.data:
                if isinstance(row, dict):
                    available_columns.update(row.keys())

        missing_columns = [col for col in columns if col not in available_columns]
        if missing_columns:
            possible_columns = ", ".join(sorted(available_columns)) if available_columns else "<none>"
            missing = ", ".join(missing_columns)
            raise typer.BadParameter(f"Unknown column(s): {missing}, available choices: {possible_columns}")

        if isinstance(self.data, list):
            filtered_data = []
            for row in self.data:
                if isinstance(row, dict):
                    filtered_data.append({col: row.get(col) for col in columns})
                else:
                    filtered_data.append(row)
            return filtered_data

        if isinstance(self.data, dict):
            return {col: self.data.get(col) for col in columns}

        return self.data

    def _mask_sensitive(self, obj: Any, sensitive: set[str]) -> Any:
        if not sensitive:
            return obj

        if isinstance(obj, dict):
            out: dict[Any, Any] = {}
            for k, v in obj.items():
                if isinstance(k, str) and k in sensitive:
                    out[k] = "****"
                else:
                    out[k] = self._mask_sensitive(v, sensitive)
            return out

        if isinstance(obj, list):
            return [self._mask_sensitive(x, sensitive) for x in obj]

        return obj

    def render_and_exit(
        self,
        context_info: str | None = None,
        columns: tuple[str] | None = None,
        *,
        sensitive_columns: tuple[str] | None = None
    ) -> NoReturn:
        def _convert_val_as_str(val: Any) -> str:
            if isinstance(val, (dict, list)):
                return json.dumps(val, ensure_ascii=False)
            return str(val)

        def _render_field(key: Any, val: Any, key_width: int) -> str:
            key_as_str = str(key)
            val_as_str = _convert_val_as_str(val)
            return f"{key_as_str:<{key_width}} = {val_as_str}"

        def _render_table_cell(value) -> str:
            def format_kv_block(obj: dict, indent: str = "  ") -> str:
                key_width = max((len(str(k)) for k in obj.keys()), default=0)
                lines = []
                for k in sorted(obj.keys(), key=lambda x: str(x)):
                    v = obj[k]
                    if isinstance(v, (dict, list)):
                        v_str = json.dumps(v, ensure_ascii=False)
                    else:
                        v_str = str(v)
                    lines.append(f"{indent}{str(k):<{key_width}} = {v_str}")
                return "\n".join(lines)

            if value is None:
                return "-"

            if isinstance(value, dict):
                if not value:
                    return "{}"
                return format_kv_block(value, indent="")

            if isinstance(value, list):
                if not value:
                    return "-"

                if all(isinstance(x, dict) for x in value):
                    blocks = []
                    for i, item in enumerate(value, start=1):
                        header = f"• #{i}"
                        blocks.append(header)
                        blocks.append(format_kv_block(item, indent="  "))
                    return "\n".join(blocks)

                lines = []
                for item in value:
                    if isinstance(item, dict):
                        lines.append("•")
                        lines.append(format_kv_block(item, indent="  "))
                    elif isinstance(item, list):
                        lines.append("• " + json.dumps(item, ensure_ascii=False))
                    else:
                        lines.append(f"• {item}")
                return "\n".join(lines)
            return str(value)

        def _print(value: Any = "") -> None:
            if self.exit_code == ExitCode.OK:
                console.print(value)
                return
            if isinstance(value, str):
                console.print(value, style="red", markup=False, highlight=False)
                return
            console.print(value, style="red", highlight=False)

        data = self._filter_data(columns) if self.exit_code == ExitCode.OK else self.data
        settings = get_ctx_settings()
        fmt = settings.format

        if fmt == Format.JSON:
            _print(json.dumps(data, indent=2, ensure_ascii=False))
        elif fmt == Format.VALUE:
            if isinstance(data, dict):
                for val in data.values():
                    _print(_convert_val_as_str(val))
            elif isinstance(data, list):
                if all(isinstance(item, dict) for item in data):
                    for item in data:
                        for val in item.values():
                            _print(_convert_val_as_str(val))
                        if item != data[-1]: # Do not print on last iteration
                            _print()
                else:
                    for item in data:
                        _print(item)
        elif fmt == Format.KEY_VALUE:
            if isinstance(data, dict):
                key_width = max((len(str(key)) for key in data.keys()), default=0)
                for key, val in data.items():
                    _print(_render_field(key, val, key_width))

            elif isinstance(data, list):
                if all(isinstance(item, dict) for item in data):
                    key_width = max((len(str(key)) for item in data for key in item.keys()), default=0)

                    for item in data:
                        for key, val in item.items():
                            _print(_render_field(key, val, key_width))
                        if item != data[-1]: # Do not print on last iteration
                            _print()
                else:
                    for item in data:
                        _print(item)
            else:
                _print(data)
        elif fmt == Format.TABLE:
            rows = data if isinstance(data, list) else [data]
            rows = [r for r in rows if isinstance(r, dict)]
            if rows:
                table = Table(show_header=True, header_style="bold", expand=True, show_lines=True, box=box.ROUNDED)

                cols = list(rows[0].keys())
                for c in cols:
                    table.add_column(str(c), overflow="fold") # Fold helps if mucho text

                for row in rows:
                    table.add_row(*[_render_table_cell(row.get(c, "")) for c in cols])
                _print(table)
            elif data:
                _print(data)

        data_to_log = data
        if not LOGGER.disabled and sensitive_columns:
            data_to_log = self._mask_sensitive(data, sensitive_columns)

        LOGGER.log(
            logging.INFO if self.exit_code == ExitCode.OK else logging.ERROR,
            f"{f'Result for {context_info} command: ' if context_info else ''}{data_to_log}"
        )
        raise typer.Exit(code=self.exit_code.value)


@dataclass(frozen=True)
class Client:
    base_url: str
    session: requests.Session
    timeout: int

    @classmethod
    def init(
        cls,
        ctx: typer.Context,
        fmt: str | None,
        *,
        timeout: int
    ) -> "Client":
        settings = load_settings(ctx, fmt)

        base_url = settings.api_url.rstrip("/")
        session = requests.Session()
        if settings.token:
            session.headers.update({"Authorization": f"Bearer {settings.token}"})
        session.headers.update({"Accept": "application/json"})
        try:
            session.request("GET", f"{base_url}/ping", timeout=10)
        except requests.RequestException as e:
            CmdResult.from_dict({"msg": "Error connecting to API server", "error": str(e)},
                                ExitCode.CRITICAL).render_and_exit()
        return cls(base_url, session, timeout or 10)

    def request(
        self,
        method: str,
        path: str,
        *,
        params=None,
        json_body=None
    ) -> "requests.Response":
        return self.session.request(method=method.upper(), url=f"{self.base_url}{path}",
                                    params=params, json=json_body, timeout=self.timeout)


# ── callback + root commands ───────────────────────────────────────────────────────────


@app.callback()
def main(
    ctx: typer.Context,
    api_url: str = typer.Option(
        None, "-u", "--api-url",
        envvar=ENV_VAR_API_URL,
        help=f"API base URL (env {ENV_VAR_API_URL} or API_URL in {SETTINGS_FILE})"
    ),
    token: str = typer.Option(
        None, "-T", "--token",
        envvar=ENV_VAR_TOKEN,
        help=f"Bearer token <id>.<token> (env {ENV_VAR_TOKEN} or TOKEN in {SETTINGS_FILE})"
    ),
    log_file: str = typer.Option(
        None, "--log-file",
        envvar=ENV_VAR_LOG_FILE
    ),
    log_level: str = typer.Option(
        None, "--log-level",
        envvar=ENV_VAR_LOG_LEVEL
    )
) -> None:
    ctx.obj = Settings(api_url=api_url, token=token, log_file=log_file, log_level=log_level, format=None)


@app.command(help="Versions and author")
def version(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/version")
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


# ── token commands ───────────────────────────────────────────────────────────


@token_app.command(name = "scope", help="Permissions for the current identity")
def token_scope(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/token/scope")
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@token_app.command(name = "identity", help="Current identity (allowed CIDRs, permissions)")
def token_identity(
    ctx: typer.Context,
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/token/identity")
    result = CmdResult.from_response(response)

    if isinstance(result.data, dict) and result.data.get("permissions"):
        result.data["permissions"] = [f"{p['scope']}:{p['action']}" for p in result.data["permissions"]]
    return result.render_and_exit(ctx.info_name, columns)


@token_app.command(name="gen-hmac", help="Generate TOKEN_<ID>_HMAC for server configuration")
def token_gen_hmac(
    hmac_key_b64: str = typer.Option(
        None, "--hmac-key-b64",
        help="Base64 HMAC key (≥32 bytes); prompted if omitted"
    ),
    token_id: str = typer.Option(
        None, "--id", "-i",
        help="Identity id; prompted if omitted"
    ),
    token_value: str = typer.Option(
        None, "--token", "-T",
        help="Raw token; prompted if omitted"
    )
) -> None:
    if token_id is None:
        token_id = input("Token ID: ").strip()
    if hmac_key_b64 is None:
        hmac_key_b64 = getpass("HMAC key (base64): ").strip()
    if token_value is None:
        t1, t2 = getpass("Token value: ").strip(), getpass("Confirm token value: ").strip()
        
        if t1 != t2:
            raise typer.BadParameter("Token values do not match")
        if not t1:
            raise typer.BadParameter("Token value cannot be empty")
        token_value = t1
        
    try:
        hmac_key = base64.b64decode(hmac_key_b64, validate=True)
    except binascii.Error:
        raise typer.BadParameter(
            "Invalid HMAC key: not valid base64.\n"
            "Generate a new one with:\n"
            "  openssl rand -base64 32\n\n"
            "NOTE !!!\nHMAC key must match server HMAC_KEY_B64"
        )
    
    if len(hmac_key) < 32:
        raise typer.BadParameter(
            "Invalid HMAC key: decoded key must be at least 32 bytes.\n"
            "Generate a secure key with:\n"
            "  openssl rand -base64 32\n\n"
            "NOTE !!!\nHMAC key must match server HMAC_KEY_B64"
        )
    
    token = str(token_value).encode()
    digest = hmac.new(hmac_key, token, hashlib.sha256).hexdigest()
    
    typer.secho("\nSuccess!\n", fg=typer.colors.GREEN)
    print("Add the following environment variable to the server:")
    print(f"TOKEN_{token_id.upper()}_HMAC={digest}\n")


# ── domain commands ────────────────────────────────────────────────────────────────────


@domain_app.command("list", help="List domains")
def domain_list(
    ctx: typer.Context,
    filter: str = Opt.filter("Filter by domain name (substring)"),
    active: Optional[bool] = Opt.active(),
    created_since: Optional[str] = Opt.created_since(),
    created_until: Optional[str] = Opt.created_until(),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    params: dict[str, Any] = {}
    if filter:
        params["filter"] = filter
    if active is not None:
        params["active"] = active
    if created_since:
        params["created_since"] = created_since
    if created_until:
        params["created_until"] = created_until
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/domains", params=params or None)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@domain_app.command("add", help="Add a domain")
def domain_add(
    ctx: typer.Context,
    domain: str = typer.Argument(...),
    dkim_selector: str = typer.Option(None, "--dkim-selector"),
    active: bool = typer.Option(True, "--active/--inactive"),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    body = {"domain": domain, "active": active}
    if dkim_selector:
        body["dkim_selector"] = dkim_selector
        
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("POST", "/api/domains", json_body=body)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@domain_app.command("show", help="Show a domain")
def domain_show(
    ctx: typer.Context,
    domain: str = typer.Argument(...),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", f"/api/domains/{domain}")
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@domain_app.command("set", help="Update a domain (dkim selector / active)")
def domain_set(
    ctx: typer.Context,
    domain: str = typer.Argument(...),
    dkim_selector: str = typer.Option(None, "--dkim-selector"),
    active: Optional[bool] = typer.Option(None, "--active/--inactive"),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    body: dict[str, Any] = {}
    if dkim_selector is not None:
        body["dkim_selector"] = dkim_selector
    if active is not None:
        body["active"] = active
        
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("PATCH", f"/api/domains/{domain}", json_body=body)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@domain_app.command("rm", help="Delete a domain")
def domain_rm(
    ctx: typer.Context,
    domain: str = typer.Argument(...),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("DELETE", f"/api/domains/{domain}")
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


# ── user commands ────────────────────────────────────────────────────────────────────────


@user_app.command("list", help="List mailboxes")
def user_list(
    ctx: typer.Context,
    domain: str = Opt.domain(),
    filter: str = Opt.filter("Filter by email (substring)"),
    active: Optional[bool] = Opt.active(),
    created_since: Optional[str] = Opt.created_since(),
    created_until: Optional[str] = Opt.created_until(),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    params: dict[str, Any] = {}
    if domain:
        params["domain"] = domain
    if filter:
        params["filter"] = filter
    if active is not None:
        params["active"] = active
    if created_since:
        params["created_since"] = created_since
    if created_until:
        params["created_until"] = created_until
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/users", params=params or None)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@user_app.command("add", help="Create a mailbox")
def user_add(
    ctx: typer.Context,
    email: str = typer.Argument(...),
    password: str = typer.Option(None, "--password", help="Prompted if omitted"),
    quota: str = Opt.quota(),
    active: bool = typer.Option(True, "--active/--inactive"),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    if not password:
        p1, p2 = getpass("Password: "), getpass("Confirm password: ")
        
        if p1 != p2:
            raise typer.BadParameter("Passwords do not match")
        if not p1:
            raise typer.BadParameter("Password cannot be empty")
        password = p1
        
    body = {
        "email": email,
        "password": password, 
        "quota_bytes": parse_quota(quota),
        "active": active
    }
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("POST", "/api/users", json_body=body)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@user_app.command("show", help="Show a mailbox")
def user_show(
    ctx: typer.Context,
    email: str = typer.Argument(...),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", f"/api/users/{email}")
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@user_app.command("passwd", help="Set/reset a mailbox password")
def user_passwd(
    ctx: typer.Context,
    email: str = typer.Argument(...),
    password: str = typer.Option(None, "--password", help="Prompted if omitted"),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    if not password:
        p1, p2 = getpass("Password: "), getpass("Confirm password: ")
        
        if p1 != p2:
            raise typer.BadParameter("Passwords do not match")
        if not p1:
            raise typer.BadParameter("Password cannot be empty")
        password = p1
        
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("POST", f"/api/users/{email}/password", json_body={"password": password})
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@user_app.command("set", help="Update a mailbox (quota / active)")
def user_set(
    ctx: typer.Context,
    email: str = typer.Argument(...),
    quota: Optional[str] = Opt.quota(),
    active: Optional[bool] = typer.Option(None, "--active/--inactive"),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    body: dict[str, Any] = {}
    if quota is not None:
        body["quota_bytes"] = parse_quota(quota)
    if active is not None:
        body["active"] = active
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("PATCH", f"/api/users/{email}", json_body=body)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@user_app.command("rm", help="Delete a mailbox")
def user_rm(
    ctx: typer.Context,
    email: str = typer.Argument(...),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("DELETE", f"/api/users/{email}")
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


# ── forwarding commands ───────────────────────────────────────────────────────────────────


@forward_app.command("list", help="List forwardings")
def forward_list(
    ctx: typer.Context,
    source: str = typer.Option(None, "--source", "-s"),
    domain: str = Opt.domain(),
    filter: str = Opt.filter("Filter by source or destination (substring)"),
    active: Optional[bool] = Opt.active(),
    keep_copy: Optional[bool] = typer.Option(None, "--keep-copy/--no-keep-copy", help="Filter by keep-copy state"),
    created_since: Optional[str] = Opt.created_since(),
    created_until: Optional[str] = Opt.created_until(),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    params: dict[str, Any] = {}
    if source:
        params["source"] = source
    if domain:
        params["domain"] = domain
    if filter:
        params["filter"] = filter
    if active is not None:
        params["active"] = active
    if keep_copy is not None:
        params["keep_copy"] = keep_copy
    if created_since:
        params["created_since"] = created_since
    if created_until:
        params["created_until"] = created_until
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/forwardings", params=params or None)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@forward_app.command("add", help="Add a forwarding")
def forward_add(
    ctx: typer.Context,
    source: str = typer.Argument(...),
    destination: str = typer.Argument(...),
    keep_copy: bool = typer.Option(False, "--keep-copy/--no-keep-copy"),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    body = {
        "source": source, 
        "destination": destination, 
        "keep_copy": keep_copy
    }
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("POST", "/api/forwardings", json_body=body)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@forward_app.command("rm", help="Delete a forwarding by id")
def forward_rm(
    ctx: typer.Context,
    fid: int = typer.Argument(...),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("DELETE", f"/api/forwardings/{fid}")
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


# ── send-as (sender_login) commands ────────────────────────────────────────────────────────


@sendas_app.command("list", help="List send-as grants")
def sendas_list(
    ctx: typer.Context,
    domain: str = Opt.domain(),
    filter: str = Opt.filter("Filter by login_email or allowed_sender (substring)"),
    active: Optional[bool] = Opt.active(),
    created_since: Optional[str] = Opt.created_since(),
    created_until: Optional[str] = Opt.created_until(),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    params: dict[str, Any] = {}
    if domain:
        params["domain"] = domain
    if filter:
        params["filter"] = filter
    if active is not None:
        params["active"] = active
    if created_since:
        params["created_since"] = created_since
    if created_until:
        params["created_until"] = created_until
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/sender-logins", params=params or None)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@sendas_app.command("grant", help="Grant: login_email may send AS allowed_sender")
def sendas_grant(
    ctx: typer.Context,
    login_email: str = typer.Argument(...),
    allowed_sender: str = typer.Argument(...),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    body = {
        "login_email": login_email, 
        "allowed_sender": allowed_sender
    }
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("POST", "/api/sender-logins", json_body=body)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


@sendas_app.command("revoke", help="Revoke a send-as grant by id")
def sendas_revoke(
    ctx: typer.Context,
    id: int = typer.Argument(...),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("DELETE", f"/api/sender-logins/{id}")
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


# ── audit commands ─────────────────────────────────────────────────────────────────────────


@app.command(help="Read the audit log")
def audit(
    ctx: typer.Context,
    login: str = typer.Option(None, "--login", help="Filter by actor login"),
    event_type: AuditEventType = typer.Option(None, "--type", help="Filter by event type"),
    since: str = typer.Option(None, "--since", help="Only entries since this timestamp (e.g. 2026-06-01)"),
    until: str = typer.Option(None, "--until", help="Only entries up to this timestamp (e.g. 2026-06-30)"),
    success: Optional[bool] = typer.Option(None, "--success/--failure", help="Filter by success state"),
    queue_id: str = typer.Option(None, "--queue-id", help="Filter by queue id"),
    message_id: str = typer.Option(None, "--message-id", help="Filter by message id"),
    host: str = typer.Option(None, "--host", help="Filter by host"),
    src_ip: str = typer.Option(None, "--src-ip", help="Filter by source IP"),
    sender: str = typer.Option(None, "--sender", help="Filter by sender"),
    recipient: str = typer.Option(None, "--recipient", help="Filter by recipient"),
    limit: int = typer.Option(100, "--limit", help="Maximum number of entries to return"),
    timeout: int = Opt.timeout(),
    format: str = Opt.format(),
    columns: list[str] = Opt.columns()
) -> None:
    params: dict[str, Any] = {"limit": limit}
    if login:
        params["login"] = login
    if event_type:
        params["event_type"] = event_type.value
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    if success is not None:
        params["success"] = success
    if queue_id:
        params["queue_id"] = queue_id
    if message_id:
        params["message_id"] = message_id
    if host:
        params["host"] = host
    if src_ip:
        params["src_ip"] = src_ip
    if sender:
        params["sender"] = sender
    if recipient:
        params["recipient"] = recipient
    client = Client.init(ctx, format, timeout=timeout)
    response = client.request("GET", "/api/audit", params=params)
    result = CmdResult.from_response(response)
    return result.render_and_exit(ctx.info_name, columns)


# ── helpers ────────────────────────────────────────────────────────────────────


def get_ctx_settings() -> Settings:
    s = click.get_current_context().obj
    if not isinstance(s, Settings):
        raise typer.Exit(code=2)
    return s


def setup_logging(log_file: str | None, log_level: str | None) -> None:
    if not log_file:
        LOGGER.disabled = True
        return
    logger = logging.getLogger()
    if any(getattr(h, "_mailctl_handler", False) for h in logger.handlers):
        return
    level = getattr(logging, (log_level or "INFO").upper(), None)
    if not isinstance(level, int):
        raise typer.BadParameter(f"Unknown log level: {log_level}")
    handler = RotatingFileHandler(log_file, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="UTF-8")
    handler._mailctl_handler = True
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s [pid=%(process)d] [%(name)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    logger.setLevel(level)


def load_settings(ctx: typer.Context, fmt: str | None = None) -> Settings:
    settings = ctx.obj
    if not isinstance(settings, Settings):
        raise typer.Exit(code=2)
    
    file_settings: dict[str, str] = {}
    if SETTINGS_FILE.exists():
        mode = SETTINGS_FILE.stat().st_mode & 0o777
        if mode != 0o600:
            raise typer.BadParameter(
                f"Invalid permissions for {SETTINGS_FILE}: expected 600, got {mode:o}; run: chmod 600 {SETTINGS_FILE}"
            )
        for line in SETTINGS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            
            k, v = line.split("=", 1)
            file_settings[k.strip().upper()] = v.strip()
            
    if not settings.api_url:
        settings.api_url = file_settings.get("API_URL")
    if not settings.token:
        settings.token = file_settings.get("TOKEN")
    if not settings.log_file:
        settings.log_file = file_settings.get("LOG_FILE")
    if not settings.log_level:
        settings.log_level = file_settings.get("LOG_LEVEL")
        
    setup_logging(settings.log_file, settings.log_level)
    settings.format = Format.from_string(fmt)
    
    if not settings.api_url:
        raise typer.BadParameter(
            f"Provide --api-url, set {ENV_VAR_API_URL}, or add API_URL=<value> in {SETTINGS_FILE}"
        )
    return settings


def parse_quota(value: str | None) -> int | None:
    """Parse a quota string like '256MB' or '2GB' into bytes. Bare numbers are bytes."""
    if value is None:
        return None

    text = value.strip().upper()
    if not text:
        raise typer.BadParameter("Quota cannot be empty")

    unit = "B"
    for suffix in ("TB", "GB", "MB", "KB", "B"):
        if text.endswith(suffix):
            unit = suffix
            text = text[: -len(suffix)].strip()
            break

    try:
        number = float(text)
    except ValueError:
        units = ", ".join(QUOTA_UNITS)
        raise typer.BadParameter(f"Invalid quota: {value}, expected a number with optional unit ({units})")

    if number < 0:
        raise typer.BadParameter("Quota cannot be negative")

    return int(number * QUOTA_UNITS[unit])


if __name__ == "__main__":
    app(prog_name="mailctl")
